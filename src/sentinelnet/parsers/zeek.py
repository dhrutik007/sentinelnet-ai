"""Zeek JSON log parser (conn, dns, http, ssl, notice).

Zeek's JSON writer emits either epoch-seconds timestamps (default) or ISO-8601
(``use_json_ts_format``). Both are accepted. Field names may be flat
(``id.orig_h``) or nested (``id: {orig_h}``). Missing optional fields are
tolerated; fields needed to place the event in time are required.

Nothing here infers payload content: for encrypted traffic (ssl) only the
metadata Zeek actually observed (SNI, version) is recorded.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from sentinelnet.parsers.common import (
    IngestContext,
    ParseError,
    UnsupportedRecord,
    decode_json_object,
    opt_int,
    opt_str,
    parse_iso_utc,
)
from sentinelnet.schema import (
    AttrValue,
    EventSource,
    FindingClass,
    NormalizedEvent,
    Severity,
    make_event_id,
)

ZEEK_LOG_TYPES = frozenset({"conn", "dns", "http", "ssl", "notice"})

_ATTR_FIELDS: dict[str, tuple[str, ...]] = {
    "conn": (
        "service",
        "conn_state",
        "history",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
    ),
    "dns": ("query", "qtype_name", "rcode_name", "trans_id", "rejected"),
    "http": ("method", "host", "uri", "status_code", "user_agent"),
    "ssl": ("server_name", "version", "established"),
    "notice": ("note", "msg", "sub", "actions"),
}


def _zeek_ts(value: Any) -> datetime:
    if value is None:
        raise ParseError("missing ts")
    if isinstance(value, bool):
        raise ParseError("ts has invalid type")
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return parse_iso_utc(value)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise ParseError("ts out of range") from exc
    raise ParseError("ts has invalid type")


def _endpoint(obj: dict[str, Any], notice: bool) -> tuple[Any, Any, Any, Any]:
    raw_id = obj.get("id")
    nested: dict[str, Any] = raw_id if isinstance(raw_id, dict) else {}
    src = obj.get("id.orig_h", nested.get("orig_h"))
    dst = obj.get("id.resp_h", nested.get("resp_h"))
    sport = obj.get("id.orig_p", nested.get("orig_p"))
    dport = obj.get("id.resp_p", nested.get("resp_p"))
    if notice:  # notice.log carries src/dst/p instead of the id.* tuple
        src = src if src is not None else obj.get("src")
        dst = dst if dst is not None else obj.get("dst")
        dport = dport if dport is not None else obj.get("p")
    return src, dst, sport, dport


def _attr(value: Any) -> AttrValue:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return ",".join(str(v) for v in value)[:512]
    return None


def parse_zeek_record(
    raw: bytes, log_type: str, ctx: IngestContext, raw_ref: str
) -> NormalizedEvent:
    if log_type not in ZEEK_LOG_TYPES:
        raise UnsupportedRecord(f"unsupported zeek log type: {log_type}")
    obj = decode_json_object(raw)
    ts = _zeek_ts(obj.get("ts"))
    notice = log_type == "notice"
    src, dst, sport, dport = _endpoint(obj, notice)
    if not notice and (src is None or dst is None):
        raise ParseError("missing connection endpoints")

    uid = opt_str(obj.get("uid"), 64)
    attrs: dict[str, AttrValue] = {
        k: _attr(obj[k]) for k in _ATTR_FIELDS[log_type] if k in obj and obj[k] is not None
    }
    refs = [f"zeek:{log_type}:uid={uid}"] if uid else []
    if notice and (note := opt_str(obj.get("note"), 128)):
        refs.append(f"zeek:notice:note={note}")

    try:
        return NormalizedEvent(
            event_id=make_event_id(ctx.org_id, ctx.sensor_id, "zeek", raw),
            org_id=ctx.org_id,
            sensor_id=ctx.sensor_id,
            source=EventSource.ZEEK,
            event_type=log_type,
            ts=ts,
            src_ip=src,
            dst_ip=dst,
            src_port=opt_int(sport, "id.orig_p"),
            dst_port=opt_int(dport, "id.resp_p"),
            proto=opt_str(obj.get("proto"), 16),
            zeek_uid=uid,
            community_id=opt_str(obj.get("community_id"), 64),
            # Provisional: Zeek notices are policy findings, not proof of malice.
            severity=Severity.LOW if notice else Severity.INFO,
            finding_class=FindingClass.ZEEK_NOTICE if notice else FindingClass.TELEMETRY,
            evidence_refs=tuple(refs),
            raw_ref=raw_ref,
            data_origin=ctx.data_origin,
            attrs=attrs,
        )
    except (ValidationError, ValueError) as exc:
        raise ParseError(f"validation failed: {_first_error(exc)}") from exc


def _first_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        err = exc.errors()[0]
        return f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
    return str(exc)
