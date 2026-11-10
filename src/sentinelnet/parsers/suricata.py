"""Suricata EVE JSON parser (alert, flow, dns, http, tls).

Signature alerts are recorded as ``signature_match`` findings: a rule matched.
That is a statement about the rule, not proof of malicious activity, so parsers
leave ``confidence`` unset; detection and correlation assign it later.
"""

from __future__ import annotations

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
from sentinelnet.parsers.zeek import _attr, _first_error
from sentinelnet.schema import (
    AttrValue,
    EventSource,
    FindingClass,
    NormalizedEvent,
    Severity,
    make_event_id,
)

SURICATA_EVENT_TYPES = frozenset({"alert", "flow", "dns", "http", "tls"})

# Suricata alert severity: 1 is the highest priority.
_SEVERITY = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}

_ATTR_FIELDS: dict[str, tuple[str, ...]] = {
    "alert": ("action",),
    "flow": (
        "pkts_toserver",
        "pkts_toclient",
        "bytes_toserver",
        "bytes_toclient",
        "state",
        "reason",
        "age",
    ),
    "dns": ("rrname", "rrtype", "rcode", "type"),
    "http": ("hostname", "url", "http_method", "status", "http_user_agent"),
    "tls": ("sni", "version"),
}


def parse_eve_record(raw: bytes, ctx: IngestContext, raw_ref: str) -> NormalizedEvent:
    obj = decode_json_object(raw)
    etype = obj.get("event_type")
    if not isinstance(etype, str):
        raise ParseError("missing event_type")
    if etype not in SURICATA_EVENT_TYPES:
        raise UnsupportedRecord(f"unsupported eve event_type: {etype}")
    ts_raw = obj.get("timestamp")
    if not isinstance(ts_raw, str):
        raise ParseError("missing timestamp")
    ts = parse_iso_utc(ts_raw)

    section = obj.get(etype)
    section = section if isinstance(section, dict) else {}
    attrs: dict[str, AttrValue] = {
        k: _attr(section[k]) for k in _ATTR_FIELDS[etype] if section.get(k) is not None
    }

    flow_id = obj.get("flow_id")
    flow_id_s = str(opt_int(flow_id, "flow_id")) if flow_id is not None else None
    refs: list[str] = []
    if flow_id_s:
        refs.append(f"suricata:{etype}:flow_id={flow_id_s}")

    sig_id = sig_rev = None
    sig_msg = category = None
    severity = Severity.INFO
    finding = FindingClass.TELEMETRY
    if etype == "alert":
        alert = section
        sig_id = opt_int(alert.get("signature_id"), "signature_id")
        if sig_id is None:
            raise ParseError("alert missing signature_id")
        sig_rev = opt_int(alert.get("rev"), "rev")
        sig_msg = opt_str(alert.get("signature"))
        category = opt_str(alert.get("category"), 128)
        sev = opt_int(alert.get("severity"), "severity")
        severity = _SEVERITY.get(sev, Severity.INFO) if sev is not None else Severity.INFO
        finding = FindingClass.SIGNATURE_MATCH
        refs.append(f"suricata:alert:sid={sig_id}")

    try:
        return NormalizedEvent(
            event_id=make_event_id(ctx.org_id, ctx.sensor_id, "suricata", raw),
            org_id=ctx.org_id,
            sensor_id=ctx.sensor_id,
            source=EventSource.SURICATA,
            event_type=etype,
            ts=ts,
            src_ip=obj.get("src_ip"),
            dst_ip=obj.get("dest_ip"),
            src_port=opt_int(obj.get("src_port"), "src_port"),
            dst_port=opt_int(obj.get("dest_port"), "dest_port"),
            proto=opt_str(obj.get("proto"), 16),
            flow_id=flow_id_s,
            community_id=opt_str(obj.get("community_id"), 64),
            signature_id=sig_id,
            signature_rev=sig_rev,
            signature_msg=sig_msg,
            category=category,
            severity=severity,
            finding_class=finding,
            evidence_refs=tuple(refs),
            raw_ref=raw_ref,
            data_origin=ctx.data_origin,
            attrs=attrs,
        )
    except (ValidationError, ValueError) as exc:
        raise ParseError(f"validation failed: {_first_error(exc)}") from exc
