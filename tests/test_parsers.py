import json
from datetime import UTC, datetime
from ipaddress import IPv6Address

import pytest

from sentinelnet.parsers.common import IngestContext, ParseError, UnsupportedRecord
from sentinelnet.parsers.suricata import parse_eve_record
from sentinelnet.parsers.zeek import parse_zeek_record
from sentinelnet.schema import DataOrigin, EventSource, FindingClass, Severity

CTX = IngestContext("org-1", "sensor-1", DataOrigin.SAMPLE)


def zeek(obj, log_type="conn"):
    return parse_zeek_record(json.dumps(obj).encode(), log_type, CTX, "f@0")


def eve(obj):
    return parse_eve_record(json.dumps(obj).encode(), CTX, "eve.json@0")


BASE_CONN = {
    "ts": 1768471200.5,
    "uid": "CX1",
    "id.orig_h": "192.0.2.1",
    "id.orig_p": 1234,
    "id.resp_h": "198.51.100.2",
    "id.resp_p": 443,
    "proto": "TCP",
    "conn_state": "SF",
}


def test_zeek_conn_normalizes_and_preserves_uid():
    ev = zeek(BASE_CONN)
    assert ev.source is EventSource.ZEEK and ev.event_type == "conn"
    assert ev.zeek_uid == "CX1"
    assert ev.proto == "tcp"
    assert ev.ts == datetime.fromtimestamp(1768471200.5, UTC)
    assert ev.ts.tzinfo is not None
    assert ev.attrs["conn_state"] == "SF"
    assert ev.finding_class is FindingClass.TELEMETRY
    assert ev.confidence is None


def test_zeek_iso_timestamp_and_nested_id_and_ipv6():
    ev = zeek(
        {
            "ts": "2026-01-15T10:00:00+01:00",
            "uid": "CX2",
            "id": {"orig_h": "2001:db8::1", "orig_p": 1, "resp_h": "2001:db8::2", "resp_p": 53},
        },
        "ssl",
    )
    assert ev.ts == datetime(2026, 1, 15, 9, 0, tzinfo=UTC)
    assert ev.src_ip == IPv6Address("2001:db8::1")


def test_zeek_notice_uses_src_dst_and_is_not_called_malicious():
    ev = zeek(
        {
            "ts": 1768471200,
            "note": "X::Y",
            "msg": "m",
            "src": "192.0.2.1",
            "dst": "192.0.2.2",
            "p": 22,
        },
        "notice",
    )
    assert ev.finding_class is FindingClass.ZEEK_NOTICE
    assert ev.severity is Severity.LOW
    assert ev.dst_port == 22
    assert ev.confidence is None


def test_zeek_missing_optional_fields_is_ok():
    obj = {k: v for k, v in BASE_CONN.items() if k not in ("uid", "proto", "conn_state")}
    ev = zeek(obj)
    assert ev.zeek_uid is None and ev.proto is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"ts": None},
        {"ts": "not a time"},
        {"ts": "2026-01-15T10:00:00"},  # naive ISO: refuse to guess a timezone
        {"ts": float("inf")},
        {"ts": True},
        {"id.orig_h": "999.1.1.1"},
        {"id.orig_h": None},
        {"id.resp_p": 70000},
        {"id.resp_p": "443"},
    ],
)
def test_zeek_invalid_fields_rejected(mutation):
    obj = {**BASE_CONN, **mutation}
    raw = json.dumps(obj, allow_nan=True).encode()
    with pytest.raises(ParseError):
        parse_zeek_record(raw, "conn", CTX, "f@0")


@pytest.mark.parametrize(
    "raw",
    [b'{"ts": 1768471200, "uid": "tr', b"", b"[1,2]", b"\xff\xfe", b"not json", b'"str"'],
)
def test_zeek_malformed_or_truncated_rejected(raw):
    with pytest.raises(ParseError):
        parse_zeek_record(raw, "conn", CTX, "f@0")


def test_zeek_oversize_record_rejected():
    with pytest.raises(ParseError):
        parse_zeek_record(b'{"x":"' + b"a" * 70_000 + b'"}', "conn", CTX, "f@0")


def test_zeek_unknown_log_type_unsupported():
    with pytest.raises(UnsupportedRecord):
        zeek(BASE_CONN, "weird")


def test_zeek_event_id_is_deterministic_and_scoped():
    a = zeek(BASE_CONN)
    b = zeek(BASE_CONN)
    other_sensor = parse_zeek_record(
        json.dumps(BASE_CONN).encode(),
        "conn",
        IngestContext("org-1", "sensor-2", DataOrigin.SAMPLE),
        "f@0",
    )
    assert a.event_id == b.event_id
    assert a.event_id != other_sensor.event_id


BASE_ALERT = {
    "timestamp": "2026-01-15T10:00:01.000000+0000",
    "flow_id": 123456789012345,
    "event_type": "alert",
    "src_ip": "192.0.2.11",
    "src_port": 40022,
    "dest_ip": "198.51.100.21",
    "dest_port": 22,
    "proto": "TCP",
    "alert": {
        "signature_id": 9000001,
        "rev": 3,
        "signature": "SAMPLE sig",
        "category": "Cat",
        "severity": 1,
    },
}


def test_eve_alert_preserves_signature_and_flow_fields():
    ev = eve(BASE_ALERT)
    assert ev.signature_id == 9000001 and ev.signature_rev == 3
    assert ev.flow_id == "123456789012345"
    assert ev.severity is Severity.HIGH
    assert ev.finding_class is FindingClass.SIGNATURE_MATCH
    assert ev.confidence is None  # a rule match is not proof; detection assigns confidence later
    assert "suricata:alert:sid=9000001" in ev.evidence_refs
    assert ev.ts == datetime(2026, 1, 15, 10, 0, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "sev,expected",
    [(2, Severity.MEDIUM), (3, Severity.LOW), (4, Severity.INFO), (None, Severity.INFO)],
)
def test_eve_severity_mapping(sev, expected):
    alert = {**BASE_ALERT["alert"], "severity": sev}
    assert eve({**BASE_ALERT, "alert": alert}).severity is expected


def test_eve_alert_without_signature_id_rejected():
    with pytest.raises(ParseError):
        eve({**BASE_ALERT, "alert": {"signature": "x"}})


def test_eve_unsupported_event_type():
    with pytest.raises(UnsupportedRecord):
        eve({"timestamp": "2026-01-15T10:00:00+0000", "event_type": "stats"})


@pytest.mark.parametrize(
    "mutation",
    [
        {"timestamp": "yesterday"},
        {"timestamp": "2026-01-15T10:00:00"},
        {"timestamp": None},
        {"event_type": None},
        {"src_ip": "not-an-ip"},
        {"flow_id": "abc"},
        {"dest_port": -1},
    ],
)
def test_eve_invalid_fields_rejected(mutation):
    with pytest.raises(ParseError):
        eve({**BASE_ALERT, **mutation})


def test_eve_flow_and_tls_metadata_only():
    flow = eve(
        {
            "timestamp": "2026-01-15T10:00:02Z",
            "event_type": "flow",
            "src_ip": "192.0.2.1",
            "dest_ip": "192.0.2.2",
            "proto": "UDP",
            "flow": {"pkts_toserver": 3, "state": "new"},
        }
    )
    assert flow.finding_class is FindingClass.TELEMETRY and flow.attrs["pkts_toserver"] == 3
    tls = eve(
        {
            "timestamp": "2026-01-15T10:00:02Z",
            "event_type": "tls",
            "src_ip": "192.0.2.1",
            "dest_ip": "192.0.2.2",
            "tls": {"sni": "sample.example.test", "version": "TLS 1.3"},
        }
    )
    assert tls.attrs == {"sni": "sample.example.test", "version": "TLS 1.3"}
