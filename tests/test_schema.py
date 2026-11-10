from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from sentinelnet.schema import DataOrigin, EventSource, NormalizedEvent, make_event_id

EID = make_event_id("o", "s", "zeek", b"raw")


def make(**kw):
    base = dict(
        event_id=EID,
        org_id="o",
        sensor_id="s",
        source=EventSource.ZEEK,
        event_type="conn",
        ts=datetime(2026, 1, 1, tzinfo=UTC),
        raw_ref="conn.log@0",
        data_origin=DataOrigin.SAMPLE,
    )
    return NormalizedEvent(**{**base, **kw})


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        make(ts=datetime(2026, 1, 1))


def test_non_utc_timestamp_converted_to_utc():
    ev = make(ts=datetime(2026, 1, 1, 12, tzinfo=timezone(timedelta(hours=2))))
    assert ev.ts == datetime(2026, 1, 1, 10, tzinfo=UTC) and ev.ts.utcoffset() == timedelta(0)


def test_event_is_immutable():
    with pytest.raises(ValidationError):
        make().org_id = "other"


def test_extra_fields_forbidden_and_ids_validated():
    with pytest.raises(ValidationError):
        make(unexpected=1)
    with pytest.raises(ValidationError):
        make(org_id="bad org")
    with pytest.raises(ValidationError):
        make(event_id="short")


def test_attrs_bounded():
    assert len(make(attrs={"k": "x" * 5000}).attrs["k"]) == 512
    with pytest.raises(ValidationError):
        make(attrs={f"k{i}": 1 for i in range(33)})


def test_ip_strings_parsed_for_both_families():
    ev = make(src_ip="192.0.2.1", dst_ip="2001:db8::1")
    assert ev.src_ip.version == 4 and ev.dst_ip.version == 6
    with pytest.raises(ValidationError):
        make(src_ip="300.0.0.1")
