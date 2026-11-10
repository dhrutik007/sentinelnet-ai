"""Normalized security event schema (contract v1.0).

Every Zeek or Suricata record is converted into a ``NormalizedEvent`` before it
enters the pipeline. Parsers never emit anything that has not passed this
validation. See ARCHITECTURE.md ("Event normalization contract").
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"
MAX_ATTRS = 32
MAX_ATTR_STR = 512
MAX_EVIDENCE_REFS = 16
_ID_PATTERN = r"^[A-Za-z0-9._-]+$"

AttrValue = str | int | float | bool | None


class EventSource(StrEnum):
    ZEEK = "zeek"
    SURICATA = "suricata"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingClass(StrEnum):
    """What kind of statement an event makes. Never implies proven malice."""

    TELEMETRY = "telemetry"  # plain observation (conn, dns, http, ssl, flow)
    SIGNATURE_MATCH = "signature_match"  # a Suricata rule matched; the rule may still be wrong
    ZEEK_NOTICE = "zeek_notice"  # Zeek policy script raised a notice


class DataOrigin(StrEnum):
    SAMPLE = "sample"  # synthetic fixtures; the UI must label these as sample data
    OFFLINE_PCAP = "offline_pcap"  # authorised offline capture analysis
    LIVE = "live"  # authorised live passive sensor


class ProcessingStatus(StrEnum):
    NORMALIZED = "normalized"
    ENQUEUED = "enqueued"
    PERSISTED = "persisted"
    DEAD_LETTER = "dead_letter"


def make_event_id(org_id: str, sensor_id: str, source: str, raw_record: bytes) -> str:
    """Deterministic ID: reprocessing the same raw record yields the same ID.

    This is the basis of idempotent ingestion (UNIQUE(org_id, event_id) in the DB).
    """
    h = hashlib.sha256()
    for part in (org_id.encode(), sensor_id.encode(), source.encode(), raw_record.strip()):
        h.update(part)
        h.update(b"\x00")
    return h.hexdigest()


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = SCHEMA_VERSION
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    org_id: str = Field(min_length=1, max_length=64, pattern=_ID_PATTERN)
    sensor_id: str = Field(min_length=1, max_length=64, pattern=_ID_PATTERN)
    source: EventSource
    event_type: str = Field(min_length=1, max_length=32, pattern=r"^[a-z0-9_]+$")
    ts: datetime
    src_ip: IPv4Address | IPv6Address | None = None
    dst_ip: IPv4Address | IPv6Address | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = Field(default=None, max_length=16)
    flow_id: str | None = Field(default=None, max_length=64)
    zeek_uid: str | None = Field(default=None, max_length=64)
    community_id: str | None = Field(default=None, max_length=64)
    signature_id: int | None = Field(default=None, ge=0)
    signature_rev: int | None = Field(default=None, ge=0)
    signature_msg: str | None = Field(default=None, max_length=MAX_ATTR_STR)
    category: str | None = Field(default=None, max_length=128)
    severity: Severity = Severity.INFO
    # Assigned by detection/correlation, never by parsers. None means "not assessed".
    confidence: Confidence | None = None
    finding_class: FindingClass = FindingClass.TELEMETRY
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=MAX_EVIDENCE_REFS)
    raw_ref: str = Field(min_length=1, max_length=256)  # "<basename>@<byte offset>"
    data_origin: DataOrigin
    processing_status: ProcessingStatus = ProcessingStatus.NORMALIZED
    attrs: dict[str, AttrValue] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _ts_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        v = v.astimezone(UTC)
        if not 1990 <= v.year <= 2100:
            raise ValueError("timestamp outside plausible range")
        return v

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _parse_ip(cls, v: Any) -> Any:
        if isinstance(v, str):
            return ip_address(v.strip())
        return v

    @field_validator("proto")
    @classmethod
    def _proto_lower(cls, v: str | None) -> str | None:
        return v.lower() if v is not None else None

    @field_validator("attrs")
    @classmethod
    def _bound_attrs(cls, v: dict[str, AttrValue]) -> dict[str, AttrValue]:
        if len(v) > MAX_ATTRS:
            raise ValueError(f"too many attrs (max {MAX_ATTRS})")
        out: dict[str, AttrValue] = {}
        for key, val in v.items():
            if len(key) > 64:
                raise ValueError("attr key too long")
            out[key] = val[:MAX_ATTR_STR] if isinstance(val, str) else val
        return out
