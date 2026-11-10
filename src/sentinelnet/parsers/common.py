"""Shared parser helpers and error types."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sentinelnet.schema import DataOrigin

_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_RECORD_BYTES = 64 * 1024


class ParseError(ValueError):
    """Record is malformed, truncated or fails validation."""


class UnsupportedRecord(ValueError):
    """Record is well-formed but of a type this version does not ingest."""


@dataclass(frozen=True)
class IngestContext:
    org_id: str
    sensor_id: str
    data_origin: DataOrigin

    def __post_init__(self) -> None:
        for name, value in (("org_id", self.org_id), ("sensor_id", self.sensor_id)):
            if not _ID_RE.match(value):
                raise ValueError(f"invalid {name}: must match {_ID_RE.pattern}")


def decode_json_object(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_RECORD_BYTES:
        raise ParseError("record exceeds size limit")
    try:
        text = raw.decode("utf-8")  # strict: invalid encoding is rejected, not repaired
    except UnicodeDecodeError as exc:
        raise ParseError("invalid UTF-8") from exc
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseError("not valid JSON (truncated or corrupt record?)") from exc
    if not isinstance(obj, dict):
        raise ParseError("record is not a JSON object")
    return obj


def parse_iso_utc(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError("unparseable timestamp") from exc
    if dt.tzinfo is None:
        # Never guess a timezone: silent skew would corrupt correlation windows.
        raise ParseError("timestamp has no timezone")
    return dt.astimezone(UTC)


def opt_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParseError(f"{field} must be an integer")
    return value


def opt_str(value: Any, max_len: int = 512) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return None
    return str(value)[:max_len]
