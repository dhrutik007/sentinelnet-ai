"""Offline ingestion pipeline: contained file -> parse -> normalize -> dedup."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from sentinelnet.parsers.common import IngestContext, ParseError, UnsupportedRecord
from sentinelnet.parsers.suricata import parse_eve_record
from sentinelnet.parsers.zeek import parse_zeek_record
from sentinelnet.pathsafe import resolve_contained
from sentinelnet.reader import IncrementalReader
from sentinelnet.schema import NormalizedEvent

# Fixed allowlist of file names. Users never supply arbitrary paths or command args.
KNOWN_FILES: dict[str, tuple[str, str]] = {
    "conn.log": ("zeek", "conn"),
    "dns.log": ("zeek", "dns"),
    "http.log": ("zeek", "http"),
    "ssl.log": ("zeek", "ssl"),
    "notice.log": ("zeek", "notice"),
    "eve.json": ("suricata", "eve"),
}


@dataclass
class IngestError:
    file: str
    offset: int
    reason: str


@dataclass
class IngestStats:
    files_ingested: int = 0
    lines_read: int = 0
    events_emitted: int = 0
    duplicates: int = 0
    malformed: int = 0
    truncated: int = 0
    unsupported: int = 0


@dataclass
class IngestResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    errors: list[IngestError] = field(default_factory=list)
    stats: IngestStats = field(default_factory=IngestStats)


class Deduplicator:
    """Bounded LRU set of event IDs (memory cannot grow without limit)."""

    def __init__(self, max_size: int = 100_000) -> None:
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._max = max_size

    def seen_before(self, event_id: str) -> bool:
        if event_id in self._seen:
            self._seen.move_to_end(event_id)
            return True
        self._seen[event_id] = None
        if len(self._seen) > self._max:
            self._seen.popitem(last=False)
        return False


def ingest_file(
    root: Path,
    filename: str,
    ctx: IngestContext,
    *,
    dedup: Deduplicator | None = None,
    max_errors: int = 100,
    result: IngestResult | None = None,
) -> IngestResult:
    if filename not in KNOWN_FILES:
        raise ValueError(f"unsupported log file name: {filename}")
    kind, log_type = KNOWN_FILES[filename]
    path = resolve_contained(root, filename)
    dedup = dedup or Deduplicator()
    res = result or IngestResult()
    reader = IncrementalReader(path)

    while True:
        before = reader.offset
        for line in reader.read_new(final=True):
            res.stats.lines_read += 1
            ref = f"{filename}@{line.offset}"
            if not line.data.strip() and line.complete and not line.oversize:
                res.stats.lines_read -= 1
                continue
            if line.data.startswith(b"#"):  # Zeek TSV header/footer lines
                res.stats.lines_read -= 1
                continue
            try:
                if line.oversize:
                    raise ParseError("record exceeds size limit")
                if kind == "zeek":
                    ev = parse_zeek_record(line.data, log_type, ctx, ref)
                else:
                    ev = parse_eve_record(line.data, ctx, ref)
            except UnsupportedRecord:
                res.stats.unsupported += 1
                continue
            except ParseError as exc:
                if not line.complete:
                    res.stats.truncated += 1
                else:
                    res.stats.malformed += 1
                if len(res.errors) < max_errors:
                    res.errors.append(IngestError(filename, line.offset, str(exc)))
                continue
            if dedup.seen_before(ev.event_id):
                res.stats.duplicates += 1
                continue
            res.events.append(ev)
            res.stats.events_emitted += 1
        if reader.offset == before:
            break
    res.stats.files_ingested += 1
    return res


def ingest_directory(
    root: Path, ctx: IngestContext, *, dedup: Deduplicator | None = None
) -> IngestResult:
    """Ingest every known log file present under ``root`` (absent files are optional)."""
    root = root.resolve(strict=True)  # FileNotFoundError if the root does not exist
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root.name}")
    dedup = dedup or Deduplicator()
    res = IngestResult()
    for name in KNOWN_FILES:
        if (root / name).exists():
            ingest_file(root, name, ctx, dedup=dedup, result=res)
    return res
