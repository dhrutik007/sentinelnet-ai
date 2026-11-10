import json
import os
from pathlib import Path

import pytest

from sentinelnet.cli import main as cli_main
from sentinelnet.parsers.common import IngestContext
from sentinelnet.pathsafe import PathContainmentError, resolve_contained
from sentinelnet.pipeline import Deduplicator, ingest_directory, ingest_file
from sentinelnet.reader import IncrementalReader
from sentinelnet.schema import DataOrigin, NormalizedEvent

FIXTURES = Path(__file__).parent / "fixtures" / "sample"
CTX = IngestContext("demo-org", "offline-sample-1", DataOrigin.SAMPLE)


def line(uid: str, ts: float = 1768471200.0) -> bytes:
    rec = {
        "ts": ts,
        "uid": uid,
        "id.orig_h": "192.0.2.1",
        "id.orig_p": 1,
        "id.resp_h": "192.0.2.2",
        "id.resp_p": 80,
    }
    return json.dumps(rec).encode() + b"\n"


# ---- incremental reader -------------------------------------------------


def test_reader_holds_partial_line_until_completed(tmp_path):
    p = tmp_path / "conn.log"
    full = line("A")
    p.write_bytes(full + full[:20])  # second record is half written
    r = IncrementalReader(p)
    first = list(r.read_new())
    assert [x.data for x in first] == [full.rstrip(b"\n")]
    p.write_bytes(full + line("B"))  # writer finishes the line
    second = list(r.read_new())
    assert len(second) == 1 and b'"B"' in second[0].data


def test_reader_detects_rotation_by_inode(tmp_path):
    p = tmp_path / "conn.log"
    p.write_bytes(line("A") + line("B"))
    r = IncrementalReader(p)
    assert len(list(r.read_new())) == 2
    os.rename(p, tmp_path / "conn.log.1")
    p.write_bytes(line("C"))
    out = list(r.read_new())
    assert r.rotations == 1 and len(out) == 1 and b'"C"' in out[0].data


def test_reader_detects_truncation(tmp_path):
    p = tmp_path / "conn.log"
    p.write_bytes(line("A") + line("B"))
    r = IncrementalReader(p)
    list(r.read_new())
    with open(p, "r+b") as fh:
        fh.truncate(0)
        fh.write(line("Z"))
    out = list(r.read_new())
    assert r.rotations == 1 and len(out) == 1


def test_reader_final_flags_unterminated_tail_as_truncated(tmp_path):
    p = tmp_path / "conn.log"
    p.write_bytes(line("A") + b'{"ts": 1')
    out = list(IncrementalReader(p).read_new(final=True))
    assert out[0].complete and not out[1].complete


def test_reader_oversize_line_flagged_not_buffered(tmp_path):
    p = tmp_path / "conn.log"
    p.write_bytes(b"x" * 500 + b"\n" + line("A"))
    out = list(IncrementalReader(p, max_line_bytes=300).read_new())
    assert out[0].oversize and out[0].data == b"" and not out[1].oversize


# ---- path containment ---------------------------------------------------


def test_path_traversal_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "secret.log").write_text("x")
    with pytest.raises(PathContainmentError):
        resolve_contained(root, "../secret.log")
    with pytest.raises(PathContainmentError):
        resolve_contained(root, str(tmp_path / "secret.log"))


def test_symlink_escape_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.log"
    outside.write_text("x")
    (root / "conn.log").symlink_to(outside)
    with pytest.raises(PathContainmentError):
        resolve_contained(root, "conn.log")


def test_only_known_filenames_ingestable(tmp_path):
    (tmp_path / "evil.log").write_text("x")
    with pytest.raises(ValueError):
        ingest_file(tmp_path, "evil.log", CTX)


# ---- pipeline -----------------------------------------------------------


def test_sample_directory_ingest_counts():
    res = ingest_directory(FIXTURES, CTX)
    assert res.stats.files_ingested == 6
    assert res.stats.events_emitted == 11
    assert res.stats.unsupported == 1  # eve "stats" record
    assert res.stats.malformed == 0 and res.stats.truncated == 0
    assert {e.data_origin for e in res.events} == {DataOrigin.SAMPLE}
    assert all(isinstance(e, NormalizedEvent) for e in res.events)
    assert len({e.event_id for e in res.events}) == 11


def test_malformed_and_truncated_records_counted_not_fatal(tmp_path):
    (tmp_path / "conn.log").write_bytes(
        line("A") + b"garbage\n" + b"\xff\xfe\n" + b"\n" + line("B") + b'{"ts": 17684'
    )
    res = ingest_file(tmp_path, "conn.log", CTX)
    assert res.stats.events_emitted == 2
    assert res.stats.malformed == 2
    assert res.stats.truncated == 1
    assert len(res.errors) == 3
    assert all(e.file == "conn.log" for e in res.errors)


def test_duplicate_records_are_dropped_and_reprocessing_is_idempotent(tmp_path):
    (tmp_path / "conn.log").write_bytes(line("A") + line("A") + line("B"))
    dedup = Deduplicator()
    first = ingest_file(tmp_path, "conn.log", CTX, dedup=dedup)
    assert first.stats.events_emitted == 2 and first.stats.duplicates == 1
    # a second run (e.g. replay after crash) with a fresh dedup yields identical IDs
    second = ingest_file(tmp_path, "conn.log", CTX)
    assert {e.event_id for e in first.events} == {e.event_id for e in second.events}


def test_deduplicator_is_bounded():
    d = Deduplicator(max_size=2)
    for i in "abc":
        d.seen_before(i)
    assert d.seen_before("a") is False  # evicted, memory stays bounded


def test_zeek_tsv_header_lines_are_skipped(tmp_path):
    (tmp_path / "conn.log").write_bytes(b"#separator \\x09\n" + line("A") + b"#close 2026\n")
    res = ingest_file(tmp_path, "conn.log", CTX)
    assert res.stats.events_emitted == 1 and res.stats.malformed == 0


def test_invalid_ids_rejected_early():
    with pytest.raises(ValueError):
        IngestContext("bad org!", "s", DataOrigin.SAMPLE)


# ---- CLI ----------------------------------------------------------------


def test_cli_ingest_writes_jsonl(tmp_path, capsys):
    out = tmp_path / "events.jsonl"
    rc = cli_main(
        [
            "ingest",
            "--root",
            str(FIXTURES),
            "--org-id",
            "demo-org",
            "--sensor-id",
            "s1",
            "--origin",
            "sample",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["stats"]["events_emitted"] == 11 and summary["data_origin"] == "sample"
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    assert len(rows) == 11 and all(r["data_origin"] == "sample" for r in rows)
    assert all(r["ts"].endswith(("Z", "+00:00")) for r in rows)


def test_cli_rejects_live_origin_and_bad_root(tmp_path):
    with pytest.raises(SystemExit):
        cli_main(
            [
                "ingest",
                "--root",
                str(tmp_path),
                "--org-id",
                "o",
                "--sensor-id",
                "s",
                "--origin",
                "live",
            ]
        )
    assert (
        cli_main(
            ["ingest", "--root", str(tmp_path / "missing"), "--org-id", "o", "--sensor-id", "s"]
        )
        == 2
    )
