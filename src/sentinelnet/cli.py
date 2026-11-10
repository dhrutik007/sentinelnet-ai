"""Command line entry point. Offline ingestion only; no network or interface access."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinelnet.parsers.common import IngestContext
from sentinelnet.pipeline import ingest_directory
from sentinelnet.schema import DataOrigin


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelnet")
    sub = parser.add_subparsers(dest="command", required=True)
    ing = sub.add_parser("ingest", help="ingest Zeek/Suricata JSON logs from a directory (offline)")
    ing.add_argument("--root", type=Path, required=True, help="directory containing the logs")
    ing.add_argument("--org-id", required=True)
    ing.add_argument("--sensor-id", required=True)
    ing.add_argument(
        "--origin",
        choices=[o.value for o in DataOrigin if o is not DataOrigin.LIVE],
        default=DataOrigin.OFFLINE_PCAP.value,
        help="label for provenance; use 'sample' for synthetic fixtures",
    )
    ing.add_argument("--out", type=Path, help="write normalized events as JSON Lines")
    args = parser.parse_args(argv)

    try:
        ctx = IngestContext(args.org_id, args.sensor_id, DataOrigin(args.origin))
        result = ingest_directory(args.root, ctx)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:  # noqa: PTH123
            for ev in result.events:
                fh.write(ev.model_dump_json() + "\n")
    summary = {
        "data_origin": args.origin,
        "stats": vars(result.stats),
        "errors": [vars(e) for e in result.errors],
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
