# SentinelNet AI

A defensive **network intrusion detection and security analytics platform** built around
[Zeek](https://zeek.org) and [Suricata](https://suricata.io): passive, explicitly
authorised monitoring → normalized events → explainable detections → investigations.

> **Project status: early (v0.1.0, Phase 1).** Only the offline ingestion slice exists.
> There is **no dashboard, API, database, detection engine or authentication yet**, and
> nothing here should be described as a working IDS. See [ROADMAP](#roadmap).

## What works today
- Parsers for Zeek JSON logs (`conn dns http ssl notice`) and Suricata EVE JSON (`alert flow dns http tls`)
- A validated, immutable normalized event schema (UTC timestamps, IPv4/IPv6, bounded fields)
- Rotation- and truncation-safe incremental file reader with bounded memory
- Strict handling of malformed, truncated, oversize and non-UTF-8 records (counted, reported, never fatal)
- Deterministic event IDs and bounded de-duplication (idempotent re-ingestion)
- Path containment and an allow-list of log file names
- CLI: `sentinelnet ingest` (offline only; cannot select a network interface)
- 59 automated tests; `ruff` and strict `mypy` clean

## Design principles
- **Authorised, passive monitoring only.** No sniffing-by-default, spoofing, interception or MITM code.
- **Signature match ≠ proof of malice.** Events carry `finding_class`; `confidence` is unset until detection assigns it.
- **No invented data.** Demo data is synthetic and labelled `sample`; there are no fabricated benchmarks.

## Quick start
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest

sentinelnet ingest --root tests/fixtures/sample \
  --org-id demo-org --sensor-id offline-sample-1 --origin sample --out events.jsonl
```
Expected summary for the bundled fixtures: 6 files, 11 events, 1 unsupported record (a Suricata `stats` line), 0 malformed.

## Documentation
[ARCHITECTURE](ARCHITECTURE.md) · [THREAT_MODEL](THREAT_MODEL.md) · [SECURITY](SECURITY.md) · [PRIVACY](PRIVACY.md) · [TESTING](TESTING.md) · [CONTRIBUTING](CONTRIBUTING.md) · [CHANGELOG](CHANGELOG.md)

## Roadmap
1. ✅ Phase 1–2: architecture, threat model, schema, offline Zeek/Suricata ingestion
2. Phase 3: PostgreSQL + Alembic, Redis Streams ingestion, FastAPI
3. Phase 4: detection rules and Zeek↔Suricata correlation
4. Phase 5: auth, RBAC, tenant isolation, React dashboard
5. Phase 6–9: investigations, reporting, optional AI, live sensor integration, hardening, CI, release

## Known limitations
No persistence, queue, API or UI. Real Zeek/Suricata output has not yet been tested
(only synthetic fixtures written to the documented formats); validation against real
tool output from a legally redistributable PCAP is a planned task. `docs/schema.sql`
has not been run against PostgreSQL.

## Author
Created and maintained by **Dhrutik** ([@dhrutik007](https://github.com/dhrutik007)).

## Licence
MIT. See [LICENSE](LICENSE).
