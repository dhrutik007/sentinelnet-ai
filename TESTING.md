# Testing

```bash
pip install -e ".[dev]"
pytest              # 59 tests
ruff check . && ruff format --check .
mypy src            # strict
```

## What is covered now
- Zeek parsing: flat/nested fields, epoch/ISO timestamps, IPv6, missing optional fields, notices
- Suricata EVE parsing: alert fields, severity mapping, flow ID preservation, unsupported types
- Malformed input: truncated JSON, bad UTF-8, non-objects, bad IPs/ports/timestamps, oversize records
- Reader: partial-line holding, rotation, truncation, oversize lines
- Path containment (traversal and symlink escape), allow-listed file names
- Dedup / idempotent IDs, bounded memory of the dedup set
- CLI behaviour, including refusal of `live` origin and missing roots

## Not yet covered (planned)
Correlation accuracy, false-positive handling, RBAC / cross-tenant isolation,
WebSocket security, queue recovery/replay, DB migrations, reporting, retention.

## Data provenance
Fixtures in `tests/fixtures/sample` are synthetic (see `tests/fixtures/README.md`).
They validate parser behaviour, **not detection quality**. Precision/recall figures
will only be published from a labelled dataset with documented size, conditions and
limitations. No benchmark numbers exist yet and none are claimed.
