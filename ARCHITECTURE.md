# Architecture

Status: **Phase 1 + first vertical slice.** Sections marked *(planned)* are design,
not yet implemented. The implemented code is the offline ingestion path
(`src/sentinelnet/`): parsers, normalized schema, incremental reader, path
containment, dedup, CLI.

## 1. Data flow and trust boundaries

```
 [Authorised SPAN/TAP or lab NIC]   [Authorised offline PCAP]
              │                                │
 ┌────────────▼────────────────────────────────▼───────────┐  TB1: SENSOR HOST
 │  Zeek + Suricata (passive; only component with           │  (only place with
 │  CAP_NET_RAW / CAP_NET_ADMIN, bound to approved NIC)     │   capture privileges)
 └────────────┬─────────────────────────────────────────────┘
              │ JSON logs (conn/dns/http/ssl/notice, eve.json)
 ┌────────────▼─────────────────────────────────────────────┐  TB2: INGESTION
 │  Python ingest worker (unprivileged, read-only mount)     │  (log content is
 │  contained path → incremental read → parse → validate →   │   UNTRUSTED input)
 │  NormalizedEvent → dedup                                  │
 └────────────┬─────────────────────────────────────────────┘
              │ Redis Streams (consumer groups, ack, DLQ)         (planned)
 ┌────────────▼─────────────────────────────────────────────┐  TB3: APPLICATION
 │  Detection + correlation engine → PostgreSQL              │  (no capture or host
 │  FastAPI REST + authenticated WebSocket                   │   network privileges)
 └────────────┬─────────────────────────────────────────────┘
              │ TLS via Nginx
 ┌────────────▼─────────────────────────────────────────────┐  TB4: BROWSER
 │  React/TypeScript SOC dashboard (RBAC, org-scoped)        │  (untrusted client)
 └──────────────────────────────────────────────────────────┘
```

| Boundary | Rule |
|---|---|
| Sensor ↔ app | Sensors only write log files / push events. The API and web containers never receive packet-capture capabilities or host networking. |
| Logs → ingestion | Log content is attacker-influenced (hostnames, URIs, user agents). It is size-bounded, strictly decoded and schema-validated, and never executed, templated into queries, or passed to a shell. |
| User → API | Every endpoint authenticated and role-checked; every query filtered by `org_id` server-side. |
| AI layer (optional) | Off by default; no outbound transmission without explicit opt-in; log text is treated as prompt-injection-capable data; the model has no tool or command access. |

## 2. Dependencies and compatibility

Verified in this build environment (the versions the tests actually ran against):
Python 3.13, pydantic 2.13.5, pytest 9.1.1, ruff, mypy (strict). Code targets
Python ≥ 3.11 (`StrEnum`, `datetime.UTC`).

*(planned, versions not yet verified or pinned)*: FastAPI, SQLAlchemy 2.x, Alembic,
PostgreSQL, Redis (Streams), React + Vite + TypeScript + Tailwind + Recharts, Nginx,
Zeek and Suricata (current supported releases). Exact versions will be pinned and
justified in Phase 3/8 after checking each against current release notes; this
document will then list them. FastAPI/SQLAlchemy were not installable in the
build sandbox (no package network), which is why Phase 1 uses pydantic + stdlib only.

Zeek JSON field names vary by version/config (flat `id.orig_h` vs nested `id`,
epoch vs ISO `ts`); the parser accepts both and tolerates missing optional fields.

## 3. Event normalization contract (schema v1.0)

Implemented in `src/sentinelnet/schema.py` as the frozen pydantic model
`NormalizedEvent` (`extra="forbid"`).

| Field | Type | Notes |
|---|---|---|
| `schema_version` | str | `"1.0"` |
| `event_id` | 64-hex | SHA-256 over `org\0sensor\0source\0raw_record`; same raw record → same ID (idempotency key) |
| `org_id`, `sensor_id` | `[A-Za-z0-9._-]{1,64}` | Tenant and sensor attribution |
| `source` | `zeek` \| `suricata` | |
| `event_type` | str | `conn dns http ssl notice` (Zeek); `alert flow dns http tls` (Suricata) |
| `ts` | tz-aware datetime, **UTC** | Naive timestamps are rejected, never guessed |
| `src_ip`, `dst_ip` | IPv4/IPv6 or null | Validated with `ipaddress` |
| `src_port`, `dst_port` | 0–65535 or null | |
| `proto` | lowercase str or null | Not inferred when absent |
| `flow_id` | str or null | Suricata flow ID (kept as string; exceeds JS safe-int) |
| `zeek_uid`, `community_id` | str or null | Preserved for correlation |
| `signature_id/rev/msg`, `category` | | Suricata alerts only |
| `severity` | info/low/medium/high/critical | Suricata 1/2/3 → high/medium/low. Zeek notice → low (provisional) |
| `confidence` | low/medium/high or null | **Never set by parsers.** null = not assessed |
| `finding_class` | `telemetry` \| `signature_match` \| `zeek_notice` | A signature match says a rule fired, not that malice is proven |
| `evidence_refs` | ≤16 strings | e.g. `zeek:conn:uid=…`, `suricata:alert:sid=…` |
| `raw_ref` | str | `<basename>@<byte offset>`; never an absolute path |
| `data_origin` | `sample` \| `offline_pcap` \| `live` | Drives the "SAMPLE DATA" UI label |
| `processing_status` | normalized/enqueued/persisted/dead_letter | |
| `attrs` | ≤32 scalar entries, strings ≤512 chars | Protocol-specific metadata |

Limits: record ≤ 64 KiB; strict UTF-8; invalid/oversize/truncated records are
counted and reported (`malformed`, `truncated`), never silently dropped or repaired.

Encrypted flows: only observed metadata (SNI, version) is recorded; no payload is inferred.

## 4. Database schema *(planned; DDL in `docs/schema.sql`)*

Tables: `organizations`, `users`, `memberships(role)`, `sensors` (+ approved
interfaces, permitted CIDRs, mode `offline_pcap`|`live`), `events`
(`UNIQUE(org_id,event_id)`), `raw_evidence` (access-restricted), `alerts`,
`investigations`, `investigation_events`, `investigation_notes`, `suppressions`
(with expiry), `detection_rules`, `reports`, `audit_log` (append-only).
Every tenant table carries `org_id`; all queries are filtered by it server-side.
**`docs/schema.sql` has not been executed against PostgreSQL yet**; migration
tests are a Phase 3 task, and indexes will be added only from measured query patterns.

## 5. Repository layout

```
sentinelnet-ai/
├── src/sentinelnet/
│   ├── schema.py          # NormalizedEvent contract, event-ID derivation
│   ├── parsers/           # common.py, zeek.py, suricata.py
│   ├── reader.py          # incremental, rotation-safe line reader
│   ├── pathsafe.py        # path containment
│   ├── pipeline.py        # ingest_file / ingest_directory, bounded dedup
│   └── cli.py             # `sentinelnet ingest` (offline only)
├── tests/                 # pytest; tests/fixtures/sample = synthetic data
├── docs/schema.sql        # planned PostgreSQL DDL (unexecuted)
└── *.md                   # ARCHITECTURE, THREAT_MODEL, SECURITY, PRIVACY, TESTING, ...
```
Planned: `backend/` (FastAPI), `frontend/`, `deploy/` (Compose, Nginx, sensor docs), `.github/workflows/`.

## 6. First vertical slice (implemented)

`sentinelnet ingest --root <dir> --org-id … --sensor-id … --origin sample|offline_pcap`
reads only allow-listed file names (`conn.log dns.log http.log ssl.log notice.log eve.json`)
from inside `--root`, parses, validates, dedups, and emits JSON Lines plus a stats summary.
No interface access, no network, no shell, no arbitrary paths. `live` origin is
intentionally not selectable from this CLI.

## 7. Safe offline testing

Use only (a) the synthetic fixtures in `tests/fixtures/sample` (documentation IP
ranges, made-up signature ID) or (b) PCAPs you are authorised to analyse, run through
Zeek/Suricata on an isolated host. Never replay captures onto a live network and
never generate attack traffic against infrastructure you do not own.

## 8. Key risks and mitigations

| Risk | Mitigation |
|---|---|
| Malicious log content (injection, huge records) | Strict decode, 64 KiB cap, schema validation, parameterised SQL, output encoding, no shell use |
| Partial writes / rotation lose or corrupt events | Newline-gated reads, inode/size rotation detection, truncated-record reporting (tested) |
| Duplicate events on replay | Deterministic content-hash IDs + DB unique key; bounded LRU in memory |
| Unbounded memory/queue growth | Bounded read chunk, line cap, LRU cap; Redis backpressure planned |
| Heuristics presented as proof | `finding_class` + nullable `confidence`; wording rules in DETECTION_ENGINE (planned) |
| Cross-tenant leakage | `org_id` on every table/query; cross-tenant tests planned |
| Privilege creep on app containers | Capture only on the sensor host; Compose forbids host network / caps for app services |
| Correlation false joins (NAT, clock skew) | Flow-ID first, bounded windows, evidence links; accuracy tests planned |
