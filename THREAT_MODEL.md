# Threat model

Scope: SentinelNet AI as designed in ARCHITECTURE.md. Implemented today: offline
ingestion only. Controls marked *(planned)* are not yet built.

## Assets
Telemetry (IPs, hostnames, URLs: personal data in many jurisdictions), alert and
investigation records, sensor credentials, user credentials, audit log integrity.

## Adversaries
1. **Network adversary** whose traffic is observed and who controls content that ends up in logs (DNS names, URIs, user agents, TLS SNI).
2. **Malicious or curious tenant user** attempting cross-organisation access or privilege escalation.
3. **Compromised sensor or sensor credential.**
4. **Anyone supplying a crafted log or PCAP-derived file** (path tricks, giant or malformed records).
5. **Misuse by the operator** (monitoring beyond authorised scope).

## Threats and controls (STRIDE-oriented)

| # | Threat | Control | Status |
|---|---|---|---|
| T1 | Oversized / malformed / invalid-UTF-8 record exhausts memory or crashes parser | 64 KiB record cap, bounded read chunk, strict decode, per-record error isolation | **Implemented, tested** |
| T2 | Path traversal or symlink escape when importing logs | Resolve-then-contain check; allow-listed file names only | **Implemented, tested** |
| T3 | Truncated writes / rotation silently corrupt data | Newline-gated reads, rotation/truncation detection, truncated-record counter | **Implemented, tested** |
| T4 | Replay creates duplicate alerts | Content-hash `event_id`, bounded dedup, DB unique key | Hash+dedup **implemented**; DB key planned |
| T5 | Naive timestamps skew correlation | Timezone required; naive rejected | **Implemented, tested** |
| T6 | Log content used for injection (SQL, XSS, command, prompt) | Parameterised queries, output encoding, no shell calls, AI isolation | Parser side done; rest planned |
| T7 | Cross-tenant data access | `org_id` on every table and query, RBAC on every endpoint, cross-tenant tests | Planned |
| T8 | Credential attacks | Argon2id, lockout, short-lived tokens, rate limits, MFA-ready | Planned |
| T9 | Sensor impersonation / flooding | Per-sensor credentials, bounded queues, drop/lag metrics, backpressure | Planned |
| T10 | App container compromise leads to packet capture | App containers get no capabilities or host networking; capture only on sensor host | Design rule; Compose check planned |
| T11 | Heuristic output mistaken for proof | `finding_class`, nullable `confidence`, wording rules | Schema done; engine planned |
| T12 | Out-of-scope monitoring | Offline-only default, explicit authorised CIDRs + interface per sensor, audit of enrolment | Planned; CLI already refuses `live` |
| T13 | Tampered audit trail | Append-only table, restricted DB role | Planned |
| T14 | Malicious ruleset updates | No automatic rule downloads; checksum/signature verification and offline validation before enable | Planned |

## Out of scope / residual risk
- A compromised sensor host can emit false telemetry; mitigation is limited to authentication, rate limits and anomaly checks on telemetry gaps.
- Encrypted traffic content is invisible by design; only metadata is analysed.
- This project is not a substitute for a professional security assessment before production use.
