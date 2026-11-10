# Privacy, retention and monitoring considerations

Network telemetry (IP addresses, DNS names, URLs, SNI) can identify individuals.
This document is guidance for operators, **not legal advice**; requirements vary by
jurisdiction (e.g. UK GDPR / Data Protection Act 2018, workplace monitoring rules).

## Operator responsibilities
- Have lawful authority and a documented purpose before monitoring any network.
- Tell users (employees, household members, guests) that monitoring occurs where required.
- Keep monitoring proportionate: limit scope with permitted CIDRs, capture only what detection needs.

## What the platform records
Metadata only: Zeek/Suricata connection, DNS, HTTP and TLS metadata. It does not
decrypt traffic and does not infer payload content of encrypted flows. HTTP URIs and
user agents may contain personal data; they are length-capped and stored in a
restricted evidence tier *(planned)*.

## Planned controls
- Configurable per-organisation retention with scheduled deletion (default 90 days).
- Optional IP pseudonymisation / truncation for non-privileged roles.
- Access to raw evidence restricted to analysts/admins, and every access audited.
- No transmission of telemetry to external AI services unless explicitly enabled per organisation.
- Sample data is always labelled `data_origin = sample`.

## Sample data
Everything in `tests/fixtures/` is synthetic and uses documentation address ranges.
