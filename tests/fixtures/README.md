# Fixture provenance

Everything under `sample/` is **synthetic**, hand-written for this project and
released under the project licence (MIT). It is not derived from any capture of
real traffic.

- IP addresses are only from documentation ranges (RFC 5737: `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`; RFC 3849: `2001:db8::/32`).
- Hostnames use the reserved `.test` / `example` names.
- Signature `9000001` is a made-up ID for fixture testing, not a real ruleset entry.

These files exercise the parsers; they are not a detection benchmark. Any
precision/recall figures must come from a separately documented labelled
dataset (see TESTING.md).
