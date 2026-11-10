# Security policy

## Reporting a vulnerability
Please report privately via GitHub's **"Report a vulnerability"** (Security
Advisories) on this repository. Do not open a public issue for security problems.
Include affected version/commit, reproduction steps and impact. Please allow a
reasonable period for a fix before public disclosure. This is a portfolio/research
project maintained on a best-effort basis; no SLA is promised.

## Safe-use rules
- Monitor only networks you own or have **explicit written authorisation** to monitor.
- The project intentionally contains no sniffing-by-default, spoofing, interception,
  redirection or man-in-the-middle functionality, and will not accept contributions adding it.
- Do not run attack tools against infrastructure you do not own. Use isolated labs.

## Current security posture (honest status)
Implemented and tested: bounded/strict parsing, path containment, timezone enforcement,
idempotent event IDs. **Not yet implemented:** authentication, RBAC, tenant isolation,
TLS, rate limiting, audit logging, secret management, container hardening. Do not
expose any future service built from this repository to untrusted networks until
those phases are complete and independently reviewed. See THREAT_MODEL.md.
