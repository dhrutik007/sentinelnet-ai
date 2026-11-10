# Contributing

1. Fork, create a branch, keep changes focused.
2. Run `pytest`, `ruff check .`, `ruff format --check .`, `mypy src` before opening a PR.
3. Add tests for every behaviour change, including malformed-input cases for parsers.
4. Do not commit secrets, real captures, or data containing personal information. Fixtures must be synthetic or legally redistributable with documented provenance.
5. Contributions adding unauthorised sniffing, interception, spoofing, MITM or attack tooling will be rejected.
6. Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
