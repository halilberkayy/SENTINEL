# Changelog

All notable changes to SENTINEL are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Dropped modules that reported attacks they did not perform: webshell upload,
  SQLi exploitation, hash cracking, stealth, evasion, post-exploitation,
  persistence, exfiltration, C2, and social engineering.
- Removed the interactive payload browser and the APT-named scan profiles.
- Removed the deployment guide, design notes, and hand-maintained API/architecture essays.
  The API is the OpenAPI document served by the app.

### Changed

- A scan requests only the target host, unless `--scope` names more domains.
- Non-interactive scans use the `bounty` profile. Module ids in that profile match the registry.
- Header, robots.txt, and security.txt checks require the response they claim to have seen.
  A missing sitemap is not a finding. A robots path is a finding only when it answers HTTP 200
  without a login form. HTML returned at `security.txt` is not a policy file.
- Stated finding severity is kept. The CVSS table no longer replaces it.
- The web console selects the bounty modules by default and shows the loaded module count.

### Changed (previous)

- Unified the toolchain on **Ruff + Poetry**. CI no longer uses flake8; it now runs
  ruff, black, a Python 3.10/3.11/3.12 test matrix, and advisory mypy/bandit/pip-audit.
- `requirements.txt` is now a documented runtime-only file; the misleading
  "synced with pyproject" claim and the unused `uvloop` / dev-tool entries were removed.
- Reformatted the entire codebase with black (120-col) so `black --check` passes.
- Fixed all enforced ruff findings in `src/` and `tests/`; remaining ignores are
  documented in `pyproject.toml` with per-rule rationale.

### Fixed

- Replaced deprecated `datetime.utcnow()` with timezone-aware `datetime.now(UTC)`
  across the core and tests (Python 3.12 compatibility).
- Added exception chaining (`raise ... from e`) where it was missing.
- Corrected a stale module count in the scanner-engine docstring (57 registered modules).
- Removed a dead `selenium.*` mypy override and the obsolete `version:` key in
  `docker-compose.yml`; replaced the broken `types-all` pre-commit dependency and
  bumped the ruff pre-commit hook to match `pyproject`.

### Added

- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`.
- GitHub issue / pull-request templates and a Dependabot configuration.

## [6.0.0]

### Added

- Red Team + Blue Team platform: 57 lazily-loaded scanning modules with full
  OWASP Top 10 (2025) coverage.
- Campaign management with scope enforcement, MITRE ATT&CK phase tracking, and
  role-based team collaboration.
- Out-of-band (OOB) callback listener for blind SSRF / XXE / OAST verification.
- Blue Team tooling: IOC checker, hardening analyzer, incident tracker.
- Reporting in JSON, HTML, Markdown, SARIF, and MITRE ATT&CK-mapped formats,
  with CVSS v3.1 + v4.0 scoring and AI executive summaries.
- FastAPI REST API (v1) with JWT + RBAC, PostgreSQL/SQLite via async SQLAlchemy,
  Redis caching, Celery task queue, Prometheus metrics, and OpenTelemetry tracing.

[Unreleased]: https://github.com/halilberkayy/SENTINEL/compare/v6.0.0...HEAD
[6.0.0]: https://github.com/halilberkayy/SENTINEL/releases/tag/v6.0.0
