# Changelog

## 0.3.0 - 2026-08-15

### Added

- Raw HTTP request importer and cURL importer.
- Explicit injection-point model for query, repeated query occurrence, form, nested JSON/GraphQL, multipart, cookie, header, path and raw/XML bodies.
- Session-aware `requests` transport with Basic/Bearer authentication.
- HTTP/HTTPS proxy and optional SOCKS proxy support.
- Custom CA bundle, TLS/redirect controls, retry limits, rate limiting, delay and jitter.
- Request preflight validation that rejects deterministic configuration errors before scanning.
- `safe`, `normal` and `thorough` scan profiles.
- Hard request budgets and clean early-stop behavior.
- Separate reproducibility metric and context-profile output.
- DBMS-aware timing scheduler.
- Redacted request/evidence timeline and normalized response diffs.
- JSON, Markdown and self-contained HTML reporting.
- Redacted reusable request templates.
- `doctor`, `update`, `parse`, `report`, and `template` CLI commands.
- Professional ANSI CLI banner/colors with `NO_COLOR` support.
- Asynchronous web scan jobs, SSE progress, pause/resume/cancel controls and evidence inspector.
- Hardened web API body/type validation and security response headers.
- Linux installer/uninstaller with dependency/package-manager discovery and environment setup.
- Windows CMD installer/uninstaller with winget dependency bootstrap and user environment setup.
- Windows Server Core Docker installer smoke definition and helper command.
- GitHub Actions matrices for Python 3.11/3.12/3.13 on Linux/Windows and native installer smoke jobs.
- End-to-end CLI command/argument smoke test and headless Chromium DOM/JavaScript smoke test.

### Changed

- HTTP transport now uses Requests for sessions, proxy support and production-grade request behavior.
- Network/configuration failures are excluded from SQLi boolean scoring.
- Mapper oracle failures are explicit runtime errors rather than assertion-dependent invariants.
- Public database reconstruction remains disabled; SQLite mapping stays restricted to private/local lab targets.

### Fixed during deep regression/debugging

- Invalid retry/request configuration could previously degrade into a zero-score scan instead of a configuration error.
- Local lab timeout tests could emit `BrokenPipeError` after the client disconnected.
- Web UI result panels could overflow a 390 px mobile viewport.
- Browser error state could be reset to idle by button-state code.
- Browser smoke script import-path handling.
- Web API malformed `headers`, `cookies`, boolean fields and DBMS types now return controlled 400 responses instead of reaching the generic 500 boundary.

## 0.2.0 - 2026-08-15

- Adaptive multi-sample baseline and volatile-response normalization.
- Repeated alternating TRUE/FALSE confirmation.
- Numeric confidence scoring, verdicts, context ordering and weighted DBMS profiling.
- Repeated timing probe/control model based on endpoint latency variation.

## 0.1.0

- Initial authorized SQLi detector, private-lab SQLite mapper, CLI, web UI, and local training server.
