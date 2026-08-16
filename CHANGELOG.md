# Changelog

## 0.4.0 - 2026-08-15

### Added

- Complete redirect engine with never/same-origin/same-host/any policies, hop evidence, loop/max-hop handling, cross-host credential stripping and redirect-drift profiling.
- Separate connect/read timeout, max-duration, streamed response byte cap, Retry-After handling, retry policies and cookie session modes.
- mTLS client certificate/private-key support.
- Cached semantic response analyzer for JSON/HTML/text.
- Adaptive early-stop and bounded syntax-probe concurrency while keeping timing tests serial.
- WAF/edge, rate-limit, session/auth, redirect and truncation interference profile.
- Session-health controls between scan phases.
- Local injection-point discovery command/API/UI.
- Structured multipart import with scalar-part discovery and preserved file parts.
- Async mapper jobs with pause/resume/cancel and auto numeric/string oracle calibration.
- Bounded Web worker pool, max-job/TTL cleanup and replayable SSE event log with event IDs.
- Remote Web bind opt-in and token protection, plus loopback Host allow-listing to reduce DNS-rebinding exposure.
- Reorganized desktop/mobile Web workspace, visual header/cookie editors, inspector tabs, filters, Web templates/reports, accessibility improvements and PWA shell assets.
- Python 3.10+ compatibility contract and CI definitions through Python 3.14.

### Changed

- Response bodies are streamed and capped before decoding.
- Scanner and mapper now share semantic response similarity.
- Mapper inference caches conditions, uses ASCII-first codepoint bounds, and revalidates private-target DNS resolution during long runs.
- Linux/Windows installers reuse the existing compatible Python >=3.10 and verify the venv keeps the same major/minor.
- Windows Python discovery uses explicit subroutines instead of compound CMD operator chains.

### Fixed during deep regression/debugging

- Interference scoring could raise a TypeError when summing regex Match/None values.
- Mapper Web context default could pass unsupported `auto` into the old oracle.
- Destructive SSE queues could lose events after a browser disconnect.
- Web jobs could accumulate forever and spawn unlimited daemon threads.
- Frontend initialization could fail when localStorage access was blocked.
- Progress used request budget rather than planned work.
- Response body limits were previously applied after `response.text` materialization.
- Repeated form parameters could be collapsed during import.
- Imported multipart scalar fields were not directly selectable.

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
