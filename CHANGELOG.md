# Changelog

## 0.4.2 - 2026-08-17

### Added

- Professional remote-console connection bar with explicit locked/connected/offline states.
- Token bootstrap through URL fragments (`#token=...`) so private access links do not send the token in the initial HTTP request.
- Remote access URL discovery for wildcard binds, including LAN/VPN interface addresses when available.
- Optional repeatable `web --allowed-origin` support for trusted cross-origin consoles with controlled CORS preflight handling.
- Bearer-token authentication as an alternative to `X-WebSQLMapper-Token` for remote API clients.
- Live target/injection/profile context strip in the Web workspace.

### Changed

- `web --host 0.0.0.0 --allow-remote` now prints usable access URLs instead of only `http://0.0.0.0:PORT`.
- Remote UI no longer enters an error state on first load before the user supplies the access token.
- Web layout uses a compact professional command bar, fixed-width configuration rail, denser status metrics, stronger empty states and cleaner responsive behavior.
- Mobile and tablet layouts keep remote authentication, target context and scan controls visible without overlapping the workspace.
- Remote custom tokens must contain at least 16 characters.

### Fixed

- `/api/health` reported the stale hard-coded version `0.4.0`; it now reports the package version.
- Initial remote `refreshTemplates()` generated a 401 and changed the entire console to `error` before authentication.
- Remote wildcard bind output was not directly actionable from another device.
- Mobile action-state synchronization could re-enable controls while the remote console was still locked.

## 0.4.1 - 2026-08-17

### Fixed

- Windows CMD installer no longer uses fragile nested `FOR /F` quoting to read Python versions.
- Windows installer verifies both the selected interpreter and venv major/minor explicitly before installing dependencies.
- Windows installer invokes generated `.cmd` wrappers with `call`, so control returns to the installer and final verification executes.
- `websqlmapper` is added to the current Command Prompt PATH immediately and persisted for future terminals without replacing the user's existing PATH.
- Windows user environment persistence is handled by a small Python `winreg` helper, avoiding destructive or truncating PATH rewrites.
- Windows CI/Docker smoke commands call nested batch files correctly.
- Configuration tabs no longer clip the Templates tab on narrow side rails.
- Tablet layout keeps configuration and results side-by-side down to 981 px and avoids wrapping Stop onto a separate toolbar row.
- Metrics use responsive sizing instead of leaving awkward empty grid positions.
- Mobile configuration tabs are arranged in a stable grid instead of hiding the last tab.
- Mobile controls now expose Map and Pause/Resume in addition to Run/Stop.
- Form controls reserve scroll space above the fixed mobile action bar.

### Validation

- Added Windows environment-helper idempotency tests and stronger CMD control-flow assertions.
- Added Chromium geometry regressions for desktop/tablet/mobile tab overflow, toolbar wrapping and mobile action availability.

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
