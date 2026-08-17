# WebSQLMapper

**WebSQLMapper** is a Python 3.10+ toolkit for **authorized SQL injection validation**. Version 0.4.1 focuses on robustness, request fidelity, redirect/session awareness, lower processing overhead, resilient Web jobs, and a more usable desktop/mobile workspace.

```text
Web SQL Injector
imr :: v0.4.1
```

> Use WebSQLMapper only on systems you own or have explicit authorization to test. Automated database reconstruction remains restricted to private/loopback lab targets.

## v0.4.1 highlights

- Redirect engine with `never`, `same-origin`, `same-host`, and `any` policies.
- Full redirect evidence: hops, status, method, source/target, cross-host/origin, HTTPS downgrade, loop/max-redirect outcome.
- Separate connect/read timeout, scan duration, response byte cap, `Retry-After`, and method-aware retry policy.
- Static/session/merge cookie modes and persistent Requests sessions.
- mTLS client certificate/private-key support.
- True streamed response limits instead of decoding an unlimited body first.
- Cached semantic response analyzer for JSON/HTML/text.
- Adaptive early-stop, limited syntax-probe concurrency, WAF/session/redirect interference profiling, and session-health controls.
- Automatic injection-point discovery for query, repeated form/query values, JSON/GraphQL paths, cookies, headers, path segments, and structured multipart text parts.
- Structured multipart import that preserves files and exposes scalar fields for testing.
- Async scan **and mapper** jobs with pause/resume/cancel.
- Bounded Web worker pool, job TTL/limits, and replayable SSE event log with event IDs.
- Remote Web binding protection: explicit `--allow-remote` plus access token.
- Reorganized tabbed Web workspace, request/response/diff/redirect inspector, filters, Web templates/reports, mobile action bar, keyboard focus and live status regions.
- PWA shell assets; service worker caches static assets only and never caches `/api/*`.
- Python compatibility contract: Python >=3.10, tested syntax against Python 3.10 grammar, CI matrix configured for 3.10–3.14.

## Installation

### Linux / Kali / Debian / Ubuntu / Arch / Fedora / Alpine / Termux / Homebrew

```bash
bash scripts/install-linux.sh
```

The installer:

1. detects an already installed Python interpreter;
2. reuses it when it is Python **3.10 or newer**;
3. installs Python/Git/venv support through a supported package manager only when needed;
4. creates the isolated environment with the exact selected Python `major.minor`;
5. installs WebSQLMapper dependencies into that environment;
6. creates the `websqlmapper` command;
7. sets `WEBSQLMAPPER_HOME` and adds the command directory to the user's shell PATH.

See [`docs/INSTALL.md`](docs/INSTALL.md) for fallback and offline behavior.

### Windows CMD

```bat
scripts\install.cmd
```

The CMD installer reuses any compatible installed Python >=3.10. If none is discoverable, it attempts installation with `winget`. It creates an isolated venv with that same interpreter version, verifies the version match, installs dependencies there, makes `websqlmapper` available immediately in the launching Command Prompt, and persists `WEBSQLMAPPER_HOME` plus the command directory in the **user** PATH without replacing existing entries.

## Quick start

```bash
websqlmapper scan \
  --url 'https://app.example.test/product?id=1' \
  --inject query:id \
  --profile normal \
  --authorized
```

Machine-readable output:

```bash
websqlmapper scan \
  --url 'https://app.example.test/product?id=1' \
  --inject query:id \
  --profile safe \
  --authorized \
  --json
```

## Import a real request

### Raw HTTP

```bash
websqlmapper scan \
  --raw request.http \
  --scheme https \
  --inject json:user.profile.id \
  --authorized
```

### cURL

```bash
websqlmapper parse --curl "curl -L 'https://example.test/?id=1'" --discover
```

## Discover injection points without traffic

```bash
websqlmapper discover --url 'https://example.test/users/42?id=1&id=2'
```

Or from an imported request:

```bash
websqlmapper parse --raw request.http --discover
```

Discovery is local parsing only. It does not send requests.

## Redirect control

Redirects are disabled by default.

```bash
# Never follow
websqlmapper scan ... --redirect-policy never

# Follow only when scheme, host and port remain identical
websqlmapper scan ... --redirect-policy same-origin

# Follow hostname-preserving redirects, including port/scheme changes
websqlmapper scan ... --redirect-policy same-host

# Follow any redirect up to the configured limit
websqlmapper scan ... --redirect-policy any --max-redirects 5
```

Compatibility aliases remain available:

```bash
--follow-redirects
--no-follow-redirects
```

Each request evidence record can include the redirect chain and outcome. Cross-host hops remove sensitive authorization/cookie state before the next hop.

## Transport controls

```bash
websqlmapper scan \
  --url 'https://example.test/api?id=1' \
  --inject query:id \
  --connect-timeout 4 \
  --read-timeout 8 \
  --max-duration 300 \
  --max-body 1500000 \
  --retries 1 \
  --retry-policy safe \
  --cookie-mode session \
  --authorized
```

Available retry policies:

- `safe`: retry only GET/HEAD/OPTIONS;
- `all`: allow retries for all supported methods;
- `none`: disable automatic retry.

`429`, `502`, `503`, and `504` are transient candidates. `Retry-After` is honored with a bounded wait.

Cookie modes:

- `static`: resend the configured cookie header exactly;
- `session`: seed a Requests cookie jar and accept server rotation;
- `merge`: seed configured cookies and then keep server updates.

Concurrency is deliberately limited to independent syntax probes. Timing probes remain serial.

```bash
--concurrency 4
```

For concurrency >1, `cookie-mode=static` is required to avoid session-state races.

## TLS, proxy, and authentication

```bash
websqlmapper scan ... \
  --proxy http://127.0.0.1:8080 \
  --ca-bundle ./lab-ca.pem \
  --client-cert ./client-cert.pem \
  --client-key ./client-key.pem \
  --basic user:password
```

Bearer tokens are also supported:

```bash
--bearer TOKEN
```

Sensitive authorization/cookie values are redacted from normal evidence/report output.

## Scan strategies

```text
safe      lowest request cost; timing disabled
normal    balanced default
thorough  more baseline/confirmation work and timing enabled by profile
```

Adaptive scheduling is enabled by default:

```bash
--adaptive
```

When a repeatable, high-confidence boolean oracle is already confirmed, lower-value remaining probe families can be skipped. To force full configured coverage:

```bash
--exhaustive
```

## Interference profile

SQLi confidence is kept separate from request interference signals. Reports can include:

```text
waf_or_edge_blocking
rate_limiting
session_or_auth_drift
redirect_interference
redirect_behavior_drift
response_truncation
```

This helps distinguish middleware/WAF/login changes from database behavior.

## Private SQLite mapper

The automated blind mapper remains hard-restricted to private/loopback targets.

```bash
websqlmapper map \
  --url 'http://127.0.0.1:8088/item?id=1' \
  --inject query:id \
  --context auto \
  --max-rows 1 \
  --max-chars 32 \
  --max-requests 1000 \
  --authorized
```

`context=auto` calibrates both numeric and quoted-string oracles and chooses the better-separated one. The mapper shares the semantic response analyzer, caches answered conditions, and narrows common ASCII codepoints before expanding to Unicode. It also snapshots the initial private/loopback DNS address set and revalidates it during inference; any resolution change or public address stops mapping fail-closed.

## Web interface

Start locally:

```bash
websqlmapper web
```

Default:

```text
http://127.0.0.1:8787
```

The Web UI includes:

- Request / Injection / Transport / Strategy / Templates tabs;
- raw HTTP and cURL import;
- automatic injection-point discovery;
- visual headers/cookies editors;
- async scan and mapper jobs;
- real progress based on planned work;
- pause/resume/stop;
- Findings / Timeline / Inspector / Raw result views;
- Request / Response / Diff / Redirects inspector tabs;
- timeline phase/status/search filters;
- Web template management;
- JSON/Markdown/HTML report download;
- mobile-specific sticky actions;
- keyboard focus styles and live status regions.

### Remote Web binding

A remote bind is intentionally rejected unless explicitly enabled:

```bash
websqlmapper web --host 0.0.0.0
# error: remote web binding requires --allow-remote
```

To permit it:

```bash
websqlmapper web --host 0.0.0.0 --allow-remote
```

A random access token is generated when one is not supplied. You can provide your own:

```bash
websqlmapper web \
  --host 0.0.0.0 \
  --allow-remote \
  --token 'wsm_example_secret'
```

The token protects API/SSE access; state-changing requests also receive an Origin check. Local-only mode additionally rejects unexpected `Host` headers to reduce DNS-rebinding exposure against the loopback UI/API.

## Web job limits

```bash
websqlmapper web \
  --max-workers 4 \
  --max-jobs 50 \
  --job-ttl 1800
```

Jobs execute through a bounded worker pool instead of one unlimited thread per scan. Terminal jobs expire after the TTL. SSE events have IDs and are retained in a bounded replay log so reconnecting clients can resume after a known event ID.

## Reports

Save during a scan:

```bash
websqlmapper scan ... --save report.json --report-format json
```

Render later:

```bash
websqlmapper report report.json --format markdown --output report.md
websqlmapper report report.json --format html --output report.html
```

Reports include confidence, reproducibility, DBMS hints, interference, request timeline, redirect evidence, and redacted request/response excerpts.

## Request templates

```bash
websqlmapper template save product --url 'https://example.test/?id=1' --inject query:id
websqlmapper template list
websqlmapper template show product
websqlmapper template delete product
```

Templates are redacted before persistence.

## Local training lab

```bash
python lab/vulnerable_server.py --host 127.0.0.1 --port 8088
```

Then:

```bash
websqlmapper scan \
  --url 'http://127.0.0.1:8088/item?id=1' \
  --inject query:id \
  --profile safe \
  --authorized
```

The lab also contains dedicated endpoints used to test redirects, loops, large streamed responses, retry behavior, cookie rotation, WAF-like blocking, dynamic JSON, timeouts, and request locations.

## Testing

```bash
python -m compileall -q websqlmapper lab tests
python -X dev -W error::ResourceWarning -m unittest discover -s tests -v
python tests/cli_smoke.py
python tests/browser_smoke.py
bash scripts/test-install-linux.sh
```

The project contains a Python 3.10 grammar compatibility test and CI definitions for Python 3.10 through 3.14 on Linux/Windows.

## Performance model

Version 0.4.1 avoids unnecessary work through:

- persistent HTTP sessions/connection reuse;
- cached normalized/semantic bodies;
- semantic JSON comparison;
- body streaming with a byte cap;
- adaptive early-stop;
- bounded concurrency for independent syntax probes;
- cached mapper boolean conditions;
- narrower ASCII-first character inference.

The default remains conservative: timing measurements are serialized and concurrency is opt-in.

## Architecture

```text
CLI / Web UI
     │
     ├── Importers + Injection Discovery
     │
     ├── RequestConfig
     │       │
     │       ▼
     │   HTTPClient
     │   ├── Session/Cookies
     │   ├── Redirect Engine
     │   ├── Retry/Timeout/Body Limits
     │   ├── Proxy/Auth/mTLS
     │   └── Request Evidence
     │
     ├── Semantic Response Analyzer
     │       │
     │       ├── SQLiScanner
     │       │   ├── Adaptive Scheduler
     │       │   ├── WAF/Auth/Redirect Interference
     │       │   └── DBMS/Confidence/Reproducibility
     │       │
     │       └── SQLiteBlindMapper (private/lab only)
     │
     └── Web Job Manager
         ├── Bounded Worker Pool
         ├── TTL / Job Limits
         └── Replayable SSE Event Log
```

## Defensive remediation

If WebSQLMapper confirms SQL injection behavior in software you maintain, prioritize parameterized/prepared queries, strict query construction, least-privilege database accounts, and server-side input handling. Do not treat WAF filtering as a replacement for fixing unsafe query construction.

## References

- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- PortSwigger SQL injection: https://portswigger.net/web-security/sql-injection
- PortSwigger SQL injection cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- Requests advanced usage: https://requests.readthedocs.io/en/latest/user/advanced/
- Python `concurrent.futures`: https://docs.python.org/3/library/concurrent.futures.html
- Python `venv`: https://docs.python.org/3/library/venv.html

## License

MIT. See [`LICENSE`](LICENSE).
