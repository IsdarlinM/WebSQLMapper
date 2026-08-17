# WebSQLMapper

**WebSQLMapper** is a Python **3.10+** toolkit for authorized SQL injection validation. Version **0.4.2** focuses on a professional Web workspace, reliable remote-console operation, request fidelity, redirect/session awareness, and reproducible differential evidence.

```text
Web SQL Injector
imr :: v0.4.2
```

> Use WebSQLMapper only on systems you own or are explicitly authorized to test. Automated database reconstruction remains restricted to private/loopback lab targets.

## Highlights

- Adaptive SQLi detector with baseline stability, repeatable TRUE/FALSE confirmation, confidence and reproducibility scores.
- Query, form, nested JSON/GraphQL, multipart, cookie, header, path and raw/XML injection points.
- Raw HTTP and cURL import plus local injection-point discovery.
- Explicit redirect policies: `never`, `same-origin`, `same-host`, `any`.
- Session cookies, Basic/Bearer auth, HTTP/SOCKS proxy support, custom CA and mTLS.
- Streamed body limits, connect/read timeouts, rate limits, retries and `Retry-After` handling.
- WAF/rate-limit/session/redirect interference profiling separated from SQLi confidence.
- JSON/Markdown/HTML reporting and redacted request templates.
- Async Web scan and private-lab mapper jobs with pause/resume/cancel and replayable SSE.
- Professional responsive Web UI for desktop, tablet and mobile.
- Protected remote Web console with token authentication, usable LAN/VPN access URLs and optional explicit CORS origins.

## Install

### Linux / Kali / Debian / Ubuntu / Fedora / Arch / Alpine / Termux

```bash
bash scripts/install-linux.sh
```

### Windows CMD

```bat
scripts\install.cmd
```

Both installers prefer an already-installed compatible **Python >=3.10**, create the venv with that same major/minor, install dependencies into it, create the `websqlmapper` command and configure the user environment.

See [`docs/INSTALL.md`](docs/INSTALL.md) for installation details.

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

## Import a captured request

Raw HTTP:

```bash
websqlmapper scan \
  --raw request.http \
  --scheme https \
  --inject json:user.profile.id \
  --authorized
```

cURL parsing/discovery:

```bash
websqlmapper parse --curl "curl -L 'https://example.test/?id=1'" --discover
```

Discovery never sends traffic:

```bash
websqlmapper discover --url 'https://example.test/users/42?id=1&id=2'
```

## Redirect control

```bash
websqlmapper scan ... --redirect-policy never
websqlmapper scan ... --redirect-policy same-origin
websqlmapper scan ... --redirect-policy same-host
websqlmapper scan ... --redirect-policy any --max-redirects 5
```

Each redirect hop can be recorded with status, method, source/target, timing, cross-host/origin state and HTTPS downgrade information.

## Web interface

Start locally:

```bash
websqlmapper web
```

Default:

```text
http://127.0.0.1:8787
```

The v0.4.2 Web UI uses a professional analyst workspace with:

- compact command bar and live connection state;
- current target/injection/profile context;
- Request / Injection / Transport / Strategy / Templates configuration tabs;
- automatic input discovery;
- visual header/cookie editors;
- Run / Map / Pause / Resume / Stop controls;
- confidence, reproducibility, DBMS, interference and request metrics;
- Findings / Timeline / Inspector / Raw result tabs;
- request/response/diff/redirect evidence inspection;
- mobile action controls and responsive layout.

## Remote Web console

Remote binding is intentionally opt-in:

```bash
websqlmapper web --host 0.0.0.0 --allow-remote
```

When no token is provided, WebSQLMapper creates one and prints usable private links, for example:

```text
WebSQLMapper web console · v0.4.2
Listening on 0.0.0.0:8787
Access URLs:
  http://127.0.0.1:8787/#token=wsm_...
  http://192.168.1.50:8787/#token=wsm_...
Web access token: wsm_...
```

`0.0.0.0` is only a bind address; clients use the server's actual LAN/VPN address. The token in the private link is stored in the URL **fragment**, which browsers do not send in the initial HTTP request. The Web UI consumes it into session storage and removes the fragment from the address bar.

Custom token:

```bash
websqlmapper web \
  --host 0.0.0.0 \
  --allow-remote \
  --token 'wsm_my_private_console_token'
```

Trusted cross-origin console/reverse-proxy integration can be enabled explicitly:

```bash
websqlmapper web \
  --host 0.0.0.0 \
  --allow-remote \
  --allowed-origin 'https://console.example.test'
```

`--allowed-origin` is repeatable. Direct same-origin WebSQLMapper usage does not require CORS configuration.

API authentication supports:

```text
X-WebSQLMapper-Token: <token>
Authorization: Bearer <token>
```

Native `EventSource` cannot attach a custom auth header, so query-token authentication is accepted only on the SSE event route and the server redacts it from logs.

For untrusted networks, put the console behind HTTPS and restrict network access. See [`docs/REMOTE_WEB.md`](docs/REMOTE_WEB.md).

## Private SQLite mapper

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

The mapper is hard-restricted to private/loopback targets and revalidates private DNS resolution during inference.

## Reports

```bash
websqlmapper scan ... --save report.json --report-format json
websqlmapper report report.json --format markdown --output report.md
websqlmapper report report.json --format html --output report.html
```

## Tests

```bash
python -m compileall -q websqlmapper lab tests
python -X dev -W error::ResourceWarning -m unittest discover -s tests -v
python tests/browser_smoke.py
python tests/remote_console_smoke.py
bash scripts/test-install-linux.sh
```

The project has a Python 3.10 grammar-compatibility contract and CI definitions through Python 3.14.

## References

- OWASP SQL Injection Prevention Cheat Sheet
- OWASP Injection Prevention Cheat Sheet
- PortSwigger SQL injection and SQLi cheat sheet
- Requests advanced usage
- Python `concurrent.futures` and `venv` documentation
- WHATWG Server-Sent Events

## License

MIT. See [`LICENSE`](LICENSE).
