# Web SQL Injector / WebSQLMapper

**WebSQLMapper** is a Python 3.11+ toolkit for **authorized SQL injection validation**. Version 0.3.0 adds a professional request engine around the adaptive detector introduced in 0.2.0: raw HTTP/cURL import, nested request injection points, sessions, proxies, request budgets, evidence timelines, reports, templates, live web jobs, installers, and CI.

```text
──────────────────────────────────────────────────
  Web SQL Injector
  imr :: v0.3.0
──────────────────────────────────────────────────
```

## Safety boundary

Use WebSQLMapper only on systems you own or are explicitly authorized to test. Active scans require `--authorized` (or the equivalent web acknowledgement). The automated SQLite data-reconstruction mapper is intentionally restricted in code to localhost/private-network training targets; public targets can be checked for SQLi indicators but cannot use the automated mapper.

The detector uses curated, high-signal probe families rather than pretending that a finite payload list can represent every SQL injection context. It correlates syntax/error behavior, repeatable TRUE/FALSE response separation, endpoint stability, and optional timing evidence.

## 0.3.0 highlights

### Professional Request Engine

- Import raw HTTP requests copied from interception proxies.
- Import common cURL commands.
- Injection locations: query, repeated query occurrence, form, nested JSON/GraphQL variables, structured multipart, cookie, selected header, path segment, and raw/XML placeholder.
- Persistent HTTP session and cookie handling.
- HTTP Basic and Bearer authentication.
- HTTP/HTTPS proxy support plus optional SOCKS support.
- Custom CA bundle, TLS verification control, redirect control, timeout and bounded retries.
- Rate limiting, fixed delay and jitter.
- Network/configuration failures are separated from SQLi evidence.
- Preflight validation rejects deterministic configuration mistakes before a scan starts.

### Detection workflow

- Scan profiles: `safe`, `normal`, `thorough`.
- Adaptive multi-sample baseline and volatile-response normalization.
- Repeated alternating TRUE/FALSE confirmation.
- 0-100 confidence score and a separate reproducibility percentage.
- Context profiling and DBMS-aware timing scheduling.
- Hard request budgets and clean early termination.
- Redacted request/evidence timeline and normalized response diffs.

### CLI and reporting

- Professional ANSI color output with `--color auto|always|never` and `NO_COLOR` support.
- JSON, Markdown and self-contained HTML reports.
- Explicit `--save`; scans remain ephemeral by default.
- Redacted reusable request templates.
- `doctor` diagnostics and a fast-forward `update` command for Git-based installations.

### Web interface

- Responsive professional dashboard.
- Raw HTTP/cURL importer.
- Live asynchronous scan jobs over Server-Sent Events (SSE).
- Start, pause, resume and cancel controls.
- Progress phases, metrics, finding list, request timeline, response diff and evidence inspector.
- API input limits, structured 4xx errors and security response headers.

## Installation

### Linux / Kali / Debian / Ubuntu / Fedora / Arch / Alpine / Termux / Homebrew environments

```bash
git clone https://github.com/IsdarlinM/WebSQLMapper.git
cd WebSQLMapper
bash scripts/install-linux.sh
```

The installer checks for Python >=3.11, pip/venv support and Git. When required it attempts installation through the detected package manager (`apt`, `dnf`, `pacman`, `apk`, Termux `pkg`, or Homebrew), creates an isolated virtual environment, installs WebSQLMapper and optional SOCKS support, creates the `websqlmapper` command, and appends `WEBSQLMAPPER_HOME` plus the command directory to the user's shell environment.

### Windows

Open **Command Prompt** in the repository and run:

```bat
scripts\install.cmd
```

The installer checks for Python >=3.11 and Git. If Python is unavailable it attempts installation with `winget`; Git is also installed with `winget` when possible. The installer creates an isolated venv under `%LOCALAPPDATA%\WebSQLMapper`, creates `websqlmapper.cmd`, sets `WEBSQLMAPPER_HOME`, and appends the command directory to the user `PATH`.

Open a new terminal after installation so persisted environment variables are reloaded.

### Manual development installation

```bash
python3 -m pip install -e '.[socks]'
```

SOCKS support is optional. Core HTTP/HTTPS scanning requires the `requests` runtime dependency.

## First checks

```bash
websqlmapper --version
websqlmapper --color never doctor
websqlmapper --help
```

## Basic scan

```bash
websqlmapper scan \
  --url 'https://authorized.example/item?id=1' \
  --inject query:id \
  --value 1 \
  --profile normal \
  --authorized
```

Legacy `--parameter id --location query` remains supported.

Exit codes:

- `0`: no probable-or-stronger SQLi indicator.
- `1`: controlled configuration, authorization, parsing, safety or runtime error.
- `2`: probable-or-stronger SQLi indication.
- `130`: interrupted by the user.

## Import a raw HTTP request

Save a request as `request.http`:

```http
POST /api/user HTTP/1.1
Host: authorized.example
Content-Type: application/json
Authorization: Bearer test-token

{"user":{"id":1},"filter":"active"}
```

Then scan a nested JSON field:

```bash
websqlmapper scan \
  --raw request.http \
  --scheme https \
  --inject json:user.id \
  --profile normal \
  --authorized
```

Parse without scanning:

```bash
websqlmapper parse --raw request.http --scheme https
```

## Import cURL

```bash
websqlmapper scan \
  --curl "curl -H 'Accept: application/json' 'https://authorized.example/item?id=1'" \
  --inject query:id \
  --authorized
```

## Injection-point syntax

```text
query:id
query:id[1]          # second repeated id parameter
form:username
json:user.profile.id
graphql:variables.userId
cookie:account_id
header:X-Account-ID
path:2               # 1-based non-empty path segment
raw:body             # raw_body must contain {{INJECT}}
```

Nested JSON arrays are supported, for example `json:filters[0].value`.

### Form / multipart

```bash
websqlmapper scan \
  --url 'https://authorized.example/profile' \
  --method POST \
  --body-mode form \
  --data '{"username":"test","role":"user"}' \
  --inject form:username \
  --authorized
```

Structured multipart requests use `--body-mode multipart` with JSON field metadata. Raw multipart copied from a proxy is preserved by the importer and can be tested using an explicit `{{INJECT}}` raw placeholder.

### Raw / XML body

```bash
websqlmapper scan \
  --url 'https://authorized.example/xml' \
  --method POST \
  --body-mode xml \
  --raw-body '<request><id>{{INJECT}}</id></request>' \
  --inject raw:body \
  --authorized
```

## Authentication, proxy and transport controls

```bash
websqlmapper scan \
  --url 'https://authorized.example/api?id=1' \
  --inject query:id \
  --bearer 'TOKEN' \
  --proxy http://127.0.0.1:8080 \
  --ca-bundle ./proxy-ca.pem \
  --timeout 8 \
  --retries 2 \
  --rate 3 \
  --delay-ms 100 \
  --jitter-ms 50 \
  --authorized
```

Basic authentication is available with `--basic USER:PASSWORD`. Use `--no-verify-tls` only when that behavior is explicitly required in an authorized test environment.

SOCKS URLs (`socks4://`, `socks5://`, `socks5h://`) require the optional PySocks dependency. The installer attempts to install it automatically; otherwise the CLI/API returns a controlled explanatory error.

## Scan profiles

| Profile | Baseline | Boolean rounds | Default budget | Timing |
| --- | ---: | ---: | ---: | --- |
| `safe` | 3 | 2 | 80 | disabled |
| `normal` | 5 | 3 | 160 | disabled |
| `thorough` | 7 | 4 | 300 | enabled unless explicitly disabled |

Override bounded values when necessary:

```bash
websqlmapper scan \
  --url 'https://authorized.example/item?id=1' \
  --inject query:id \
  --baseline-samples 7 \
  --confirmation-rounds 4 \
  --max-requests 220 \
  --context auto \
  --authorized
```

## Reports

Explicitly save a scan:

```bash
websqlmapper scan \
  --url 'https://authorized.example/item?id=1' \
  --inject query:id \
  --authorized \
  --save finding.json \
  --report-format json
```

Convert it later:

```bash
websqlmapper report finding.json --format markdown --output finding.md
websqlmapper report finding.json --format html --output finding.html
```

Reports contain the target/injection point, verdict, confidence, reproducibility, DBMS profile, evidence, redacted request timeline, remediation and references. Authentication secrets and common sensitive headers are redacted.

## Request templates

```bash
websqlmapper template save api-user \
  --url 'https://authorized.example/api/user?id=1' \
  --inject query:id

websqlmapper template list
websqlmapper template show api-user
websqlmapper scan --template api-user --authorized
websqlmapper template delete api-user
```

Templates intentionally do not persist bearer tokens, authentication passwords, cookies or sensitive authorization headers.

## Web UI

```bash
websqlmapper web --host 127.0.0.1 --port 8787
```

Open `http://127.0.0.1:8787`. The dashboard supports request import/editing, live asynchronous scan progress, pause/resume/cancel, evidence inspection, response diffs and the private-lab mapper.

## Private training mapper

Start the bundled local lab:

```bash
python3 lab/vulnerable_server.py --port 8088
```

Scan it:

```bash
websqlmapper scan \
  --url 'http://127.0.0.1:8088/item?id=1' \
  --inject query:id \
  --authorized
```

Run the bounded SQLite mapper:

```bash
websqlmapper map \
  --url 'http://127.0.0.1:8088/item?id=1' \
  --inject query:id \
  --value 1 \
  --context numeric \
  --max-rows 3 \
  --max-chars 64 \
  --authorized
```

The mapper rejects public Internet targets before inference begins.

## Update and uninstall

For an installation whose copied source contains its Git metadata:

```bash
websqlmapper update
```

The updater refuses a dirty source checkout unless `--force` is explicitly supplied and uses a fast-forward-only merge.

Linux:

```bash
bash scripts/uninstall-linux.sh
```

Windows:

```bat
scripts\uninstall.cmd
```

User configuration/templates are preserved by the uninstallers.

## Validation and tests

```bash
python3 -m compileall -q websqlmapper lab tests
python3 -m unittest discover -s tests -v
python3 tests/cli_smoke.py
python3 tests/browser_smoke.py
bash scripts/test-install-linux.sh
```

The automated test surface covers response analysis, request parsing, each injection location, retries/redirects/timeouts, SQLi detection, false-positive controls, request budgets, mapper behavior, reports/templates, CLI error boundaries, web API/job controls and installer structure.

GitHub Actions runs the unit/integration suite across Python 3.11, 3.12 and 3.13 on Linux and Windows. A separate workflow executes both Linux and native Windows installer smoke tests.

### Windows installer Docker smoke

A Windows-container definition is included:

```bat
scripts\test-windows-docker.cmd
```

It requires Docker running in **Windows container mode** and builds `docker\Dockerfile.windows`, which uses the official Python Windows Server Core image. This cannot run under a Linux Docker daemon as a Windows container.

## Architecture

```text
websqlmapper/
  analyzer.py      response normalization, stability profile, similarity and diffs
  cli.py           command/argument validation and colored output
  control.py       pause/resume/cancel and progress callbacks
  importers.py     raw HTTP and cURL request parsing
  models.py        request, response, evidence and report dataclasses
  payloads.py      curated detector probes and DBMS error signatures
  scanner.py       adaptive differential detector, profiles, scoring and budgets
  mapper.py        private-lab SQLite boolean inference mapper
  reporting.py     JSON / Markdown / HTML reports
  safety.py        authorization and private-target controls
  templates.py     redacted reusable request profiles
  terminal.py      banner and ANSI color handling
  transport.py     session-aware HTTP request/injection engine
  updater.py       controlled Git fast-forward updater
  web.py           local JSON/SSE API and job control
  static/          responsive browser application
scripts/           installers, uninstallers and installer smoke scripts
lab/               intentionally vulnerable local SQLite training server
tests/             unit, integration, CLI and browser smoke coverage
```

## Methodology and references

Detection methodology is documented in [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md). Installation details are in [`docs/INSTALL.md`](docs/INSTALL.md).

The detector follows OWASP/PortSwigger SQL injection testing and prevention guidance while adding repeatability and endpoint-specific variance controls. Python implementation and packaging choices follow Python's official documentation and the Python Packaging User Guide. HTTP session/proxy behavior follows Requests' official documentation.

## License

MIT.
