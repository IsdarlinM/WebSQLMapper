# Web SQL Injector / WebSQLMapper

**WebSQLMapper** is a Python 3.11+ toolkit for authorized SQL injection validation. It accepts a target URL, HTTP method, and injection parameter, then runs differential probes to identify SQL injection behavior. A separate SQLite blind-inference mapper is included for **localhost/private lab targets only**.

```text
Web SQL Injector
imr :: v0.1.0
```

## Safety boundary

Use this project only on systems you own or have explicit permission to test. Every active scan requires an authorization acknowledgement (`--authorized` or the equivalent web checkbox). The automated database reconstruction feature intentionally rejects public Internet targets and is meant for local/private training labs.

The scanner does **not** claim to contain every SQL injection payload in existence. Instead, it uses curated, high-signal probe families based on OWASP and PortSwigger testing methodology and keeps the payload layer extensible.

## Features

- GET, POST, PUT, PATCH, and DELETE request support.
- Query-string, form, and JSON parameter injection.
- Reusable headers and cookies.
- Baseline comparison with status, body length, similarity, and timing metrics.
- Syntax/error indicators with DBMS hints for MySQL, PostgreSQL, SQLite, Microsoft SQL Server, and Oracle error strings.
- Paired boolean true/false probes for numeric and string contexts.
- Optional small time-delay probes for MySQL, PostgreSQL, and Microsoft SQL Server.
- Private-lab SQLite mapping with common table/column dictionaries and character-by-character boolean inference.
- Modern responsive web interface using only the Python standard library.
- Zero mandatory third-party runtime dependencies.
- Unit and local integration tests, including an intentionally vulnerable SQLite training server.

## Install

Clone the repository and install it in editable mode:

```bash
git clone https://github.com/IsdarlinM/WebSQLMapper.git
cd WebSQLMapper
python3 -m pip install -e .
```

Or run directly without installation:

```bash
python3 -m websqlmapper --help
```

## CLI: detection scan

```bash
websqlmapper scan \
  --url 'https://authorized.example/item?id=1' \
  --method GET \
  --parameter id \
  --value 1 \
  --authorized
```

POST form example:

```bash
websqlmapper scan \
  --url 'https://authorized.example/login' \
  --method POST \
  --parameter username \
  --body-mode form \
  --data '{"password":"test-password"}' \
  --value test-user \
  --authorized
```

Optional timing probes:

```bash
websqlmapper scan \
  --url 'https://authorized.example/item?id=1' \
  --method GET \
  --parameter id \
  --authorized \
  --time-probes \
  --dbms postgresql
```

Exit code `2` means the scanner found one or more medium/high-confidence SQLi indicators; `0` means no strong indicator was found; `1` means configuration/safety failure.

## Web UI

```bash
websqlmapper web --host 127.0.0.1 --port 8787
```

Open `http://127.0.0.1:8787` in a browser. The interface exposes the same core scan parameters and a separate private-lab mapping action.

## Local vulnerable lab

Start the bundled intentionally vulnerable server in one terminal:

```bash
python3 lab/vulnerable_server.py --port 8088
```

Run the scanner:

```bash
python3 -m websqlmapper scan \
  --url 'http://127.0.0.1:8088/item?id=1' \
  --method GET \
  --parameter id \
  --authorized
```

Map the lab's common SQLite data:

```bash
python3 -m websqlmapper map \
  --url 'http://127.0.0.1:8088/item?id=1' \
  --method GET \
  --parameter id \
  --value 1 \
  --context numeric \
  --max-rows 3 \
  --max-chars 64 \
  --authorized
```

## Tests

The test suite uses only the Python standard library:

```bash
python3 -m unittest discover -s tests -v
```

Compile-time verification:

```bash
python3 -m compileall -q websqlmapper lab tests
```

## Architecture

```text
websqlmapper/
  cli.py          CLI and argument validation
  models.py       request/report dataclasses
  payloads.py     curated detection probe families
  scanner.py      baseline and differential SQLi detector
  mapper.py       private-lab SQLite boolean inference mapper
  safety.py       authorization and private-target controls
  transport.py    stdlib HTTP request construction/execution
  web.py          stdlib HTTP server and JSON API
  static/         responsive web UI
lab/
  vulnerable_server.py
tests/
docs/METHODOLOGY.md
```

## Methodology and references

The detection strategy is informed by OWASP guidance and PortSwigger Web Security Academy's systematic SQL injection testing model: syntax anomalies, boolean condition differences, error behavior, and time delays. Implementation choices for URL handling, CLI parsing, and automated tests follow Python's official documentation. See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for source links and design notes.

## Defensive remediation

When a SQL injection issue is confirmed, fix the query construction itself: use prepared statements / parameterized queries, avoid string-concatenated dynamic SQL, allow-list any unavoidable dynamic identifiers, and grant application database accounts the minimum privileges they require.

## License

MIT.
