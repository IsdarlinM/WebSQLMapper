# Web SQL Injector / WebSQLMapper

**WebSQLMapper** is a Python 3.11+ toolkit for authorized SQL injection validation. It accepts a target URL, HTTP method, and injection parameter, builds an endpoint-specific baseline, and runs repeatable differential probes to identify SQL injection behavior. A separate SQLite blind-inference mapper is included for **localhost/private lab targets only**.

```text
Web SQL Injector
imr :: v0.2.0
```

## Safety boundary

Use this project only on systems you own or have explicit permission to test. Every active scan requires an authorization acknowledgement (`--authorized` or the equivalent web checkbox). The automated database reconstruction feature intentionally rejects public Internet targets and is meant for local/private training labs.

The scanner is a validation tool, not a claim to contain every SQL injection payload. Its probe families are curated around high-signal behaviors documented by OWASP and PortSwigger: syntax anomalies, repeatable boolean differentials, database errors, and optional timing behavior.

## v0.2.0 highlights

- **Adaptive baseline:** 3-9 baseline samples model normal response variance per endpoint.
- **Dynamic-response normalization:** common timestamps, UUIDs, request IDs, long hexadecimal tokens, and similar volatile values are masked before response comparison.
- **Repeatable boolean confirmation:** TRUE/FALSE probes run in multiple alternating rounds and are evaluated as response clusters rather than one-off differences.
- **Confidence score 0-100:** findings receive a numeric score plus `noise`, `low`, `medium`, `high`, or `confirmed` confidence.
- **Scan verdict:** `no-strong-indicator`, `possible`, `probable`, `high-confidence`, or `confirmed`.
- **Automatic context ordering:** numeric-looking values test numeric context first; other values test string context first. Explicit context selection is also supported.
- **DBMS profile:** correlated error and timing evidence is summarized as a weighted DBMS probability profile.
- **Robust timing probes:** optional delay probes use three probe/control pairs and compare them against measured baseline jitter.
- **False-positive regression test:** the bundled lab includes a safe endpoint whose response changes on every request.

## Core features

- GET, POST, PUT, PATCH, and DELETE request support.
- Query-string, form, and JSON parameter injection.
- Reusable headers and cookies.
- Baseline comparison using status, byte length, normalized body similarity, and timing metrics.
- Syntax/error indicators for MySQL/MariaDB, PostgreSQL, SQLite, Microsoft SQL Server, and Oracle-style errors.
- Paired boolean probes for numeric and string contexts.
- Optional small time-delay probes for MySQL, PostgreSQL, and Microsoft SQL Server.
- Private-lab SQLite mapping with common table/column dictionaries and character-by-character boolean inference.
- Responsive local web interface.
- Zero mandatory third-party runtime dependencies.
- Unit and local integration tests using Python's standard library.

## Install

```bash
git clone https://github.com/IsdarlinM/WebSQLMapper.git
cd WebSQLMapper
python3 -m pip install -e .
```

Or run directly:

```bash
python3 -m websqlmapper --help
```

## Detection scan

```bash
websqlmapper scan \
  --url 'https://authorized.example/item?id=1' \
  --method GET \
  --parameter id \
  --value 1 \
  --authorized
```

The v0.2.0 defaults use five baseline samples and three confirmation rounds per boolean pair. Tune them when an authorized target is unusually dynamic:

```bash
websqlmapper scan \
  --url 'https://authorized.example/item?id=1' \
  --parameter id \
  --baseline-samples 7 \
  --confirmation-rounds 5 \
  --context auto \
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
  --context string \
  --authorized
```

Optional timing probes:

```bash
websqlmapper scan \
  --url 'https://authorized.example/item?id=1' \
  --method GET \
  --parameter id \
  --time-probes \
  --dbms postgresql \
  --authorized
```

Timing probes are disabled by default because network latency is noisy and each selected DBMS profile adds controlled delay requests.

### Result model

A scan includes the adaptive baseline and a correlated result summary:

```json
{
  "confidence_score": 92,
  "verdict": "confirmed",
  "detected_context": "numeric",
  "dbms_profile": {"sqlite": 100.0},
  "likely_vulnerable": true
}
```

Each finding also contains its own score and evidence such as cluster similarity, round confirmations, baseline stability, status separation, response length separation, or timing deltas.

CLI exit codes:

- `0`: no probable/confirmed SQL injection indicator.
- `1`: invalid configuration, authorization failure, or safety failure.
- `2`: confidence score is at least 55 (`probable` or stronger).

## Web UI

```bash
websqlmapper web --host 127.0.0.1 --port 8787
```

Open `http://127.0.0.1:8787`. The web interface exposes context selection, adaptive baseline size, confirmation rounds, optional timing probes, and the private-lab mapper.

## Local training lab

Start the intentionally vulnerable SQLite endpoint:

```bash
python3 lab/vulnerable_server.py --port 8088
```

Vulnerable endpoint:

```text
http://127.0.0.1:8088/item?id=1
```

Safe but intentionally volatile control endpoint:

```text
http://127.0.0.1:8088/dynamic?id=1
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

The mapping feature remains hard-restricted to local/private targets.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q websqlmapper lab tests
```

The integration suite verifies both sides of the detector:

- the deliberately vulnerable SQLite endpoint produces a high-confidence/confirmed finding;
- a safe endpoint with changing timestamp and UUID values does not produce a probable SQLi finding;
- the private SQLite mapper still reconstructs bounded test values correctly.

## Architecture

```text
websqlmapper/
  analyzer.py     response normalization, stability profiling and similarity metrics
  cli.py          CLI and argument validation
  models.py       request/report dataclasses
  payloads.py     curated detection probe families and DBMS error signatures
  scanner.py      adaptive baseline, repeated differential detection and scoring
  mapper.py       private-lab SQLite boolean inference mapper
  safety.py       authorization and private-target controls
  transport.py    stdlib HTTP request construction/execution
  web.py          stdlib HTTP server and JSON API
  static/         responsive web UI
lab/
  vulnerable_server.py
 tests/
 docs/
  METHODOLOGY.md
```

## Methodology and references

The active detection strategy follows PortSwigger Web Security Academy's systematic SQL injection testing model: introduce syntax anomalies, compare true and false SQL conditions, observe database errors, and optionally measure DBMS-specific time delays. The v0.2.0 implementation adds repeatability and endpoint-specific variance controls to reduce false positives.

Defensive recommendations follow OWASP: use prepared statements / parameterized queries, avoid unsafe dynamic SQL construction, allow-list identifiers when binding is impossible, and grant application database accounts the minimum privileges they need.

Implementation details use Python standard-library primitives, including `statistics.median` for robust center estimates, `difflib.SequenceMatcher` for text similarity, `re` for conservative volatile-value normalization, and `unittest` for automated tests.

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## License

MIT.
