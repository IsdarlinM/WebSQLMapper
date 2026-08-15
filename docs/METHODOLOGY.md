# WebSQLMapper v0.3.0 methodology

WebSQLMapper is an **authorized SQL injection validation tool**. It is designed to distinguish SQL-controlled behavior from normal application/network variation and to preserve reproducible evidence for analyst review.

Automated database reconstruction is a separate capability and remains restricted in code to localhost/private training targets.

## Detection pipeline

A normal scan follows this high-level sequence:

1. require explicit authorization acknowledgement;
2. validate URL, HTTP method, injection point and deterministic transport settings;
3. establish a multi-sample baseline;
4. normalize conservative volatile response values;
5. calculate endpoint-specific stability and differential thresholds;
6. send minimal syntax/error probes;
7. test context-appropriate TRUE/FALSE probe pairs in repeated alternating rounds;
8. correlate content clusters, status, length and baseline affinity;
9. optionally execute repeated DBMS-aware timing probe/control pairs;
10. produce finding confidence, overall verdict, reproducibility and DBMS profile;
11. preserve redacted evidence/timeline data for manual review.

A single changed HTTP response is not treated as proof of SQL injection.

## Request model

Version 0.3.0 separates the request representation from the detector. A request can originate from CLI fields, a raw HTTP message, a cURL command or a saved redacted template.

Supported injection locations include:

- query parameters, including an indexed repeated occurrence such as `id[1]`;
- URL-encoded form fields;
- nested JSON and GraphQL variable paths such as `user.items[0].id`;
- structured multipart fields;
- cookies;
- explicitly selected request headers;
- 1-based URL path segments;
- raw/XML body templates containing `{{INJECT}}`.

The transport uses a persistent Requests `Session`, so ordinary response cookies/session state are retained between scan requests. Basic and Bearer authentication, proxies, CA bundles, redirects, timeout/retry controls and pacing are represented explicitly in `RequestConfig`.

Deterministic configuration mistakes are rejected in a preflight step. Per-request network failures are represented as response snapshots with status `0` and an error message; they do not become SQLi evidence.

## Adaptive baseline

Modern responses frequently contain timestamps, trace IDs, nonces and other values unrelated to the tested parameter. WebSQLMapper collects multiple baseline responses and records:

- median byte length;
- median absolute deviation (MAD) of length;
- median elapsed time and timing MAD;
- median/minimum pairwise normalized-body similarity;
- a stability score;
- an endpoint-specific differential margin.

The median is intentionally used as a robust center estimate in the presence of outliers.

## Conservative response normalization

The normalizer masks narrowly recognized volatile shapes such as:

- UUIDs;
- ISO-like date/time values;
- plausible epoch timestamps;
- long hexadecimal identifiers;
- values associated with common request/trace/correlation identifiers.

It does not remove arbitrary application numbers or text because excessive normalization can hide genuine SQL-controlled differences.

Bodies are compared using a symmetric average of `difflib.SequenceMatcher` ratios with `autojunk=False`.

## Boolean differential confirmation

TRUE and FALSE conditions are evaluated as repeated clusters. Depending on the scan profile, multiple alternating rounds are executed to reduce ordering/network bias.

Evidence includes:

- within-TRUE consistency;
- within-FALSE consistency;
- cross-cluster similarity;
- affinity with the baseline;
- repeatable status separation;
- median response-length separation;
- number and percentage of independently confirming rounds.

A network/configuration failure in either cluster prevents that pair from receiving a positive boolean score.

## Confidence and reproducibility

Confidence and reproducibility are deliberately separate.

Confidence asks: **how strongly does the correlated evidence support SQL-controlled behavior?**

Reproducibility asks: **how consistently did repeated confirmation rounds reproduce the differential?**

Overall verdicts are:

| Score | Verdict |
| ---: | --- |
| 0-34 | `no-strong-indicator` |
| 35-54 | `possible` |
| 55-74 | `probable` |
| 75-89 | `high-confidence` |
| 90-100 | `confirmed` |

`confirmed` means confirmed by WebSQLMapper's differential model; scope and business/security impact still require analyst validation.

## Timing model

Timing tests are profile/option controlled because Internet latency is noisy. A single slow response is insufficient.

Timing detection uses repeated adjacent probe/control pairs and compares their deltas with measured baseline timing variation. When early evidence strongly identifies a supported DBMS, the scheduler prioritizes that DBMS's timing probe rather than indiscriminately sending every timing syntax.

## DBMS profile

The DBMS profile is evidence-weighted. Current evidence sources include newly introduced database error signatures and successful DBMS-specific timing behavior.

Recognized error families include MySQL/MariaDB, PostgreSQL, SQLite, Microsoft SQL Server and Oracle-style errors. Timing probes currently cover MySQL, PostgreSQL and SQL Server.

## Context profile

The scanner orders numeric/string probe contexts from the original value and records higher-level hints for likely numeric, quoted-string, ORDER BY, or LIMIT/OFFSET-style parameter roles. These are scheduling/analyst hints rather than a claim to parse the server-side SQL statement.

## Request budgets and cancellation

Every profile has a default hard request budget and users can provide a bounded custom budget. The scan controller checks budget/cancel/pause state between requests. Reaching the budget or receiving cancellation stops cleanly and is recorded in the report.

## Evidence handling

Timelines contain method, redacted URL/headers/body excerpts, status, length, elapsed time, phase and labels. Common authorization/cookie/API-key headers and password/token-like body fields are redacted before report storage.

Finding evidence may contain bounded normalized response diffs for baseline/error or TRUE/FALSE comparison.

Scans are ephemeral by default; persistence requires explicit `--save` or a user report action.

## Web API robustness

The local API imposes a 2 MB request-body limit, validates JSON root/type expectations, returns structured 4xx errors for deterministic user input problems, and keeps a generic 500 boundary only as a last-resort server protection. SSE disconnects and ordinary connection resets are handled without intentionally propagating tracebacks to the user interface.

## Private-lab SQLite mapper

The mapper:

- rejects public targets before inference;
- validates request configuration before calibration;
- calibrates a TRUE/FALSE boolean oracle;
- stops on oracle/network failure instead of comparing empty responses;
- checks bounded common table names through `sqlite_master`;
- checks bounded column names through `pragma_table_info`;
- infers bounded row counts;
- reconstructs selected values character-by-character using SQLite `length`, `substr`, and `unicode` functions.

Public Internet databases are not automatically reconstructed.

## Primary references

### SQL injection security/testing

- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Query Parameterization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- PortSwigger Web Security Academy — SQL injection: https://portswigger.net/web-security/sql-injection
- PortSwigger SQL injection cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- PortSwigger blind SQL injection: https://portswigger.net/web-security/sql-injection/blind
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

### Database behavior

- SQLite PRAGMA documentation: https://sqlite.org/pragma.html
- SQLite core functions: https://sqlite.org/lang_corefunc.html

### Python and packaging

- Python `argparse`: https://docs.python.org/3/library/argparse.html
- Python `difflib`: https://docs.python.org/3/library/difflib.html
- Python `statistics`: https://docs.python.org/3/library/statistics.html
- Python `unittest`: https://docs.python.org/3/library/unittest.html
- Python virtual environments: https://docs.python.org/3/library/venv.html
- Python Packaging User Guide: https://packaging.python.org/

### HTTP runtime

- Requests advanced usage (sessions, proxies, TLS): https://requests.readthedocs.io/en/stable/user/advanced/

## Defensive guidance

The remediation target is the server-side query construction. OWASP recommends prepared statements/parameterized queries, strict allow-listing for dynamic identifiers that cannot be bound, and least-privilege database accounts. Input validation is useful defense-in-depth but is not a substitute for safe query parameterization.
