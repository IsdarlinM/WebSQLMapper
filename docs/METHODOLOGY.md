# WebSQLMapper detection methodology

WebSQLMapper is designed for **authorized security validation**. Public targets may use the detection scanner only. Automated database reconstruction remains restricted in code to localhost/private lab addresses.

## v0.2.0 detection pipeline

The scanner now follows this sequence:

1. Validate the URL and explicit authorization acknowledgement.
2. Collect 3-9 baseline responses (five by default).
3. Normalize common volatile response values.
4. Measure endpoint-specific content, length, and latency variance.
5. Run minimal syntax/error probes.
6. Run context-aware TRUE/FALSE boolean probe pairs in repeated alternating rounds.
7. Measure within-TRUE consistency, within-FALSE consistency, and cross-cluster separation.
8. Optionally run repeated DBMS timing probes interleaved with control requests.
9. Correlate finding evidence into a 0-100 confidence score and DBMS profile.
10. Return evidence for analyst review rather than treating a single changed response as proof.

## Adaptive baseline

A single HTTP response is not a reliable reference for modern applications. Pages frequently include timestamps, request IDs, CSRF-like tokens, trace identifiers, and other values unrelated to the tested parameter.

WebSQLMapper therefore collects multiple baseline responses and records:

- median response byte length;
- median absolute deviation (MAD) of response length;
- median elapsed time;
- MAD of elapsed time;
- median pairwise normalized-body similarity;
- minimum pairwise similarity;
- a 0-100 stability score;
- an endpoint-specific minimum differential margin.

The median is used instead of the arithmetic mean for baseline center estimates because it is less affected by outliers. This behavior is documented by Python's `statistics` module.

## Conservative response normalization

Before text comparison, the analyzer masks common volatile shapes:

- UUID values;
- ISO-like date/time values;
- plausible epoch timestamps;
- long hexadecimal identifiers/tokens;
- values attached to common nonce/request/trace/correlation identifiers.

The normalizer intentionally does **not** delete arbitrary numbers or application text. Over-normalization can hide a real SQL-controlled response difference.

Normalized bodies are compared using a symmetric average of Python `difflib.SequenceMatcher` ratios with `autojunk=False`. Python documents that SequenceMatcher's automatic junk heuristic may be asymmetric on some inputs; symmetric comparison makes detector behavior more predictable.

## Boolean differential confirmation

Boolean SQL injection is evaluated as two repeated response clusters, not one TRUE request and one FALSE request.

For every selected probe pair, the default scanner sends three TRUE/FALSE rounds and alternates which condition is requested first. The analyzer then measures:

- consistency among TRUE responses;
- consistency among FALSE responses;
- similarity between the two clusters;
- affinity of each cluster with the baseline;
- status-code separation;
- median byte-length separation;
- the number of rounds that independently confirm a difference.

A content difference must exceed the endpoint's observed baseline variability before it contributes strong evidence.

## Confidence scoring

Findings use a 0-100 confidence scale.

| Score | Finding confidence | Scan interpretation |
| --- | --- | --- |
| 0-34 | noise | no strong indicator |
| 35-54 | low | possible |
| 55-74 | medium | probable |
| 75-89 | high | high-confidence |
| 90-100 | confirmed | confirmed by repeated detector evidence |

Boolean scoring rewards repeated rounds, cluster separation, stable baselines, reproducible status differences, and meaningful byte-length separation. Error-based scoring rewards newly introduced DBMS-specific error signatures. Timing scoring requires repeated delay/control separation.

The word `confirmed` describes confirmation by WebSQLMapper's differential model. An analyst should still validate scope, application logic, and reproducibility before submitting a security report.

## DBMS profiling

The DBMS profile is evidence-weighted rather than guessed from a single header. Current evidence comes from:

- newly introduced DBMS error signatures;
- successful optional DBMS-specific timing probes.

The profile currently recognizes MySQL/MariaDB, PostgreSQL, SQLite, Microsoft SQL Server, and Oracle-style error patterns. A profile is omitted when the scan has no DBMS-specific evidence.

## Timing model

Timing tests are opt-in. A single slow request is not enough because network and application latency naturally vary.

For each selected DBMS timing probe, WebSQLMapper performs three probe/control pairs and alternates ordering. It compares each probe directly with its adjacent control and requires at least two confirming rounds. The minimum delay threshold is also increased when the baseline has measurable latency MAD.

## Context selection

`--context auto` orders probe contexts from most plausible to least plausible:

- numeric-looking original values: numeric, then string;
- other values: string, then numeric.

Users can force `--context numeric` or `--context string` when the SQL context is already known.

## Lab-only SQLite mapper

The mapper is deliberately separate from public-target detection. It:

- rejects public targets before mapping;
- calibrates a boolean oracle;
- checks a bounded common table dictionary against `sqlite_master`;
- checks bounded common column names through `pragma_table_info`;
- infers bounded row counts;
- reconstructs selected cell values character-by-character using SQLite `length`, `substr`, and `unicode` operations.

The public scanner does not automatically reconstruct remote Internet databases.

## Reference sources

Security/testing methodology:

- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Query Parameterization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- PortSwigger Web Security Academy — SQL injection: https://portswigger.net/web-security/sql-injection
- PortSwigger SQL injection cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- PortSwigger blind SQL injection: https://portswigger.net/web-security/sql-injection/blind

Database references:

- SQLite PRAGMA documentation: https://sqlite.org/pragma.html
- SQLite core SQL functions: https://sqlite.org/lang_corefunc.html

Python implementation references:

- Python `statistics`: https://docs.python.org/3/library/statistics.html
- Python `difflib`: https://docs.python.org/3/library/difflib.html
- Python `re`: https://docs.python.org/3/library/re.html
- Python `urllib.parse`: https://docs.python.org/3/library/urllib.parse.html
- Python `argparse`: https://docs.python.org/3/library/argparse.html
- Python `unittest`: https://docs.python.org/3/library/unittest.html

## Defensive guidance

OWASP's primary recommendation is to stop constructing SQL with untrusted input through string concatenation and use prepared statements / parameterized queries. Where identifiers cannot be bound as parameters, use strict allow-lists. Apply least privilege to application database accounts so a successful injection has the smallest possible impact.
