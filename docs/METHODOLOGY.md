# WebSQLMapper v0.4.0 methodology

## Goal

WebSQLMapper is an authorized SQL-injection verification tool. Its detector is designed to correlate repeatable application behavior rather than treat a single error, status change, or slow request as proof of SQL injection.

Automated database reconstruction remains limited to private/loopback lab targets.

## Request model

A request can originate from CLI fields, raw HTTP, cURL, or a saved redacted template. The request model supports:

- query and repeated query occurrences;
- URL-encoded form fields and repeated occurrences;
- nested JSON / GraphQL values;
- structured multipart scalar parts while preserving file parts;
- cookies;
- selected headers;
- path segments;
- raw/XML placeholders.

The discovery engine enumerates request-controlled scalar values locally without network traffic.

## Redirect methodology

Redirect handling is explicit rather than delegated blindly to a client library. Policies are:

```text
never
same-origin
same-host
any
```

Each hop records status, request method, source URL, target URL, elapsed time, cross-host/cross-origin state, and HTTPS downgrade. Loops and maximum-hop termination are controlled outcomes. Authorization/cookie headers are removed before a cross-host hop.

The scanner compares redirect behavior with its baseline and reports redirect drift as interference independently from SQLi confidence.

## Baseline and semantic comparison

The scanner collects multiple baseline responses and builds an endpoint-specific stability profile. Volatile values such as UUIDs, timestamps and common request identifiers are normalized.

Version 0.4 adds cached semantic representations:

- JSON is parsed and normalized structurally;
- HTML is reduced to stable semantic text/structure hints;
- plain text uses normalized textual comparison.

Normalized and semantic representations are cached to avoid repeating expensive transformations across cluster comparisons.

## Detection families

### Syntax/error behavior

A small set of syntax probes looks for new database-error fingerprints or stable server-error changes not present in baseline.

### Boolean differential behavior

TRUE/FALSE probes run in alternating order for multiple confirmation rounds. Scoring considers:

- within-cluster consistency;
- TRUE/FALSE cross-cluster separation;
- affinity to the baseline;
- stable status separation;
- meaningful length separation;
- per-round reproducibility;
- endpoint baseline variability.

Network failures and WAF-like blocking are excluded or penalized rather than counted as SQL evidence.

### Timing behavior

Timing probes remain serialized. Controls and probes are interleaved and compared against baseline latency variation. Concurrency is never used for timing measurements.

## Interference model

The report contains a separate interference profile for signals such as:

- WAF/edge blocking;
- rate limiting;
- session/authentication drift;
- redirect-policy/loop interference;
- redirect behavior drift;
- response truncation.

A session-health control is sent between major phases to detect login expiry, middleware changes or a target that has started blocking the scanner.

## Adaptive scheduler

The scanner estimates planned work and can stop lower-value remaining probe families after a high-confidence, fully reproducible boolean oracle has already been confirmed. `--exhaustive` disables adaptive early-stop.

Independent syntax probes may use a bounded worker pool when `--concurrency` is greater than one. Stateful cookie modes require concurrency one.

## HTTP robustness

The transport provides:

- persistent Requests sessions and connection reuse;
- separate connect/read timeouts;
- global scan/map duration;
- true streamed response byte limits;
- method-aware retry policy;
- bounded `Retry-After` handling;
- static/session/merge cookie modes;
- HTTP/HTTPS/SOCKS proxy support;
- custom CA bundle;
- optional mTLS client certificate/private key;
- Basic/Bearer authentication;
- explicit redirect policy.

## Private SQLite mapper

The mapper uses the same semantic response analyzer as the scanner. `context=auto` calibrates numeric and quoted-string boolean oracles and chooses the better-separated oracle.

Inference improvements include:

- bounded request/time budgets;
- pause/cancel checkpoints;
- cached boolean conditions;
- common table/column candidates;
- bounded row/character extraction;
- ASCII-first codepoint search before extending to larger Unicode ranges.
- private/loopback DNS resolution is snapshotted at calibration and revalidated during inference; an address-set change or public resolution stops mapping fail-closed.

## Web job architecture

Web scans and mappings run through a bounded `ThreadPoolExecutor`. Job count and terminal-job TTL are configurable. Local-only Web mode also enforces a loopback `Host` allow-list; non-loopback binding requires explicit remote opt-in and token protection.

Events are stored in a bounded per-job log with monotonic IDs. SSE responses include `id:` fields; a reconnecting client can request events after the last seen ID rather than consuming a destructive queue.

Remote Web binding is opt-in and requires an API token. State-changing API requests also receive an Origin check.

## Reporting

Evidence is redacted and bounded. Reports include:

- target/injection point;
- confidence and verdict;
- reproducibility;
- baseline profile;
- DBMS hints;
- interference profile;
- request timeline;
- redirect chains;
- request/response excerpts;
- normalized response diff.

## Defensive guidance

For affected applications, use parameterized/prepared queries, strict query construction, least privilege, and server-side validation. WAF filtering is not a substitute for correcting unsafe query construction.

## References

- OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- PortSwigger SQL injection — https://portswigger.net/web-security/sql-injection
- PortSwigger SQL injection cheat sheet — https://portswigger.net/web-security/sql-injection/cheat-sheet
- Requests advanced usage — https://requests.readthedocs.io/en/latest/user/advanced/
- Python concurrent.futures — https://docs.python.org/3/library/concurrent.futures.html
- WHATWG Server-sent events — https://html.spec.whatwg.org/multipage/server-sent-events.html
