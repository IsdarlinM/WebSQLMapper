# WebSQLMapper methodology

WebSQLMapper is designed for authorized security validation. Its scanner focuses on **detection signals**, not bulk data extraction from Internet targets. Automated blind reconstruction is deliberately limited to localhost/private lab addresses.

## Detection model

The scanner establishes two baseline requests and then evaluates three families of signals:

1. **Syntax/error probes** — minimal quote/parenthesis mutations that can reveal newly introduced DBMS error signatures.
2. **Boolean differential probes** — paired predicates such as true vs. false conditions. A likely finding requires a systematic response difference rather than a single anomalous status code.
3. **Optional timing probes** — small DBMS-specific delays for MySQL, PostgreSQL, and Microsoft SQL Server. These are disabled by default because timing is noisy and increases test cost.

The response comparator considers status, byte length, body similarity, and elapsed time. Findings are indicators requiring analyst confirmation; they are not treated as proof merely because one request changed.

## Lab-only SQLite mapper

The mapping engine supports boolean inference against SQLite in a controlled local/private lab. It:

- calibrates a true/false response oracle;
- checks a curated list of common table names against `sqlite_master`;
- checks common column names via `pragma_table_info`;
- infers bounded row counts;
- reconstructs selected cell values character-by-character using boolean comparisons on Unicode code points.

Hard limits are applied to rows and characters, and public IP targets are rejected before mapping begins.

## Reference sources

- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — SQL injection: https://portswigger.net/web-security/sql-injection
- PortSwigger SQL injection cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- SQLite PRAGMA documentation: https://sqlite.org/pragma.html
- SQLite core SQL functions: https://sqlite.org/lang_corefunc.html
- Python `urllib.parse`: https://docs.python.org/3/library/urllib.parse.html
- Python `argparse`: https://docs.python.org/3/library/argparse.html
- Python `unittest`: https://docs.python.org/3/library/unittest.html

## Defensive guidance

A detected issue should be fixed at the query boundary. Prefer prepared statements / parameterized queries, reduce dynamic SQL, allow-list identifiers when dynamic identifiers are unavoidable, and apply least privilege to application DB accounts. These practices align with OWASP guidance.
