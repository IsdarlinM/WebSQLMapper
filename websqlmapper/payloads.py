from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProbePair:
    name: str
    true_payload: str
    false_payload: str
    context: str
    technique: str = "boolean"
    dialects: tuple[str, ...] = ("generic",)


SYNTAX_PROBES = [
    "'",
    '"',
    "')",
    '\")',
    "'))",
    '\"))',
    "\\",
]

BOOLEAN_PROBES = [
    ProbePair("numeric-and", " AND 1=1 -- ", " AND 1=2 -- ", "numeric"),
    ProbePair("numeric-or", " OR 1=1 -- ", " OR 1=2 -- ", "numeric"),
    ProbePair("numeric-parenthesized", ") AND (1=1) -- ", ") AND (1=2) -- ", "numeric"),
    ProbePair("string-and", "' AND '1'='1' -- ", "' AND '1'='2' -- ", "string"),
    ProbePair("string-or", "' OR '1'='1' -- ", "' OR '1'='2' -- ", "string"),
    ProbePair("string-parenthesized", "') AND ('1'='1' -- ", "') AND ('1'='2' -- ", "string"),
]

# Timing probes remain opt-in because they add latency and are inherently noisier
# than content-based differential testing.
TIME_PROBES = {
    "mysql": "' AND SLEEP(2) -- ",
    "postgresql": "'; SELECT pg_sleep(2) -- ",
    "mssql": "'; WAITFOR DELAY '0:0:2' -- ",
}

ERROR_SIGNATURES = {
    "mysql": [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "mysqli",
        "sqlstate[42000]",
        "mariadb server version",
    ],
    "postgresql": [
        "postgresql",
        "pg_query",
        "unterminated quoted string",
        "syntax error at or near",
        "psycopg",
    ],
    "sqlite": [
        "sqlite error",
        "sqlite3.operationalerror",
        "unrecognized token",
        "near \"",
        "sqlite",
    ],
    "mssql": [
        "sql server",
        "microsoft ole db provider",
        "unclosed quotation mark",
        "odbc sql server driver",
        "sqlserverexception",
    ],
    "oracle": [
        "ora-",
        "oracle error",
        "quoted string not properly terminated",
        "oracle.jdbc",
    ],
}
