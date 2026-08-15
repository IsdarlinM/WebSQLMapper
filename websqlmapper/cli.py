from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .mapper import SQLiteBlindMapper
from .models import RequestConfig
from .scanner import SQLiScanner
from .safety import SafetyError
from .web import run_web


BANNER = "Web SQL Injector\nimr :: v0.2.0"


def _json_object(value: str) -> dict[str, Any]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("expected a JSON object")
    return parsed


def _kv_pair(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("expected KEY:VALUE")
    key, val = value.split(":", 1)
    return key.strip(), val.strip()


def _add_request_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    parser.add_argument("--parameter", required=True)
    parser.add_argument("--value", default="1", help="Original parameter value before probes are appended")
    parser.add_argument("--body-mode", default="auto", choices=["auto", "query", "form", "json"])
    parser.add_argument("--data", type=_json_object, default={}, help="Base request data as a JSON object")
    parser.add_argument("--header", action="append", type=_kv_pair, default=[], help="Repeatable KEY:VALUE header")
    parser.add_argument("--cookie", action="append", type=_kv_pair, default=[], help="Repeatable NAME:VALUE cookie")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--authorized", action="store_true", help="Acknowledge explicit authorization to test the target")


def _config(args: argparse.Namespace) -> RequestConfig:
    return RequestConfig(
        url=args.url,
        method=args.method,
        parameter=args.parameter,
        data=dict(args.data),
        headers=dict(args.header),
        cookies=dict(args.cookie),
        body_mode=args.body_mode,
        timeout=args.timeout,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="websqlmapper", description="Authorized SQL injection detector and lab mapper")
    parser.add_argument("--version", action="version", version="WebSQLMapper 0.2.0")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run non-destructive SQL injection probes")
    _add_request_args(scan)
    scan.add_argument("--time-probes", action="store_true", help="Enable optional ~2 second DBMS timing probes")
    scan.add_argument("--dbms", action="append", choices=["mysql", "postgresql", "mssql"], default=[])
    scan.add_argument("--context", choices=["auto", "numeric", "string"], default="auto", help="Injection context; auto tries the most plausible context first")
    scan.add_argument("--baseline-samples", type=int, default=5, help="Baseline requests used to model normal response variance (3-9)")
    scan.add_argument("--confirmation-rounds", type=int, default=3, help="Repeated TRUE/FALSE rounds per boolean probe pair (2-5)")

    mapper = sub.add_parser("map", help="Map a SQLite database using boolean inference on private lab targets only")
    _add_request_args(mapper)
    mapper.add_argument("--context", choices=["numeric", "string"], default="numeric")
    mapper.add_argument("--max-rows", type=int, default=3)
    mapper.add_argument("--max-chars", type=int, default=64)

    web = sub.add_parser("web", help="Start the local web interface")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8787)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            report = SQLiScanner().scan(
                _config(args),
                original_value=args.value,
                authorized=args.authorized,
                time_probes=args.time_probes,
                dbms=args.dbms or None,
                context=args.context,
                baseline_samples=args.baseline_samples,
                confirmation_rounds=args.confirmation_rounds,
            )
            print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
            return 2 if report.likely_vulnerable else 0
        if args.command == "map":
            result = SQLiteBlindMapper().map_database(
                _config(args),
                original_value=args.value,
                context=args.context,
                authorized=args.authorized,
                max_rows=args.max_rows,
                max_chars=args.max_chars,
            )
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
            return 0
        if args.command == "web":
            print(BANNER)
            run_web(args.host, args.port)
            return 0
    except (SafetyError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1
