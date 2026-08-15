from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from .importers import (
    RequestParseError,
    infer_original_value,
    parse_curl,
    parse_raw_request,
    read_text_input,
)
from .mapper import SQLiteBlindMapper
from .models import RequestConfig
from .reporting import load_report, render_report
from .scanner import SQLiScanner
from .safety import SafetyError
from .templates import delete_template, list_templates, load_template, save_template
from .terminal import P, VERSION, banner, color_enabled, paint, severity_color
from .updater import update_installation
from .web import run_web


BANNER = f"Web SQL Injector\nimr :: v{VERSION}"
_LOCATIONS = ["auto", "query", "form", "json", "graphql", "cookie", "header", "path", "raw"]
_BODY_MODES = ["auto", "query", "form", "json", "graphql", "multipart", "raw", "xml"]


def _json_value(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"invalid JSON: {exc.msg}") from exc


def _kv_pair(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("expected KEY:VALUE")
    key, val = value.split(":", 1)
    if not key.strip():
        raise argparse.ArgumentTypeError("key cannot be empty")
    return key.strip(), val.strip()


def _inject_point(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("expected LOCATION:PARAMETER, for example query:id or json:user.id")
    location, parameter = value.split(":", 1)
    location = location.strip().lower()
    parameter = parameter.strip()
    if location not in _LOCATIONS or location == "auto":
        raise argparse.ArgumentTypeError(f"LOCATION must be one of: {', '.join(_LOCATIONS[1:])}")
    if not parameter:
        raise argparse.ArgumentTypeError("injection parameter cannot be empty")
    return location, parameter


def _basic_auth(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("expected USER:PASSWORD")
    return tuple(value.split(":", 1))  # type: ignore[return-value]


def _add_request_args(parser: argparse.ArgumentParser, *, allow_template: bool = True) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="Target URL")
    source.add_argument("--raw", metavar="FILE_OR_TEXT", help="Raw HTTP request file, '-' for stdin, or inline request")
    source.add_argument("--curl", metavar="FILE_OR_TEXT", help="cURL command file or inline command")
    if allow_template:
        source.add_argument("--template", help="Load a saved request template")
    parser.add_argument("--scheme", choices=["http", "https"], default="https", help="Scheme for relative raw HTTP requests")
    parser.add_argument("--method", choices=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    parser.add_argument("--inject", type=_inject_point, metavar="LOCATION:PARAM", help="Injection point, e.g. query:id or json:user.id")
    parser.add_argument("--parameter", help="Legacy parameter name; combine with --location when needed")
    parser.add_argument("--location", choices=_LOCATIONS, help="Legacy injection location used with --parameter")
    parser.add_argument("--value", help="Original value; inferred from imported requests when omitted")
    parser.add_argument("--body-mode", choices=_BODY_MODES)
    parser.add_argument("--data", type=_json_value, help="Base request data as JSON")
    parser.add_argument("--raw-body", help="Raw/XML body template containing {{INJECT}}")
    parser.add_argument("--header", action="append", type=_kv_pair, default=[], help="Repeatable KEY:VALUE header")
    parser.add_argument("--cookie", action="append", type=_kv_pair, default=[], help="Repeatable NAME:VALUE cookie")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--proxy", help="HTTP/HTTPS/SOCKS proxy URL")
    parser.add_argument("--verify-tls", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--ca-bundle", help="Custom CA bundle path for TLS verification")
    parser.add_argument("--follow-redirects", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--basic", type=_basic_auth, metavar="USER:PASSWORD", help="HTTP Basic authentication")
    parser.add_argument("--bearer", help="Bearer token (redacted from reports)")
    parser.add_argument("--rate", type=float, help="Maximum requests per second (0 = unlimited)")
    parser.add_argument("--delay-ms", type=int, help="Minimum delay before each request")
    parser.add_argument("--jitter-ms", type=int, help="Additional random delay range")
    parser.add_argument("--retries", type=int, help="Network/transient HTTP retry count (0-5)")
    parser.add_argument("--authorized", action="store_true", help="Acknowledge explicit authorization to test the target")


def _build_config(args: argparse.Namespace) -> tuple[RequestConfig, str]:
    imported = False
    if getattr(args, "raw", None) is not None:
        item = parse_raw_request(read_text_input(args.raw), scheme=args.scheme)
        config = item.config
        imported = True
    elif getattr(args, "curl", None) is not None:
        item = parse_curl(read_text_input(args.curl))
        config = item.config
        imported = True
    elif getattr(args, "template", None) is not None:
        config = load_template(args.template)
        imported = True
    elif getattr(args, "url", None):
        config = RequestConfig(url=args.url)
    else:
        raise ValueError("one request source is required")

    if args.method:
        config.method = args.method
    if args.body_mode:
        config.body_mode = args.body_mode
    if args.data is not None:
        config.data = args.data
    if args.raw_body is not None:
        config.raw_body = args.raw_body
    if args.header:
        config.headers.update(dict(args.header))
    if args.cookie:
        config.cookies.update(dict(args.cookie))
    if args.timeout is not None:
        config.timeout = args.timeout
    if args.proxy is not None:
        config.proxy = args.proxy
    if args.verify_tls is not None:
        config.verify_tls = args.verify_tls
    if args.ca_bundle is not None:
        config.ca_bundle = args.ca_bundle
    if args.follow_redirects is not None:
        config.follow_redirects = args.follow_redirects
    if args.basic:
        config.auth_type = "basic"
        config.auth_username, config.auth_password = args.basic
    if args.bearer is not None:
        config.bearer_token = args.bearer
    if args.rate is not None:
        config.rate = args.rate
    if args.delay_ms is not None:
        config.delay_ms = args.delay_ms
    if args.jitter_ms is not None:
        config.jitter_ms = args.jitter_ms
    if args.retries is not None:
        config.retries = args.retries

    if args.inject:
        config.location, config.parameter = args.inject
    elif args.parameter:
        config.parameter = args.parameter
        config.location = args.location or config.location or "auto"
    elif not getattr(args, "template", None):
        source = "imported request" if imported else "URL"
        raise ValueError(f"{source} requires --inject LOCATION:PARAM or --parameter")

    original_value = args.value
    if original_value is None:
        original_value = infer_original_value(config, config.location, config.parameter, "1")
    return config, original_value


def _add_scan_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only")
    parser.add_argument("--verbose", action="store_true", help="Show request timeline in human output")
    parser.add_argument("--save", metavar="PATH", help="Explicitly save a report; scans are ephemeral by default")
    parser.add_argument("--report-format", choices=["json", "markdown", "html"], default="json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websqlmapper",
        description="Authorized SQL injection differential detector and private-lab mapper",
        epilog="Use only on systems you own or have explicit authorization to test.",
    )
    parser.add_argument("--version", action="version", version=f"WebSQLMapper {VERSION}")
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="CLI color mode")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run adaptive non-destructive SQL injection probes")
    _add_request_args(scan)
    scan.add_argument("--profile", choices=["safe", "normal", "thorough"], default="normal")
    scan.add_argument("--time-probes", action=argparse.BooleanOptionalAction, default=None)
    scan.add_argument("--dbms", action="append", choices=["mysql", "postgresql", "mssql"], default=[])
    scan.add_argument("--context", choices=["auto", "numeric", "string"], default="auto")
    scan.add_argument("--baseline-samples", type=int)
    scan.add_argument("--confirmation-rounds", type=int)
    scan.add_argument("--max-requests", type=int, help="Hard request budget (10-2000)")
    _add_scan_output_args(scan)

    mapper = sub.add_parser("map", help="Map SQLite data using boolean inference on private targets only")
    _add_request_args(mapper)
    mapper.add_argument("--context", choices=["numeric", "string"], default="numeric")
    mapper.add_argument("--max-rows", type=int, default=3)
    mapper.add_argument("--max-chars", type=int, default=64)
    mapper.add_argument("--json", action="store_true")

    parse = sub.add_parser("parse", help="Parse and normalize a raw HTTP or cURL request without scanning")
    source = parse.add_mutually_exclusive_group(required=True)
    source.add_argument("--raw", metavar="FILE_OR_TEXT")
    source.add_argument("--curl", metavar="FILE_OR_TEXT")
    parse.add_argument("--scheme", choices=["http", "https"], default="https")

    report = sub.add_parser("report", help="Render a saved JSON scan report")
    report.add_argument("input")
    report.add_argument("--format", choices=["json", "markdown", "html"], default="markdown")
    report.add_argument("--output")

    template = sub.add_parser("template", help="Manage redacted request templates")
    tsub = template.add_subparsers(dest="template_command", required=True)
    tsave = tsub.add_parser("save")
    tsave.add_argument("name")
    _add_request_args(tsave, allow_template=False)
    tlist = tsub.add_parser("list")
    tshow = tsub.add_parser("show")
    tshow.add_argument("name")
    tdelete = tsub.add_parser("delete")
    tdelete.add_argument("name")

    web = sub.add_parser("web", help="Start the professional local web interface")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8787)

    update = sub.add_parser("update", help="Fast-forward the installed Git checkout and reinstall")
    update.add_argument("--force", action="store_true")

    sub.add_parser("doctor", help="Check runtime, dependencies, PATH, and platform support")
    return parser


def _human_scan(report: Any, *, color_mode: str, verbose: bool) -> None:
    enabled = color_enabled(color_mode)
    print(banner(enabled=enabled))
    print(f"{paint('Target', P.gray, enabled=enabled):18} {report.method} {report.target}")
    print(f"{paint('Injection', P.gray, enabled=enabled):18} {report.injection_location}:{report.parameter}")
    score_color = severity_color(report.confidence_score)
    print(f"{paint('Verdict', P.gray, enabled=enabled):18} {paint(report.verdict.upper(), P.bold, score_color, enabled=enabled)}")
    print(f"{paint('Confidence', P.gray, enabled=enabled):18} {paint(str(report.confidence_score) + '/100', score_color, enabled=enabled)}")
    print(f"{paint('Reproducibility', P.gray, enabled=enabled):18} {report.reproducibility}%")
    print(f"{paint('Requests', P.gray, enabled=enabled):18} {report.requests_sent}/{report.request_budget}")
    if report.dbms_profile:
        dbms = ", ".join(f"{name} {value}%" for name, value in report.dbms_profile.items())
        print(f"{paint('DBMS profile', P.gray, enabled=enabled):18} {dbms}")
    print()
    if report.findings:
        print(paint("Findings", P.bold, P.cyan, enabled=enabled))
        for finding in report.findings:
            print(f"  {paint(str(finding.score), severity_color(finding.score), enabled=enabled):>3}  {finding.title}")
    else:
        print(paint("No medium-or-higher confidence SQLi indicator confirmed.", P.green, enabled=enabled))
    if report.errors:
        print("\n" + paint("Controlled warnings", P.bold, P.yellow, enabled=enabled))
        for error in report.errors:
            print(f"  - {error}")
    if verbose:
        print("\n" + paint("Request timeline", P.bold, P.cyan, enabled=enabled))
        for item in report.timeline:
            print(f"  #{item.index:03d} {item.phase:<9} {item.status:>3} {item.elapsed_ms:>8.2f}ms {item.label}")


def _doctor(color_mode: str) -> int:
    enabled = color_enabled(color_mode)
    import requests
    try:
        import socks  # type: ignore
        socks_version = getattr(socks, "__version__", "installed")
    except ImportError:
        socks_version = "missing (only required for SOCKS proxy URLs)"
    checks = {
        "Python": sys.version.split()[0],
        "requests": requests.__version__,
        "PySocks": socks_version,
        "Git": shutil.which("git") or "missing",
        "Command": shutil.which("websqlmapper") or "not on PATH in this shell",
        "Platform": platform.platform(),
    }
    print(banner(enabled=enabled))
    for key, value in checks.items():
        print(f"{key:12} {value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            config, original = _build_config(args)
            report = SQLiScanner().scan(
                config,
                original_value=original,
                authorized=args.authorized,
                time_probes=args.time_probes,
                dbms=args.dbms or None,
                context=args.context,
                baseline_samples=args.baseline_samples,
                confirmation_rounds=args.confirmation_rounds,
                profile=args.profile,
                max_requests=args.max_requests,
            )
            if args.save:
                Path(args.save).write_text(render_report(report, args.report_format), encoding="utf-8")
            if args.json:
                print(render_report(report, "json"), end="")
            else:
                _human_scan(report, color_mode=args.color, verbose=args.verbose)
                if args.save:
                    print(f"\nSaved {args.report_format} report: {args.save}")
            return 2 if report.likely_vulnerable else 0

        if args.command == "map":
            config, original = _build_config(args)
            result = SQLiteBlindMapper().map_database(
                config,
                original_value=original,
                context=args.context,
                authorized=args.authorized,
                max_rows=args.max_rows,
                max_chars=args.max_chars,
            )
            if args.json:
                print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
            else:
                enabled = color_enabled(args.color)
                print(banner(enabled=enabled))
                print(paint("Private-lab SQLite mapping complete", P.bold, P.green, enabled=enabled))
                print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
            return 0

        if args.command == "parse":
            item = parse_raw_request(read_text_input(args.raw), scheme=args.scheme) if args.raw is not None else parse_curl(read_text_input(args.curl))
            print(json.dumps(item.to_dict(), indent=2, ensure_ascii=False))
            return 0

        if args.command == "report":
            output = render_report(load_report(args.input), args.format)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
            else:
                print(output, end="")
            return 0

        if args.command == "template":
            if args.template_command == "list":
                for name in list_templates():
                    print(name)
            elif args.template_command == "show":
                config = load_template(args.name)
                print(json.dumps(config.clone_dict(), indent=2, ensure_ascii=False))
            elif args.template_command == "delete":
                delete_template(args.name)
                print(f"Deleted template: {args.name}")
            elif args.template_command == "save":
                config, _ = _build_config(args)
                path = save_template(args.name, config)
                print(f"Saved redacted template: {path}")
            return 0

        if args.command == "web":
            enabled = color_enabled(args.color)
            print(banner(enabled=enabled))
            run_web(args.host, args.port)
            return 0

        if args.command == "update":
            for line in update_installation(force=args.force):
                print(line)
            return 0

        if args.command == "doctor":
            return _doctor(args.color)
    except (SafetyError, ValueError, RuntimeError, RequestParseError, OSError) as exc:
        enabled = color_enabled(getattr(args, "color", "auto"), sys.stderr)
        print(paint(f"error: {exc}", P.red, enabled=enabled), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        return 130
    return 1
