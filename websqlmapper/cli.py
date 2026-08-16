from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from .importers import RequestParseError, discover_injection_points, infer_original_value, parse_curl, parse_raw_request, read_text_input
from .mapper import SQLiteBlindMapper
from .models import RequestConfig
from .reporting import load_report, render_report
from .scanner import SQLiScanner
from .safety import SafetyError
from .templates import delete_template, list_templates, load_template, save_template
from .terminal import P, VERSION, banner, color_enabled, paint, severity_color
from .updater import update_installation
from .web import run_web

BANNER=f"Web SQL Injector\nimr :: v{VERSION}"
_LOCATIONS=["auto","query","form","json","graphql","cookie","header","path","raw"]
_BODY_MODES=["auto","query","form","json","graphql","multipart","raw","xml"]


def _json_value(value: str) -> Any:
    try: return json.loads(value)
    except json.JSONDecodeError as exc: raise argparse.ArgumentTypeError(f"invalid JSON: {exc.msg}") from exc

def _kv_pair(value: str) -> tuple[str,str]:
    if ":" not in value: raise argparse.ArgumentTypeError("expected KEY:VALUE")
    key,val=value.split(":",1)
    if not key.strip(): raise argparse.ArgumentTypeError("key cannot be empty")
    return key.strip(),val.strip()

def _inject_point(value: str) -> tuple[str,str]:
    if ":" not in value: raise argparse.ArgumentTypeError("expected LOCATION:PARAMETER, e.g. query:id or json:user.id")
    location,parameter=value.split(":",1); location=location.strip().lower(); parameter=parameter.strip()
    if location not in _LOCATIONS or location=="auto": raise argparse.ArgumentTypeError(f"LOCATION must be one of: {', '.join(_LOCATIONS[1:])}")
    if not parameter: raise argparse.ArgumentTypeError("injection parameter cannot be empty")
    return location,parameter

def _basic_auth(value: str) -> tuple[str,str]:
    if ":" not in value: raise argparse.ArgumentTypeError("expected USER:PASSWORD")
    user,password=value.split(":",1); return user,password


def _add_source_args(parser: argparse.ArgumentParser, *, allow_template: bool=True, required: bool=True) -> None:
    source=parser.add_mutually_exclusive_group(required=required)
    source.add_argument("--url",help="Target URL")
    source.add_argument("--raw",metavar="FILE_OR_TEXT",help="Raw HTTP request file, '-' for stdin, or inline request")
    source.add_argument("--curl",metavar="FILE_OR_TEXT",help="cURL command file or inline command")
    if allow_template: source.add_argument("--template",help="Load a saved request template")
    parser.add_argument("--scheme",choices=["http","https"],default="https",help="Scheme for relative raw HTTP requests")


def _add_request_args(parser: argparse.ArgumentParser, *, allow_template: bool=True) -> None:
    _add_source_args(parser,allow_template=allow_template)
    parser.add_argument("--method",choices=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
    parser.add_argument("--inject",type=_inject_point,metavar="LOCATION:PARAM")
    parser.add_argument("--parameter",help="Legacy parameter name; combine with --location")
    parser.add_argument("--location",choices=_LOCATIONS)
    parser.add_argument("--value",help="Original value; inferred when omitted")
    parser.add_argument("--body-mode",choices=_BODY_MODES)
    parser.add_argument("--data",type=_json_value,help="Base request data as JSON")
    parser.add_argument("--raw-body",help="Raw/XML body template containing {{INJECT}}")
    parser.add_argument("--header",action="append",type=_kv_pair,default=[],help="Repeatable KEY:VALUE header")
    parser.add_argument("--cookie",action="append",type=_kv_pair,default=[],help="Repeatable NAME:VALUE cookie")
    parser.add_argument("--timeout",type=float,help="Legacy connect/read timeout")
    parser.add_argument("--connect-timeout",type=float)
    parser.add_argument("--read-timeout",type=float)
    parser.add_argument("--max-duration",type=float,help="Maximum scan/map duration in seconds")
    parser.add_argument("--max-body",type=int,dest="max_body_bytes",help="Maximum response body bytes retained")
    parser.add_argument("--proxy",help="HTTP/HTTPS/SOCKS proxy URL")
    parser.add_argument("--verify-tls",action=argparse.BooleanOptionalAction,default=None)
    parser.add_argument("--ca-bundle",help="Custom CA bundle path")
    parser.add_argument("--client-cert",help="mTLS client certificate PEM path")
    parser.add_argument("--client-key",help="mTLS client private key PEM path")
    parser.add_argument("--follow-redirects",action=argparse.BooleanOptionalAction,default=None,help="Compatibility alias for redirect-policy any/never")
    parser.add_argument("--redirect-policy",choices=["never","same-origin","same-host","any"])
    parser.add_argument("--max-redirects",type=int)
    parser.add_argument("--basic",type=_basic_auth,metavar="USER:PASSWORD")
    parser.add_argument("--bearer",help="Bearer token; redacted from reports")
    parser.add_argument("--cookie-mode",choices=["static","session","merge"])
    parser.add_argument("--rate",type=float,help="Maximum requests/second (0=unlimited)")
    parser.add_argument("--delay-ms",type=int)
    parser.add_argument("--jitter-ms",type=int)
    parser.add_argument("--retries",type=int)
    parser.add_argument("--retry-policy",choices=["safe","all","none"])
    parser.add_argument("--concurrency",type=int,help="Parallel syntax probes (1-8; static cookies only)")
    parser.add_argument("--authorized",action="store_true")


def _load_source(args: argparse.Namespace) -> tuple[RequestConfig,bool]:
    if getattr(args,"raw",None) is not None: return parse_raw_request(read_text_input(args.raw),scheme=args.scheme).config,True
    if getattr(args,"curl",None) is not None: return parse_curl(read_text_input(args.curl)).config,True
    if getattr(args,"template",None) is not None: return load_template(args.template),True
    if getattr(args,"url",None): return RequestConfig(url=args.url),False
    raise ValueError("one request source is required")


def _apply_request_overrides(config: RequestConfig,args: argparse.Namespace) -> None:
    for attr in ("method","body_mode","raw_body","proxy","ca_bundle","client_cert","client_key","connect_timeout","read_timeout","max_duration","max_redirects","cookie_mode","rate","delay_ms","jitter_ms","retries","retry_policy","max_body_bytes","concurrency"):
        value=getattr(args,attr,None)
        if value is not None: setattr(config,attr,value)
    if getattr(args,"data",None) is not None: config.data=args.data
    if getattr(args,"header",None): config.headers.update(dict(args.header))
    if getattr(args,"cookie",None): config.cookies.update(dict(args.cookie))
    if getattr(args,"timeout",None) is not None: config.timeout=args.timeout
    if getattr(args,"verify_tls",None) is not None: config.verify_tls=args.verify_tls
    if getattr(args,"redirect_policy",None) is not None: config.redirect_policy=args.redirect_policy
    if getattr(args,"follow_redirects",None) is not None:
        config.follow_redirects=args.follow_redirects
        if getattr(args,"redirect_policy",None) is None: config.redirect_policy="any" if args.follow_redirects else "never"
    if getattr(args,"basic",None): config.auth_type="basic"; config.auth_username,config.auth_password=args.basic
    if getattr(args,"bearer",None) is not None: config.bearer_token=args.bearer


def _build_config(args: argparse.Namespace, *, require_injection: bool=True) -> tuple[RequestConfig,str]:
    config,imported=_load_source(args); _apply_request_overrides(config,args)
    if getattr(args,"inject",None): config.location,config.parameter=args.inject
    elif getattr(args,"parameter",None): config.parameter=args.parameter; config.location=getattr(args,"location",None) or config.location or "auto"
    elif require_injection and not getattr(args,"template",None):
        raise ValueError(f"{'imported request' if imported else 'URL'} requires --inject LOCATION:PARAM or --parameter")
    original=getattr(args,"value",None)
    if original is None and require_injection: original=infer_original_value(config,config.location,config.parameter,"1")
    return config,original or "1"


def _add_scan_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json",action="store_true"); parser.add_argument("--verbose",action="store_true")
    parser.add_argument("--save",metavar="PATH"); parser.add_argument("--report-format",choices=["json","markdown","html"],default="json")


def build_parser() -> argparse.ArgumentParser:
    parser=argparse.ArgumentParser(prog="websqlmapper",description="Authorized SQL injection differential detector and private-lab mapper",epilog="Use only on systems you own or have explicit authorization to test.")
    parser.add_argument("--version",action="version",version=f"WebSQLMapper {VERSION}"); parser.add_argument("--color",choices=["auto","always","never"],default="auto")
    sub=parser.add_subparsers(dest="command",required=True)
    scan=sub.add_parser("scan",help="Run adaptive non-destructive SQL injection probes"); _add_request_args(scan)
    scan.add_argument("--profile",choices=["safe","normal","thorough"],default="normal"); scan.add_argument("--time-probes",action=argparse.BooleanOptionalAction,default=None)
    scan.add_argument("--dbms",action="append",choices=["mysql","postgresql","mssql"],default=[]); scan.add_argument("--context",choices=["auto","numeric","string"],default="auto")
    scan.add_argument("--baseline-samples",type=int); scan.add_argument("--confirmation-rounds",type=int); scan.add_argument("--max-requests",type=int)
    scan.add_argument("--adaptive",action=argparse.BooleanOptionalAction,default=True); scan.add_argument("--exhaustive",action="store_true")
    _add_scan_output_args(scan)
    mapper=sub.add_parser("map",help="Map SQLite data using boolean inference on private targets only"); _add_request_args(mapper)
    mapper.add_argument("--context",choices=["auto","numeric","string"],default="auto"); mapper.add_argument("--max-rows",type=int,default=3); mapper.add_argument("--max-chars",type=int,default=64); mapper.add_argument("--max-requests",type=int,default=2000); mapper.add_argument("--json",action="store_true")
    parse=sub.add_parser("parse",help="Parse and normalize raw HTTP/cURL without scanning"); _add_source_args(parse,allow_template=False); parse.add_argument("--discover",action="store_true",help="Also enumerate injection points")
    discover=sub.add_parser("discover",help="Enumerate injection points without sending traffic"); _add_source_args(discover); discover.add_argument("--method",choices=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]); discover.add_argument("--body-mode",choices=_BODY_MODES); discover.add_argument("--data",type=_json_value); discover.add_argument("--header",action="append",type=_kv_pair,default=[]); discover.add_argument("--cookie",action="append",type=_kv_pair,default=[])
    report=sub.add_parser("report"); report.add_argument("input"); report.add_argument("--format",choices=["json","markdown","html"],default="markdown"); report.add_argument("--output")
    template=sub.add_parser("template"); tsub=template.add_subparsers(dest="template_command",required=True)
    tsave=tsub.add_parser("save"); tsave.add_argument("name"); _add_request_args(tsave,allow_template=False); tsub.add_parser("list"); tshow=tsub.add_parser("show"); tshow.add_argument("name"); tdel=tsub.add_parser("delete"); tdel.add_argument("name")
    web=sub.add_parser("web",help="Start the web interface"); web.add_argument("--host",default="127.0.0.1"); web.add_argument("--port",type=int,default=8787); web.add_argument("--allow-remote",action="store_true"); web.add_argument("--token"); web.add_argument("--max-workers",type=int,default=4); web.add_argument("--max-jobs",type=int,default=50); web.add_argument("--job-ttl",type=int,default=1800)
    update=sub.add_parser("update"); update.add_argument("--force",action="store_true"); sub.add_parser("doctor")
    return parser


def _human_scan(report: Any, *, color_mode: str, verbose: bool) -> None:
    enabled=color_enabled(color_mode); print(banner(enabled=enabled)); score_color=severity_color(report.confidence_score)
    rows=[("Target",f"{report.method} {report.target}"),("Injection",f"{report.injection_location}:{report.parameter}"),("Verdict",report.verdict.upper()),("Confidence",f"{report.confidence_score}/100"),("Reproducibility",f"{report.reproducibility}%"),("Requests",f"{report.requests_sent}/{report.request_budget}"),("Adaptive stop","yes" if report.adaptive_stopped else "no")]
    for label,value in rows:
        rendered=paint(value,P.bold,score_color,enabled=enabled) if label in {"Verdict","Confidence"} else value
        print(f"{paint(label,P.gray,enabled=enabled):18} {rendered}")
    if report.dbms_profile: print(f"{paint('DBMS profile',P.gray,enabled=enabled):18} "+", ".join(f"{n} {v}%" for n,v in report.dbms_profile.items()))
    if report.interference_profile: print(f"{paint('Interference',P.gray,enabled=enabled):18} "+", ".join(f"{n} {v}%" for n,v in report.interference_profile.items()))
    print(); print(paint("Findings",P.bold,P.cyan,enabled=enabled) if report.findings else paint("No medium-or-higher confidence SQLi indicator confirmed.",P.green,enabled=enabled))
    for f in report.findings: print(f"  {paint(str(f.score),severity_color(f.score),enabled=enabled):>3}  {f.title}")
    if report.errors:
        print("\n"+paint("Controlled warnings",P.bold,P.yellow,enabled=enabled)); [print(f"  - {e}") for e in report.errors]
    if verbose:
        print("\n"+paint("Request timeline",P.bold,P.cyan,enabled=enabled))
        for item in report.timeline: print(f"  #{item.index:03d} {item.phase:<9} {item.status:>3} {item.elapsed_ms:>8.2f}ms r={len(item.redirects)} {item.label}")


def _doctor(color_mode: str) -> int:
    enabled=color_enabled(color_mode); import requests
    try: import socks; socks_version=getattr(socks,"__version__","installed")  # type: ignore
    except ImportError: socks_version="missing (only required for SOCKS proxy URLs)"
    checks={"Python":sys.version.split()[0],"requests":requests.__version__,"PySocks":socks_version,"Git":shutil.which("git") or "missing","Command":shutil.which("websqlmapper") or "not on PATH in this shell","Platform":platform.platform()}
    print(banner(enabled=enabled)); [print(f"{k:12} {v}") for k,v in checks.items()]; return 0


def main(argv: list[str]|None=None) -> int:
    parser=build_parser(); args=parser.parse_args(argv)
    try:
        if args.command=="scan":
            config,original=_build_config(args); report=SQLiScanner().scan(config,original_value=original,authorized=args.authorized,time_probes=args.time_probes,dbms=args.dbms or None,context=args.context,baseline_samples=args.baseline_samples,confirmation_rounds=args.confirmation_rounds,profile=args.profile,max_requests=args.max_requests,adaptive=args.adaptive,exhaustive=args.exhaustive)
            if args.save: Path(args.save).write_text(render_report(report,args.report_format),encoding="utf-8")
            print(render_report(report,"json"),end="") if args.json else _human_scan(report,color_mode=args.color,verbose=args.verbose)
            if args.save and not args.json: print(f"\nSaved {args.report_format} report: {args.save}")
            return 2 if report.likely_vulnerable else 0
        if args.command=="map":
            config,original=_build_config(args); result=SQLiteBlindMapper().map_database(config,original_value=original,context=args.context,authorized=args.authorized,max_rows=args.max_rows,max_chars=args.max_chars,max_requests=args.max_requests)
            if args.json: print(json.dumps(result.to_dict(),indent=2,ensure_ascii=False))
            else: print(banner(enabled=color_enabled(args.color))); print(paint("Private-lab SQLite mapping complete",P.bold,P.green,enabled=color_enabled(args.color))); print(json.dumps(result.to_dict(),indent=2,ensure_ascii=False))
            return 0
        if args.command=="parse":
            item=parse_raw_request(read_text_input(args.raw),scheme=args.scheme) if args.raw is not None else parse_curl(read_text_input(args.curl)); out=item.to_dict();
            if args.discover: out["injection_points"]=[p.to_dict() for p in discover_injection_points(item.config)]
            print(json.dumps(out,indent=2,ensure_ascii=False)); return 0
        if args.command=="discover":
            config,_=_build_config(args,require_injection=False); print(json.dumps([p.to_dict() for p in discover_injection_points(config)],indent=2,ensure_ascii=False)); return 0
        if args.command=="report":
            output=render_report(load_report(args.input),args.format); Path(args.output).write_text(output,encoding="utf-8") if args.output else print(output,end=""); return 0
        if args.command=="template":
            if args.template_command=="list": [print(n) for n in list_templates()]
            elif args.template_command=="show": print(json.dumps(load_template(args.name).clone_dict(),indent=2,ensure_ascii=False))
            elif args.template_command=="delete": delete_template(args.name); print(f"Deleted template: {args.name}")
            elif args.template_command=="save": config,_=_build_config(args); print(f"Saved redacted template: {save_template(args.name,config)}")
            return 0
        if args.command=="web": print(banner(enabled=color_enabled(args.color))); run_web(args.host,args.port,allow_remote=args.allow_remote,token=args.token,max_workers=args.max_workers,max_jobs=args.max_jobs,job_ttl=args.job_ttl); return 0
        if args.command=="update": [print(line) for line in update_installation(force=args.force)]; return 0
        if args.command=="doctor": return _doctor(args.color)
    except (SafetyError,ValueError,RuntimeError,RequestParseError,OSError) as exc:
        print(paint(f"error: {exc}",P.red,enabled=color_enabled(getattr(args,"color","auto"),sys.stderr)),file=sys.stderr); return 1
    except KeyboardInterrupt:
        print("\nInterrupted by user.",file=sys.stderr); return 130
    return 1
