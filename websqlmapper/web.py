from __future__ import annotations

import ipaddress
import json
import mimetypes
import re
import secrets
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from .control import ScanControl
from .importers import discover_injection_points, parse_curl, parse_raw_request
from .mapper import SQLiteBlindMapper
from .models import RequestConfig
from .reporting import render_report
from .scanner import SQLiScanner
from .safety import SafetyError, require_authorization
from .templates import delete_template, list_templates, load_template, save_template
from .transport import HTTPClient

_MAX_BODY=2_000_000
_TERMINAL={"complete","cancelled","error"}

@dataclass(slots=True)
class ServerSettings:
    token: str|None=None
    remote: bool=False
    allowed_hosts: tuple[str,...]=()

SETTINGS=ServerSettings()


def _send_common_headers(handler: BaseHTTPRequestHandler, *, api: bool=False) -> None:
    handler.send_header("X-Content-Type-Options","nosniff"); handler.send_header("X-Frame-Options","DENY"); handler.send_header("Referrer-Policy","no-referrer")
    handler.send_header("Permissions-Policy","camera=(), microphone=(), geolocation=()")
    if api: handler.send_header("Cache-Control","no-store")

def _json_response(handler: BaseHTTPRequestHandler,status:int,payload:object) -> None:
    raw=json.dumps(payload,ensure_ascii=False,indent=2).encode("utf-8")
    try:
        handler.send_response(status); handler.send_header("Content-Type","application/json; charset=utf-8"); handler.send_header("Content-Length",str(len(raw))); _send_common_headers(handler,api=True); handler.end_headers(); handler.wfile.write(raw)
    except (BrokenPipeError,ConnectionResetError): return

def _text_response(handler: BaseHTTPRequestHandler,status:int,text:str,content_type:str="text/plain; charset=utf-8") -> None:
    raw=text.encode("utf-8")
    try:
        handler.send_response(status); handler.send_header("Content-Type",content_type); handler.send_header("Content-Length",str(len(raw))); _send_common_headers(handler,api=True); handler.end_headers(); handler.wfile.write(raw)
    except (BrokenPipeError,ConnectionResetError): return

def _read_json(handler: BaseHTTPRequestHandler) -> dict[str,object]:
    raw_length=handler.headers.get("Content-Length","0")
    try: length=int(raw_length or 0)
    except ValueError as exc: raise ValueError("invalid Content-Length") from exc
    if length<0 or length>_MAX_BODY: raise ValueError(f"request body must be between 0 and {_MAX_BODY} bytes")
    raw=handler.rfile.read(length)
    try: payload=json.loads(raw or b"{}")
    except json.JSONDecodeError as exc: raise ValueError(f"invalid JSON body: {exc.msg}") from exc
    if not isinstance(payload,dict): raise ValueError("JSON body must be an object")
    return payload

def _bool(payload: dict[str,object],name:str,default:bool) -> bool:
    if name not in payload: return default
    if not isinstance(payload[name],bool): raise ValueError(f"{name} must be a JSON boolean")
    return bool(payload[name])

def _config_from_payload(payload: dict[str,object]) -> RequestConfig:
    raw_data=payload.get("data"); raw_data={} if raw_data is None else raw_data
    raw_headers=payload.get("headers") or {}; raw_cookies=payload.get("cookies") or {}
    if not isinstance(raw_headers,dict): raise ValueError("headers must be a JSON object")
    if not isinstance(raw_cookies,dict): raise ValueError("cookies must be a JSON object")
    return RequestConfig(
        url=str(payload.get("url","")),method=str(payload.get("method","GET")).upper(),parameter=str(payload.get("parameter","id")),location=str(payload.get("location","auto")),data=raw_data,
        headers={str(k):str(v) for k,v in raw_headers.items()},cookies={str(k):str(v) for k,v in raw_cookies.items()},body_mode=str(payload.get("body_mode","auto")),raw_body=None if payload.get("raw_body") is None else str(payload.get("raw_body")),
        timeout=float(payload.get("timeout",8.0)),connect_timeout=None if payload.get("connect_timeout") in {None,""} else float(payload["connect_timeout"]),read_timeout=None if payload.get("read_timeout") in {None,""} else float(payload["read_timeout"]),max_duration=float(payload.get("max_duration",300.0)),
        proxy=None if not payload.get("proxy") else str(payload.get("proxy")),verify_tls=_bool(payload,"verify_tls",True),ca_bundle=None if not payload.get("ca_bundle") else str(payload.get("ca_bundle")),client_cert=None if not payload.get("client_cert") else str(payload.get("client_cert")),client_key=None if not payload.get("client_key") else str(payload.get("client_key")),follow_redirects=_bool(payload,"follow_redirects",False),redirect_policy=str(payload.get("redirect_policy","never")),max_redirects=int(payload.get("max_redirects",5)),
        auth_type=None if not payload.get("auth_type") else str(payload.get("auth_type")),auth_username=None if payload.get("auth_username") is None else str(payload.get("auth_username")),auth_password=None if payload.get("auth_password") is None else str(payload.get("auth_password")),bearer_token=None if payload.get("bearer_token") is None else str(payload.get("bearer_token")),
        rate=float(payload.get("rate",0.0)),delay_ms=int(payload.get("delay_ms",0)),jitter_ms=int(payload.get("jitter_ms",0)),retries=int(payload.get("retries",1)),retry_policy=str(payload.get("retry_policy","safe")),cookie_mode=str(payload.get("cookie_mode","static")),max_body_bytes=int(payload.get("max_body_bytes",1_500_000)),concurrency=int(payload.get("concurrency",1)),
    )

def _dbms_from_payload(payload: dict[str,object]) -> list[str]|None:
    raw=payload.get("dbms")
    if raw in (None,[]): return None
    if not isinstance(raw,list) or not all(isinstance(item,str) for item in raw): raise ValueError("dbms must be a JSON array of strings")
    allowed={"mysql","postgresql","mssql"}; invalid=[item for item in raw if item not in allowed]
    if invalid: raise ValueError(f"unsupported dbms value: {invalid[0]}")
    return list(raw) or None

def _scan_from_payload(payload: dict[str,object], *, control: ScanControl|None=None):
    config=_config_from_payload(payload)
    return SQLiScanner().scan(config,original_value=str(payload.get("original_value","1")),authorized=_bool(payload,"authorized",False),time_probes=None if payload.get("time_probes") is None else _bool(payload,"time_probes",False),dbms=_dbms_from_payload(payload),context=str(payload.get("context","auto")),baseline_samples=None if payload.get("baseline_samples") in {None,""} else int(payload["baseline_samples"]),confirmation_rounds=None if payload.get("confirmation_rounds") in {None,""} else int(payload["confirmation_rounds"]),profile=str(payload.get("profile","normal")),max_requests=None if payload.get("max_requests") in {None,""} else int(payload["max_requests"]),control=control,adaptive=_bool(payload,"adaptive",True),exhaustive=_bool(payload,"exhaustive",False))

def _map_from_payload(payload: dict[str,object], *, control: ScanControl|None=None):
    config=_config_from_payload(payload)
    return SQLiteBlindMapper().map_database(config,original_value=str(payload.get("original_value","1")),context=str(payload.get("context","auto")),authorized=_bool(payload,"authorized",False),max_rows=int(payload.get("max_rows",3)),max_chars=int(payload.get("max_chars",64)),max_requests=int(payload.get("map_max_requests",payload.get("max_requests") or 2000)),control=control)

@dataclass(slots=True)
class EventRecord:
    id:int
    payload:dict[str,object]

@dataclass(slots=True)
class Job:
    id:str
    kind:str
    control:ScanControl
    status:str="queued"
    result:dict[str,object]|None=None
    error:str|None=None
    created_at:float=field(default_factory=time.time)
    updated_at:float=field(default_factory=time.time)
    events:deque[EventRecord]=field(default_factory=lambda:deque(maxlen=2000))
    next_event_id:int=1
    condition:threading.Condition=field(default_factory=threading.Condition)
    def emit(self,payload:dict[str,object]) -> None:
        with self.condition:
            self.events.append(EventRecord(self.next_event_id,payload)); self.next_event_id+=1; self.updated_at=time.time(); self.condition.notify_all()
    def after(self,last_id:int) -> list[EventRecord]:
        with self.condition: return [item for item in self.events if item.id>last_id]

class JobManager:
    def __init__(self,max_workers:int=4,max_jobs:int=50,ttl:int=1800) -> None:
        self._jobs:dict[str,Job]={}; self._lock=threading.Lock(); self.max_jobs=max_jobs; self.ttl=ttl; self._executor=ThreadPoolExecutor(max_workers=max_workers,thread_name_prefix="websqlmapper-job")
    def configure(self,max_workers:int,max_jobs:int,ttl:int) -> None:
        with self._lock:
            if any(job.status not in _TERMINAL for job in self._jobs.values()): raise RuntimeError("cannot reconfigure job pool while jobs are active")
            self._executor.shutdown(wait=False,cancel_futures=True); self._executor=ThreadPoolExecutor(max_workers=max_workers,thread_name_prefix="websqlmapper-job"); self.max_jobs=max_jobs; self.ttl=ttl; self._jobs.clear()
    def _cleanup_locked(self) -> None:
        now=time.time()
        for job_id,job in list(self._jobs.items()):
            if job.status in _TERMINAL and now-job.updated_at>self.ttl: self._jobs.pop(job_id,None)
        if len(self._jobs)>self.max_jobs:
            terminal=sorted((j for j in self._jobs.values() if j.status in _TERMINAL),key=lambda j:j.updated_at)
            for job in terminal[:max(0,len(self._jobs)-self.max_jobs)]: self._jobs.pop(job.id,None)
    def start(self,kind:str,payload:dict[str,object]) -> Job:
        if kind not in {"scan","map"}: raise ValueError("job kind must be scan or map")
        with self._lock:
            self._cleanup_locked()
            if len(self._jobs)>=self.max_jobs: raise RuntimeError("job limit reached; wait for active jobs or cleanup")
            job=Job(id=uuid.uuid4().hex,kind=kind,control=ScanControl()); self._jobs[job.id]=job
        job.control.progress=lambda event:job.emit(event)
        def worker() -> None:
            job.status="running"; job.emit({"event":"job","status":"running","job_id":job.id,"kind":kind})
            try:
                result=_scan_from_payload(payload,control=job.control).to_dict() if kind=="scan" else _map_from_payload(payload,control=job.control).to_dict()
                job.result=result; job.status="cancelled" if bool(result.get("stopped_early")) and any("cancel" in str(x) for x in result.get("errors",[]) or []) else "complete"; job.emit({"event":"result","status":job.status,"kind":kind,"result":result})
            except (SafetyError,ValueError,RuntimeError) as exc:
                job.error=str(exc); job.status="error"; job.emit({"event":"error","error":str(exc)})
            except Exception as exc:
                job.error=f"unexpected server error: {exc}"; job.status="error"; job.emit({"event":"error","error":job.error})
            finally:
                job.updated_at=time.time(); job.emit({"event":"terminal","status":job.status})
        self._executor.submit(worker); return job
    def get(self,job_id:str) -> Job|None:
        with self._lock: self._cleanup_locked(); return self._jobs.get(job_id)
    def list(self) -> list[dict[str,object]]:
        with self._lock:
            self._cleanup_locked(); return [{"id":j.id,"kind":j.kind,"status":j.status,"created_at":j.created_at,"updated_at":j.updated_at} for j in sorted(self._jobs.values(),key=lambda j:j.created_at,reverse=True)]
    def shutdown(self) -> None: self._executor.shutdown(wait=False,cancel_futures=True)

JOBS=JobManager()


def _is_loopback_host(host:str) -> bool:
    if host.lower() in {"localhost","localhost.localdomain"}: return True
    try: return ipaddress.ip_address(host).is_loopback
    except ValueError: return False

class WebSQLMapperHandler(BaseHTTPRequestHandler):
    server_version="WebSQLMapper/0.4"; protocol_version="HTTP/1.1"
    def log_message(self,fmt:str,*args:object) -> None:
        message = fmt % args
        message = re.sub(r"([?&]token=)[^&\s\"]+", r"\1<redacted>", message)
        print(f"[web] {self.address_string()} - {message}")
    def _host_ok(self) -> bool:
        if not SETTINGS.allowed_hosts:
            return True
        raw = self.headers.get("Host", "")
        try:
            hostname = (urlsplit("//" + raw).hostname or "").lower()
        except ValueError:
            return False
        return hostname in SETTINGS.allowed_hosts
    def _require_host(self) -> bool:
        if self._host_ok():
            return True
        _json_response(self,421,{"error":"unexpected Host header"})
        return False
    def _api_token_ok(self) -> bool:
        if not SETTINGS.token: return True
        query=parse_qs(urlsplit(self.path).query); supplied=self.headers.get("X-WebSQLMapper-Token") or (query.get("token") or [""])[0]
        return secrets.compare_digest(str(supplied),SETTINGS.token)
    def _origin_ok(self) -> bool:
        origin=self.headers.get("Origin")
        if not origin: return True
        try: return urlsplit(origin).netloc.lower()==self.headers.get("Host","").lower()
        except ValueError: return False
    def _require_api_access(self) -> bool:
        if not self._api_token_ok(): _json_response(self,401,{"error":"invalid or missing WebSQLMapper access token"}); return False
        if self.command in {"POST","PUT","PATCH","DELETE"} and not self._origin_ok(): _json_response(self,403,{"error":"origin check failed"}); return False
        return True
    def do_GET(self) -> None:
        path=urlsplit(self.path).path
        try:
            if not self._require_host(): return
            if path in {"/","/index.html"}: self._serve_static("index.html")
            elif path=="/manifest.webmanifest": self._serve_static("manifest.webmanifest")
            elif path=="/service-worker.js": self._serve_static("service-worker.js")
            elif path.startswith("/static/"): self._serve_static(path.removeprefix("/static/"))
            elif path=="/api/health": _json_response(self,200,{"status":"ok","service":"WebSQLMapper","version":"0.4.0","remote":SETTINGS.remote,"token_required":bool(SETTINGS.token)})
            elif path=="/api/jobs":
                if self._require_api_access(): _json_response(self,200,{"jobs":JOBS.list()})
            elif path=="/api/templates":
                if self._require_api_access(): _json_response(self,200,{"templates":list_templates()})
            elif path.startswith("/api/templates/"):
                if not self._require_api_access(): return
                name=path.split("/",3)[3]; _json_response(self,200,{"name":name,"request":load_template(name).clone_dict()})
            elif path.startswith("/api/jobs/") and path.endswith("/events"):
                if self._require_api_access(): self._serve_events(path.split("/")[3])
            elif path.startswith("/api/jobs/") and path.endswith("/report"):
                if not self._require_api_access(): return
                job=JOBS.get(path.split("/")[3]); fmt=(parse_qs(urlsplit(self.path).query).get("format") or ["json"])[0]
                if not job: _json_response(self,404,{"error":"job not found"})
                elif not job.result: _json_response(self,409,{"error":"job has no result yet"})
                elif job.kind!="scan": _json_response(self,400,{"error":"reports are available for scan jobs"})
                else: _text_response(self,200,render_report(job.result,fmt),{"json":"application/json; charset=utf-8","markdown":"text/markdown; charset=utf-8","html":"text/html; charset=utf-8"}.get(fmt,"text/plain; charset=utf-8"))
            elif path.startswith("/api/jobs/"):
                if not self._require_api_access(): return
                job=JOBS.get(path.split("/")[3]); _json_response(self,404,{"error":"job not found"}) if not job else _json_response(self,200,{"id":job.id,"kind":job.kind,"status":job.status,"error":job.error,"result":job.result})
            else: _json_response(self,404,{"error":"not found"})
        except (BrokenPipeError,ConnectionResetError): return
        except (SafetyError,ValueError,RuntimeError) as exc: _json_response(self,400,{"error":str(exc)})
        except Exception as exc: _json_response(self,500,{"error":f"unexpected server error: {exc}"})
    def do_POST(self) -> None:
        path=urlsplit(self.path).path
        try:
            if not self._require_host(): return
            if not path.startswith("/api/") or not self._require_api_access(): return
            payload=_read_json(self)
            if path=="/api/scan": _json_response(self,200,_scan_from_payload(payload).to_dict())
            elif path=="/api/map": _json_response(self,200,_map_from_payload(payload).to_dict())
            elif path=="/api/jobs":
                kind=str(payload.get("kind","scan")); config=_config_from_payload(payload); require_authorization(_bool(payload,"authorized",False)); HTTPClient.validate_config(config,str(payload.get("original_value","1"))); _dbms_from_payload(payload) if kind=="scan" else None
                job=JOBS.start(kind,payload); _json_response(self,202,{"job_id":job.id,"status":job.status,"kind":kind})
            elif path=="/api/parse":
                kind=str(payload.get("kind","raw"));
                if kind not in {"raw","curl"}: raise ValueError("parse kind must be 'raw' or 'curl'")
                text=str(payload.get("text","")); item=parse_raw_request(text,scheme=str(payload.get("scheme","https"))) if kind=="raw" else parse_curl(text); out=item.to_dict(redact=False); out["injection_points"]=[p.to_dict() for p in discover_injection_points(item.config)]; _json_response(self,200,out)
            elif path=="/api/discover":
                config=_config_from_payload(payload); _json_response(self,200,{"injection_points":[p.to_dict() for p in discover_injection_points(config)]})
            elif path=="/api/templates/save":
                name=str(payload.get("name","")); request=payload.get("request");
                if not isinstance(request,dict): raise ValueError("request must be an object")
                saved=save_template(name,_config_from_payload(request)); _json_response(self,200,{"saved":str(saved),"name":name})
            elif path=="/api/templates/delete":
                name=str(payload.get("name","")); delete_template(name); _json_response(self,200,{"deleted":name})
            elif path.startswith("/api/jobs/"):
                parts=path.split("/")
                if len(parts)!=5: _json_response(self,404,{"error":"not found"}); return
                job=JOBS.get(parts[3])
                if not job: _json_response(self,404,{"error":"job not found"}); return
                action=parts[4]
                if action=="cancel":
                    if job.status in _TERMINAL: _json_response(self,409,{"error":f"cannot cancel a {job.status} job"}); return
                    job.control.cancel(); job.status="cancelling"
                elif action=="pause":
                    if job.status not in {"queued","running"}: _json_response(self,409,{"error":f"cannot pause a {job.status} job"}); return
                    job.control.pause(); job.status="paused"
                elif action=="resume":
                    if job.status!="paused": _json_response(self,409,{"error":f"cannot resume a {job.status} job"}); return
                    job.control.resume(); job.status="running"
                else: _json_response(self,404,{"error":"unknown job action"}); return
                job.emit({"event":"job","status":job.status,"action":action}); _json_response(self,200,{"job_id":job.id,"status":job.status})
            else: _json_response(self,404,{"error":"not found"})
        except (SafetyError,ValueError,RuntimeError) as exc: _json_response(self,400,{"error":str(exc)})
        except Exception as exc: _json_response(self,500,{"error":f"unexpected server error: {exc}"})
    def _serve_events(self,job_id:str) -> None:
        job=JOBS.get(job_id)
        if not job: _json_response(self,404,{"error":"job not found"}); return
        query=parse_qs(urlsplit(self.path).query); raw_last=self.headers.get("Last-Event-ID") or (query.get("lastEventId") or ["0"])[0]
        try: last_id=max(0,int(raw_last or 0))
        except ValueError: last_id=0
        self.send_response(200); self.send_header("Content-Type","text/event-stream; charset=utf-8"); self.send_header("Cache-Control","no-cache"); self.send_header("Connection","keep-alive"); _send_common_headers(self,api=True); self.end_headers()
        while True:
            records=job.after(last_id)
            if not records:
                with job.condition: job.condition.wait(timeout=10)
                records=job.after(last_id)
            if not records:
                try: self.wfile.write(b": keep-alive\n\n"); self.wfile.flush()
                except (BrokenPipeError,ConnectionResetError): return
                if job.status in _TERMINAL: return
                continue
            for record in records:
                raw=json.dumps(record.payload,ensure_ascii=False).encode("utf-8")
                try: self.wfile.write(f"id: {record.id}\n".encode()+b"data: "+raw+b"\n\n"); self.wfile.flush()
                except (BrokenPipeError,ConnectionResetError): return
                last_id=record.id
                if record.payload.get("event")=="terminal": return
    def _serve_static(self,name:str) -> None:
        if "/" in name or "\\" in name or name.startswith("."): _json_response(self,404,{"error":"not found"}); return
        resource=files("websqlmapper").joinpath("static",name)
        if not resource.is_file(): _json_response(self,404,{"error":"not found"}); return
        raw=resource.read_bytes(); content_type=mimetypes.guess_type(name)[0] or "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type",content_type+("; charset=utf-8" if content_type.startswith("text/") or content_type in {"application/javascript","application/manifest+json"} else "")); self.send_header("Content-Length",str(len(raw))); self.send_header("Content-Security-Policy","default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; manifest-src 'self'; worker-src 'self'"); _send_common_headers(self); self.end_headers(); self.wfile.write(raw)

def run_web(host:str="127.0.0.1",port:int=8787,*,allow_remote:bool=False,token:str|None=None,max_workers:int=4,max_jobs:int=50,job_ttl:int=1800) -> None:
    if port<0 or port>65535: raise ValueError("port must be between 0 and 65535")
    if max_workers<1 or max_workers>16: raise ValueError("max_workers must be between 1 and 16")
    if max_jobs<5 or max_jobs>500: raise ValueError("max_jobs must be between 5 and 500")
    if job_ttl<60 or job_ttl>86400: raise ValueError("job_ttl must be between 60 and 86400 seconds")
    remote=not _is_loopback_host(host)
    if remote and not allow_remote: raise ValueError("remote web binding requires --allow-remote")
    if remote and not token: token="wsm_"+secrets.token_urlsafe(24)
    SETTINGS.remote=remote; SETTINGS.token=token
    SETTINGS.allowed_hosts=() if remote else ("127.0.0.1","localhost","localhost.localdomain","::1")
    JOBS.configure(max_workers,max_jobs,job_ttl)
    try: server=ThreadingHTTPServer((host,port),WebSQLMapperHandler)
    except OSError as exc: raise RuntimeError(f"cannot bind web server on {host}:{port}: {exc}") from exc
    print(f"WebSQLMapper web UI: http://{host}:{server.server_port}")
    if token: print(f"Web access token: {token}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close(); JOBS.shutdown()
