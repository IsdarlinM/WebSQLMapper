from __future__ import annotations

import json
import mimetypes
import queue
import threading
import uuid
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import urlsplit

from .control import ScanControl
from .importers import parse_curl, parse_raw_request
from .mapper import SQLiteBlindMapper
from .models import RequestConfig
from .scanner import SQLiScanner
from .transport import HTTPClient
from .safety import SafetyError, require_authorization


_MAX_BODY = 2_000_000


def _send_common_headers(handler: BaseHTTPRequestHandler, *, api: bool = False) -> None:
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    if api:
        handler.send_header("Cache-Control", "no-store")


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    try:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(raw)))
        _send_common_headers(handler, api=True)
        handler.end_headers()
        handler.wfile.write(raw)
    except (BrokenPipeError, ConnectionResetError):
        return


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, object]:
    raw_length = handler.headers.get("Content-Length", "0")
    try:
        length = int(raw_length or 0)
    except ValueError as exc:
        raise ValueError("invalid Content-Length") from exc
    if length < 0 or length > _MAX_BODY:
        raise ValueError(f"request body must be between 0 and {_MAX_BODY} bytes")
    raw = handler.rfile.read(length)
    try:
        payload = json.loads(raw or b"{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON body: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON body must be an object")
    return payload


def _config_from_payload(payload: dict[str, object]) -> RequestConfig:
    raw_data = payload.get("data")
    if raw_data is None:
        raw_data = {}
    raw_headers = payload.get("headers") or {}
    raw_cookies = payload.get("cookies") or {}
    if not isinstance(raw_headers, dict):
        raise ValueError("headers must be a JSON object")
    if not isinstance(raw_cookies, dict):
        raise ValueError("cookies must be a JSON object")
    for boolean_name in ("verify_tls", "follow_redirects"):
        if boolean_name in payload and not isinstance(payload[boolean_name], bool):
            raise ValueError(f"{boolean_name} must be a JSON boolean")
    return RequestConfig(
        url=str(payload.get("url", "")),
        method=str(payload.get("method", "GET")).upper(),
        parameter=str(payload.get("parameter", "id")),
        location=str(payload.get("location", "auto")),
        data=raw_data,
        headers={str(k): str(v) for k, v in raw_headers.items()},
        cookies={str(k): str(v) for k, v in raw_cookies.items()},
        body_mode=str(payload.get("body_mode", "auto")),
        raw_body=None if payload.get("raw_body") is None else str(payload.get("raw_body")),
        timeout=float(payload.get("timeout", 8.0)),
        proxy=None if not payload.get("proxy") else str(payload.get("proxy")),
        verify_tls=bool(payload.get("verify_tls", True)),
        ca_bundle=None if not payload.get("ca_bundle") else str(payload.get("ca_bundle")),
        follow_redirects=bool(payload.get("follow_redirects", False)),
        auth_type=None if not payload.get("auth_type") else str(payload.get("auth_type")),
        auth_username=None if payload.get("auth_username") is None else str(payload.get("auth_username")),
        auth_password=None if payload.get("auth_password") is None else str(payload.get("auth_password")),
        bearer_token=None if payload.get("bearer_token") is None else str(payload.get("bearer_token")),
        rate=float(payload.get("rate", 0.0)),
        delay_ms=int(payload.get("delay_ms", 0)),
        jitter_ms=int(payload.get("jitter_ms", 0)),
        retries=int(payload.get("retries", 1)),
    )


def _dbms_from_payload(payload: dict[str, object]) -> list[str] | None:
    raw = payload.get("dbms")
    if raw in (None, []):
        return None
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError("dbms must be a JSON array of strings")
    allowed = {"mysql", "postgresql", "mssql"}
    invalid = [item for item in raw if item not in allowed]
    if invalid:
        raise ValueError(f"unsupported dbms value: {invalid[0]}")
    return list(raw) or None


def _scan_from_payload(payload: dict[str, object], *, control: ScanControl | None = None):
    config = _config_from_payload(payload)
    return SQLiScanner().scan(
        config,
        original_value=str(payload.get("original_value", "1")),
        authorized=bool(payload.get("authorized", False)),
        time_probes=None if payload.get("time_probes") is None else bool(payload.get("time_probes")),
        dbms=_dbms_from_payload(payload),
        context=str(payload.get("context", "auto")),
        baseline_samples=None if payload.get("baseline_samples") in {None, ""} else int(payload["baseline_samples"]),
        confirmation_rounds=None if payload.get("confirmation_rounds") in {None, ""} else int(payload["confirmation_rounds"]),
        profile=str(payload.get("profile", "normal")),
        max_requests=None if payload.get("max_requests") in {None, ""} else int(payload["max_requests"]),
        control=control,
    )


@dataclass(slots=True)
class Job:
    id: str
    control: ScanControl
    events: queue.Queue[dict[str, object]] = field(default_factory=queue.Queue)
    status: str = "queued"
    result: dict[str, object] | None = None
    error: str | None = None


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, payload: dict[str, object]) -> Job:
        job_id = uuid.uuid4().hex
        job = Job(id=job_id, control=ScanControl())

        def emit(event: dict[str, object]) -> None:
            job.events.put(event)

        job.control.progress = emit
        with self._lock:
            self._jobs[job_id] = job

        def worker() -> None:
            job.status = "running"
            job.events.put({"event": "job", "status": "running", "job_id": job_id})
            try:
                report = _scan_from_payload(payload, control=job.control)
                job.result = report.to_dict()
                job.status = "cancelled" if report.stopped_early and "scan cancelled" in report.errors else "complete"
                job.events.put({"event": "result", "status": job.status, "result": job.result})
            except (SafetyError, ValueError, RuntimeError) as exc:
                job.error = str(exc)
                job.status = "error"
                job.events.put({"event": "error", "error": str(exc)})
            except Exception as exc:  # defensive worker boundary
                job.error = f"unexpected server error: {exc}"
                job.status = "error"
                job.events.put({"event": "error", "error": job.error})
            finally:
                job.events.put({"event": "terminal", "status": job.status})

        threading.Thread(target=worker, name=f"websqlmapper-{job_id[:8]}", daemon=True).start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)


JOBS = JobManager()


class WebSQLMapperHandler(BaseHTTPRequestHandler):
    server_version = "WebSQLMapper/0.3"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[web] {self.address_string()} - {fmt % args}")

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        try:
            if path in {"/", "/index.html"}:
                self._serve_static("index.html")
            elif path.startswith("/static/"):
                self._serve_static(path.removeprefix("/static/"))
            elif path == "/api/health":
                _json_response(self, 200, {"status": "ok", "service": "WebSQLMapper", "version": "0.3.0"})
            elif path.startswith("/api/jobs/") and path.endswith("/events"):
                job_id = path.split("/")[3]
                self._serve_events(job_id)
            elif path.startswith("/api/jobs/"):
                job_id = path.split("/")[3]
                job = JOBS.get(job_id)
                if not job:
                    _json_response(self, 404, {"error": "job not found"})
                else:
                    _json_response(self, 200, {"id": job.id, "status": job.status, "error": job.error, "result": job.result})
            else:
                _json_response(self, 404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            _json_response(self, 500, {"error": f"unexpected server error: {exc}"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        try:
            payload = _read_json(self)
            if path == "/api/scan":
                _json_response(self, 200, _scan_from_payload(payload).to_dict())
            elif path == "/api/jobs":
                # Reject deterministic mistakes synchronously before allocating
                # a background scan job.
                config = _config_from_payload(payload)
                require_authorization(bool(payload.get("authorized", False)))
                HTTPClient.validate_config(config, str(payload.get("original_value", "1")))
                _dbms_from_payload(payload)
                job = JOBS.start(payload)
                _json_response(self, 202, {"job_id": job.id, "status": job.status})
            elif path == "/api/parse":
                kind = str(payload.get("kind", "raw"))
                if kind not in {"raw", "curl"}:
                    raise ValueError("parse kind must be 'raw' or 'curl'")
                text = str(payload.get("text", ""))
                item = parse_raw_request(text, scheme=str(payload.get("scheme", "https"))) if kind == "raw" else parse_curl(text)
                _json_response(self, 200, item.to_dict(redact=False))
            elif path == "/api/map":
                config = _config_from_payload(payload)
                result = SQLiteBlindMapper().map_database(
                    config,
                    original_value=str(payload.get("original_value", "1")),
                    context=str(payload.get("context", "numeric")),
                    authorized=bool(payload.get("authorized", False)),
                    max_rows=int(payload.get("max_rows", 3)),
                    max_chars=int(payload.get("max_chars", 64)),
                )
                _json_response(self, 200, result.to_dict())
            elif path.startswith("/api/jobs/"):
                parts = path.split("/")
                if len(parts) != 5:
                    _json_response(self, 404, {"error": "not found"})
                    return
                job = JOBS.get(parts[3])
                if not job:
                    _json_response(self, 404, {"error": "job not found"})
                    return
                action = parts[4]
                if action == "cancel":
                    job.control.cancel()
                elif action == "pause":
                    job.control.pause()
                    job.status = "paused"
                elif action == "resume":
                    job.control.resume()
                    if job.status == "paused":
                        job.status = "running"
                else:
                    _json_response(self, 404, {"error": "unknown job action"})
                    return
                job.events.put({"event": "job", "status": job.status, "action": action})
                _json_response(self, 200, {"job_id": job.id, "status": job.status})
            else:
                _json_response(self, 404, {"error": "not found"})
        except (SafetyError, ValueError, RuntimeError) as exc:
            _json_response(self, 400, {"error": str(exc)})
        except Exception as exc:  # defensive API boundary
            _json_response(self, 500, {"error": f"unexpected server error: {exc}"})

    def _serve_events(self, job_id: str) -> None:
        job = JOBS.get(job_id)
        if not job:
            _json_response(self, 404, {"error": "job not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        _send_common_headers(self, api=True)
        self.end_headers()
        while True:
            try:
                event = job.events.get(timeout=10)
            except queue.Empty:
                self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
                if job.status in {"complete", "cancelled", "error"}:
                    break
                continue
            raw = json.dumps(event, ensure_ascii=False).encode("utf-8")
            self.wfile.write(b"data: " + raw + b"\n\n")
            self.wfile.flush()
            if event.get("event") == "terminal":
                break

    def _serve_static(self, name: str) -> None:
        if "/" in name or "\\" in name or name.startswith("."):
            _json_response(self, 404, {"error": "not found"})
            return
        resource = files("websqlmapper").joinpath("static", name)
        if not resource.is_file():
            _json_response(self, 404, {"error": "not found"})
            return
        raw = resource.read_bytes()
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
        _send_common_headers(self)
        self.end_headers()
        self.wfile.write(raw)


def run_web(host: str = "127.0.0.1", port: int = 8787) -> None:
    if port < 0 or port > 65535:
        raise ValueError("port must be between 0 and 65535")
    try:
        server = ThreadingHTTPServer((host, port), WebSQLMapperHandler)
    except OSError as exc:
        raise RuntimeError(f"cannot bind web server on {host}:{port}: {exc}") from exc
    print(f"WebSQLMapper web UI: http://{host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
