from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import urlsplit

from .mapper import SQLiteBlindMapper
from .models import RequestConfig
from .scanner import SQLiScanner
from .safety import SafetyError


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _config_from_payload(payload: dict[str, object]) -> RequestConfig:
    return RequestConfig(
        url=str(payload.get("url", "")),
        method=str(payload.get("method", "GET")).upper(),
        parameter=str(payload.get("parameter", "id")),
        data=dict(payload.get("data") or {}),
        headers={str(k): str(v) for k, v in dict(payload.get("headers") or {}).items()},
        cookies={str(k): str(v) for k, v in dict(payload.get("cookies") or {}).items()},
        body_mode=str(payload.get("body_mode", "auto")),
        timeout=float(payload.get("timeout", 8.0)),
    )


class WebSQLMapperHandler(BaseHTTPRequestHandler):
    server_version = "WebSQLMapper/0.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[web] {self.address_string()} - {fmt % args}")

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in {"/", "/index.html"}:
            self._serve_static("index.html")
        elif path.startswith("/static/"):
            self._serve_static(path.removeprefix("/static/"))
        elif path == "/api/health":
            _json_response(self, 200, {"status": "ok", "service": "WebSQLMapper"})
        else:
            _json_response(self, 404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", "0") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object")
            config = _config_from_payload(payload)
            authorized = bool(payload.get("authorized", False))
            original_value = str(payload.get("original_value", "1"))

            if path == "/api/scan":
                report = SQLiScanner().scan(
                    config,
                    original_value=original_value,
                    authorized=authorized,
                    time_probes=bool(payload.get("time_probes", False)),
                )
                _json_response(self, 200, report.to_dict())
            elif path == "/api/map":
                result = SQLiteBlindMapper().map_database(
                    config,
                    original_value=original_value,
                    context=str(payload.get("context", "numeric")),
                    authorized=authorized,
                    max_rows=int(payload.get("max_rows", 3)),
                    max_chars=int(payload.get("max_chars", 64)),
                )
                _json_response(self, 200, result.to_dict())
            else:
                _json_response(self, 404, {"error": "not found"})
        except (SafetyError, ValueError, RuntimeError) as exc:
            _json_response(self, 400, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover - defensive API boundary
            _json_response(self, 500, {"error": f"unexpected server error: {exc}"})

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
        self.end_headers()
        self.wfile.write(raw)


def run_web(host: str = "127.0.0.1", port: int = 8787) -> None:
    server = ThreadingHTTPServer((host, port), WebSQLMapperHandler)
    print(f"WebSQLMapper web UI: http://{host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
