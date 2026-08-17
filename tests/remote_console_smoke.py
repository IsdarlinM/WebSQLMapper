#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lab.vulnerable_server import build_server  # noqa: E402


def non_loopback_ipv4() -> str:
    for info in socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_STREAM):
        host = info[4][0].split("%", 1)[0]
        if ":" not in host and not host.startswith("127.") and host != "0.0.0.0":
            return host
    raise RuntimeError("no non-loopback IPv4 address is available for remote-console smoke")


def json_request(opener, url: str, *, method: str = "GET", token: str | None = None, origin: str | None = None, payload=None):
    headers = {}
    if token:
        headers["X-WebSQLMapper-Token"] = token
    if origin:
        headers["Origin"] = origin
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    with opener.open(request, timeout=4) as response:
        return response.status, dict(response.headers), json.load(response)


def main() -> None:
    lab = build_server("127.0.0.1", 0)
    lab_thread = threading.Thread(target=lab.serve_forever, daemon=True)
    lab_thread.start()
    host = non_loopback_ipv4()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0)); port = sock.getsockname()[1]
    token = "remote-console-smoke-token-123456"
    env = os.environ.copy(); env["PYTHONPATH"] = str(ROOT); env["NO_COLOR"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "websqlmapper", "--color", "never", "web",
         "--host", "0.0.0.0", "--port", str(port), "--allow-remote", "--token", token,
         "--allowed-origin", "https://console.example"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f"http://{host}:{port}"
    try:
        deadline = time.time() + 8
        health = None
        while time.time() < deadline and proc.poll() is None:
            try:
                _, _, health = json_request(opener, base + "/api/health")
                break
            except Exception:
                time.sleep(0.05)
        if not health:
            raise AssertionError("remote web process did not become healthy")
        assert health["version"] == "0.4.2" and health["remote"] is True and health["token_required"] is True

        with opener.open(base + "/", timeout=3) as response:
            html = response.read().decode()
        assert "imr :: v0.4.2" in html and "REMOTE CONSOLE" in html

        try:
            json_request(opener, base + "/api/jobs")
            raise AssertionError("protected remote API accepted a request without token")
        except urllib.error.HTTPError as exc:
            assert exc.code == 401

        # Cross-origin mode explicitly allowed by the CLI.
        preflight = urllib.request.Request(
            base + "/api/discover", method="OPTIONS",
            headers={"Origin":"https://console.example", "Access-Control-Request-Method":"POST"},
        )
        with opener.open(preflight, timeout=3) as response:
            assert response.status == 204
            assert response.headers.get("Access-Control-Allow-Origin") == "https://console.example"

        lab_url = f"http://127.0.0.1:{lab.server_port}/item?id=1"
        payload = {
            "kind":"scan", "url":lab_url, "method":"GET", "parameter":"id", "location":"query",
            "original_value":"1", "authorized":True, "profile":"safe", "context":"numeric",
        }
        status, _, started = json_request(opener, base + "/api/jobs", method="POST", token=token, origin=base, payload=payload)
        assert status == 202
        job_id = started["job_id"]

        # Native EventSource cannot set custom headers; the server intentionally
        # accepts the token only on the SSE query route and redacts it from logs.
        event_url = base + f"/api/jobs/{job_id}/events?token={token}"
        request = urllib.request.Request(event_url)
        events = []
        with opener.open(request, timeout=12) as response:
            while True:
                line = response.readline().decode("utf-8", "replace")
                if not line:
                    break
                if line.startswith("data: "):
                    event = json.loads(line[6:])
                    events.append(event)
                    if event.get("event") == "terminal":
                        break
        assert any(event.get("event") == "result" for event in events)
        assert events[-1].get("event") == "terminal"

        _, _, state = json_request(opener, base + f"/api/jobs/{job_id}", token=token)
        assert state["status"] == "complete"
        assert state["result"]["confidence_score"] >= 75

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(timeout=4)
        stdout = proc.stdout.read() if proc.stdout else ""
        stderr = proc.stderr.read() if proc.stderr else ""
        lab.shutdown(); lab.server_close(); lab.db.close(); lab_thread.join(timeout=2)  # type: ignore[attr-defined]

    assert "Access URLs:" in stdout
    assert f"http://{host}:{port}/#token=" in stdout
    assert "http://0.0.0.0:" not in stdout
    assert "Traceback (most recent call last)" not in stdout + stderr
    print("remote console smoke (LAN bind/API/SSE/token/origin): OK")


if __name__ == "__main__":
    main()
