#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lab.vulnerable_server import build_server  # noqa: E402


def run(args: list[str], *, env: dict[str, str], expected: set[int] = {0}, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "websqlmapper", *args]
    result = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode not in expected:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    if "Traceback (most recent call last)" in (result.stdout + result.stderr):
        raise AssertionError(f"unhandled traceback: {' '.join(cmd)}")
    return result


def main() -> None:
    server = build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        env["XDG_CONFIG_HOME"] = str(tmp_path / "config")
        env["NO_COLOR"] = "1"

        try:
            run(["--version"], env=env)
            run(["--help"], env=env)
            run(["--color", "never", "doctor"], env=env)

            # Parser/importer surfaces.
            raw = f"GET /item?id=1 HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nCookie: sid=secret\r\n\r\n"
            parsed = run(["parse", "--raw", raw, "--scheme", "http"], env=env)
            assert "<redacted>" in parsed.stdout
            curl = f"curl -s -H 'X-Test: yes' --cookie 'sid=secret' '{base}/item?id=1'"
            run(["parse", "--curl", curl], env=env)

            # Profiles and legacy/new injection syntax.
            for profile in ("safe", "normal", "thorough"):
                result = run([
                    "--color", "never", "scan", "--url", f"{base}/item?id=1", "--inject", "query:id", "--value", "1",
                    "--profile", profile, "--authorized"
                ], env=env, expected={2})
                assert "Verdict" in result.stdout and ("HIGH-CONFIDENCE" in result.stdout or "CONFIRMED" in result.stdout)
            run([
                "scan", "--url", f"{base}/dynamic?id=1", "--parameter", "id", "--location", "query",
                "--value", "1", "--profile", "safe", "--authorized", "--json",
                "--header", "X-Test:yes", "--cookie", "sid:value", "--timeout", "2", "--rate", "100",
                "--delay-ms", "0", "--jitter-ms", "0", "--retries", "1", "--no-follow-redirects",
                "--no-time-probes", "--context", "auto", "--baseline-samples", "3",
                "--confirmation-rounds", "2", "--max-requests", "80",
            ], env=env, expected={0})

            # Nested JSON execution.
            run([
                "scan", "--url", f"{base}/api/item", "--method", "POST", "--body-mode", "json",
                "--data", '{"user":{"id":1}}', "--inject", "json:user.id", "--value", "1",
                "--profile", "safe", "--authorized", "--json",
            ], env=env, expected={2})

            # Reports and explicit persistence.
            report_json = tmp_path / "scan.json"
            run([
                "scan", "--url", f"{base}/item?id=1", "--inject", "query:id", "--authorized",
                "--profile", "safe", "--save", str(report_json), "--report-format", "json", "--json",
            ], env=env, expected={2})
            assert report_json.exists()
            for fmt, suffix in (("json", ".json"), ("markdown", ".md"), ("html", ".html")):
                out = tmp_path / f"report{suffix}"
                run(["report", str(report_json), "--format", fmt, "--output", str(out)], env=env)
                assert out.exists() and out.stat().st_size > 50

            # Redacted templates.
            run([
                "template", "save", "lab", "--url", f"{base}/item?id=1", "--inject", "query:id",
                "--bearer", "very-secret-token", "--cookie", "session:private",
            ], env=env)
            assert "lab" in run(["template", "list"], env=env).stdout
            shown = run(["template", "show", "lab"], env=env)
            assert "very-secret-token" not in shown.stdout and "private" not in shown.stdout
            run(["scan", "--template", "lab", "--value", "1", "--profile", "safe", "--authorized", "--json"], env=env, expected={2})
            run(["template", "delete", "lab"], env=env)

            # Lab-only mapping command.
            mapped = run([
                "map", "--url", f"{base}/item?id=1", "--inject", "query:id", "--value", "1",
                "--context", "numeric", "--max-rows", "1", "--max-chars", "8", "--authorized", "--json",
            ], env=env, timeout=60)
            assert '"username": "admin"' in mapped.stdout

            # Controlled failures / validation boundaries.
            failures = [
                ["scan", "--url", f"{base}/item?id=1", "--inject", "query:id"],
                ["scan", "--url", f"{base}/item?id=1", "--inject", "query:id", "--authorized", "--max-requests", "9"],
                ["scan", "--url", f"{base}/item?id=1", "--inject", "query:id", "--authorized", "--retries", "9"],
                ["scan", "--url", f"{base}/item?id=1", "--inject", "raw:id", "--authorized", "--body-mode", "raw"],
                ["report", str(tmp_path / "missing.json")],
                ["template", "show", "missing"],
            ]
            for args in failures:
                run(args, env=env, expected={1})
            # In an extracted source tree update must fail cleanly; in CI's Git
            # checkout it may legitimately fast-forward/reinstall successfully.
            run(["update"], env=env, expected={0, 1}, timeout=60)

            # Web CLI startup + real health request.
            proc = subprocess.Popen(
                [sys.executable, "-u", "-m", "websqlmapper", "--color", "never", "web", "--host", "127.0.0.1", "--port", "0"],
                cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                # Port 0 is printed after bind; use a small bounded read loop.
                deadline = time.time() + 5
                line = ""
                while time.time() < deadline:
                    chunk = proc.stdout.readline() if proc.stdout else ""
                    line += chunk
                    if "http://127.0.0.1:" in chunk:
                        break
                import re
                match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
                if not match:
                    raise AssertionError(f"web command did not report bound port: {line!r}")
                with urllib.request.urlopen(f"http://127.0.0.1:{match.group(1)}/api/health", timeout=3) as response:
                    health = json.load(response)
                assert health["status"] == "ok"
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=3)
                err = proc.stderr.read() if proc.stderr else ""
                if "Traceback (most recent call last)" in err:
                    raise AssertionError(err)

        finally:
            server.shutdown()
            server.server_close()
            server.db.close()  # type: ignore[attr-defined]
            thread.join(timeout=2)

    print("CLI command/argument smoke: OK")


if __name__ == "__main__":
    main()
