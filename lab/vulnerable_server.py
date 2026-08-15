#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit


def build_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(
        """
        CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
        INSERT INTO items(id, name) VALUES (1, 'visible item'), (2, 'second item');
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL);
        INSERT INTO users(id, username, password) VALUES (1, 'admin', 'secret');
        """
    )
    return db


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8", **headers: str) -> None:
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                return

    def _sql(self, value: str) -> None:
        sql = f"SELECT name FROM items WHERE id = {value}"  # intentionally vulnerable local lab code
        try:
            rows = self.server.db.execute(sql).fetchall()  # type: ignore[attr-defined]
            self._send(200, ("FOUND: " + rows[0][0]) if rows else "NOT FOUND")
        except sqlite3.Error as exc:
            self._send(500, f"sqlite error: {exc}")

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(max(0, min(length, 1_000_000)))

    def _echo(self, body: bytes = b"") -> None:
        parsed = urlsplit(self.path)
        payload = {
            "method": self.command,
            "path": unquote(parsed.path),
            "query": parse_qs(parsed.query, keep_blank_values=True),
            "headers": {key: value for key, value in self.headers.items()},
            "body": body.decode("utf-8", errors="replace"),
        }
        self._send(200, json.dumps(payload), "application/json")

    def do_HEAD(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle(self._read_body())

    def do_PUT(self) -> None:
        self._handle(self._read_body())

    def do_PATCH(self) -> None:
        self._handle(self._read_body())

    def do_DELETE(self) -> None:
        self._handle(self._read_body())

    def _handle(self, raw_body: bytes = b"") -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/dynamic":
            body = "OK generated=" + datetime.now(timezone.utc).isoformat() + " request_id=" + str(uuid.uuid4())
            self._send(200, body)
            return
        if parsed.path == "/item":
            value = parse_qs(parsed.query, keep_blank_values=True).get("id", ["1"])[0]
            self._sql(value)
            return
        if parsed.path == "/api/item":
            content_type = self.headers.get("Content-Type", "")
            if "json" in content_type:
                try:
                    obj = json.loads(raw_body or b"{}")
                    value = str(obj.get("user", {}).get("id", obj.get("id", "1")))
                except (json.JSONDecodeError, AttributeError):
                    self._send(400, "bad json")
                    return
            else:
                value = parse_qs(raw_body.decode(errors="replace"), keep_blank_values=True).get("id", ["1"])[0]
            self._sql(value)
            return
        if parsed.path == "/cookie-item":
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            value = cookie.get("id").value if cookie.get("id") else "1"
            self._sql(value)
            return
        if parsed.path == "/header-item":
            self._sql(self.headers.get("X-Item-ID", "1"))
            return
        if parsed.path.startswith("/path-item/"):
            self._sql(unquote(parsed.path.removeprefix("/path-item/")))
            return
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/dynamic")
            self.end_headers()
            return
        if parsed.path == "/flaky":
            self.server.flaky_count += 1  # type: ignore[attr-defined]
            if self.server.flaky_count == 1:  # type: ignore[attr-defined]
                self._send(503, "try again")
            else:
                self._send(200, "ok")
            return
        if parsed.path == "/slow":
            time.sleep(0.3)
            self._send(200, "slow")
            return
        if parsed.path == "/echo":
            self._echo(raw_body)
            return
        self._send(404, "not found")


def build_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), VulnerableHandler)
    server.db = build_db()  # type: ignore[attr-defined]
    server.flaky_count = 0  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Intentionally vulnerable local WebSQLMapper lab")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()
    server = build_server(args.host, args.port)
    print(f"Vulnerable lab listening on http://{args.host}:{server.server_port}/item?id=1")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.db.close()  # type: ignore[attr-defined]
        server.server_close()


if __name__ == "__main__":
    main()
