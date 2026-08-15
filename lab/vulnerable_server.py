#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


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

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/dynamic":
            # Safe control endpoint with deliberately volatile response values.
            body = (
                "OK generated="
                + datetime.now(timezone.utc).isoformat()
                + " request_id="
                + str(uuid.uuid4())
            )
            status = 200
        elif parsed.path == "/item":
            value = parse_qs(parsed.query, keep_blank_values=True).get("id", ["1"])[0]
            sql = f"SELECT name FROM items WHERE id = {value}"  # intentionally vulnerable lab code
            try:
                rows = self.server.db.execute(sql).fetchall()  # type: ignore[attr-defined]
                body = ("FOUND: " + rows[0][0]) if rows else "NOT FOUND"
                status = 200
            except sqlite3.Error as exc:
                body = f"sqlite error: {exc}"
                status = 500
        else:
            self.send_error(404)
            return
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def build_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), VulnerableHandler)
    server.db = build_db()  # type: ignore[attr-defined]
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
