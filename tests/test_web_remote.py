from __future__ import annotations

import socket
import threading
import unittest

import requests

from websqlmapper import __version__
from websqlmapper.web import (
    SETTINGS,
    ThreadingHTTPServer,
    WebSQLMapperHandler,
    _access_urls,
    _canonical_origin,
    _interface_hosts,
    run_web,
)


class RemoteWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._old = (
            SETTINGS.token,
            SETTINGS.remote,
            SETTINGS.allowed_hosts,
            SETTINGS.allowed_origins,
            SETTINGS.bind_host,
            SETTINGS.bind_port,
            SETTINGS.access_urls,
        )
        cls.token = "remote-test-token-123456789"
        SETTINGS.token = cls.token
        SETTINGS.remote = True
        SETTINGS.allowed_hosts = ()
        SETTINGS.allowed_origins = ()
        SETTINGS.bind_host = "0.0.0.0"
        cls.server = ThreadingHTTPServer(("0.0.0.0", 0), WebSQLMapperHandler)
        SETTINGS.bind_port = cls.server.server_port
        SETTINGS.access_urls = _access_urls("0.0.0.0", cls.server.server_port, cls.token)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.session = requests.Session()
        cls.session.trust_env = False
        hosts = _interface_hosts("0.0.0.0")
        cls.remote_host = hosts[0] if hosts else "127.0.0.1"
        display = f"[{cls.remote_host}]" if ":" in cls.remote_host else cls.remote_host
        cls.base = f"http://{display}:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(timeout=2)
        cls.session.close()
        (
            SETTINGS.token,
            SETTINGS.remote,
            SETTINGS.allowed_hosts,
            SETTINGS.allowed_origins,
            SETTINGS.bind_host,
            SETTINGS.bind_port,
            SETTINGS.access_urls,
        ) = cls._old

    def test_remote_listener_is_reachable_and_health_is_current(self) -> None:
        response = self.session.get(self.base + "/api/health", timeout=2)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertNotIn("Python/", response.headers.get("Server", ""))
        self.assertEqual(body["version"], __version__)
        self.assertTrue(body["remote"])
        self.assertTrue(body["token_required"])
        self.assertEqual(body["bind_port"], self.server.server_port)

    def test_remote_api_accepts_header_and_bearer_tokens(self) -> None:
        denied = self.session.get(self.base + "/api/jobs", timeout=2)
        header = self.session.get(self.base + "/api/jobs", headers={"X-WebSQLMapper-Token": self.token}, timeout=2)
        bearer = self.session.get(self.base + "/api/jobs", headers={"Authorization": f"Bearer {self.token}"}, timeout=2)
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(header.status_code, 200)
        self.assertEqual(bearer.status_code, 200)

    def test_rejected_remote_post_closes_connection_cleanly(self) -> None:
        payload = {"url": "http://example.test/?id=1", "method": "GET", "parameter": "id"}
        response = self.session.post(
            self.base + "/api/discover", json=payload,
            headers={"X-WebSQLMapper-Token":"wrong-token", "Origin":self.base}, timeout=2,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers.get("Connection"), "close")
        # A subsequent request must be parsed as a fresh HTTP request rather than
        # treating the rejected JSON body as a new request line.
        follow = self.session.get(self.base + "/api/jobs", headers={"X-WebSQLMapper-Token":self.token}, timeout=2)
        self.assertEqual(follow.status_code, 200)

    def test_same_origin_remote_post_works_and_mismatch_is_rejected(self) -> None:
        payload = {"url": "http://example.test/?id=1", "method": "GET", "parameter": "id"}
        headers = {"X-WebSQLMapper-Token": self.token, "Origin": self.base}
        ok = self.session.post(self.base + "/api/discover", json=payload, headers=headers, timeout=2)
        self.assertEqual(ok.status_code, 200, ok.text)
        bad_headers = {"X-WebSQLMapper-Token": self.token, "Origin": "https://attacker.example"}
        denied = self.session.post(self.base + "/api/discover", json=payload, headers=bad_headers, timeout=2)
        self.assertEqual(denied.status_code, 403)

    def test_explicit_allowed_origin_supports_preflight_and_post(self) -> None:
        old = SETTINGS.allowed_origins
        SETTINGS.allowed_origins = ("https://console.example",)
        try:
            preflight = self.session.options(
                self.base + "/api/discover",
                headers={"Origin": "https://console.example", "Access-Control-Request-Method": "POST"},
                timeout=2,
            )
            self.assertEqual(preflight.status_code, 204)
            self.assertEqual(preflight.headers.get("Access-Control-Allow-Origin"), "https://console.example")
            response = self.session.post(
                self.base + "/api/discover",
                json={"url": "http://example.test/?id=1", "method": "GET", "parameter": "id"},
                headers={"Origin": "https://console.example", "X-WebSQLMapper-Token": self.token},
                timeout=2,
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "https://console.example")
        finally:
            SETTINGS.allowed_origins = old

    def test_access_links_never_publish_wildcard_address(self) -> None:
        urls = _access_urls("0.0.0.0", 8787, "secret-token-123456")
        self.assertTrue(urls)
        self.assertTrue(all("0.0.0.0" not in url for url in urls))
        self.assertTrue(all("#token=secret-token-123456" in url for url in urls))

    def test_remote_custom_token_has_minimum_strength(self) -> None:
        with self.assertRaisesRegex(ValueError, "16 characters"):
            run_web("0.0.0.0", 0, allow_remote=True, token="short")

    def test_origin_normalization(self) -> None:
        self.assertEqual(_canonical_origin("https://Example.COM:443/path"), "https://example.com")
        self.assertEqual(_canonical_origin("http://example.com:8080"), "http://example.com:8080")
        self.assertIsNone(_canonical_origin("file:///tmp/test"))


if __name__ == "__main__":
    unittest.main()
