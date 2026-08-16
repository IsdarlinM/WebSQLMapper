from __future__ import annotations

import json
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from lab.vulnerable_server import build_server
from websqlmapper.models import RequestConfig
from websqlmapper.transport import HTTPClient


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = build_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown(); cls.server.server_close(); cls.server.db.close()  # type: ignore[attr-defined]
        cls.thread.join(timeout=2)

    def test_query_parameter_injection_replaces_existing_value(self) -> None:
        config = RequestConfig(url="http://example.test/item?id=1&x=y", parameter="id")
        url, body, _ = HTTPClient.inject(config, "1 AND 1=1")
        self.assertIsNone(body)
        parsed = parse_qs(urlsplit(url).query)
        self.assertEqual(parsed["id"], ["1 AND 1=1"])
        self.assertEqual(parsed["x"], ["y"])

    def test_repeated_query_parameter_by_index(self) -> None:
        config = RequestConfig(url="http://example.test/?id=1&id=2", parameter="id[1]", location="query")
        url, _, _ = HTTPClient.inject(config, "changed")
        self.assertEqual(parse_qs(urlsplit(url).query)["id"], ["1", "changed"])

    def test_json_nested_and_array_injection(self) -> None:
        config = RequestConfig(url="http://example.test/api", method="POST", parameter="user.items[0].id", location="json", body_mode="json", data={"user":{"items":[{"id":1}]}})
        _, body, headers = HTTPClient.inject(config, "abc")
        self.assertEqual(json.loads(body or b"{}"), {"user":{"items":[{"id":"abc"}]}})
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_form_multipart_cookie_header_path_and_raw_locations(self) -> None:
        cases = [
            (RequestConfig(url=self.base+"/echo", method="POST", parameter="id", location="form", body_mode="form", data={"x":"y"}), "PAY"),
            (RequestConfig(url=self.base+"/echo", method="POST", parameter="id", location="form", body_mode="multipart", data={"x":"y"}), "PAY"),
            (RequestConfig(url=self.base+"/echo", parameter="id", location="cookie"), "PAY"),
            (RequestConfig(url=self.base+"/echo", parameter="X-Item-ID", location="header"), "PAY"),
            (RequestConfig(url=self.base+"/path-item/1", parameter="2", location="path"), "PAY"),
            (RequestConfig(url=self.base+"/echo", method="POST", parameter="body", location="raw", body_mode="xml", raw_body="<id>{{INJECT}}</id>"), "PAY"),
        ]
        for config, value in cases:
            with self.subTest(location=config.location, mode=config.body_mode):
                snap = HTTPClient().request(config, value)
                self.assertNotEqual(snap.status, 0, snap.error)

    def test_retry_follow_redirect_and_timeout_are_controlled(self) -> None:
        self.server.flaky_count = 0  # type: ignore[attr-defined]
        snap = HTTPClient().request(RequestConfig(url=self.base+"/flaky", parameter="x", retries=1), "1")
        self.assertEqual(snap.status, 200)
        no_follow = HTTPClient().request(RequestConfig(url=self.base+"/redirect", parameter="x", follow_redirects=False), "1")
        follow = HTTPClient().request(RequestConfig(url=self.base+"/redirect", parameter="x", follow_redirects=True), "1")
        self.assertEqual(no_follow.status, 302)
        self.assertEqual(follow.status, 200)
        timed = HTTPClient().request(RequestConfig(url=self.base+"/slow", parameter="x", timeout=0.05, retries=0), "1")
        self.assertEqual(timed.status, 0)
        self.assertIn("Timeout", timed.error or "")

    def test_invalid_configuration_returns_snapshot_not_exception(self) -> None:
        snap = HTTPClient().request(RequestConfig(url="file:///tmp/test", parameter="id"), "x")
        self.assertEqual(snap.status, 0)
        self.assertIn("configuration", snap.error or "")

    def test_preflight_rejects_static_configuration_errors(self) -> None:
        bad_retries = RequestConfig(url=self.base + "/echo?id=1", parameter="id", location="query", retries=9)
        with self.assertRaisesRegex(ValueError, "retries"):
            HTTPClient.validate_config(bad_retries, "1")
        bad_method = RequestConfig(url=self.base + "/echo?id=1", method="TRACE", parameter="id", location="query")
        with self.assertRaisesRegex(ValueError, "method"):
            HTTPClient.validate_config(bad_method, "1")
        bad_proxy = RequestConfig(url=self.base + "/echo?id=1", parameter="id", location="query", proxy="not-a-proxy")
        with self.assertRaisesRegex(ValueError, "proxy"):
            HTTPClient.validate_config(bad_proxy, "1")
        bad_ca = RequestConfig(url=self.base + "/echo?id=1", parameter="id", location="query", ca_bundle="/definitely/missing/ca.pem")
        with self.assertRaisesRegex(ValueError, "CA bundle"):
            HTTPClient.validate_config(bad_ca, "1")


if __name__ == "__main__":
    unittest.main()

class TransportV040Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = build_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown(); cls.server.server_close(); cls.server.db.close()  # type: ignore[attr-defined]
        cls.thread.join(timeout=2)

    def test_redirect_chain_policy_and_loop_are_recorded(self) -> None:
        any_follow = HTTPClient().request(RequestConfig(url=self.base+"/redirect-chain", parameter="x", redirect_policy="any"), "1")
        self.assertEqual(any_follow.status, 200)
        self.assertEqual(len(any_follow.redirects), 2)
        self.assertEqual(any_follow.redirect_outcome, "followed")
        never = HTTPClient().request(RequestConfig(url=self.base+"/redirect-chain", parameter="x", redirect_policy="never"), "1")
        self.assertEqual(never.status, 302)
        self.assertEqual(never.redirect_outcome, "blocked-policy")
        loop = HTTPClient().request(RequestConfig(url=self.base+"/redirect-loop-a", parameter="x", redirect_policy="any", max_redirects=10), "1")
        self.assertEqual(loop.redirect_outcome, "loop")
        self.assertIn("loop", loop.error or "")

    def test_same_host_policy_blocks_hostname_change(self) -> None:
        snap = HTTPClient().request(RequestConfig(url=self.base+"/redirect-cross-host", parameter="x", redirect_policy="same-host"), "1")
        self.assertEqual(snap.status, 302)
        self.assertEqual(snap.redirect_outcome, "blocked-policy")
        self.assertTrue(snap.redirects[0].cross_host)

    def test_streaming_body_limit_is_real(self) -> None:
        snap = HTTPClient().request(RequestConfig(url=self.base+"/large", parameter="x", max_body_bytes=4096), "1")
        self.assertEqual(snap.status, 200)
        self.assertLessEqual(snap.length, 4096)
        self.assertTrue(snap.body_truncated)


    def test_mtls_paths_are_validated_before_network_use(self) -> None:
        missing_cert = RequestConfig(url=self.base+"/echo?id=1", parameter="id", location="query", client_cert="/definitely/missing/client.pem")
        with self.assertRaisesRegex(ValueError, "client certificate"):
            HTTPClient.validate_config(missing_cert, "1")
        key_without_cert = RequestConfig(url=self.base+"/echo?id=1", parameter="id", location="query", client_key=__file__)
        with self.assertRaisesRegex(ValueError, "client_key requires client_cert"):
            HTTPClient.validate_config(key_without_cert, "1")

    def test_imported_multipart_can_be_reencoded_and_injected(self) -> None:
        data = {
            "name": "alice",
            "file": {"filename": "a.txt", "content_type": "text/plain", "content_base64": "aGVsbG8="},
        }
        cfg = RequestConfig(url=self.base+"/echo", method="POST", parameter="name", location="form", body_mode="multipart", data=data)
        snap = HTTPClient().request(cfg, "changed")
        self.assertEqual(snap.status, 200)
        echoed = json.loads(snap.body)["body"]
        self.assertIn('name="name"', echoed)
        self.assertIn("changed", echoed)
        self.assertIn("hello", echoed)

    def test_retry_after_and_cookie_rotation(self) -> None:
        self.server.retry_after_count = 0  # type: ignore[attr-defined]
        snap = HTTPClient().request(RequestConfig(url=self.base+"/retry-after", parameter="x", retries=1, retry_policy="safe"), "1")
        self.assertEqual(snap.status, 200)
        rotating = HTTPClient()
        cfg = RequestConfig(url=self.base+"/cookie-rotate", parameter="x", cookie_mode="session", cookies={"rotating":"first"})
        first = rotating.request(cfg, "1"); second = rotating.request(cfg, "1")
        self.assertEqual(first.body, "first")
        self.assertEqual(second.body, "next")
        static = HTTPClient(); scfg = RequestConfig(url=self.base+"/cookie-rotate", parameter="x", cookie_mode="static", cookies={"rotating":"first"})
        self.assertEqual(static.request(scfg,"1").body, "first")
        self.assertEqual(static.request(scfg,"1").body, "first")

    def test_repeated_form_parameter_by_index(self) -> None:
        cfg = RequestConfig(url=self.base+"/echo", method="POST", parameter="id[1]", location="form", body_mode="form", data=[["id","1"],["id","2"]])
        snap = HTTPClient().request(cfg, "changed")
        self.assertIn("id=1&id=changed", snap.body)
