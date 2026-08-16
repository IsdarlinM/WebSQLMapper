from __future__ import annotations

import unittest

from websqlmapper.importers import RequestParseError, infer_original_value, parse_curl, parse_raw_request


class ImporterTests(unittest.TestCase):
    def test_parse_raw_json_request(self) -> None:
        raw = "POST /api/user?id=2 HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nCookie: sid=abc\r\n\r\n{\"user\":{\"id\":1}}"
        item = parse_raw_request(raw, scheme="https")
        self.assertEqual(item.config.url, "https://example.test/api/user?id=2")
        self.assertEqual(item.config.method, "POST")
        self.assertEqual(item.config.data["user"]["id"], 1)
        self.assertEqual(item.config.cookies["sid"], "abc")
        self.assertEqual(infer_original_value(item.config, "json", "user.id"), "1")

    def test_parse_curl_request(self) -> None:
        item = parse_curl("curl -X POST 'https://example.test/api' -H 'Content-Type: application/json' -H 'X-Test: yes' -b 'sid=abc' --data-raw '{\"id\":1}' -L")
        self.assertEqual(item.config.method, "POST")
        self.assertEqual(item.config.data["id"], 1)
        self.assertTrue(item.config.follow_redirects)
        self.assertEqual(item.config.cookies["sid"], "abc")




    def test_parse_curl_transport_options(self) -> None:
        item = parse_curl("curl -L --max-redirs 3 --retry 2 --connect-timeout 4 --max-time 20 --cert cert.pem --key key.pem -A agent https://example.test/")
        cfg = item.config
        self.assertEqual(cfg.redirect_policy, "any")
        self.assertEqual(cfg.max_redirects, 3)
        self.assertEqual(cfg.retries, 2)
        self.assertEqual(cfg.connect_timeout, 4)
        self.assertEqual(cfg.max_duration, 20)
        self.assertEqual(cfg.client_cert, "cert.pem")
        self.assertEqual(cfg.client_key, "key.pem")
        self.assertEqual(cfg.headers["User-Agent"], "agent")

    def test_parse_curl_multipart_scalar_fields_and_duplicate_header_errors(self) -> None:
        item = parse_curl("curl -F 'name=alice' -F 'id=2' https://example.test/upload")
        self.assertEqual(item.config.body_mode, "multipart")
        self.assertEqual(item.config.data["name"], "alice")
        with self.assertRaisesRegex(RequestParseError, "file references"):
            parse_curl("curl -F 'file=@/etc/passwd' https://example.test/upload")
        with self.assertRaisesRegex(RequestParseError, "duplicate cURL header"):
            parse_curl("curl -H 'X-Test: 1' -H 'X-Test: 2' https://example.test/")
        raw = "GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: 1\r\nX-Test: 2\r\n\r\n"
        with self.assertRaisesRegex(RequestParseError, "duplicate HTTP header"):
            parse_raw_request(raw)

    def test_parse_structured_multipart_and_discover_text_fields(self) -> None:
        from websqlmapper.importers import discover_injection_points
        boundary = "----abc123"
        raw = (
            "POST /upload HTTP/1.1\r\nHost: example.test\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.txt\"\r\n"
            "Content-Type: text/plain\r\n\r\nhello\r\n"
            f"--{boundary}--\r\n"
        )
        item = parse_raw_request(raw, scheme="https")
        self.assertEqual(item.config.body_mode, "multipart")
        self.assertEqual(item.config.data["name"], "alice")
        self.assertEqual(item.config.data["avatar"]["filename"], "a.txt")
        points = {(p.location, p.parameter) for p in discover_injection_points(item.config)}
        self.assertIn(("form", "name"), points)
        self.assertNotIn(("form", "avatar"), points)

    def test_parse_errors_are_explicit(self) -> None:
        for value in ["", "GET / HTTP/1.1\n\n", "BAD"]:
            with self.subTest(value=value):
                with self.assertRaises(RequestParseError):
                    parse_raw_request(value)
        with self.assertRaises(RequestParseError):
            parse_curl("curl --definitely-unknown https://example.test")


if __name__ == "__main__":
    unittest.main()

class DiscoveryTests(unittest.TestCase):
    def test_discover_injection_points_in_query_json_cookie_header_and_path(self) -> None:
        from websqlmapper.importers import discover_injection_points
        from websqlmapper.models import RequestConfig
        cfg = RequestConfig(
            url="https://example.test/users/42?id=1&id=2",
            method="POST", body_mode="json", data={"user":{"name":"alice","id":7}},
            cookies={"session":"secret","lang":"en"}, headers={"X-Account-ID":"9","Accept":"application/json"}
        )
        points = {(p.location,p.parameter):p for p in discover_injection_points(cfg)}
        self.assertIn(("query","id[0]"), points)
        self.assertIn(("query","id[1]"), points)
        self.assertIn(("json","user.id"), points)
        self.assertIn(("cookie","session"), points)
        self.assertTrue(points[("cookie","session")].sensitive)
        self.assertIn(("header","X-Account-ID"), points)
        self.assertIn(("path","2"), points)
