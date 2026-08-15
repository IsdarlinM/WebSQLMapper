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

    def test_parse_errors_are_explicit(self) -> None:
        for value in ["", "GET / HTTP/1.1\n\n", "BAD"]:
            with self.subTest(value=value):
                with self.assertRaises(RequestParseError):
                    parse_raw_request(value)
        with self.assertRaises(RequestParseError):
            parse_curl("curl --definitely-unknown https://example.test")


if __name__ == "__main__":
    unittest.main()
