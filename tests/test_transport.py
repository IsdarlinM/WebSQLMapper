from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlsplit

from websqlmapper.models import RequestConfig
from websqlmapper.transport import HTTPClient


class TransportTests(unittest.TestCase):
    def test_query_parameter_injection_replaces_existing_value(self) -> None:
        config = RequestConfig(url="http://example.test/item?id=1&x=y", parameter="id")
        url, body, _ = HTTPClient.inject(config, "1 AND 1=1")
        self.assertIsNone(body)
        parsed = parse_qs(urlsplit(url).query)
        self.assertEqual(parsed["id"], ["1 AND 1=1"])
        self.assertEqual(parsed["x"], ["y"])

    def test_json_body_injection(self) -> None:
        config = RequestConfig(
            url="http://example.test/api", method="POST", parameter="id", body_mode="json", data={"x": 2}
        )
        _, body, headers = HTTPClient.inject(config, "abc")
        self.assertEqual(json.loads(body or b"{}"), {"x": 2, "id": "abc"})
        self.assertEqual(headers["Content-Type"], "application/json")


if __name__ == "__main__":
    unittest.main()
