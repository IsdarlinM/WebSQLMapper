from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lab.vulnerable_server import build_server  # noqa: E402
from websqlmapper.mapper import SQLiteBlindMapper  # noqa: E402
from websqlmapper.models import RequestConfig  # noqa: E402
from websqlmapper.scanner import SQLiScanner  # noqa: E402


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = build_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/item?id=1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.db.close()  # type: ignore[attr-defined]
        cls.thread.join(timeout=2)

    def test_scanner_detects_local_vulnerable_parameter(self) -> None:
        config = RequestConfig(url=self.url, method="GET", parameter="id")
        report = SQLiScanner().scan(config, original_value="1", authorized=True)
        self.assertTrue(report.likely_vulnerable)
        self.assertGreaterEqual(report.confidence_score, 90)
        self.assertEqual(report.verdict, "confirmed")
        self.assertEqual(report.detected_context, "numeric")
        self.assertEqual(report.dbms_profile.get("sqlite"), 100.0)
        self.assertTrue(any(f.category == "boolean-based-indicator" for f in report.findings))

    def test_scanner_ignores_volatile_safe_endpoint(self) -> None:
        url = f"http://127.0.0.1:{self.server.server_port}/dynamic?id=1"
        config = RequestConfig(url=url, method="GET", parameter="id")
        report = SQLiScanner().scan(config, original_value="1", authorized=True)
        self.assertFalse(report.likely_vulnerable)
        self.assertLess(report.confidence_score, 55)
        self.assertGreaterEqual(report.baseline["stability_score"], 90)

    def test_mapper_recovers_common_sqlite_values(self) -> None:
        config = RequestConfig(url=self.url, method="GET", parameter="id")
        result = SQLiteBlindMapper().map_database(
            config,
            original_value="1",
            context="numeric",
            authorized=True,
            common_tables=["users"],
            common_columns=["username", "password"],
            max_rows=1,
            max_chars=8,
        )
        users = result.tables["users"]
        self.assertEqual(users["columns"], ["username", "password"])
        self.assertEqual(users["rows"][0]["username"], "admin")
        self.assertEqual(users["rows"][0]["password"], "secret")


if __name__ == "__main__":
    unittest.main()
