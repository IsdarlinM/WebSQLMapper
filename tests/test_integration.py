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
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.url = cls.base + "/item?id=1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown(); cls.server.server_close(); cls.server.db.close()  # type: ignore[attr-defined]
        cls.thread.join(timeout=2)

    def test_scanner_detects_local_vulnerable_parameter(self) -> None:
        config = RequestConfig(url=self.url, method="GET", parameter="id", location="query")
        report = SQLiScanner().scan(config, original_value="1", authorized=True)
        self.assertTrue(report.likely_vulnerable)
        self.assertGreaterEqual(report.confidence_score, 90)
        self.assertEqual(report.verdict, "confirmed")
        self.assertEqual(report.detected_context, "numeric")
        self.assertEqual(report.dbms_profile.get("sqlite"), 100.0)
        self.assertGreaterEqual(report.reproducibility, 66)
        self.assertEqual(report.requests_sent, len(report.timeline))

    def test_scanner_detects_nested_json_parameter(self) -> None:
        config = RequestConfig(
            url=self.base + "/api/item", method="POST", parameter="user.id", location="json",
            body_mode="json", data={"user":{"id":1}}
        )
        report = SQLiScanner().scan(config, original_value="1", authorized=True, profile="safe", context="numeric")
        self.assertTrue(report.likely_vulnerable)
        self.assertEqual(report.injection_location, "json")

    def test_scanner_ignores_volatile_safe_endpoint(self) -> None:
        config = RequestConfig(url=self.base + "/dynamic?id=1", method="GET", parameter="id", location="query")
        report = SQLiScanner().scan(config, original_value="1", authorized=True)
        self.assertFalse(report.likely_vulnerable)
        self.assertLess(report.confidence_score, 55)
        self.assertGreaterEqual(report.baseline["stability_score"], 90)

    def test_request_budget_stops_cleanly(self) -> None:
        config = RequestConfig(url=self.url, parameter="id", location="query")
        report = SQLiScanner().scan(config, original_value="1", authorized=True, max_requests=10)
        self.assertTrue(report.stopped_early)
        self.assertEqual(report.requests_sent, 10)
        self.assertIn("request budget reached", report.errors)

    def test_network_failure_does_not_become_sqli(self) -> None:
        config = RequestConfig(url="http://127.0.0.1:1/item?id=1", parameter="id", location="query", timeout=0.05, retries=0)
        report = SQLiScanner().scan(config, original_value="1", authorized=True, profile="safe")
        self.assertFalse(report.likely_vulnerable)
        self.assertTrue(report.stopped_early)
        self.assertTrue(report.errors)

    def test_mapper_recovers_common_sqlite_values(self) -> None:
        config = RequestConfig(url=self.url, method="GET", parameter="id", location="query")
        result = SQLiteBlindMapper().map_database(
            config, original_value="1", context="numeric", authorized=True,
            common_tables=["users"], common_columns=["username", "password"], max_rows=1, max_chars=8,
        )
        users = result.tables["users"]
        self.assertEqual(users["columns"], ["username", "password"])
        self.assertEqual(users["rows"][0]["username"], "admin")
        self.assertEqual(users["rows"][0]["password"], "secret")


if __name__ == "__main__":
    unittest.main()

class V040IntegrationTests(unittest.TestCase):
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

    def test_adaptive_early_stop_reduces_work(self) -> None:
        cfg = RequestConfig(url=self.base+"/item?id=1", parameter="id", location="query")
        report = SQLiScanner().scan(cfg, original_value="1", authorized=True, profile="normal", context="numeric", adaptive=True)
        self.assertTrue(report.likely_vulnerable)
        self.assertTrue(report.adaptive_stopped)
        self.assertLess(report.requests_sent, report.request_budget or 9999)

    def test_waf_interference_is_not_confirmed_sqli(self) -> None:
        cfg = RequestConfig(url=self.base+"/waf?id=1", parameter="id", location="query")
        report = SQLiScanner().scan(cfg, original_value="1", authorized=True, profile="safe", context="numeric")
        self.assertFalse(report.likely_vulnerable)
        self.assertGreaterEqual(report.interference_profile.get("waf_or_edge_blocking", 0), 50)


    def test_redirect_behavior_drift_is_profiled_separately(self) -> None:
        cfg = RequestConfig(url=self.base+"/redirect-on-probe?id=1", parameter="id", location="query", redirect_policy="any")
        report = SQLiScanner().scan(cfg, original_value="1", authorized=True, profile="safe", context="numeric")
        self.assertGreater(report.interference_profile.get("redirect_behavior_drift", 0), 0)

    def test_mapper_auto_context_recovers_data(self) -> None:
        cfg = RequestConfig(url=self.base+"/item?id=1", parameter="id", location="query")
        result = SQLiteBlindMapper().map_database(cfg, original_value="1", context="auto", authorized=True, common_tables=["users"], common_columns=["username"], max_rows=1, max_chars=8, max_requests=500)
        self.assertEqual(result.context, "numeric")
        self.assertEqual(result.tables["users"]["rows"][0]["username"], "admin")
