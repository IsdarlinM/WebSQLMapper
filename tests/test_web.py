from __future__ import annotations

import json
import threading
import time
import unittest

import requests

from lab.vulnerable_server import build_server
from websqlmapper.web import ThreadingHTTPServer, WebSQLMapperHandler


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = build_server("127.0.0.1", 0)
        cls.lab_thread = threading.Thread(target=cls.lab.serve_forever, daemon=True); cls.lab_thread.start()
        cls.lab_url = f"http://127.0.0.1:{cls.lab.server_port}/item?id=1"
        cls.web = ThreadingHTTPServer(("127.0.0.1", 0), WebSQLMapperHandler)
        cls.web_thread = threading.Thread(target=cls.web.serve_forever, daemon=True); cls.web_thread.start()
        cls.base = f"http://127.0.0.1:{cls.web.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.web.shutdown(); cls.web.server_close(); cls.web_thread.join(timeout=2)
        cls.lab.shutdown(); cls.lab.server_close(); cls.lab.db.close()  # type: ignore[attr-defined]
        cls.lab_thread.join(timeout=2)

    def test_static_health_and_security_headers(self) -> None:
        index = requests.get(self.base + "/", timeout=2)
        self.assertEqual(index.status_code, 200)
        self.assertIn("Content-Security-Policy", index.headers)
        self.assertIn("Web SQL Injector", index.text)
        health = requests.get(self.base + "/api/health", timeout=2).json()
        self.assertEqual(health["version"], "0.3.0")

    def test_invalid_json_and_parse_errors_are_400(self) -> None:
        bad = requests.post(self.base + "/api/scan", data="{bad", headers={"Content-Type":"application/json"}, timeout=2)
        self.assertEqual(bad.status_code, 400)
        self.assertIn("invalid JSON", bad.json()["error"])
        parse = requests.post(self.base + "/api/parse", json={"kind":"raw","text":"BAD"}, timeout=2)
        self.assertEqual(parse.status_code, 400)
        unknown_parse = requests.post(self.base + "/api/parse", json={"kind":"wat","text":"curl http://example.test"}, timeout=2)
        self.assertEqual(unknown_parse.status_code, 400)
        bad_headers = requests.post(self.base + "/api/scan", json={"url":self.lab_url,"parameter":"id","authorized":True,"headers":["bad"]}, timeout=2)
        self.assertEqual(bad_headers.status_code, 400)
        bad_bool = requests.post(self.base + "/api/scan", json={"url":self.lab_url,"parameter":"id","authorized":True,"verify_tls":"false"}, timeout=2)
        self.assertEqual(bad_bool.status_code, 400)
        bad_dbms = requests.post(self.base + "/api/scan", json={"url":self.lab_url,"parameter":"id","authorized":True,"dbms":"mysql"}, timeout=2)
        self.assertEqual(bad_dbms.status_code, 400)
        bad_job = requests.post(self.base + "/api/jobs", json={"url":self.lab_url,"parameter":"id","authorized":True,"retries":99}, timeout=2)
        self.assertEqual(bad_job.status_code, 400)
        unauthorized_job = requests.post(self.base + "/api/jobs", json={"url":self.lab_url,"parameter":"id"}, timeout=2)
        self.assertEqual(unauthorized_job.status_code, 400)

    def test_sync_scan_and_async_job(self) -> None:
        payload = {"url":self.lab_url,"method":"GET","parameter":"id","location":"query","original_value":"1","authorized":True,"profile":"safe","context":"numeric"}
        sync = requests.post(self.base + "/api/scan", json=payload, timeout=10)
        self.assertEqual(sync.status_code, 200)
        self.assertTrue(sync.json()["likely_vulnerable"])
        start = requests.post(self.base + "/api/jobs", json=payload, timeout=2)
        self.assertEqual(start.status_code, 202)
        job_id = start.json()["job_id"]
        status = ""
        result = None
        for _ in range(100):
            state = requests.get(self.base + f"/api/jobs/{job_id}", timeout=2).json()
            status = state["status"]
            result = state.get("result")
            if status in {"complete","cancelled","error"}: break
            time.sleep(0.03)
        self.assertEqual(status, "complete")
        self.assertTrue(result["likely_vulnerable"])

    def test_job_pause_resume_cancel_endpoints_are_controlled(self) -> None:
        payload = {"url":self.lab_url,"method":"GET","parameter":"id","location":"query","original_value":"1","authorized":True,"profile":"thorough","context":"numeric","delay_ms":20}
        job_id = requests.post(self.base + "/api/jobs", json=payload, timeout=2).json()["job_id"]
        paused = requests.post(self.base + f"/api/jobs/{job_id}/pause", json={}, timeout=2)
        self.assertEqual(paused.status_code, 200)
        resumed = requests.post(self.base + f"/api/jobs/{job_id}/resume", json={}, timeout=2)
        self.assertEqual(resumed.status_code, 200)
        cancelled = requests.post(self.base + f"/api/jobs/{job_id}/cancel", json={}, timeout=2)
        self.assertEqual(cancelled.status_code, 200)


if __name__ == "__main__": unittest.main()
