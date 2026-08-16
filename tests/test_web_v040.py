from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import requests

from lab.vulnerable_server import build_server
from websqlmapper.web import JOBS, SETTINGS, Job, JobManager, ThreadingHTTPServer, WebSQLMapperHandler, run_web
from websqlmapper.control import ScanControl


class WebV040Tests(unittest.TestCase):
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
        SETTINGS.token = None; SETTINGS.remote = False; SETTINGS.allowed_hosts = ()
        cls.web.shutdown(); cls.web.server_close(); cls.web_thread.join(timeout=2)
        cls.lab.shutdown(); cls.lab.server_close(); cls.lab.db.close()  # type: ignore[attr-defined]
        cls.lab_thread.join(timeout=2)

    def test_pwa_assets_and_discovery_endpoint(self) -> None:
        manifest = requests.get(self.base + "/manifest.webmanifest", timeout=2)
        sw = requests.get(self.base + "/service-worker.js", timeout=2)
        self.assertEqual(manifest.status_code, 200)
        self.assertIn("WebSQLMapper", manifest.text)
        self.assertEqual(sw.status_code, 200)
        self.assertNotIn("cache.put(event.request", sw.text.split("/api/")[0] if "/api/" in sw.text else "")
        body = requests.post(self.base + "/api/discover", json={"url":self.lab_url,"method":"GET","parameter":"id"}, timeout=2).json()
        self.assertTrue(any(x["location"] == "query" and x["parameter"] == "id" for x in body["injection_points"]))


    def test_local_host_allowlist_blocks_dns_rebinding_style_host(self) -> None:
        old = SETTINGS.allowed_hosts
        SETTINGS.allowed_hosts = ("127.0.0.1", "localhost", "::1")
        try:
            response = requests.get(self.base + "/api/health", headers={"Host":"attacker.example"}, timeout=2)
            self.assertEqual(response.status_code, 421)
            self.assertIn("Host", response.json()["error"])
        finally:
            SETTINGS.allowed_hosts = old

    def test_remote_token_protects_api(self) -> None:
        old = SETTINGS.token
        SETTINGS.token = "test-token"
        try:
            denied = requests.get(self.base + "/api/jobs", timeout=2)
            allowed = requests.get(self.base + "/api/jobs", headers={"X-WebSQLMapper-Token":"test-token"}, timeout=2)
            self.assertEqual(denied.status_code, 401)
            self.assertEqual(allowed.status_code, 200)
        finally:
            SETTINGS.token = old

    def test_remote_binding_requires_explicit_opt_in(self) -> None:
        with self.assertRaisesRegex(ValueError, "allow-remote"):
            run_web("0.0.0.0", 0)

    def test_async_map_job_is_controlled(self) -> None:
        payload = {"kind":"map","url":self.lab_url,"method":"GET","parameter":"id","location":"query","original_value":"1","authorized":True,"context":"auto","max_rows":1,"max_chars":4,"map_max_requests":30}
        start = requests.post(self.base + "/api/jobs", json=payload, timeout=2)
        self.assertEqual(start.status_code, 202)
        job_id = start.json()["job_id"]
        state = {}
        for _ in range(200):
            state = requests.get(self.base + f"/api/jobs/{job_id}", timeout=2).json()
            if state.get("status") in {"complete","cancelled","error"}: break
            time.sleep(0.02)
        self.assertEqual(state.get("status"), "complete")
        self.assertEqual(state.get("kind"), "map")
        self.assertIn("context", state.get("result") or {})



    def test_terminal_job_rejects_state_mutation(self) -> None:
        payload = {"kind":"scan","url":self.lab_url,"method":"GET","parameter":"id","location":"query","original_value":"1","authorized":True,"profile":"safe","context":"numeric"}
        job_id = requests.post(self.base + "/api/jobs", json=payload, timeout=2).json()["job_id"]
        for _ in range(200):
            state = requests.get(self.base + f"/api/jobs/{job_id}", timeout=2).json()
            if state.get("status") in {"complete","cancelled","error"}: break
            time.sleep(0.02)
        self.assertEqual(state.get("status"), "complete")
        pause = requests.post(self.base + f"/api/jobs/{job_id}/pause", json={}, timeout=2)
        resume = requests.post(self.base + f"/api/jobs/{job_id}/resume", json={}, timeout=2)
        self.assertEqual(pause.status_code, 409)
        self.assertEqual(resume.status_code, 409)

    def test_web_templates_and_report_download(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
            request = {"url": self.lab_url, "method": "GET", "parameter": "id", "location": "query", "cookies": {"session": "secret"}, "bearer_token": "top-secret"}
            saved = requests.post(self.base + "/api/templates/save", json={"name": "web-demo", "request": request}, timeout=2)
            self.assertEqual(saved.status_code, 200)
            listed = requests.get(self.base + "/api/templates", timeout=2).json()["templates"]
            self.assertIn("web-demo", listed)
            loaded = requests.get(self.base + "/api/templates/web-demo", timeout=2).json()["request"]
            self.assertEqual(loaded["cookies"], {})
            self.assertIsNone(loaded["bearer_token"])
            deleted = requests.post(self.base + "/api/templates/delete", json={"name": "web-demo"}, timeout=2)
            self.assertEqual(deleted.status_code, 200)

        payload = {"kind":"scan","url":self.lab_url,"method":"GET","parameter":"id","location":"query","original_value":"1","authorized":True,"profile":"safe","context":"numeric"}
        start = requests.post(self.base + "/api/jobs", json=payload, timeout=2)
        self.assertEqual(start.status_code, 202)
        job_id = start.json()["job_id"]
        for _ in range(200):
            state = requests.get(self.base + f"/api/jobs/{job_id}", timeout=2).json()
            if state.get("status") in {"complete","cancelled","error"}:
                break
            time.sleep(0.02)
        self.assertEqual(state.get("status"), "complete")
        md = requests.get(self.base + f"/api/jobs/{job_id}/report?format=markdown", timeout=2)
        html = requests.get(self.base + f"/api/jobs/{job_id}/report?format=html", timeout=2)
        self.assertEqual(md.status_code, 200)
        self.assertIn("SQL Injection Assessment", md.text)
        self.assertEqual(html.status_code, 200)
        self.assertIn("<!doctype html>", html.text.lower())

    def test_job_event_log_replays_without_consuming(self) -> None:
        job = Job(id="x", kind="scan", control=ScanControl())
        job.emit({"event":"one"}); job.emit({"event":"two"}); job.emit({"event":"three"})
        self.assertEqual([e.payload["event"] for e in job.after(1)], ["two","three"])
        self.assertEqual([e.payload["event"] for e in job.after(1)], ["two","three"])

    def test_job_manager_ttl_and_limit_cleanup(self) -> None:
        manager = JobManager(max_workers=1, max_jobs=1, ttl=0)
        try:
            old = Job(id="old", kind="scan", control=ScanControl(), status="complete")
            old.updated_at = time.time() - 10
            manager._jobs[old.id] = old  # intentional white-box lifecycle test
            self.assertEqual(manager.list(), [])
        finally:
            manager.shutdown()


if __name__ == "__main__":
    unittest.main()
