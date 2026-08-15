from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from websqlmapper.models import RequestConfig
from websqlmapper.reporting import render_report
from websqlmapper.templates import delete_template, list_templates, load_template, save_template


class ReportingTemplateTests(unittest.TestCase):
    def test_all_report_formats_render(self) -> None:
        report = {"target":"http://example.test","method":"GET","parameter":"id","injection_location":"query","verdict":"confirmed","confidence_score":95,"reproducibility":100,"findings":[],"timeline":[],"requests_sent":4,"dbms_profile":{"sqlite":100}}
        self.assertIn("SQL Injection Assessment", render_report(report, "markdown"))
        self.assertIn("<!doctype html>", render_report(report, "html").lower())
        self.assertEqual(json.loads(render_report(report, "json"))["confidence_score"], 95)
        with self.assertRaises(ValueError): render_report(report, "pdf")

    def test_templates_redact_secrets_and_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
            config = RequestConfig(url="https://example.test/?id=1", parameter="id", location="query", cookies={"sid":"secret"}, bearer_token="token", headers={"X-API-Key":"key","X-Test":"ok"})
            save_template("demo", config)
            self.assertEqual(list_templates(), ["demo"])
            loaded = load_template("demo")
            self.assertEqual(loaded.url, config.url)
            self.assertEqual(loaded.cookies, {})
            self.assertIsNone(loaded.bearer_token)
            self.assertEqual(loaded.headers["X-API-Key"], "<redacted>")
            delete_template("demo")
            self.assertEqual(list_templates(), [])


if __name__ == "__main__": unittest.main()
