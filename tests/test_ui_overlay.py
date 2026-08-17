"""Regression guard for the modular Web UI overlay."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "websqlmapper" / "static"


class ModularUiTests(unittest.TestCase):
    def test_loader_preserves_v042_runtime_and_loads_ui_modules(self):
        app = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertIn("app-v042.js", app)
        self.assertIn("ui-core.js", app)
        self.assertIn("ui-enhance.js", app)

    def test_stylesheet_composes_base_and_three_ui_layers(self):
        css = (STATIC / "style.css").read_text(encoding="utf-8")
        self.assertIn("style-v042.css", css)
        self.assertIn("ui-shell.css", css)
        self.assertIn("ui-results.css", css)
        self.assertIn("ui-responsive.css", css)

    def test_professional_ui_features_are_present(self):
        core = (STATIC / "ui-core.js").read_text(encoding="utf-8")
        enhance = (STATIC / "ui-enhance.js").read_text(encoding="utf-8")
        responsive = (STATIC / "ui-responsive.css").read_text(encoding="utf-8")
        for marker in ("ui-command-palette", "ui-rail-resizer", "ui-results-head", "ui-confidence-ring"):
            self.assertIn(marker, core)
        for marker in ("decorateFindings", "decorateTimeline", "toggleFocus", "toggleSidebar"):
            self.assertIn(marker, enhance)
        self.assertIn("max-width:720px", responsive)
        self.assertIn("mobile-action-bar", responsive)

    def test_service_worker_uses_fresh_ui_cache(self):
        sw = (STATIC / "service-worker.js").read_text(encoding="utf-8")
        self.assertIn("websqlmapper-static-v0.4.2-ui4", sw)
        self.assertIn("skipWaiting", sw)
        self.assertIn("clients.claim", sw)


if __name__ == "__main__":
    unittest.main()
