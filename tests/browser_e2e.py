from __future__ import annotations

import shutil
import sys
import threading
from pathlib import Path

from playwright.sync_api import Error as PlaywrightError, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lab.vulnerable_server import build_server  # noqa: E402
import websqlmapper.web as web  # noqa: E402


def main() -> None:
    chromium = shutil.which("chromium") or shutil.which("chromium-browser")
    if not chromium:
        raise RuntimeError("Chromium executable not found")

    lab = build_server("127.0.0.1", 0)
    lab_thread = threading.Thread(target=lab.serve_forever, daemon=True)
    lab_thread.start()

    web.SETTINGS.remote = False
    web.SETTINGS.token = None
    web.JOBS.configure(2, 20, 120)
    server = web.ThreadingHTTPServer(("127.0.0.1", 0), web.WebSQLMapperHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    base = f"http://127.0.0.1:{server.server_port}"
    target = f"http://127.0.0.1:{lab.server_port}/item?id=1"
    console_errors: list[str] = []
    page_errors: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, executable_path=chromium, args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.on("pageerror", lambda exc: page_errors.append(str(exc)))
            try:
                page.goto(base, wait_until="networkidle")
            except PlaywrightError as exc:
                if "ERR_BLOCKED_BY_ADMINISTRATOR" in str(exc):
                    print("browser e2e (real HTTP/API/SSE): SKIPPED - runner blocks localhost browser navigation")
                    browser.close()
                    return
                raise
            assert page.title() == "WebSQLMapper · Web SQL Injector"
            assert "imr :: v0.4.1" in page.locator(".version").inner_text()

            page.locator("#url").fill(target)
            page.locator(".config-tab[data-tab='injection']").click()
            page.locator("#location").select_option("query")
            page.locator("#parameter").fill("id")
            page.locator("#original-value").fill("1")
            page.locator("#context").select_option("numeric")
            page.locator(".config-tab[data-tab='strategy']").click()
            page.locator("#profile").select_option("safe")
            page.locator("#authorized").check()
            page.locator("#scan-btn").click()
            page.wait_for_function(
                "['complete','error','cancelled'].includes(document.querySelector('#state').textContent)",
                timeout=15_000,
            )
            state = page.locator("#state").inner_text()
            assert state == "complete", page.locator("#summary").inner_text()
            confidence = page.locator("#metric-confidence").inner_text()
            assert int(confidence.split("/", 1)[0]) >= 90, confidence
            assert int(page.locator("#finding-count").inner_text()) >= 1
            assert page.locator("#timeline tr").count() >= 1

            page.locator(".result-tab[data-result-tab='timeline']").click()
            page.locator("#timeline tr").first.locator("button").click()
            assert "GET" in page.locator("#inspector-output").inner_text()

            # Real discovery API through the UI.
            page.locator(".config-tab[data-tab='injection']").click()
            page.locator("#discover-btn").click()
            page.wait_for_function("document.querySelectorAll('#injection-points .point').length >= 1", timeout=3000)
            assert page.locator("#injection-points .point").count() >= 1

            # PWA assets are available on the same real HTTP origin.
            manifest = page.request.get(base + "/manifest.webmanifest")
            worker = page.request.get(base + "/service-worker.js")
            assert manifest.ok and worker.ok

            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
            assert page.locator(".mobile-action-bar").is_visible()

            browser.close()
    finally:
        server.shutdown(); server.server_close(); server_thread.join(timeout=2)
        lab.shutdown(); lab.server_close(); lab.db.close(); lab_thread.join(timeout=2)  # type: ignore[attr-defined]
        web.JOBS.shutdown()

    if console_errors:
        raise AssertionError(f"console errors: {console_errors}")
    if page_errors:
        raise AssertionError(f"page errors: {page_errors}")


if __name__ == "__main__":
    main()
    print("browser e2e (real HTTP/API/SSE): OK or environment-skipped")
