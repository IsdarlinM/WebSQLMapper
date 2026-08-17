from __future__ import annotations

import json
import shutil
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "websqlmapper" / "static"

RESULT = {
    "confidence_score": 96,
    "reproducibility": 100,
    "verdict": "confirmed",
    "dbms_profile": {"sqlite": 100.0},
    "interference_profile": {},
    "context_profile": {"primary": "numeric"},
    "baseline": {"stability_score": 99},
    "requests_sent": 3,
    "planned_requests": 3,
    "request_budget": 80,
    "findings": [{"title": "Boolean SQLi", "score": 96, "confidence": "confirmed", "category": "boolean", "evidence": {"response_diff": "-NO\n+YES"}}],
    "timeline": [{"index": 1, "phase": "baseline", "label": "baseline", "status": 200, "length": 10, "elapsed_ms": 2, "redirects": [], "method": "GET", "url": "http://lab.test/?id=1"}],
}


def document(remote: bool = False) -> str:
    html = (STATIC / "index.html").read_text()
    css = (STATIC / "style.css").read_text()
    app = (STATIC / "app.js").read_text()
    remote_js = "true" if remote else "false"
    mock = f"""
<script>
const RESULT={json.dumps(RESULT)};
class R {{ constructor(body,status=200){{this.body=body;this.status=status;this.ok=status>=200&&status<300;}} async json(){{return this.body;}} async blob(){{return new Blob([JSON.stringify(this.body)]);}} }}
window.fetch=async(url,opts)=>{{
 const p=String(url), token=opts?.headers?.['X-WebSQLMapper-Token']||'';
 if(p==='/api/health')return new R({{status:'ok',version:'0.4.2',remote:{remote_js},token_required:{remote_js}}});
 if(p==='/api/jobs'&&!opts?.method)return new R({{jobs:[]}},(!{remote_js}||token==='demo-token')?200:401);
 if(p==='/api/templates')return new R({{templates:[]}});
 if(p==='/api/jobs'&&opts?.method==='POST')return new R({{job_id:'job',status:'queued'}},202);
 if(p==='/api/discover')return new R({{injection_points:[{{location:'query',parameter:'id',value:'1',sensitive:false}}]}});
 if(p==='/api/jobs/job')return new R({{id:'job',kind:'scan',status:'complete',result:RESULT}});
 return new R({{error:'not found'}},404);
}};
window.EventSource=class{{constructor(){{this.onmessage=null;setTimeout(()=>{{for(const e of [{{event:'job',status:'running'}},{{event:'plan',planned_requests:3}},{{event:'result',status:'complete',kind:'scan',result:RESULT}},{{event:'terminal',status:'complete'}}])this.onmessage&&this.onmessage({{data:JSON.stringify(e)}});}},20);}}close(){{}}}};
</script>
"""
    return html.replace('<link rel="manifest" href="/manifest.webmanifest">', '').replace('<link rel="stylesheet" href="/static/style.css">', f'<style>{css}</style>').replace('<script src="/static/app.js"></script>', mock + f'<script>{app}</script>')


def main() -> None:
    chromium = shutil.which("chromium") or shutil.which("chromium-browser")
    if not chromium:
        raise RuntimeError("Chromium executable not found")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=chromium, args=["--no-sandbox"])
        errors: list[str] = []
        page = browser.new_page(viewport={"width": 1365, "height": 900})
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.set_content(document(), wait_until="load")
        page.wait_for_function("connection_label => document.querySelector('#connection-label').textContent === connection_label", arg="local console")
        assert "imr :: v0.4.2" in page.locator(".version").inner_text()
        assert page.locator("#remote-access").is_hidden()
        assert page.locator(".config-tabs").evaluate("e => e.scrollWidth <= e.clientWidth + 1")
        page.locator(".config-tab[data-tab='strategy']").click()
        page.locator("#authorized").check()
        page.locator("#scan-btn").click()
        page.wait_for_function("document.querySelector('#state').textContent === 'complete'")
        assert page.locator("#metric-confidence").inner_text() == "96/100"
        assert page.locator("#finding-count").inner_text() == "1"

        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        assert page.locator(".mobile-action-bar").is_visible()
        assert page.locator(".mobile-action-bar button").count() == 4

        remote = browser.new_page(viewport={"width": 1280, "height": 820})
        remote_errors: list[str] = []
        remote.on("pageerror", lambda exc: remote_errors.append(str(exc)))
        remote.set_content(document(True), wait_until="load")
        remote.wait_for_function("document.querySelector('#state').textContent === 'locked'")
        assert remote.locator("#remote-access").is_visible()
        assert remote.locator("#scan-btn").is_disabled()
        remote.locator("#web-token").fill("demo-token")
        remote.locator("#connect-console").click()
        remote.wait_for_function("document.querySelector('#connection-label').textContent === 'remote connected'")
        assert not remote.locator("#scan-btn").is_disabled()
        remote.locator("#forget-console").click()
        assert remote.locator("#scan-btn").is_disabled()
        assert not errors and not remote_errors, (errors, remote_errors)
        browser.close()


if __name__ == "__main__":
    main()
    print("browser smoke (professional local/remote UI): OK")
