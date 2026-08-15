from __future__ import annotations

import json
import shutil
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "websqlmapper" / "static"


def fake_result() -> dict[str, object]:
    return {
        "target":"http://lab.test/item?id=1", "method":"GET", "parameter":"id", "injection_location":"query",
        "baseline":{"stability_score":99}, "findings":[{
            "category":"boolean-based-indicator", "title":"Repeatable true/false SQL response separation (numeric-and)",
            "confidence":"confirmed", "score":96, "payload":"TRUE/FALSE", "dbms_hint":"sqlite",
            "evidence":{"reproducibility":100,"response_diff":"--- left\n+++ right\n-NOT FOUND\n+FOUND"}
        }],
        "tested_payloads":12, "confidence_score":96, "verdict":"confirmed", "detected_context":"numeric",
        "dbms_profile":{"sqlite":100.0}, "errors":[], "reproducibility":100, "requests_sent":3, "request_budget":80,
        "profile":"safe", "stopped_early":False, "context_profile":{"primary":"numeric","scores":{"numeric":95}},
        "timeline":[
            {"index":1,"phase":"baseline","label":"baseline-1","status":200,"length":18,"elapsed_ms":2.1,"error":None,"method":"GET","url":"http://lab.test/item?id=1","request_headers":{},"request_body":None,"response_excerpt":"FOUND"},
            {"index":2,"phase":"boolean","label":"numeric-and-true-1","status":200,"length":18,"elapsed_ms":2.2,"error":None,"method":"GET","url":"http://lab.test/item?id=1+AND+1%3D1","request_headers":{},"request_body":None,"response_excerpt":"FOUND"},
            {"index":3,"phase":"boolean","label":"numeric-and-false-1","status":200,"length":9,"elapsed_ms":2.0,"error":None,"method":"GET","url":"http://lab.test/item?id=1+AND+1%3D2","request_headers":{},"request_body":None,"response_excerpt":"NOT FOUND"},
        ],
    }


def build_document() -> str:
    html = (STATIC / "index.html").read_text()
    css = (STATIC / "style.css").read_text()
    app = (STATIC / "app.js").read_text()
    result_json = json.dumps(fake_result())
    mock = f"""
<script>
const __fakeResult = {result_json};
class MockResponse {{
  constructor(body, status=200) {{ this._body=body; this.status=status; this.ok=status>=200 && status<300; }}
  async json() {{ return this._body; }}
}}
window.fetch = async function(url, opts) {{
  const path = String(url);
  if (path === '/api/jobs') return new MockResponse({{job_id:'browser-smoke',status:'queued'}}, 202);
  if (path === '/api/parse') return new MockResponse({{source:'raw-http',request:{{url:'http://lab.test/api/item',method:'POST',parameter:'id',location:'auto',data:{{user:{{id:1}}}},headers:{{'Content-Type':'application/json'}},cookies:{{sid:'abc'}},body_mode:'json',raw_body:null,timeout:8,proxy:null,verify_tls:true,ca_bundle:null,follow_redirects:false,auth_type:null,auth_username:null,auth_password:null,bearer_token:null,rate:0,delay_ms:0,jitter_ms:0,retries:1}}}});
  if (path === '/api/map') return new MockResponse({{dbms:'sqlite',tables:{{users:{{columns:['username'],row_count:1,rows:[{{username:'admin'}}]}}}},requests_sent:42,truncated:false}});
  if (path.includes('/api/jobs/browser-smoke/')) return new MockResponse({{job_id:'browser-smoke',status:'running'}});
  return new MockResponse({{error:'not found'}},404);
}};
window.EventSource = class {{
  constructor(url) {{
    this.url=url; this.onmessage=null; this.onerror=null;
    const events = [
      {{event:'job',status:'running',job_id:'browser-smoke'}},
      {{event:'phase',name:'baseline',status:'running'}},
      {{event:'request-complete',phase:'baseline',label:'baseline-1',index:1,budget:80,status:200,length:18,elapsed_ms:2.1}},
      {{event:'phase',name:'baseline',status:'complete',stability:99}},
      {{event:'result',status:'complete',result:__fakeResult}},
      {{event:'terminal',status:'complete'}}
    ];
    setTimeout(() => events.forEach((event,i) => setTimeout(() => this.onmessage && this.onmessage({{data:JSON.stringify(event)}}), i*10)), 10);
  }}
  close() {{}}
}};
</script>
"""
    html = html.replace('<link rel="stylesheet" href="/static/style.css">', f"<style>{css}</style>")
    html = html.replace('<script src="/static/app.js"></script>', mock + f"<script>{app}</script>")
    return html


def main() -> None:
    chromium = shutil.which("chromium") or shutil.which("chromium-browser")
    if not chromium:
        raise RuntimeError("Chromium executable not found")
    console_errors: list[str] = []
    page_errors: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=chromium, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width":1365,"height":900})
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.set_content(build_document(), wait_until="load")
        assert page.title() == "WebSQLMapper · Web SQL Injector"
        assert "imr :: v0.3.0" in page.locator(".version").inner_text()
        page.locator("#authorized").check()
        page.locator("#context").select_option("numeric")
        page.locator("#profile").select_option("safe")
        page.locator("#scan-btn").click()
        page.wait_for_function("document.querySelector('#state').textContent === 'complete'", timeout=5000)
        assert "CONFIRMED" in page.locator("#summary").inner_text().upper()
        assert page.locator("#metric-confidence").inner_text() == "96/100"
        assert int(page.locator("#finding-count").inner_text()) == 1
        assert page.locator("#timeline tr").count() == 3
        page.locator("#findings .finding").click()
        assert "response_diff" in page.locator("#inspector-output").inner_text()

        page.locator("#import-kind").select_option("raw")
        page.locator("#import-scheme").select_option("http")
        page.locator("#import-text").fill("POST /api/item HTTP/1.1\nHost: lab.test\n\n")
        page.locator("#parse-btn").click()
        page.wait_for_function("document.querySelector('#url').value.includes('/api/item')")
        assert page.locator("#body-mode").input_value() == "json"

        page.set_viewport_size({"width":390,"height":844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        page.locator("#data").fill("{bad")
        page.locator("#scan-btn").click()
        page.wait_for_function("document.querySelector('#state').textContent === 'error'", timeout=3000)
        assert "JSON" in page.locator("#summary").inner_text()
        assert not console_errors, console_errors
        assert not page_errors, page_errors
        browser.close()


if __name__ == "__main__":
    main()
    print("browser smoke (Chromium DOM/JS): OK")
