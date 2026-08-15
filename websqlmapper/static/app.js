"use strict";
const $ = (id) => document.getElementById(id);
let currentJob = null;
let eventSource = null;
let lastResult = null;
let requestCount = 0;
const phaseStates = new Map();

function jsonField(id, fallback) {
  const raw = $(id).value.trim();
  if (!raw) return fallback;
  const parsed = JSON.parse(raw);
  return parsed;
}

function numberOrNull(id) {
  const raw = $(id).value.trim();
  return raw === "" ? null : Number(raw);
}

function configPayload() {
  const timingValue = $("time-probes").value;
  const authUser = $("auth-user").value;
  return {
    url: $("url").value.trim(),
    method: $("method").value,
    parameter: $("parameter").value.trim(),
    location: $("location").value,
    original_value: $("original-value").value,
    body_mode: $("body-mode").value,
    data: jsonField("data", {}),
    raw_body: $("raw-body").value || null,
    headers: jsonField("headers", {}),
    cookies: jsonField("cookies", {}),
    proxy: $("proxy").value.trim() || null,
    timeout: Number($("timeout").value),
    retries: Number($("retries").value),
    rate: Number($("rate").value),
    delay_ms: Number($("delay-ms").value),
    jitter_ms: Number($("jitter-ms").value),
    verify_tls: $("verify-tls").checked,
    ca_bundle: $("ca-bundle").value.trim() || null,
    follow_redirects: $("follow-redirects").checked,
    auth_type: authUser ? "basic" : null,
    auth_username: authUser || null,
    auth_password: authUser ? $("auth-pass").value : null,
    bearer_token: $("bearer").value || null,
    context: $("context").value,
    profile: $("profile").value,
    baseline_samples: numberOrNull("baseline-samples"),
    confirmation_rounds: numberOrNull("confirmation-rounds"),
    max_requests: numberOrNull("max-requests"),
    time_probes: timingValue === "auto" ? null : timingValue === "true",
    authorized: $("authorized").checked,
  };
}

function setRunning(running) {
  $("scan-btn").disabled = running;
  $("map-btn").disabled = running;
  $("parse-btn").disabled = running;
  $("pause-btn").disabled = !running;
  $("resume-btn").disabled = !running;
  $("stop-btn").disabled = !running;
}

function showError(error) {
  $("state").textContent = "error";
  $("summary").textContent = error instanceof Error ? error.message : String(error);
  setRunning(false);
}

async function postJSON(url, payload = {}) {
  const response = await fetch(url, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)});
  const body = await response.json().catch(() => ({error:`HTTP ${response.status}`}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function resetResults() {
  requestCount = 0;
  lastResult = null;
  phaseStates.clear();
  $("timeline").textContent = "";
  $("findings").className = "finding-list empty";
  $("findings").textContent = "No findings yet.";
  $("finding-count").textContent = "0";
  $("metric-confidence").textContent = "—";
  $("metric-repro").textContent = "—";
  $("metric-dbms").textContent = "—";
  $("metric-requests").textContent = "0";
  $("progress").style.width = "0%";
  $("phases").textContent = "";
  $("output").textContent = "{}";
}

function renderPhases() {
  $("phases").textContent = "";
  for (const [name, status] of phaseStates.entries()) {
    const node = document.createElement("span");
    node.className = `phase ${status === "complete" ? "done" : "live"}`;
    node.textContent = `${name} · ${status}`;
    $("phases").appendChild(node);
  }
}

function appendTimeline(event) {
  const tr = document.createElement("tr");
  tr.dataset.index = String(event.index ?? "");
  const cells = [event.index, event.phase, event.label, event.status, event.length, `${Number(event.elapsed_ms || 0).toFixed(1)} ms`];
  for (const value of cells) {
    const td = document.createElement("td");
    td.textContent = value == null ? "" : String(value);
    tr.appendChild(td);
  }
  tr.addEventListener("click", () => {
    const item = (lastResult?.timeline || []).find((x) => Number(x.index) === Number(event.index));
    if (item) $("inspector-output").textContent = JSON.stringify(item, null, 2);
  });
  $("timeline").appendChild(tr);
}

function renderResult(result) {
  lastResult = result;
  $("output").textContent = JSON.stringify(result, null, 2);
  $("metric-confidence").textContent = `${result.confidence_score || 0}/100`;
  $("metric-repro").textContent = `${result.reproducibility || 0}%`;
  const topDbms = Object.entries(result.dbms_profile || {})[0];
  $("metric-dbms").textContent = topDbms ? `${topDbms[0]} ${topDbms[1]}%` : "unknown";
  $("metric-requests").textContent = `${result.requests_sent || 0}/${result.request_budget || "—"}`;
  $("summary").textContent = `${result.verdict} · ${result.context_profile?.primary || "unknown context"} · baseline ${result.baseline?.stability_score ?? 0}% stable`;
  const findings = result.findings || [];
  $("finding-count").textContent = String(findings.length);
  $("findings").textContent = "";
  $("findings").className = findings.length ? "finding-list" : "finding-list empty";
  if (!findings.length) {
    $("findings").textContent = "No medium-or-higher confidence SQLi indicator confirmed.";
  }
  for (const finding of findings) {
    const card = document.createElement("article");
    card.className = `finding ${finding.confidence === "confirmed" ? "confirmed" : finding.confidence === "high" ? "high" : ""}`;
    const title = document.createElement("h3");
    title.textContent = finding.title;
    const meta = document.createElement("p");
    meta.textContent = `${finding.score}/100 · ${finding.confidence} · ${finding.category}${finding.dbms_hint ? ` · ${finding.dbms_hint}` : ""}`;
    const evidence = document.createElement("p");
    evidence.className = "score";
    evidence.textContent = `Payload evidence captured · reproducibility ${finding.evidence?.reproducibility ?? "n/a"}%`;
    card.append(title, meta, evidence);
    card.addEventListener("click", () => { $("inspector-output").textContent = JSON.stringify(finding.evidence || {}, null, 2); });
    $("findings").appendChild(card);
  }
  $("timeline").textContent = "";
  for (const item of result.timeline || []) appendTimeline(item);
}

async function startScan() {
  try {
    resetResults();
    const payload = configPayload();
    if (!payload.url) throw new Error("URL is required");
    if (!payload.parameter) throw new Error("Injection parameter/path is required");
    setRunning(true);
    $("summary").textContent = "Starting adaptive scan…";
    const started = await postJSON("/api/jobs", payload);
    currentJob = started.job_id;
    $("state").textContent = "running";
    eventSource = new EventSource(`/api/jobs/${currentJob}/events`);
    eventSource.onmessage = (message) => {
      const event = JSON.parse(message.data);
      if (event.event === "phase") {
        phaseStates.set(event.name, event.status);
        renderPhases();
      } else if (event.event === "request-complete") {
        requestCount = Number(event.index || requestCount + 1);
        $("metric-requests").textContent = `${requestCount}/${event.budget || "—"}`;
        const pct = event.budget ? Math.min(96, requestCount * 100 / event.budget) : Math.min(96, requestCount);
        $("progress").style.width = `${pct}%`;
        appendTimeline(event);
      } else if (event.event === "result") {
        renderResult(event.result);
        $("state").textContent = event.status;
        $("progress").style.width = "100%";
      } else if (event.event === "error") {
        showError(new Error(event.error));
      } else if (event.event === "terminal") {
        if (eventSource) eventSource.close();
        setRunning(false);
        $("state").textContent = event.status;
        currentJob = null;
      } else if (event.event === "job") {
        $("state").textContent = event.status;
      }
    };
    eventSource.onerror = () => {
      if (currentJob) {
        $("summary").textContent = "Live event stream disconnected; query the job status or run again.";
      }
    };
  } catch (error) {
    showError(error);
  }
}

async function jobAction(action) {
  if (!currentJob) return;
  try {
    const body = await postJSON(`/api/jobs/${currentJob}/${action}`);
    $("state").textContent = body.status;
  } catch (error) { showError(error); }
}

async function runMap() {
  try {
    setRunning(true);
    $("state").textContent = "mapping";
    const body = await postJSON("/api/map", configPayload());
    lastResult = body;
    $("output").textContent = JSON.stringify(body, null, 2);
    $("summary").textContent = `Mapped ${Object.keys(body.tables || {}).length} table candidate(s) using ${body.requests_sent} private-lab requests.`;
    $("state").textContent = "complete";
  } catch (error) { showError(error); }
  finally { setRunning(false); }
}

async function parseImport() {
  try {
    const body = await postJSON("/api/parse", {kind:$("import-kind").value, scheme:$("import-scheme").value, text:$("import-text").value});
    const r = body.request;
    $("url").value = r.url || "";
    $("method").value = r.method || "GET";
    $("body-mode").value = r.body_mode || "auto";
    $("data").value = JSON.stringify(r.data ?? {}, null, 2);
    $("raw-body").value = r.raw_body || "";
    $("headers").value = JSON.stringify(r.headers || {}, null, 2);
    $("cookies").value = JSON.stringify(r.cookies || {}, null, 2);
    $("proxy").value = r.proxy || "";
    $("verify-tls").checked = r.verify_tls !== false;
    $("ca-bundle").value = r.ca_bundle || "";
    $("follow-redirects").checked = r.follow_redirects === true;
    $("auth-user").value = r.auth_username || "";
    $("auth-pass").value = r.auth_password || "";
    $("bearer").value = r.bearer_token || "";
    $("summary").textContent = `Imported ${body.source} request. Select the injection location and parameter.`;
  } catch (error) { showError(error); }
}

$("scan-btn").addEventListener("click", startScan);
$("map-btn").addEventListener("click", runMap);
$("parse-btn").addEventListener("click", parseImport);
$("pause-btn").addEventListener("click", () => jobAction("pause"));
$("resume-btn").addEventListener("click", () => jobAction("resume"));
$("stop-btn").addEventListener("click", () => jobAction("cancel"));
$("copy-btn").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(JSON.stringify(lastResult || {}, null, 2)); $("copy-btn").textContent = "Copied"; setTimeout(() => $("copy-btn").textContent = "Copy JSON", 1200); }
  catch (_) { $("copy-btn").textContent = "Copy unavailable"; }
});
