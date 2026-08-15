const $ = (id) => document.getElementById(id);

function configPayload() {
  let data = {};
  const raw = $("data").value.trim();
  if (raw) data = JSON.parse(raw);
  return {
    url: $("url").value.trim(),
    method: $("method").value,
    parameter: $("parameter").value.trim(),
    original_value: $("original-value").value,
    body_mode: $("body-mode").value,
    context: $("context").value,
    baseline_samples: Number($("baseline-samples").value),
    confirmation_rounds: Number($("confirmation-rounds").value),
    data,
    authorized: $("authorized").checked,
    time_probes: $("time-probes").checked,
  };
}

async function run(endpoint) {
  const buttons = document.querySelectorAll("button");
  buttons.forEach((button) => button.disabled = true);
  $("state").textContent = "running";
  $("summary").textContent = endpoint === "/api/scan" ? "Testing response behavior…" : "Running private-lab boolean inference…";
  try {
    const payload = configPayload();
    const response = await fetch(endpoint, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)});
    const body = await response.json();
    $("output").textContent = JSON.stringify(body, null, 2);
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    if (endpoint === "/api/scan") {
      const dbms = Object.entries(body.dbms_profile || {})[0];
      const dbmsText = dbms ? ` · DBMS ${dbms[0]} ${dbms[1]}%` : "";
      $("summary").textContent = `${body.verdict} · confidence ${body.confidence_score}/100 · ${body.tested_payloads} probes${dbmsText}`;
    } else {
      const tables = Object.keys(body.tables || {});
      $("summary").textContent = `Mapped ${tables.length} common table candidate(s) using ${body.requests_sent} local-lab requests.`;
    }
    $("state").textContent = "complete";
  } catch (error) {
    $("state").textContent = "error";
    $("summary").textContent = error.message;
  } finally {
    buttons.forEach((button) => button.disabled = false);
  }
}

$("scan-form").addEventListener("submit", (event) => {event.preventDefault(); run("/api/scan");});
$("map-btn").addEventListener("click", () => run("/api/map"));
