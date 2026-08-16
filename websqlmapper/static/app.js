"use strict";
const $ = (id) => document.getElementById(id);
let currentJob = null;
let lastJobId = null;
let currentJobKind = null;
let eventSource = null;
let lastResult = null;
let requestCount = 0;
let plannedRequests = null;
let selectedEvidence = null;
let selectedFinding = null;
const phaseStates = new Map();

function token() { return $("web-token").value.trim(); }
function apiHeaders() { const h={"Content-Type":"application/json"}; if (token()) h["X-WebSQLMapper-Token"]=token(); return h; }
function eventUrl(jobId) { const t=token(); return `/api/jobs/${jobId}/events${t?`?token=${encodeURIComponent(t)}`:""}`; }
function numberOrNull(id){const raw=$(id).value.trim();return raw===""?null:Number(raw);}
function jsonField(id,fallback){const raw=$(id).value.trim();if(!raw)return fallback;return JSON.parse(raw);}

function objectFromEditor(editorId){
  const out={};
  document.querySelectorAll(`#${editorId} .kv-row`).forEach((row)=>{const k=row.querySelector(".kv-key").value.trim();const v=row.querySelector(".kv-value").value;if(k)out[k]=v;});
  return out;
}
function addKvRow(editorId,key="",value=""){
  const row=document.createElement("div");row.className="kv-row";
  const k=document.createElement("input");k.className="kv-key";k.placeholder="Name";k.value=key;
  const v=document.createElement("input");v.className="kv-value";v.placeholder="Value";v.value=value;
  const del=document.createElement("button");del.type="button";del.className="ghost icon-button";del.textContent="×";del.setAttribute("aria-label",`Remove ${key||"entry"}`);del.addEventListener("click",()=>{row.remove();syncAdvancedJson();});
  for(const input of [k,v]) input.addEventListener("input",syncAdvancedJson);
  row.append(k,v,del);$(editorId).appendChild(row);
}
function fillKvEditor(editorId,obj){$(editorId).textContent="";for(const [k,v] of Object.entries(obj||{}))addKvRow(editorId,k,String(v));}
function syncAdvancedJson(){$("headers").value=JSON.stringify(objectFromEditor("header-editor"),null,2);$("cookies").value=JSON.stringify(objectFromEditor("cookie-editor"),null,2);}
function syncEditorsFromAdvanced(){try{fillKvEditor("header-editor",jsonField("headers",{}));fillKvEditor("cookie-editor",jsonField("cookies",{}));}catch(_){} }

function configPayload(){
  const timing=$("time-probes").value;const authUser=$("auth-user").value;
  return {
    url:$("url").value.trim(),method:$("method").value,parameter:$("parameter").value.trim(),location:$("location").value,original_value:$("original-value").value,
    body_mode:$("body-mode").value,data:jsonField("data",{}),raw_body:$("raw-body").value||null,headers:objectFromEditor("header-editor"),cookies:objectFromEditor("cookie-editor"),
    proxy:$("proxy").value.trim()||null,timeout:Number($("read-timeout").value),connect_timeout:Number($("connect-timeout").value),read_timeout:Number($("read-timeout").value),max_duration:Number($("max-duration").value),
    retries:Number($("retries").value),retry_policy:$("retry-policy").value,cookie_mode:$("cookie-mode").value,rate:Number($("rate").value),delay_ms:Number($("delay-ms").value),jitter_ms:Number($("jitter-ms").value),
    verify_tls:$("verify-tls").checked,ca_bundle:$("ca-bundle").value.trim()||null,client_cert:$("client-cert").value.trim()||null,client_key:$("client-key").value.trim()||null,follow_redirects:$("redirect-policy").value!=="never",redirect_policy:$("redirect-policy").value,max_redirects:Number($("max-redirects").value),max_body_bytes:Number($("max-body").value),concurrency:Number($("concurrency").value),
    auth_type:authUser?"basic":null,auth_username:authUser||null,auth_password:authUser?$("auth-pass").value:null,bearer_token:$("bearer").value||null,
    context:$("context").value,profile:$("profile").value,baseline_samples:numberOrNull("baseline-samples"),confirmation_rounds:numberOrNull("confirmation-rounds"),max_requests:numberOrNull("max-requests"),time_probes:timing==="auto"?null:timing==="true",adaptive:$("adaptive").checked,exhaustive:$("exhaustive").checked,
    max_rows:Number($("map-max-rows").value),max_chars:Number($("map-max-chars").value),map_max_requests:Number($("map-max-requests").value),authorized:$("authorized").checked,
  };
}

function setUiState(state){
  $("state").textContent=state;const active=["queued","running","paused","cancelling","mapping"].includes(state);
  $("scan-btn").disabled=active;$("map-btn").disabled=active;$("parse-btn").disabled=active;$("discover-btn").disabled=active;
  $("pause-btn").disabled=state!=="running";$("resume-btn").disabled=state!=="paused";$("stop-btn").disabled=!active;$("mobile-run").disabled=active;$("mobile-stop").disabled=!active;
}
function showError(error){setUiState("error");$("summary").textContent=error instanceof Error?error.message:String(error);}
async function postJSON(url,payload={}){const response=await fetch(url,{method:"POST",headers:apiHeaders(),body:JSON.stringify(payload)});const body=await response.json().catch(()=>({error:`HTTP ${response.status}`}));if(!response.ok)throw new Error(body.error||`HTTP ${response.status}`);return body;}
async function getJSON(url){const h={};if(token())h["X-WebSQLMapper-Token"]=token();const response=await fetch(url,{headers:h});const body=await response.json().catch(()=>({error:`HTTP ${response.status}`}));if(!response.ok)throw new Error(body.error||`HTTP ${response.status}`);return body;}

function resetResults(){requestCount=0;plannedRequests=null;lastResult=null;selectedEvidence=null;selectedFinding=null;phaseStates.clear();$("timeline").textContent="";$("findings").className="finding-list empty";$("findings").textContent="No findings yet.";$("finding-count").textContent="0";for(const id of ["metric-confidence","metric-repro","metric-dbms","metric-interference"])$(id).textContent="—";$("metric-requests").textContent="0";$("progress-text").textContent="0 / —";$("progress").style.width="0%";$("phases").textContent="";$("output").textContent="{}";$("inspector-output").textContent="Select a finding or timeline request.";}
function renderPhases(){$("phases").textContent="";for(const [name,status] of phaseStates.entries()){const node=document.createElement("span");node.className=`phase ${status==="complete"?"done":"live"}`;node.textContent=`${name} · ${status}`;$("phases").appendChild(node);}}
function updateProgress(){const denom=plannedRequests||null;$("progress-text").textContent=`${requestCount} / ${denom||"—"}`;$("metric-requests").textContent=`${requestCount}${denom?`/${denom}`:""}`;const pct=denom?Math.min(98,requestCount*100/denom):Math.min(95,requestCount);$("progress").style.width=`${pct}%`;}

function selectResultTab(name){document.querySelectorAll(".result-tab").forEach((b)=>b.classList.toggle("active",b.dataset.resultTab===name));document.querySelectorAll(".result-panel").forEach((p)=>p.classList.toggle("active",p.dataset.resultPanel===name));}
function selectInspector(name){document.querySelectorAll(".inspector-tab").forEach((b)=>b.classList.toggle("active",b.dataset.inspector===name));renderInspector(name);}
function renderInspector(name){
  let text="Select a finding or timeline request.";
  if(selectedFinding){const e=selectedFinding.evidence||{};if(name==="diff")text=e.response_diff||"No diff captured.";else text=JSON.stringify(e,null,2);}
  else if(selectedEvidence){if(name==="request")text=JSON.stringify({method:selectedEvidence.method,url:selectedEvidence.url,headers:selectedEvidence.request_headers,body:selectedEvidence.request_body},null,2);else if(name==="response")text=JSON.stringify({status:selectedEvidence.status,content_type:selectedEvidence.content_type,length:selectedEvidence.length,elapsed_ms:selectedEvidence.elapsed_ms,error:selectedEvidence.error,excerpt:selectedEvidence.response_excerpt},null,2);else if(name==="redirects")text=JSON.stringify(selectedEvidence.redirects||[],null,2);else text="Select a finding to view its response diff.";}
  $("inspector-output").textContent=text;
}

function timelineMatches(item){const phase=$("timeline-phase").value,status=$("timeline-status").value,search=$("timeline-search").value.toLowerCase();if(phase&&item.phase!==phase)return false;if(status){if(status==="0"&&item.status!==0)return false;if(status!=="0"&&Math.floor(Number(item.status)/100)!==Number(status))return false;}return !search||String(item.label||"").toLowerCase().includes(search);}
function renderTimeline(){$("timeline").textContent="";for(const item of (lastResult?.timeline||[]).filter(timelineMatches)){const tr=document.createElement("tr");const cells=[item.index,item.phase,item.label,item.status,item.length,`${Number(item.elapsed_ms||0).toFixed(1)} ms`,(item.redirects||[]).length];for(const value of cells){const td=document.createElement("td");td.textContent=value==null?"":String(value);tr.appendChild(td);}const td=document.createElement("td");const btn=document.createElement("button");btn.type="button";btn.className="ghost tiny";btn.textContent="Inspect";btn.addEventListener("click",()=>{selectedEvidence=item;selectedFinding=null;selectResultTab("inspector");selectInspector("request");});td.appendChild(btn);tr.appendChild(td);$("timeline").appendChild(tr);}}

function renderResult(result,kind="scan"){
  lastResult=result;$("output").textContent=JSON.stringify(result,null,2);$("progress").style.width="100%";
  if(kind==="map"){$("metric-confidence").textContent="lab";$("metric-repro").textContent=result.context||"—";$("metric-dbms").textContent=result.dbms||"sqlite";$("metric-interference").textContent="—";$("metric-requests").textContent=String(result.requests_sent||0);$("summary").textContent=`Mapped ${Object.keys(result.tables||{}).length} table candidate(s) · context ${result.context||"unknown"} · ${result.requests_sent||0} requests`;$("findings").className="finding-list";$("findings").textContent="";for(const [name,table] of Object.entries(result.tables||{})){const card=document.createElement("article");card.className="mapping-card";const h=document.createElement("h3");h.textContent=name;const pre=document.createElement("pre");pre.textContent=JSON.stringify(table,null,2);card.append(h,pre);$("findings").appendChild(card);}return;}
  $("metric-confidence").textContent=`${result.confidence_score||0}/100`;$("metric-repro").textContent=`${result.reproducibility||0}%`;const topDbms=Object.entries(result.dbms_profile||{})[0];$("metric-dbms").textContent=topDbms?`${topDbms[0]} ${topDbms[1]}%`:"unknown";const topInterference=Object.entries(result.interference_profile||{})[0];$("metric-interference").textContent=topInterference?`${topInterference[0]} ${topInterference[1]}%`:"none";$("metric-requests").textContent=`${result.requests_sent||0}/${result.planned_requests||result.request_budget||"—"}`;$("summary").textContent=`${result.verdict} · ${result.context_profile?.primary||"unknown context"} · baseline ${result.baseline?.stability_score??0}% stable${result.adaptive_stopped?" · adaptive stop":""}`;
  const findings=result.findings||[];$("finding-count").textContent=String(findings.length);$("findings").textContent="";$("findings").className=findings.length?"finding-list":"finding-list empty";if(!findings.length)$("findings").textContent="No medium-or-higher confidence SQLi indicator confirmed.";
  for(const finding of findings){const btn=document.createElement("button");btn.type="button";btn.className=`finding ${finding.confidence==="confirmed"?"confirmed":finding.confidence==="high"?"high":""}`;const title=document.createElement("strong");title.textContent=finding.title;const meta=document.createElement("span");meta.textContent=`${finding.score}/100 · ${finding.confidence} · ${finding.category}${finding.dbms_hint?` · ${finding.dbms_hint}`:""}`;btn.append(title,meta);btn.addEventListener("click",()=>{selectedFinding=finding;selectedEvidence=null;selectResultTab("inspector");selectInspector("diff");});$("findings").appendChild(btn);}
  renderTimeline();
}

async function startJob(kind){
  try{resetResults();const payload=configPayload();if(!payload.url)throw new Error("URL is required");if(!payload.parameter)throw new Error("Injection parameter/path is required");payload.kind=kind;setUiState("queued");$("summary").textContent=`Starting ${kind}…`;const started=await postJSON("/api/jobs",payload);currentJob=started.job_id;lastJobId=currentJob;currentJobKind=kind;setUiState("running");openEventStream();}
  catch(error){showError(error);}
}
function openEventStream(){if(!currentJob)return;if(eventSource)eventSource.close();eventSource=new EventSource(eventUrl(currentJob));eventSource.onmessage=(message)=>{let event;try{event=JSON.parse(message.data);}catch(_){return;}if(event.event==="plan"){plannedRequests=Number(event.planned_requests||0)||null;updateProgress();}else if(event.event==="phase"){phaseStates.set(event.name,event.status);renderPhases();}else if(event.event==="request-complete"){requestCount=Math.max(requestCount,Number(event.index||0));if(event.planned)plannedRequests=Number(event.planned);updateProgress();}else if(event.event==="mapping-progress"){$("summary").textContent=`Mapping character ${event.position}/${event.length} · ${event.requests} requests`;}else if(event.event==="mapping-table"){$("summary").textContent=`Checking table ${event.index}/${event.total}: ${event.name}`;}else if(event.event==="adaptive-stop"){$("summary").textContent=`Adaptive early-stop: ${event.reason}`;}else if(event.event==="result"){renderResult(event.result,event.kind||currentJobKind);setUiState(event.status);renderTimeline();}else if(event.event==="error"){showError(new Error(event.error));}else if(event.event==="terminal"){if(eventSource)eventSource.close();setUiState(event.status);currentJob=null;}else if(event.event==="job"){setUiState(event.status);}};
  eventSource.onerror=async()=>{if(!currentJob)return;$("summary").textContent="Live stream interrupted; recovering job state…";try{const state=await getJSON(`/api/jobs/${currentJob}`);if(state.result)renderResult(state.result,state.kind);if(["complete","cancelled","error"].includes(state.status)){setUiState(state.status);currentJob=null;if(eventSource)eventSource.close();}}catch(error){$("summary").textContent=`Stream recovery failed: ${error.message}`;}};
}
async function jobAction(action){if(!currentJob)return;try{const body=await postJSON(`/api/jobs/${currentJob}/${action}`,{});setUiState(body.status);}catch(error){showError(error);}}

function renderPoints(points){const box=$("injection-points");box.textContent="";if(!points?.length){box.innerHTML='<p class="empty">No existing injection points discovered.</p>';return;}for(const point of points){const btn=document.createElement("button");btn.type="button";btn.className="point";const title=document.createElement("strong");title.textContent=`${point.location}:${point.parameter}`;const value=document.createElement("span");value.textContent=point.sensitive?"<redacted>":String(point.value||"").slice(0,80);btn.append(title,value);btn.addEventListener("click",()=>{$("location").value=point.location;$("parameter").value=point.parameter;if(!point.sensitive&&point.value!=="<redacted>")$("original-value").value=point.value||"1";});box.appendChild(btn);}}
async function discover(){try{const body=await postJSON("/api/discover",configPayload());renderPoints(body.injection_points);$("summary").textContent=`Discovered ${body.injection_points.length} request input point(s) without sending target traffic.`;}catch(error){showError(error);}}
async function parseImport(){try{const body=await postJSON("/api/parse",{kind:$("import-kind").value,scheme:$("import-scheme").value,text:$("import-text").value});applyRequest(body.request);renderPoints(body.injection_points||[]);$("summary").textContent=`Imported ${body.source} request and discovered ${(body.injection_points||[]).length} input point(s).`;}catch(error){showError(error);}}
function applyRequest(r){$("url").value=r.url||"";$("method").value=r.method||"GET";$("body-mode").value=r.body_mode||"auto";$("data").value=JSON.stringify(r.data??{},null,2);$("raw-body").value=r.raw_body||"";$("headers").value=JSON.stringify(r.headers||{},null,2);$("cookies").value=JSON.stringify(r.cookies||{},null,2);fillKvEditor("header-editor",r.headers||{});fillKvEditor("cookie-editor",r.cookies||{});$("proxy").value=r.proxy||"";$("verify-tls").checked=r.verify_tls!==false;$("ca-bundle").value=r.ca_bundle||"";$("client-cert").value=r.client_cert||"";$("client-key").value=r.client_key||"";$("redirect-policy").value=r.redirect_policy||(r.follow_redirects?"any":"never");$("max-redirects").value=r.max_redirects??5;$("cookie-mode").value=r.cookie_mode||"static";$("retry-policy").value=r.retry_policy||"safe";$("auth-user").value=r.auth_username||"";$("auth-pass").value=r.auth_password||"";$("bearer").value=r.bearer_token||"";}

async function refreshTemplates(){try{const body=await getJSON("/api/templates");const select=$("template-list");select.innerHTML='<option value="">No template selected</option>';for(const name of body.templates){const o=document.createElement("option");o.value=name;o.textContent=name;select.appendChild(o);}}catch(error){showError(error);}}
async function loadTemplate(){const name=$("template-list").value;if(!name)return;try{const body=await getJSON(`/api/templates/${encodeURIComponent(name)}`);applyRequest(body.request);await discover();}catch(error){showError(error);}}
async function saveTemplate(){const name=$("template-name").value.trim();if(!name)return showError(new Error("Template name is required"));try{await postJSON("/api/templates/save",{name,request:configPayload()});await refreshTemplates();$("template-list").value=name;$("summary").textContent=`Saved redacted template ${name}.`;}catch(error){showError(error);}}
async function deleteTemplateAction(){const name=$("template-list").value;if(!name)return;try{await postJSON("/api/templates/delete",{name});await refreshTemplates();$("summary").textContent=`Deleted template ${name}.`;}catch(error){showError(error);}}

async function downloadReport(format){if(!lastJobId||currentJobKind==="map"){showError(new Error("A completed scan job is required for report download"));return;}try{const h={};if(token())h["X-WebSQLMapper-Token"]=token();const response=await fetch(`/api/jobs/${lastJobId}/report?format=${encodeURIComponent(format)}`,{headers:h});if(!response.ok){const b=await response.json().catch(()=>({error:`HTTP ${response.status}`}));throw new Error(b.error||`HTTP ${response.status}`);}const blob=await response.blob();const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`websqlmapper-report.${format==="markdown"?"md":format}`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(error){showError(error);}}

function initTabs(){document.querySelectorAll(".config-tab").forEach((btn)=>btn.addEventListener("click",()=>{document.querySelectorAll(".config-tab").forEach((b)=>b.classList.toggle("active",b===btn));document.querySelectorAll(".tab-panel").forEach((p)=>p.classList.toggle("active",p.dataset.panel===btn.dataset.tab));}));document.querySelectorAll(".result-tab").forEach((btn)=>btn.addEventListener("click",()=>selectResultTab(btn.dataset.resultTab)));document.querySelectorAll(".inspector-tab").forEach((btn)=>btn.addEventListener("click",()=>selectInspector(btn.dataset.inspector)));}

$("scan-btn").addEventListener("click",()=>startJob("scan"));$("map-btn").addEventListener("click",()=>startJob("map"));$("mobile-run").addEventListener("click",()=>startJob("scan"));$("mobile-stop").addEventListener("click",()=>jobAction("cancel"));$("parse-btn").addEventListener("click",parseImport);$("discover-btn").addEventListener("click",discover);$("pause-btn").addEventListener("click",()=>jobAction("pause"));$("resume-btn").addEventListener("click",()=>jobAction("resume"));$("stop-btn").addEventListener("click",()=>jobAction("cancel"));
$("add-header").addEventListener("click",()=>addKvRow("header-editor"));$("add-cookie").addEventListener("click",()=>addKvRow("cookie-editor"));$("headers").addEventListener("change",syncEditorsFromAdvanced);$("cookies").addEventListener("change",syncEditorsFromAdvanced);
$("refresh-templates").addEventListener("click",refreshTemplates);$("load-template").addEventListener("click",loadTemplate);$("save-template").addEventListener("click",saveTemplate);$("delete-template").addEventListener("click",deleteTemplateAction);
for(const id of ["timeline-phase","timeline-status","timeline-search"])$(id).addEventListener(id==="timeline-search"?"input":"change",renderTimeline);
$("copy-btn").addEventListener("click",async()=>{try{await navigator.clipboard.writeText(JSON.stringify(lastResult||{},null,2));$("copy-btn").textContent="Copied";setTimeout(()=>$("copy-btn").textContent="Copy JSON",1200);}catch(_){$("copy-btn").textContent="Copy unavailable";}});document.querySelectorAll(".report-btn").forEach((b)=>b.addEventListener("click",()=>downloadReport(b.dataset.format)));
function safeStorageGet(key){try{return window.sessionStorage?sessionStorage.getItem(key):null;}catch(_){return null;}}
function safeStorageSet(key,value){try{if(!window.sessionStorage)return;if(value)sessionStorage.setItem(key,value);else sessionStorage.removeItem(key);}catch(_){} }
$("web-token").value=safeStorageGet("websqlmapper-token")||"";$("web-token").addEventListener("change",()=>{safeStorageSet("websqlmapper-token",token());refreshTemplates();});
initTabs();fillKvEditor("header-editor",{});fillKvEditor("cookie-editor",{});setUiState("idle");refreshTemplates();
if("serviceWorker" in navigator) navigator.serviceWorker.register("/service-worker.js").catch(()=>{});
