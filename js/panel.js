// DevTools Panel Controller - TT Monitor

const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

const TAB_ID = chrome.devtools.inspectedWindow.tabId;
let violations = [];
let clusters = [];
let currentDetail = null;
let currentSort = { field: "timestamp", ascending: false };
let searchTerm = "";
let aiKey = "", aiProv = "auto";
let aiHistory = [];

// ── Resilient port to background (auto-reconnect on SW termination) ──

let port = null;
let pollTimer = null;
let lastKnownUrl = "";

function connectPort() {
  try {
    port = chrome.runtime.connect({ name: "tt-panel" });
  } catch {
    scheduleReconnect();
    return;
  }

  port.postMessage({ action: "setTabId", tabId: TAB_ID });

  port.onMessage.addListener(msg => {
    if (msg.action === "navigationReset") {
      resetPanelState();
      return;
    }

    if (msg.action === "newViolation") {
      if (msg.violation.tabId !== TAB_ID) return;

      violations.push(msg.violation);
      renderLiveTable();
      updateStats();
      chrome.runtime.sendMessage({ action: "getClusters", tabId: TAB_ID }, r => {
        if (!r) return;
        clusters = r.clusters || [];
        if ($("#pt-clusters").classList.contains("active")) renderClusters();
      });
    }
  });

  port.onDisconnect.addListener(() => {
    port = null;
    scheduleReconnect();
  });

  stopPolling();
}

function scheduleReconnect() {
  setTimeout(() => {
    connectPort();
    checkForPageChange();
  }, 1000);
  startPolling();
}

function checkForPageChange() {
  chrome.devtools.inspectedWindow.eval("location.href", (url) => {
    if (!url) return;
    const changed = hasUrlChanged(lastKnownUrl, url);
    lastKnownUrl = url;

    if (changed && violations.length > 0) {
      resetPanelState();
    }

    // Always reload current state from storage
    chrome.runtime.sendMessage({ action: "getFullState", tabId: TAB_ID }, r => {
      if (!r) return;
      violations = r.violations || [];
      clusters = r.clusters || [];
      renderLiveTable();
      renderClusters();
      updateStats();
    });
  });
}

function hasUrlChanged(oldUrl, newUrl) {
  if (!oldUrl) return false;
  try {
    const prev = new URL(oldUrl);
    const next = new URL(newUrl);
    return prev.origin !== next.origin || prev.pathname !== next.pathname;
  } catch { return true; }
}

function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(checkForPageChange, 3000);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

connectPort();

// Catch up immediately when the panel regains focus
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    if (!port) connectPort();
    checkForPageChange();
  }
});

function resetPanelState() {
  violations = [];
  clusters = [];
  currentDetail = null;
  aiHistory = [];
  searchTerm = "";

  const searchBox = $("#search-input");
  if (searchBox) searchBox.value = "";

  renderLiveTable();
  renderClusters();
  updateStats();

  closeSidebar();

  // Reset fix guide back to intro
  $("#fix-intro")?.classList.remove("hidden");
  $("#fix-detail")?.classList.add("hidden");

  // Reset policy output
  $("#policy-output").textContent = '// Click "Generate" to create a policy from observed violations';
  $("#policy-warnings").innerHTML = "";
  $("#btn-gen-policy").textContent = "Generate";

  // Clear AI chat messages
  const msgs = $("#ai-messages");
  if (msgs) msgs.innerHTML = "";
}

// ── Init ──

document.addEventListener("DOMContentLoaded", () => {
  bindTabs();
  bindHeader();
  bindLive();
  bindFix();
  bindPolicy();
  bindAI();
  bindSidebar();
  loadState();
});

function loadState() {
  // Seed the URL tracker so we can detect page changes after SW restart
  chrome.devtools.inspectedWindow.eval("location.href", (url) => {
    if (url) lastKnownUrl = url;
  });

  chrome.runtime.sendMessage({ action: "getFullState", tabId: TAB_ID }, r => {
    if (!r) return;
    violations = r.violations || [];
    clusters = r.clusters || [];
    aiKey = (r.apiKeys || {}).key || "";
    aiProv = (r.apiKeys || {}).provider || "auto";
    const enabled = r.enabled !== false;
    $("#monitoring-toggle").checked = enabled;
    if (aiKey) { $("#ai-key").value = aiKey; $("#ai-provider").value = aiProv; showAIChat(); }
    renderLiveTable();
    renderClusters();
    updateStats();
  });
}

// ── Tabs ──

function bindTabs() {
  $$(".ptab").forEach(t => t.addEventListener("click", () => {
    $$(".ptab").forEach(b => b.classList.remove("active"));
    $$(".ptab-content").forEach(c => c.classList.remove("active"));
    t.classList.add("active");
    $(`#pt-${t.dataset.tab}`).classList.add("active");

    if (t.dataset.tab === "clusters") {
      chrome.runtime.sendMessage({ action: "getClusters", tabId: TAB_ID }, r => {
        if (!r) return;
        clusters = r.clusters || [];
        renderClusters();
        updateStats();
      });
    }
  }));
}

// ── Header ──

function bindHeader() {
  $("#monitoring-toggle").addEventListener("change", e => {
    chrome.runtime.sendMessage({ action: "setEnabled", enabled: e.target.checked });
  });
  $("#search-input").addEventListener("input", e => {
    searchTerm = e.target.value.toLowerCase();
    renderLiveTable();
  });
  $("#btn-export").addEventListener("click", exportData);
  $("#btn-clear").addEventListener("click", () => {
    if (!confirm("Clear violations for this tab?")) return;
    chrome.runtime.sendMessage({ action: "clearViolations", tabId: TAB_ID }, () => {
      resetPanelState();
    });
  });
}

function updateStats() {
  const f = filtered();
  $("#s-total").textContent = f.length;
  $("#s-html").textContent = f.filter(v => v.violationType === "TrustedHTML").length;
  $("#s-script").textContent = f.filter(v => v.violationType === "TrustedScript").length;
  $("#s-url").textContent = f.filter(v => v.violationType === "TrustedScriptURL").length;
  $("#s-clusters").textContent = clusters.length;
}

function filtered() {
  if (!searchTerm) return violations;
  return violations.filter(v =>
    (v.url || "").toLowerCase().includes(searchTerm) ||
    (v.sample || "").toLowerCase().includes(searchTerm) ||
    (v.sourceFile || "").toLowerCase().includes(searchTerm) ||
    (v.violationType || "").toLowerCase().includes(searchTerm) ||
    (v.directive || "").toLowerCase().includes(searchTerm)
  );
}

// ── Live Stream ──

function bindLive() {
  $$("th.sortable").forEach(th => th.addEventListener("click", () => {
    const f = th.dataset.sort;
    if (currentSort.field === f) currentSort.ascending = !currentSort.ascending;
    else { currentSort.field = f; currentSort.ascending = f !== "timestamp"; }
    renderLiveTable();
  }));
}

function renderLiveTable() {
  const tbody = $("#live-body");
  tbody.innerHTML = "";
  const list = filtered();
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="t-empty">No violations on this tab. Browse pages to capture Trusted Types issues.</td></tr>';
    return;
  }
  const sorted = [...list].sort((a, b) => {
    const fa = a[currentSort.field], fb = b[currentSort.field];
    let c = fa < fb ? -1 : fa > fb ? 1 : 0;
    return currentSort.ascending ? c : -c;
  });
  sorted.forEach((v, i) => renderLiveRow(v, i, tbody));
}

function renderLiveRow(v, idx, tbody) {
  const tr = document.createElement("tr");
  const time = new Date(v.timestamp).toLocaleTimeString();
  const bc = badgeClass(v.violationType);
  const src = v.sourceFile && v.sourceFile !== "unknown"
    ? (v.sourceFile || "").split("/").pop() + ":" + v.lineNumber
    : "";
  const sample = esc((v.sample || "").substring(0, 80));

  tr.innerHTML = `
    <td class="t-time">${esc(time)}</td>
    <td><span class="badge ${bc}">${esc(v.violationType || "?")}</span></td>
    <td class="t-sample" title="${esc(v.sample || "")}">${sample}</td>
    <td class="t-source" title="${esc(v.sourceFile || "")}">${esc(src)}</td>
    <td class="t-acts"><button class="row-btn" data-act="detail">Info</button> <button class="row-btn fix" data-act="fix">Fix</button></td>`;

  tr.querySelector('[data-act="detail"]').addEventListener("click", () => showSidebar(v));
  tr.querySelector('[data-act="fix"]').addEventListener("click", () => showFixFor(v));
  tbody.appendChild(tr);
}

function badgeClass(t) {
  switch (t) { case "TrustedHTML": return "b-html"; case "TrustedScript": return "b-script"; case "TrustedScriptURL": return "b-url"; default: return "b-unknown"; }
}

// ── Sidebar ──

function bindSidebar() {
  $("#sidebar-close").addEventListener("click", closeSidebar);
  $("#sidebar-fix").addEventListener("click", () => { if (currentDetail) { closeSidebar(); showFixFor(currentDetail); } });
  $("#sidebar-ai").addEventListener("click", () => { if (currentDetail) { closeSidebar(); askAIAbout(currentDetail); } });
}

function showSidebar(v) {
  currentDetail = v;
  const body = $("#sidebar-body");

  const hasLine = v.lineNumber && v.lineNumber !== "unknown";
  const hasCol = v.columnNumber && v.columnNumber !== "unknown";
  const lineStr = hasLine ? (hasCol ? `${v.lineNumber}:${v.columnNumber}` : String(v.lineNumber)) : null;

  const fields = [
    ["Type", `<span class="badge ${badgeClass(v.violationType)}">${esc(v.violationType)}</span>`],
    ["Directive", esc(v.directive)],
    ["URL", v.url && v.url.startsWith("http") ? `<a href="${esc(v.url)}" target="_blank">${esc(v.url)}</a>` : esc(v.url)],
    ["Source", v.sourceFile && v.sourceFile !== "unknown" ? esc(v.sourceFile) : null],
    ["Line", lineStr],
    ["Blocked", v.blockedUri && v.blockedUri !== "unknown" ? esc(v.blockedUri) : null],
    ["Time", new Date(v.timestamp).toLocaleString()],
    ["Sample", v.sample && v.sample !== "unknown" ? `<pre class="code-pre">${esc(v.sample)}</pre>` : null],
    ["Stack", v.stackTrace ? `<pre class="code-pre">${esc(v.stackTrace)}</pre>` : null]
  ].filter(f => f[1]);

  body.innerHTML = fields.map(([l, val]) =>
    `<div class="sd-row"><span class="sd-label">${l}</span><span class="sd-value">${val}</span></div>`
  ).join("");

  body.querySelectorAll("a").forEach(a => a.addEventListener("click", e => { e.preventDefault(); chrome.tabs.create({ url: a.href }); }));
  $("#detail-sidebar").classList.remove("hidden");
}

function closeSidebar() { $("#detail-sidebar").classList.add("hidden"); }

// ── Clusters ──

function renderClusters() {
  const c = $("#clusters-container");
  if (clusters.length === 0) { c.innerHTML = '<div class="t-empty">No clusters yet.</div>'; return; }
  c.innerHTML = clusters.map((cl, i) => {
    const bc = badgeClass(cl.violationType);
    return `<div class="cl-card">
      <div class="cl-top"><span class="badge ${bc}">${esc(cl.violationType)}</span><span class="cl-count">${cl.count}x</span></div>
      <div class="cl-root">${esc(cl.rootCause.length > 100 ? cl.rootCause.substring(0,97)+"..." : cl.rootCause)}</div>
      <div class="cl-sample">${esc(cl.samplePreview)}</div>
      <div class="cl-meta"><span>First: ${new Date(cl.firstSeen).toLocaleTimeString()}</span></div>
      <div class="cl-btns"><button class="row-btn fix" data-ci="${i}">Get Fix</button></div>
    </div>`;
  }).join("");
  c.querySelectorAll("[data-ci]").forEach(b => b.addEventListener("click", () => {
    showFixFor(clusters[+b.dataset.ci].violations[0]);
  }));
}

// ── Fix Guide ──

function bindFix() {
  $$(".fcard").forEach(c => c.addEventListener("click", () => {
    showFixFor({ violationType: c.dataset.type, sample: "", directive: "require-trusted-types-for 'script'" });
  }));
  $("#fix-back").addEventListener("click", () => { $("#fix-intro").classList.remove("hidden"); $("#fix-detail").classList.add("hidden"); });
}

function showFixFor(v) {
  $$(".ptab").forEach(b => b.classList.remove("active"));
  $$(".ptab-content").forEach(c => c.classList.remove("active"));
  $('[data-tab="fix"]').classList.add("active");
  $("#pt-fix").classList.add("active");

  chrome.runtime.sendMessage({ action: "getFixGuidance", violation: v }, r => {
    if (!r) return;
    const g = r.guidance;
    $("#fix-intro").classList.add("hidden");
    $("#fix-detail").classList.remove("hidden");
    const sc = g.severity === "critical" ? "sev-critical" : g.severity === "high" ? "sev-high" : "sev-medium";
    let h = `<div class="fix-hdr"><h2>${esc(g.title)}</h2><span class="sev-badge ${sc}">${esc(g.severity)}</span></div>`;
    h += `<div class="fix-meta"><strong>Sink:</strong> ${esc(g.sinkType)}<br><strong>Risk:</strong> ${esc(g.dangerLevel)}</div>`;
    if (v.sample && v.sample !== "unknown") h += `<div class="fix-sec"><h3>Sample</h3><pre class="code-pre">${esc(v.sample)}</pre></div>`;
    h += `<div class="fix-sec"><h3>Explanation</h3><p>${esc(g.explanation)}</p></div>`;
    h += `<div class="fix-sec"><h3>Fix Steps</h3><ol>${g.fixSteps.map(s => `<li>${esc(s)}</li>`).join("")}</ol></div>`;
    h += `<div class="fix-sec"><h3>Code Example</h3><div class="code-wrap"><button class="copy-code" id="cc-fix">Copy</button><pre class="code-pre" id="fix-code-block">${esc(g.codeExample)}</pre></div></div>`;
    h += `<div class="fix-sec"><h3>References</h3><ul class="ref-list">${g.references.map(r => `<li><a href="${esc(r.url)}" target="_blank">${esc(r.title)}</a></li>`).join("")}</ul></div>`;
    if (aiKey) h += `<button class="hdr-btn primary" id="fix-ask-ai" style="margin-top:6px">Ask AI for Deeper Analysis</button>`;
    $("#fix-detail-body").innerHTML = h;
    $("#cc-fix")?.addEventListener("click", () => { navigator.clipboard.writeText($("#fix-code-block").textContent); $("#cc-fix").textContent = "Copied!"; setTimeout(() => $("#cc-fix").textContent = "Copy", 1200); });
    $$("#fix-detail-body a").forEach(a => a.addEventListener("click", e => { e.preventDefault(); chrome.tabs.create({ url: a.href }); }));
    $("#fix-ask-ai")?.addEventListener("click", () => askAIAbout(v));
  });
}

// ── Policy Gen ──

let policyMode = "standard";

function bindPolicy() {
  $$(".mode-btn").forEach(btn => btn.addEventListener("click", () => {
    $$(".mode-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    policyMode = btn.dataset.mode;
    updatePolicyModeUI();
  }));

  $("#btn-gen-policy").addEventListener("click", () => {
    $("#btn-gen-policy").textContent = "Generating...";
    chrome.runtime.sendMessage({ action: "generatePolicy", tabId: TAB_ID, mode: policyMode }, r => {
      if (!r) return;
      $("#policy-output").textContent = r.policy;
      renderPolicyWarnings();
      $("#btn-gen-policy").textContent = "Regenerate";
    });
  });
  $("#btn-copy-policy").addEventListener("click", () => {
    navigator.clipboard.writeText($("#policy-output").textContent);
    $("#btn-copy-policy").textContent = "Copied!";
    setTimeout(() => $("#btn-copy-policy").textContent = "Copy", 1200);
  });
}

function updatePolicyModeUI() {
  const title = $("#policy-title");
  const desc = $("#policy-mode-desc");
  if (policyMode === "perfect-types") {
    title.textContent = "Perfect Types Policy";
    desc.innerHTML = 'Zero-policy approach: replaces <code>innerHTML</code> with <code>setHTML()</code> (Sanitizer API). ' +
      'Blocks all legacy HTML sinks via <code>trusted-types \'none\'</code>. ' +
      '<a href="#" id="pt-ref-link">Learn more</a>';
    $("#pt-ref-link")?.addEventListener("click", e => {
      e.preventDefault();
      chrome.tabs.create({ url: "https://frederikbraun.de/perfect-types-with-sethtml.html" });
    });
  } else {
    title.textContent = "Generated Default Policy";
    desc.innerHTML = 'Generates a <code>default</code> Trusted Types policy with allowlists derived from observed violations.';
  }
  $("#policy-output").textContent = '// Click "Generate" to create a policy from observed violations';
  $("#policy-warnings").innerHTML = "";
  $("#btn-gen-policy").textContent = "Generate";
}

function renderPolicyWarnings() {
  const w = [];
  const types = new Set(violations.map(v => v.violationType));

  if (policyMode === "perfect-types") {
    if (types.has("TrustedHTML")) {
      const htmlCount = violations.filter(v => v.violationType === "TrustedHTML").length;
      w.push({ l: "sethtml", t: `${htmlCount} HTML sink(s) to migrate to setHTML(). These will be fully resolved by the Sanitizer API.` });
    }
    if (types.has("TrustedScript")) {
      w.push({ l: "crit", t: "Script sinks (eval/setTimeout) detected — these require code refactoring. setHTML() does not cover script evaluation." });
    }
    if (types.has("TrustedScriptURL")) {
      w.push({ l: "crit", t: "Script URL sinks detected — dynamic script loading must be replaced with static imports or a hybrid CSP approach." });
    }
    if (!types.has("TrustedScript") && !types.has("TrustedScriptURL") && types.has("TrustedHTML")) {
      w.push({ l: "ok", t: "All violations are HTML sinks — Perfect Types with setHTML() can fully replace Trusted Types policies here." });
    }
    w.push({ l: "info", t: "setHTML() requires Chrome 124+, Firefox 130+, Safari 18.2+. Use DOMPurify as fallback for older browsers." });
  } else {
    if (types.has("TrustedScript")) w.push({ l: "crit", t: "Includes eval-like patterns. Strongly consider refactoring." });
    if (violations.some(v => (v.sample||"").includes("<script"))) w.push({ l: "crit", t: "Contains <script> in HTML. Use DOMPurify.sanitize()." });
    if (types.has("TrustedHTML")) {
      w.push({ l: "sethtml", t: "HTML sinks detected — consider using setHTML() (Sanitizer API) to eliminate innerHTML entirely. Try Perfect Types mode." });
    }
    w.push({ l: "info", t: "Review and tighten before production. Consider named policies." });
  }

  $("#policy-warnings").innerHTML = w.map(x => {
    const icon = x.l === "crit" ? "&#9888;" : x.l === "ok" ? "&#10003;" : x.l === "sethtml" ? "&#9889;" : "&#9432;";
    return `<div class="warn-item warn-${x.l}"><span>${icon}</span><span>${esc(x.t)}</span></div>`;
  }).join("");
}

// ── AI Assistant (multi-turn) ──

function bindAI() {
  $("#ai-save").addEventListener("click", saveAIKey);
  $("#ai-settings").addEventListener("click", () => { $("#ai-setup-panel").classList.remove("hidden"); $("#ai-chat-panel").classList.add("hidden"); });
  $("#ai-eye").addEventListener("click", () => { const i = $("#ai-key"); i.type = i.type === "password" ? "text" : "password"; });
  $("#ai-send").addEventListener("click", sendAI);
  $("#ai-input").addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendAI(); } });
  $$(".qbtn").forEach(b => b.addEventListener("click", () => { $("#ai-input").value = b.dataset.q; sendAI(); }));
}

function saveAIKey() {
  const k = $("#ai-key").value.trim(), p = $("#ai-provider").value;
  if (!k) { showAISt("Enter an API key.", "err"); return; }
  aiKey = k; aiProv = p;
  chrome.runtime.sendMessage({ action: "saveApiKeys", apiKeys: { key: k, provider: p } }, () => {
    showAISt("Saved!", "ok");
    setTimeout(showAIChat, 600);
  });
}

function showAIChat() {
  $("#ai-setup-panel").classList.add("hidden");
  $("#ai-chat-panel").classList.remove("hidden");
  const det = aiProv !== "auto" ? aiProv : (window.AIAssistant?.detectProvider(aiKey) || "AI");
  $("#ai-connected-label").textContent = `Connected: ${{ claude: "Claude", gemini: "Gemini", gpt: "GPT" }[det] || det}`;
}

function showAISt(msg, type) {
  const el = $("#ai-status");
  el.textContent = msg;
  el.className = `st-${type}`;
  el.classList.remove("hidden");
}

let aiSending = false;
async function sendAI() {
  const q = $("#ai-input").value.trim();
  if (!q || !aiKey || aiSending) return;
  aiSending = true;
  $("#ai-input").value = "";
  appendMsg("user", q);
  aiHistory.push({ role: "user", content: q });
  const tid = appendMsg("bot", "", true);

  try {
    const prov = aiProv !== "auto" ? aiProv : undefined;
    const resp = await window.AIAssistant.queryAIMultiTurn(aiKey, prov, violations, aiHistory);
    removeMsg(tid);
    appendMsg("bot", resp);
    aiHistory.push({ role: "assistant", content: resp });
    if (aiHistory.length > 20) aiHistory = aiHistory.slice(-16);
  } catch (err) {
    removeMsg(tid);
    appendMsg("bot", `Error: ${err.message}`, false, true);
  } finally {
    aiSending = false;
  }
}

function askAIAbout(v) {
  $$(".ptab").forEach(b => b.classList.remove("active"));
  $$(".ptab-content").forEach(c => c.classList.remove("active"));
  $('[data-tab="ai"]').classList.add("active");
  $("#pt-ai").classList.add("active");
  if (!aiKey) { showAISt("Configure API key first.", "info"); return; }
  showAIChat();
  const q = `Analyze this violation:\nType: ${v.violationType}\nSource: ${v.sourceFile}:${v.lineNumber}\nSample: ${v.sample}\nStack: ${v.stackTrace || "N/A"}`;
  $("#ai-input").value = q;
  sendAI();
}

let msgId = 0;
function appendMsg(role, text, thinking, isErr) {
  const id = `m${++msgId}`;
  const el = document.createElement("div");
  el.className = `ai-msg ${role}${isErr ? " err" : ""}`;
  el.id = id;
  el.innerHTML = thinking ? '<div class="dots"><span></span><span></span><span></span></div>' : fmtAI(text);
  $("#ai-messages").appendChild(el);
  $("#ai-messages").scrollTop = $("#ai-messages").scrollHeight;
  return id;
}
function removeMsg(id) { document.getElementById(id)?.remove(); }

function fmtAI(text) {
  // Extract code blocks BEFORE escaping so their contents stay raw
  const codeBlocks = [];
  let safe = text.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const idx = codeBlocks.length;
    codeBlocks.push(`<pre><code>${esc(code)}</code></pre>`);
    return `%%CODEBLOCK_${idx}%%`;
  });

  // Now escape the non-code text
  safe = esc(safe);

  // Inline formatting
  safe = safe.replace(/`([^`]+)`/g, "<code>$1</code>");
  safe = safe.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  safe = safe.replace(/^### (.+)$/gm, "<h4>$1</h4>");
  safe = safe.replace(/^## (.+)$/gm, "<h3>$1</h3>");
  safe = safe.replace(/^- (.+)$/gm, "<li>$1</li>");
  safe = safe.replace(/^(\d+)\. (.+)$/gm, "<li>$2</li>");
  safe = safe.replace(/\n\n/g, "</p><p>");

  // Restore code blocks
  safe = safe.replace(/%%CODEBLOCK_(\d+)%%/g, (_, i) => codeBlocks[+i]);

  return `<p>${safe}</p>`;
}

// ── Export ──

function exportData() {
  if (violations.length === 0) return;
  const data = { exported: new Date().toISOString(), tabId: TAB_ID, violations, clusters: clusters.map(c => ({ ...c, violations: undefined })) };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `tt-violations-${new Date().toISOString().split("T")[0]}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 100);
}
