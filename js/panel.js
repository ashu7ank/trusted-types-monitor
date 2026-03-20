// DevTools Panel Controller - TT Monitor

const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

const TAB_ID = chrome.devtools.inspectedWindow.tabId;
const MAX_PANEL_VIOLATIONS = 1000;
const MAX_RENDERED_ROWS = 200;
let violations = [];
let clusters = [];
let currentDetail = null;
let originAnalysis = null;
let frameworksDetected = [];
let frameworkGuidance = {};
let scatterAnalysis = null;
let namedPoliciesResult = null;
let cspResult = null;
let firstPartyAliases = [];
let currentSort = { field: "timestamp", ascending: false };
let searchTerm = "";
let aiKey = "", aiProv = "auto";
let aiHistory = [];
let insightsDebounce = null;
let clearPending = false;

// ── Extension context guards ──

function contextAlive() { return !!chrome.runtime?.id; }

function safeSend(msg, cb) {
  if (!contextAlive()) { stopPolling(); return; }
  try {
    chrome.runtime.sendMessage(msg, (response) => {
      if (chrome.runtime.lastError) {
        console.warn("safeSend:", chrome.runtime.lastError.message);
        if (cb) cb(undefined);
        return;
      }
      if (cb) cb(response);
    });
  } catch (e) {
    console.warn("safeSend:", e.message);
    if (cb) cb(undefined);
  }
}

// ── Resilient port to background (auto-reconnect on SW termination) ──

let port = null;
let pollTimer = null;
let lastKnownUrl = "";

function connectPort() {
  if (!contextAlive()) { stopPolling(); return; }
  try {
    port = chrome.runtime.connect({ name: "tt-panel" });
  } catch {
    scheduleReconnect();
    return;
  }

  port.postMessage({ action: "setTabId", tabId: TAB_ID });

  port.onMessage.addListener(msg => {
    if (!contextAlive()) return;

    if (msg.action === "navigationReset") {
      resetPanelState();
      return;
    }

    if (msg.action === "newViolation") {
      if (msg.violation.tabId !== TAB_ID) return;
      if (clearPending) return;

      violations.push(msg.violation);
      if (violations.length > MAX_PANEL_VIOLATIONS) {
        violations = violations.slice(-MAX_PANEL_VIOLATIONS);
      }
      renderLiveTable();
      updateStats();
      safeSend({ action: "getClusters", tabId: TAB_ID }, r => {
        if (!r) return;
        clusters = r.clusters || [];
        if ($("#pt-clusters").classList.contains("active")) renderClusters();
      });
      if ($("#pt-insights").classList.contains("active")) {
        scheduleInsightsRefresh();
      }
    }
  });

  port.onDisconnect.addListener(() => {
    port = null;
    if (contextAlive()) scheduleReconnect();
  });

  stopPolling();
}

function scheduleReconnect() {
  if (!contextAlive()) { stopPolling(); return; }
  setTimeout(() => {
    connectPort();
    checkForPageChange();
  }, 1000);
  startPolling();
}

function checkForPageChange() {
  if (!contextAlive()) { stopPolling(); return; }
  chrome.devtools.inspectedWindow.eval("location.href", (url) => {
    if (!contextAlive()) { stopPolling(); return; }
    if (!url) return;
    const changed = hasUrlChanged(lastKnownUrl, url);
    lastKnownUrl = url;

    if (changed && violations.length > 0) {
      resetPanelState();
    }

    safeSend({ action: "getFullState", tabId: TAB_ID }, r => {
      if (!r) return;
      violations = r.violations || [];
      clusters = r.clusters || [];
      renderLiveTable();
      renderClusters();
      updateStats();
      if ($("#pt-insights").classList.contains("active")) loadInsights();
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
  if (!contextAlive()) { stopPolling(); return; }
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
  originAnalysis = null;
  frameworksDetected = [];
  frameworkGuidance = {};
  scatterAnalysis = null;
  namedPoliciesResult = null;
  cspResult = null;
  cancelInsightsRefresh();
  // firstPartyAliases intentionally NOT reset — they are user config, not per-page state

  const searchBox = $("#search-input");
  if (searchBox) searchBox.value = "";

  renderLiveTable();
  renderClusters();
  updateStats();

  if ($("#pt-insights").classList.contains("active")) {
    renderOriginAnalysis();
    renderSinkMap([]);
    renderFrameworkInfo([], {});
    renderScatterAnalysis(null);
    renderNamedPolicies(null);
    renderCspHeader(null);
  }

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
  bindAliases();
  loadState();
});

function loadState() {
  if (!contextAlive()) return;
  chrome.devtools.inspectedWindow.eval("location.href", (url) => {
    if (url) lastKnownUrl = url;
  });

  safeSend({ action: "getFullState", tabId: TAB_ID }, r => {
    if (!r) return;
    violations = r.violations || [];
    clusters = r.clusters || [];
    originAnalysis = r.originAnalysis || null;
    frameworksDetected = r.frameworks || [];
    scatterAnalysis = r.scatter || null;
    firstPartyAliases = r.firstPartyAliases || [];
    aiKey = (r.apiKeys || {}).key || "";
    aiProv = (r.apiKeys || {}).provider || "auto";
    const enabled = r.enabled !== false;
    $("#monitoring-toggle").checked = enabled;
    if (aiKey) { $("#ai-key").value = aiKey; $("#ai-provider").value = aiProv; showAIChat(); }
    renderLiveTable();
    renderClusters();
    updateStats();
    renderAliasTags();
    if ($("#pt-insights").classList.contains("active")) loadInsights();
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
      safeSend({ action: "getClusters", tabId: TAB_ID }, r => {
        if (!r) return;
        clusters = r.clusters || [];
        renderClusters();
        updateStats();
      });
    }

    if (t.dataset.tab === "insights") {
      loadInsights();
    }
  }));
}

// ── Header ──

function bindHeader() {
  $("#monitoring-toggle").addEventListener("change", e => {
    safeSend({ action: "setEnabled", enabled: e.target.checked });
  });
  $("#search-input").addEventListener("input", e => {
    searchTerm = e.target.value.toLowerCase();
    renderLiveTable();
  });
  $("#btn-export").addEventListener("click", exportData);
  $("#btn-clear").addEventListener("click", () => {
    if (!confirm("Clear violations for this tab?")) return;
    clearPending = true;
    safeSend({ action: "clearViolations", tabId: TAB_ID }, () => {
      resetPanelState();
      clearPending = false;
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
    tbody.innerHTML = '<tr><td colspan="7" class="t-empty">No violations on this tab. Browse pages to capture Trusted Types issues.</td></tr>';
    return;
  }
  const sorted = [...list].sort((a, b) => {
    const fa = a[currentSort.field], fb = b[currentSort.field];
    let c = fa < fb ? -1 : fa > fb ? 1 : 0;
    return currentSort.ascending ? c : -c;
  });
  const display = sorted.slice(0, MAX_RENDERED_ROWS);
  display.forEach((v, i) => renderLiveRow(v, i, tbody));
  if (sorted.length > MAX_RENDERED_ROWS) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="7" class="t-empty">Showing ${MAX_RENDERED_ROWS} of ${sorted.length} violations. Use search to narrow results.</td>`;
    tbody.appendChild(tr);
  }
}

function renderLiveRow(v, idx, tbody) {
  const tr = document.createElement("tr");
  const time = new Date(v.timestamp).toLocaleTimeString();
  const bc = badgeClass(v.violationType);
  const src = v.sourceFile && v.sourceFile !== "unknown"
    ? (v.sourceFile || "").split("/").pop() + ":" + v.lineNumber
    : "";
  const sample = esc((v.sample || "").substring(0, 80));
  const sinkName = esc(v.sinkName || "—");
  const partyBadge = v.party === "third-party"
    ? '<span class="badge b-3p">3rd party</span>'
    : v.party === "first-party"
    ? '<span class="badge b-1p">1st party</span>'
    : '<span class="badge b-unknown">—</span>';

  tr.innerHTML = `
    <td class="t-time">${esc(time)}</td>
    <td><span class="badge ${bc}">${esc(v.violationType || "?")}</span></td>
    <td class="t-sink" title="${sinkName}">${sinkName}</td>
    <td class="t-sample" title="${esc(v.sample || "")}">${sample}</td>
    <td class="t-source" title="${esc(v.sourceFile || "")}">${esc(src)}</td>
    <td class="t-party">${partyBadge}</td>
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

  const partyLabel = v.party === "third-party"
    ? '<span class="badge b-3p">Third-party</span>'
    : v.party === "first-party"
    ? '<span class="badge b-1p">First-party</span>'
    : null;

  const sinkLabel = v.sinkName && v.sinkName !== "Unknown sink"
    ? `<code>${esc(v.sinkName)}</code>`
    : null;

  const fields = [
    ["Type", `<span class="badge ${badgeClass(v.violationType)}">${esc(v.violationType)}</span>`],
    ["Sink", sinkLabel],
    ["Origin", partyLabel],
    ["Directive", esc(v.directive)],
    ["URL", v.url && v.url.startsWith("http") ? `<a href="${esc(v.url)}" target="_blank">${esc(v.url)}</a>` : esc(v.url)],
    ["Source", v.sourceFile && v.sourceFile !== "unknown" ? esc(v.sourceFile) : null],
    ["Line", lineStr],
    ["Blocked", v.blockedUri && v.blockedUri !== "unknown" ? esc(v.blockedUri) : null],
    ["Src Origin", v.sourceOrigin && v.sourceOrigin !== "" ? esc(v.sourceOrigin) : null],
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

  safeSend({ action: "getFixGuidance", violation: v, violations }, r => {
    if (!r) return;
    const g = r.guidance;
    $("#fix-intro").classList.add("hidden");
    $("#fix-detail").classList.remove("hidden");
    const sc = g.severity === "critical" ? "sev-critical" : g.severity === "high" ? "sev-high" : "sev-medium";
    let h = `<div class="fix-hdr"><h2>${esc(g.title)}</h2><span class="sev-badge ${sc}">${esc(g.severity)}</span></div>`;
    h += `<div class="fix-meta"><strong>Sink:</strong> ${esc(g.sinkType)}<br><strong>Risk:</strong> ${esc(g.dangerLevel)}`;
    if (g.sinkMapping && g.sinkMapping.sinkName !== "Unknown sink") {
      h += `<br><strong>DOM Sink:</strong> <code>${esc(g.sinkMapping.sinkName)}</code>`;
    }
    if (g.sinkMapping && g.sinkMapping.sourceLocation) {
      h += `<br><strong>Location:</strong> <code>${esc(g.sinkMapping.sourceLocation)}</code>`;
    }
    h += `</div>`;
    if (v.sample && v.sample !== "unknown") h += `<div class="fix-sec"><h3>Sample</h3><pre class="code-pre">${esc(v.sample)}</pre></div>`;
    h += `<div class="fix-sec"><h3>Explanation</h3><p>${esc(g.explanation)}</p></div>`;
    h += `<div class="fix-sec"><h3>Fix Steps</h3><ol>${g.fixSteps.map(s => `<li>${esc(s)}</li>`).join("")}</ol></div>`;
    h += `<div class="fix-sec"><h3>Code Example</h3><div class="code-wrap"><button class="copy-code" id="cc-fix">Copy</button><pre class="code-pre" id="fix-code-block">${esc(g.codeExample)}</pre></div></div>`;

    if (g.detectedFrameworks && g.detectedFrameworks.length > 0 && g.frameworkGuidance) {
      h += '<div class="fix-sec"><h3>Framework-Specific Guidance</h3>';
      for (const fw of g.detectedFrameworks) {
        const fg = g.frameworkGuidance[fw.name];
        if (!fg) continue;
        h += `<div class="fw-inline"><strong>${esc(fw.name)} detected</strong>`;
        h += `<p class="fw-tip">${esc(fg.tip)}</p>`;
        h += '<ol>';
        for (const step of fg.fixSteps) {
          h += `<li>${esc(step)}</li>`;
        }
        h += '</ol>';
        if (fg.policyPattern) {
          h += `<div class="code-wrap"><button class="copy-code cc-fw">Copy</button><pre class="code-pre">${esc(fg.policyPattern)}</pre></div>`;
        }
        h += '</div>';
      }
      h += '</div>';
    }

    h += `<div class="fix-sec"><h3>References</h3><ul class="ref-list">${g.references.map(r => `<li><a href="${esc(r.url)}" target="_blank">${esc(r.title)}</a></li>`).join("")}</ul></div>`;
    if (aiKey) h += `<button class="hdr-btn primary" id="fix-ask-ai" style="margin-top:6px">Ask AI for Deeper Analysis</button>`;
    $("#fix-detail-body").innerHTML = h;
    $("#cc-fix")?.addEventListener("click", () => { navigator.clipboard.writeText($("#fix-code-block").textContent); $("#cc-fix").textContent = "Copied!"; setTimeout(() => $("#cc-fix").textContent = "Copy", 1200); });
    $$(".cc-fw").forEach(btn => btn.addEventListener("click", () => {
      const code = btn.closest(".code-wrap").querySelector(".code-pre").textContent;
      navigator.clipboard.writeText(code);
      btn.textContent = "Copied!";
      setTimeout(() => btn.textContent = "Copy", 1200);
    }));
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
    safeSend({ action: "generatePolicy", tabId: TAB_ID, mode: policyMode }, r => {
      if (!r) { $("#btn-gen-policy").textContent = "Generate"; return; }
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
  safeSend({ action: "saveApiKeys", apiKeys: { key: k, provider: p } }, () => {
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

function gatherAIAnalysis() {
  return {
    originAnalysis: originAnalysis || null,
    namedPolicies: namedPoliciesResult || null,
    csp: cspResult || null,
    frameworks: frameworksDetected.length > 0 ? frameworksDetected : null,
    frameworkGuidance: Object.keys(frameworkGuidance).length > 0 ? frameworkGuidance : null,
    scatter: scatterAnalysis || null,
    firstPartyAliases: firstPartyAliases.length > 0 ? firstPartyAliases : null
  };
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
    const analysis = gatherAIAnalysis();
    const resp = await window.AIAssistant.queryAIMultiTurn(aiKey, prov, violations, aiHistory, analysis);
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
  let q = `Analyze this violation:\nType: ${v.violationType}\nSource: ${v.sourceFile}:${v.lineNumber}`;
  if (v.sinkName && v.sinkName !== "Unknown sink") q += `\nSink: ${v.sinkName} (${v.sinkCategory || "unknown"})`;
  if (v.party && v.party !== "unknown") q += `\nOrigin: ${v.party}${v.sourceOrigin ? " (" + v.sourceOrigin + ")" : ""}`;
  q += `\nSample: ${v.sample}\nStack: ${v.stackTrace || "N/A"}`;
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

// ── First-Party Aliases ──

function bindAliases() {
  $("#alias-add-btn").addEventListener("click", addAliasFromInput);
  $("#alias-input").addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); addAliasFromInput(); }
  });
  $("#alias-suggest-btn").addEventListener("click", fetchAliasSuggestions);
}

function normalizeHostInput(raw) {
  let host = raw;
  try {
    if (host.includes("://")) host = new URL(host).hostname;
    else if (host.includes("/")) host = host.split("/")[0];
    if (host.includes(":")) host = host.split(":")[0];
  } catch { return null; }
  host = host.trim().toLowerCase();
  if (!host) return null;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(host)) return null;
  return host;
}

function addAliasFromInput() {
  const input = $("#alias-input");
  const raw = input.value.trim();
  if (!raw) return;
  const val = normalizeHostInput(raw);
  if (!val) {
    input.style.outline = "2px solid #ef4444";
    setTimeout(() => { input.style.outline = ""; }, 1200);
    return;
  }
  if (firstPartyAliases.includes(val)) { input.value = ""; return; }
  firstPartyAliases.push(val);
  input.value = "";
  saveAliasesAndRefresh();
}

function removeAlias(host) {
  firstPartyAliases = firstPartyAliases.filter(a => a !== host);
  saveAliasesAndRefresh();
}

function addSuggestedAlias(host) {
  if (firstPartyAliases.includes(host)) return;
  firstPartyAliases.push(host);
  saveAliasesAndRefresh();
  fetchAliasSuggestions();
}

function saveAliasesAndRefresh() {
  renderAliasTags();
  safeSend({ action: "saveFirstPartyAliases", aliases: firstPartyAliases }, () => {
    reClassifyAndRefresh();
  });
}

function reClassifyAndRefresh() {
  loadInsights();
  safeSend({ action: "getFullState", tabId: TAB_ID }, r => {
    if (!r) return;
    violations = r.violations || [];
    renderLiveTable();
    updateStats();
  });
}

function renderAliasTags() {
  const el = $("#alias-tags");
  if (firstPartyAliases.length === 0) {
    el.innerHTML = '<span class="alias-empty">No aliases configured. Use Auto-Suggest or add manually.</span>';
    return;
  }
  el.innerHTML = firstPartyAliases.map(a =>
    `<span class="alias-tag">${esc(a)}<button class="alias-rm" data-host="${esc(a)}" title="Remove">&times;</button></span>`
  ).join("");
  el.querySelectorAll(".alias-rm").forEach(btn => {
    btn.addEventListener("click", () => removeAlias(btn.dataset.host));
  });
}

function fetchAliasSuggestions() {
  const btn = $("#alias-suggest-btn");
  btn.textContent = "Scanning...";
  btn.disabled = true;
  safeSend({ action: "suggestAliases", tabId: TAB_ID }, r => {
    btn.textContent = "Auto-Suggest";
    btn.disabled = false;
    const el = $("#alias-suggestions");
    if (!r || !r.suggestions || r.suggestions.length === 0) {
      el.innerHTML = '<div class="alias-no-suggestions">No suggestions — all third-party origins look genuinely external, or not enough violations captured yet.</div>';
      return;
    }
    let html = '<div class="alias-suggestion-list">';
    html += '<p class="alias-sug-intro">These domains may be internal CDNs or related assets:</p>';
    for (const s of r.suggestions) {
      const alreadyAdded = firstPartyAliases.includes(s.host);
      html += `<div class="alias-sug-item">
        <div class="alias-sug-info">
          <code>${esc(s.host)}</code>
          <span class="alias-sug-reason">${esc(s.reason)}</span>
          <span class="ins-count">${s.count} violations</span>
        </div>
        <button class="hdr-btn small alias-sug-add" data-host="${esc(s.host)}" ${alreadyAdded ? "disabled" : ""}>${alreadyAdded ? "Added" : "Add"}</button>
      </div>`;
    }
    html += '</div>';
    el.innerHTML = html;
    el.querySelectorAll(".alias-sug-add").forEach(b => {
      b.addEventListener("click", () => {
        addSuggestedAlias(b.dataset.host);
        b.textContent = "Added";
        b.disabled = true;
      });
    });
  });
}

// ── Insights ──

function scheduleInsightsRefresh() {
  clearTimeout(insightsDebounce);
  insightsDebounce = setTimeout(() => {
    insightsDebounce = null;
    loadInsights();
  }, 800);
}

function cancelInsightsRefresh() {
  clearTimeout(insightsDebounce);
  insightsDebounce = null;
}

function loadInsights() {
  safeSend({ action: "getOriginAnalysis", tabId: TAB_ID }, r => {
    if (r) { originAnalysis = r.analysis; renderOriginAnalysis(); }
  });
  safeSend({ action: "getSinkMap", tabId: TAB_ID }, r => {
    if (r) renderSinkMap(r.sinkMap);
  });
  safeSend({ action: "getFrameworkInfo", tabId: TAB_ID }, r => {
    if (r) {
      frameworksDetected = r.frameworks || [];
      frameworkGuidance = r.guidance || {};
      renderFrameworkInfo(r.frameworks, r.guidance);
    }
  });
  safeSend({ action: "getScatterAnalysis", tabId: TAB_ID }, r => {
    if (r) { scatterAnalysis = r.scatter; renderScatterAnalysis(r.scatter); }
  });
  safeSend({ action: "getNamedPolicies", tabId: TAB_ID }, r => {
    if (r) { namedPoliciesResult = r.result; renderNamedPolicies(r.result); }
  });
  safeSend({ action: "getCspHeader", tabId: TAB_ID }, r => {
    if (r) { cspResult = r.csp; renderCspHeader(r.csp); }
  });
}

function renderOriginAnalysis() {
  if (!originAnalysis) {
    $("#origin-summary").innerHTML = '<span class="ins-empty">No violations to analyze.</span>';
    return;
  }
  const a = originAnalysis;
  const total = a.summary.total;

  $("#origin-summary").innerHTML = `
    <div class="origin-stats">
      <div class="ostat"><span class="ostat-num ostat-1p">${a.firstParty.count}</span><span class="ostat-lbl">First-party</span></div>
      <div class="ostat"><span class="ostat-num ostat-3p">${a.thirdParty.count}</span><span class="ostat-lbl">Third-party</span></div>
      <div class="ostat"><span class="ostat-num">${a.unknown.count}</span><span class="ostat-lbl">Unknown</span></div>
    </div>`;

  if (total > 0) {
    let fpW = a.firstParty.count > 0 ? Math.max(1, a.summary.firstPartyPct) : 0;
    let tpW = a.thirdParty.count > 0 ? Math.max(1, a.summary.thirdPartyPct) : 0;
    const barSum = fpW + tpW;
    if (barSum > 100) {
      const scale = 100 / barSum;
      fpW = Math.round(fpW * scale);
      tpW = 100 - fpW;
    }
    let barSegs = "";
    if (a.firstParty.count > 0) barSegs += `<div class="obar-seg obar-1p" style="width:${fpW}%" title="First-party: ${a.firstParty.count}"></div>`;
    if (a.thirdParty.count > 0) barSegs += `<div class="obar-seg obar-3p" style="width:${tpW}%" title="Third-party: ${a.thirdParty.count}"></div>`;
    $("#origin-bar").innerHTML = `
      <div class="obar">${barSegs}</div>
      <div class="obar-legend">
        <span class="obar-label"><span class="obar-dot obar-1p-dot"></span> First-party ${a.summary.firstPartyPct}%</span>
        <span class="obar-label"><span class="obar-dot obar-3p-dot"></span> Third-party ${a.summary.thirdPartyPct}%</span>
      </div>`;
  }

  let detailHtml = "";
  if (a.thirdParty.count > 0) {
    const origins = Object.entries(a.thirdParty.origins).sort((a, b) => b[1] - a[1]);
    detailHtml += '<div class="ins-subsec"><h4>Third-party Origins</h4><div class="ins-list">';
    for (const [origin, count] of origins) {
      detailHtml += `<div class="ins-list-item"><code>${esc(origin)}</code><span class="ins-count">${count}</span></div>`;
    }
    detailHtml += '</div><p class="ins-tip">Third-party violations need targeted named policies or library updates. Fix first-party code first.</p></div>';
  }
  $("#origin-details").innerHTML = detailHtml;
}

function renderSinkMap(sinkMap) {
  const el = $("#sink-map-content");
  if (!sinkMap || sinkMap.length === 0) {
    el.innerHTML = '<span class="ins-empty">No violations to map.</span>';
    return;
  }

  const sinkGroups = new Map();
  for (const entry of sinkMap) {
    const name = entry.sink.sinkName || "Unknown";
    if (!sinkGroups.has(name)) {
      sinkGroups.set(name, { sink: entry.sink, sources: [], count: 0 });
    }
    const g = sinkGroups.get(name);
    g.count++;
    if (entry.sink.sourceLocation && g.sources.length < 5) {
      const loc = entry.sink.sourceLocation;
      if (!g.sources.includes(loc)) g.sources.push(loc);
    }
  }

  const sorted = [...sinkGroups.entries()].sort((a, b) => b[1].count - a[1].count);

  let html = '<div class="sink-grid">';
  for (const [name, data] of sorted) {
    const catClass = `sink-cat-${data.sink.sinkCategory || "unknown"}`;
    html += `<div class="sink-card ${catClass}">
      <div class="sink-card-hdr">
        <code class="sink-name">${esc(name)}</code>
        <span class="ins-count">${data.count}x</span>
      </div>
      <div class="sink-api">${esc(data.sink.sinkApi || "")}</div>`;
    if (data.sources.length > 0) {
      html += '<div class="sink-sources">';
      for (const loc of data.sources) {
        html += `<div class="sink-source" title="${esc(loc)}"><span class="sink-src-icon">&#x2192;</span> <code>${esc(loc.length > 60 ? "..." + loc.slice(-57) : loc)}</code></div>`;
      }
      html += '</div>';
    }
    html += '</div>';
  }
  html += '</div>';
  el.innerHTML = html;
}

function renderFrameworkInfo(frameworks, guidance) {
  const el = $("#framework-content");
  if (!frameworks || frameworks.length === 0) {
    el.innerHTML = '<span class="ins-empty">No frameworks detected from violation data. This analysis improves as more violations are captured.</span>';
    return;
  }

  let html = '<div class="fw-list">';
  for (const fw of frameworks) {
    const g = guidance[fw.name];
    html += `<div class="fw-card">
      <div class="fw-hdr">
        <strong class="fw-name">${esc(fw.name)}</strong>
        <span class="badge b-1p">${esc(fw.confidence)}</span>
      </div>`;
    if (g) {
      html += `<p class="fw-tip">${esc(g.tip)}</p>`;
      html += '<div class="fw-steps"><h4>Recommended Steps</h4><ol>';
      for (const step of g.fixSteps) {
        html += `<li>${esc(step)}</li>`;
      }
      html += '</ol></div>';
      if (g.policyPattern) {
        html += `<div class="fw-code-wrap"><h4>Policy Pattern</h4><div class="code-wrap"><button class="copy-code fw-copy">Copy</button><pre class="code-pre">${esc(g.policyPattern)}</pre></div></div>`;
      }
    }
    html += '</div>';
  }
  html += '</div>';
  el.innerHTML = html;

  el.querySelectorAll(".fw-copy").forEach(btn => {
    btn.addEventListener("click", () => {
      const code = btn.closest(".code-wrap").querySelector(".code-pre").textContent;
      navigator.clipboard.writeText(code);
      btn.textContent = "Copied!";
      setTimeout(() => btn.textContent = "Copy", 1200);
    });
  });
}

function renderScatterAnalysis(scatter) {
  const el = $("#scatter-content");
  if (!scatter) {
    el.innerHTML = '<span class="ins-empty">No scatter data available.</span>';
    return;
  }

  const sevClass = scatter.severity === "high" ? "sev-critical" : scatter.severity === "medium" ? "sev-high" : "sev-medium";

  let html = `<div class="scatter-summary">
    <div class="scatter-indicator">
      <span class="sev-badge ${sevClass}">${esc(scatter.severity)} scatter</span>
      <span class="scatter-stat">${scatter.sourceFileCount} source files, ${scatter.sourceOriginCount} origins</span>
    </div>
    <p class="scatter-msg">${esc(scatter.message)}</p>
  </div>`;

  if (scatter.isScattered) {
    html += '<div class="scatter-rec"><h4>Centralization Recommendation</h4>';
    html += '<ol class="scatter-steps">';
    for (const step of scatter.steps) {
      html += `<li>${esc(step)}</li>`;
    }
    html += '</ol>';
    if (scatter.modulePattern) {
      html += '<div class="code-wrap"><button class="copy-code scatter-copy">Copy</button><pre class="code-pre">' + esc(scatter.modulePattern) + '</pre></div>';
    }
    html += '</div>';
  }

  if (scatter.sourceSummary && scatter.sourceSummary.length > 0) {
    html += '<div class="scatter-sources"><h4>Violations by Source File</h4><div class="ins-list">';
    for (const src of scatter.sourceSummary.slice(0, 15)) {
      const shortFile = src.file.length > 60 ? "..." + src.file.slice(-57) : src.file;
      html += `<div class="ins-list-item">
        <div><code title="${esc(src.file)}">${esc(shortFile)}</code>
          <span class="sink-tags">${src.sinks.map(s => `<span class="sink-tag">${esc(s)}</span>`).join("")}</span>
        </div>
        <span class="ins-count">${src.violationCount}</span>
      </div>`;
    }
    html += '</div></div>';
  }

  el.innerHTML = html;

  el.querySelectorAll(".scatter-copy").forEach(btn => {
    btn.addEventListener("click", () => {
      const code = btn.closest(".code-wrap").querySelector(".code-pre").textContent;
      navigator.clipboard.writeText(code);
      btn.textContent = "Copied!";
      setTimeout(() => btn.textContent = "Copy", 1200);
    });
  });
}

function renderNamedPolicies(result) {
  const el = $("#named-policies-content");
  if (!result || result.policies.length === 0) {
    el.innerHTML = '<span class="ins-empty">No violations available to generate policy recommendations. Capture violations first.</span>';
    return;
  }

  let html = `<div class="np-summary">
    <span>${result.totalPolicies} named ${result.totalPolicies === 1 ? "policy" : "policies"} recommended</span>
    <span class="np-names">${result.policyNames.map(n => `<code>${esc(n)}</code>`).join(" ")}</span>
  </div>`;

  html += '<div class="np-list">';
  for (const p of result.policies) {
    const bc = p.type === "TrustedHTML" ? "b-html" : p.type === "TrustedScript" ? "b-script" : "b-url";
    html += `<div class="np-card">
      <div class="np-hdr">
        <code class="np-name">${esc(p.name)}</code>
        <span class="badge ${bc}">${esc(p.type)}</span>
        <span class="ins-count">${p.violationCount} violations</span>
      </div>
      <p class="np-desc">${esc(p.description)}</p>
      <div class="code-wrap"><button class="copy-code np-copy">Copy</button><pre class="code-pre">${esc(p.code)}</pre></div>
    </div>`;
  }
  html += '</div>';

  if (result.centralizationModule) {
    html += `<div class="np-module">
      <h4>Centralized Module (Copy All)</h4>
      <div class="code-wrap"><button class="copy-code np-copy-module">Copy Module</button><pre class="code-pre">${esc(result.centralizationModule)}</pre></div>
    </div>`;
  }

  el.innerHTML = html;

  el.querySelectorAll(".np-copy, .np-copy-module").forEach(btn => {
    btn.addEventListener("click", () => {
      const code = btn.closest(".code-wrap").querySelector(".code-pre").textContent;
      navigator.clipboard.writeText(code);
      btn.textContent = "Copied!";
      setTimeout(() => btn.textContent = "Copy", 1200);
    });
  });
}

function renderCspHeader(csp) {
  const el = $("#csp-content");
  if (!csp) {
    el.innerHTML = '<span class="ins-empty">No CSP data available.</span>';
    return;
  }

  let html = '<div class="csp-section">';
  html += `<p class="csp-explanation">${esc(csp.explanation)}</p>`;

  const items = [
    { label: "Report-Only (test first)", value: csp.reportOnly, rec: true },
    { label: "Enforcing", value: csp.enforcing },
  ];
  if (csp.withDefault) items.push({ label: "With default fallback", value: csp.withDefault });
  if (csp.metaTag) items.push({ label: "HTML meta tag", value: csp.metaTag });
  if (csp.nginxConfig) items.push({ label: "Nginx config", value: csp.nginxConfig });
  if (csp.apacheConfig) items.push({ label: "Apache config", value: csp.apacheConfig });

  for (const item of items) {
    html += `<div class="csp-item${item.rec ? " csp-recommended" : ""}">
      <div class="csp-item-hdr"><strong>${esc(item.label)}</strong>${item.rec ? '<span class="badge b-1p">Recommended first</span>' : ""}</div>
      <div class="code-wrap"><button class="copy-code csp-copy">Copy</button><pre class="code-pre">${esc(item.value)}</pre></div>
    </div>`;
  }
  html += '</div>';

  el.innerHTML = html;

  el.querySelectorAll(".csp-copy").forEach(btn => {
    btn.addEventListener("click", () => {
      const code = btn.closest(".code-wrap").querySelector(".code-pre").textContent;
      navigator.clipboard.writeText(code);
      btn.textContent = "Copied!";
      setTimeout(() => btn.textContent = "Copy", 1200);
    });
  });
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
