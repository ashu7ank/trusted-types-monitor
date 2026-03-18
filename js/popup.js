// Lightweight popup - current tab dashboard only
// All heavy features live in the DevTools panel (panel.js)

const $ = s => document.querySelector(s);

document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0]?.id || -1;

    chrome.runtime.sendMessage({ action: "getFullState", tabId }, r => {
      if (!r) return;
      const tabViolations = r.violations || [];
      const clusters = r.clusters || [];
      const enabled = r.enabled !== false;

      $("#toggle-enabled").checked = enabled;
      $("#p-total").textContent = tabViolations.length;
      $("#p-clusters").textContent = clusters.length;

      const critical = tabViolations.filter(v =>
        v.violationType === "TrustedScript" ||
        (v.violationType === "TrustedHTML" && /<script|on\w+\s*=/i.test(v.sample || ""))
      ).length;
      $("#p-critical").textContent = critical;

      renderBreakdown(tabViolations);
      renderRecent(tabViolations);
    });

    $("#toggle-enabled").addEventListener("change", e => {
      chrome.runtime.sendMessage({ action: "setEnabled", enabled: e.target.checked });
    });

    $("#btn-export").addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "getViolations", tabId }, r => {
        if (!r) return;
        const v = r.violations || [];
        if (!v.length) return;
        const hdr = "timestamp,type,directive,url,sourceFile,lineNumber,sample\n";
        const rows = v.map(x =>
          [
            csvField(x.timestamp),
            csvField(x.violationType),
            csvField(x.directive),
            csvField(x.url),
            csvField(x.sourceFile),
            csvField(String(x.lineNumber)),
            csvField((x.sample || "").substring(0, 200))
          ].join(",")
        ).join("\n");
        const blob = new Blob([hdr + rows], { type: "text/csv" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `tt-violations-${new Date().toISOString().split("T")[0]}.csv`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 100);
      });
    });

    $("#btn-clear").addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "clearViolations", tabId }, () => {
        $("#p-total").textContent = "0";
        $("#p-critical").textContent = "0";
        $("#p-clusters").textContent = "0";
        $("#type-breakdown").innerHTML = "";
        $("#recent-list").innerHTML = '<div class="empty">Cleared.</div>';
      });
    });
  });
});

function csvField(val) {
  const s = String(val || "");
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function renderBreakdown(violations) {
  const counts = { TrustedHTML: 0, TrustedScript: 0, TrustedScriptURL: 0, Unknown: 0 };
  violations.forEach(v => { counts[v.violationType] = (counts[v.violationType] || 0) + 1; });
  const total = violations.length || 1;
  const el = $("#type-breakdown");
  el.innerHTML = [
    { cls: "tb-html", n: counts.TrustedHTML },
    { cls: "tb-script", n: counts.TrustedScript },
    { cls: "tb-url", n: counts.TrustedScriptURL },
    { cls: "tb-unknown", n: counts.Unknown }
  ].filter(x => x.n > 0).map(x =>
    `<div class="tb-bar ${x.cls}" style="width:${Math.max(2, (x.n / total) * 100)}%" title="${x.cls.replace('tb-','')} (${x.n})"></div>`
  ).join("");
}

function renderRecent(violations) {
  const el = $("#recent-list");
  if (!violations.length) { el.innerHTML = '<div class="empty">No violations on this tab yet.</div>'; return; }
  const recent = violations.slice(-8).reverse();
  el.innerHTML = recent.map(v => {
    const bc = { TrustedHTML: "ri-html", TrustedScript: "ri-script", TrustedScriptURL: "ri-url" }[v.violationType] || "ri-unknown";
    const sample = (v.sample || "").substring(0, 50);
    const time = new Date(v.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return `<div class="recent-item">
      <span class="ri-badge ${bc}">${esc(v.violationType || "?")}</span>
      <span class="ri-text" title="${esc(v.sample || "")}">${esc(sample)}</span>
      <span class="ri-time">${time}</span>
    </div>`;
  }).join("");
}

function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
