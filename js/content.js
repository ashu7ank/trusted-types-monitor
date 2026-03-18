// Content script (ISOLATED world) - captures CSP events and relays to background

document.addEventListener('securitypolicyviolation', (e) => {
  if (e.violatedDirective && e.violatedDirective.includes('trusted-types')) {
    chrome.runtime.sendMessage({
      action: "reportViolation",
      violation: {
        timestamp: new Date().toISOString(),
        url: document.location.href,
        directive: e.violatedDirective,
        blockedUri: e.blockedURI || "unknown",
        sourceFile: e.sourceFile || "unknown",
        lineNumber: e.lineNumber || "unknown",
        columnNumber: e.columnNumber || "unknown",
        sample: e.sample || "unknown",
        stackTrace: new Error().stack || ""
      }
    });
  }
});

if (window.ReportingObserver) {
  new ReportingObserver((reports) => {
    for (const report of reports) {
      if (report.type === 'csp-violation' && report.body &&
          report.body.violatedDirective &&
          report.body.violatedDirective.includes('trusted-types')) {
        chrome.runtime.sendMessage({
          action: "reportViolation",
          violation: {
            timestamp: new Date().toISOString(),
            url: document.location.href,
            directive: report.body.violatedDirective || "unknown",
            blockedUri: report.body.blockedURI || "unknown",
            sourceFile: report.body.sourceFile || "unknown",
            lineNumber: report.body.lineNumber || "unknown",
            columnNumber: report.body.columnNumber || "unknown",
            sample: report.body.sample || "unknown"
          }
        });
      }
    }
  }, { buffered: true }).observe();
}

const meta = document.createElement('meta');
meta.httpEquiv = 'Content-Security-Policy-Report-Only';
meta.content = "require-trusted-types-for 'script'; report-uri /trusted-types-violation; report-to csp-endpoint";

const reportingMeta = document.createElement('meta');
reportingMeta.httpEquiv = 'Reporting-Endpoints';
reportingMeta.content = 'csp-endpoint="/trusted-types-violation"';

if (document.head) {
  document.head.appendChild(meta);
  document.head.appendChild(reportingMeta);
} else {
  new MutationObserver(function (_, obs) {
    if (document.head) {
      document.head.appendChild(meta);
      document.head.appendChild(reportingMeta);
      obs.disconnect();
    }
  }).observe(document.documentElement || document, { childList: true, subtree: true });
}

// Bridge: receive violations from MAIN world content-main.js
window.addEventListener('message', (event) => {
  if (event.source !== window || event.data?.type !== '__tt_monitor__') return;
  chrome.runtime.sendMessage({ action: "reportViolation", violation: event.data.violation });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkTrustedTypesSupport") {
    sendResponse({ supported: typeof window.trustedTypes !== 'undefined' });
  }
  return true;
});

if (document.URL.includes('trusted-types-monitor-test') || document.URL.includes('test-page.html')) {
  setTimeout(() => {
    try {
      const div = document.createElement('div');
      div.innerHTML = "<script>console.log('test');<\/script>";
      document.body.appendChild(div);
    } catch {}
  }, 1000);
}
