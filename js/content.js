// Content script (ISOLATED world) - captures CSP events and relays to background

document.addEventListener('securitypolicyviolation', (e) => {
  if (!chrome.runtime?.id) return;
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
        stackTrace: ""
      }
    });
  }
});

if (window.ReportingObserver) {
  new ReportingObserver((reports) => {
    if (!chrome.runtime?.id) return;
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

// Bridge: receive violations from MAIN world content-main.js
// Validates structure and types to prevent arbitrary injection from page scripts.
window.addEventListener('message', (event) => {
  if (!chrome.runtime?.id) return;
  if (event.source !== window || event.data?.type !== '__tt_monitor__') return;

  const v = event.data.violation;
  if (!v || typeof v !== 'object' || Array.isArray(v)) return;
  if (typeof v.directive !== 'string' || !v.directive.includes('trusted-types')) return;

  const str = (val, fallback, maxLen = 2000) =>
    typeof val === 'string' ? val.substring(0, maxLen) : fallback;
  const num = (val, fallback) =>
    (typeof val === 'number' && Number.isFinite(val)) ? val : fallback;

  chrome.runtime.sendMessage({
    action: "reportViolation",
    violation: {
      timestamp: str(v.timestamp, new Date().toISOString()),
      url: str(v.url, document.location.href),
      directive: v.directive,
      blockedUri: str(v.blockedUri, "unknown"),
      sourceFile: str(v.sourceFile, "unknown"),
      lineNumber: num(v.lineNumber, "unknown"),
      columnNumber: num(v.columnNumber, "unknown"),
      sample: str(v.sample, "unknown"),
      stackTrace: str(v.stackTrace, ""),
      detectedVia: str(v.detectedVia, "postMessage")
    }
  });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkTrustedTypesSupport") {
    sendResponse({ supported: typeof window.trustedTypes !== 'undefined' });
    return true;
  }

  if (request.action === "sanitizeHTML") {
    const raw = typeof request.html === 'string' ? request.html.substring(0, 50000) : '';
    if (!raw) {
      sendResponse({ sanitized: '', error: null });
      return true;
    }
    if (typeof DOMPurify !== 'undefined') {
      try {
        sendResponse({ sanitized: DOMPurify.sanitize(raw), error: null });
      } catch (e) {
        sendResponse({ sanitized: '', error: e.message });
      }
    } else {
      sendResponse({ sanitized: '', error: 'DOMPurify not loaded' });
    }
    return true;
  }

  return true;
});
