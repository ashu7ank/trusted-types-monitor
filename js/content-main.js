// Content script (MAIN world) - patches XHR/fetch in the page's JS context
// Posts messages to the isolated content script via window.postMessage

(function () {
  const MAGIC = "__tt_monitor__";
  const origXHROpen = XMLHttpRequest.prototype.open;
  const origXHRSend = XMLHttpRequest.prototype.send;
  const origFetch = window.fetch;

  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    this._ttMethod = method;
    this._ttUrl = url;
    return origXHROpen.call(this, method, url, ...args);
  };

  XMLHttpRequest.prototype.send = function (body) {
    if (this._ttMethod === 'POST' && this._ttUrl &&
        this._ttUrl.includes('trusted-types-violation')) {
      tryParseAndPost(body, "xhr");
    }
    return origXHRSend.call(this, body);
  };

  window.fetch = function (resource, init) {
    const url = typeof resource === 'string' ? resource : resource?.url;
    if (init?.body && url && url.includes('trusted-types-violation')) {
      tryParseAndPost(init.body, "fetch");
    }
    return origFetch.call(window, resource, init);
  };

  function tryParseAndPost(body, source) {
    if (typeof body !== 'string') return;
    try {
      const parsed = JSON.parse(body);
      const report = parsed["csp-report"];
      if (report && report["violated-directive"] &&
          report["violated-directive"].includes("trusted-types")) {
        window.postMessage({
          type: MAGIC,
          violation: {
            timestamp: new Date().toISOString(),
            url: report["document-uri"] || document.location.href,
            directive: report["violated-directive"] || "unknown",
            blockedUri: report["blocked-uri"] || "unknown",
            sourceFile: report["source-file"] || "unknown",
            lineNumber: report["line-number"] || "unknown",
            columnNumber: report["column-number"] || "unknown",
            sample: report["script-sample"] || "unknown",
            detectedVia: source
          }
        }, document.location.origin);
      }
    } catch {}
  }

  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if ((entry.initiatorType === 'fetch' || entry.initiatorType === 'xmlhttprequest') &&
            entry.name.includes('trusted-types-violation')) {
          window.postMessage({
            type: MAGIC,
            violation: {
              timestamp: new Date().toISOString(),
              url: document.location.href,
              directive: "trusted-types (resource timing)",
              observedRequest: entry.name,
              initiatorType: entry.initiatorType
            }
          }, document.location.origin);
        }
      }
    }).observe({ entryTypes: ['resource'] });
  } catch {}
})();
