// Content script to capture Trusted Types violations
console.log("Trusted Types Monitor: Content script loaded");

// Store original methods we'll be patching
const originalXHROpen = XMLHttpRequest.prototype.open;
const originalXHRSend = XMLHttpRequest.prototype.send;
const originalFetch = window.fetch;

// Set up a listener for Trusted Types CSP violations
document.addEventListener('securitypolicyviolation', function(e) {
  // Only process Trusted Types violations
  if (e.violatedDirective && e.violatedDirective.includes('trusted-types')) {
    console.log("Trusted Types Monitor: Captured violation via event", e);
    
    const violation = {
      timestamp: new Date().toISOString(),
      url: document.location.href,
      directive: e.violatedDirective,
      blockedUri: e.blockedURI || "unknown",
      sourceFile: e.sourceFile || "unknown",
      lineNumber: e.lineNumber || "unknown",
      columnNumber: e.columnNumber || "unknown",
      sample: e.sample || "unknown",
      stackTrace: new Error().stack || "unknown"
    };
    
    // Send to background script for storage
    chrome.runtime.sendMessage({
      action: "reportViolation",
      violation: violation
    });
  }
});

// For browsers that support ReportingObserver, use it to capture reports
if (window.ReportingObserver) {
  console.log("Trusted Types Monitor: ReportingObserver supported");
  const reportingObserver = new ReportingObserver((reports) => {
    for (const report of reports) {
      if (report.type === 'csp-violation' && report.body && report.body.violatedDirective && 
          report.body.violatedDirective.includes('trusted-types')) {
        console.log('Trusted Types Monitor: Captured violation via ReportingObserver', report);
        
        const violation = {
          timestamp: new Date().toISOString(),
          url: document.location.href,
          directive: report.body.violatedDirective || "unknown",
          blockedUri: report.body.blockedURI || "unknown",
          sourceFile: report.body.sourceFile || "unknown",
          lineNumber: report.body.lineNumber || "unknown",
          columnNumber: report.body.columnNumber || "unknown",
          sample: report.body.sample || "unknown"
        };
        
        // Send to background script for storage
        chrome.runtime.sendMessage({
          action: "reportViolation",
          violation: violation
        });
      }
    }
  }, { buffered: true });
  
  reportingObserver.observe();
} else {
  console.log("Trusted Types Monitor: ReportingObserver not supported");
}

// Patch XMLHttpRequest to intercept CSP violation reports
XMLHttpRequest.prototype.open = function(method, url, ...args) {
  // Store the original call info for later
  this._ttMonitorMethod = method;
  this._ttMonitorUrl = url;
  return originalXHROpen.call(this, method, url, ...args);
};

XMLHttpRequest.prototype.send = function(body) {
  // Check if this might be a CSP violation report
  if (this._ttMonitorMethod === 'POST') {
    // If URL has trusted-types-violation, always log this request
    if (this._ttMonitorUrl && this._ttMonitorUrl.includes('trusted-types-violation')) {
      console.log("Trusted Types Monitor: POST detected to violation endpoint", this._ttMonitorUrl);
      
      // Create a basic violation report even if we can't parse the body
      const basicViolation = {
        timestamp: new Date().toISOString(),
        url: document.location.href,
        directive: "trusted-types (from URL pattern)",
        endpoint: this._ttMonitorUrl
      };
      
      // Send to background script
      chrome.runtime.sendMessage({
        action: "reportViolation",
        violation: basicViolation
      });
    }
  
    try {
      // Try to parse the body if it's a string
      if (typeof body === 'string') {
        try {
          const parsedBody = JSON.parse(body);
          
          // Check if it looks like a CSP report with trusted-types violations
          if (parsedBody && 
              parsedBody["csp-report"] && 
              parsedBody["csp-report"]["violated-directive"] && 
              parsedBody["csp-report"]["violated-directive"].includes("trusted-types")) {
            
            console.log("Trusted Types Monitor: Intercepted violation via XHR", parsedBody);
            
            // Extract the useful information and send to background script
            const report = parsedBody["csp-report"];
            const violation = {
              timestamp: new Date().toISOString(),
              url: report["document-uri"] || document.location.href,
              directive: report["violated-directive"] || "unknown",
              blockedUri: report["blocked-uri"] || "unknown",
              sourceFile: report["source-file"] || "unknown",
              lineNumber: report["line-number"] || "unknown",
              columnNumber: report["column-number"] || "unknown",
              sample: report["script-sample"] || "unknown"
            };
            
            // Send to background script for storage
            chrome.runtime.sendMessage({
              action: "reportViolation",
              violation: violation
            });
          }
        } catch (e) {
          // Not JSON, continue
        }
      }
    } catch (e) {
      // Error parsing or processing, just continue
      console.debug("Trusted Types Monitor: Error processing XHR", e);
    }
  }
  
  // Let the original call continue
  return originalXHRSend.call(this, body);
};

// Monkey patch fetch to intercept CSP violation reports
window.fetch = function(resource, init) {
  // Check if the URL might be a violation endpoint
  if (typeof resource === 'string' && resource.includes('trusted-types-violation')) {
    console.log("Trusted Types Monitor: fetch to violation endpoint", resource);
    
    // Create a basic violation report for the URL match
    const violation = {
      timestamp: new Date().toISOString(),
      url: document.location.href,
      directive: "trusted-types (from fetch URL)",
      endpoint: resource
    };
    
    // Send to background script
    chrome.runtime.sendMessage({
      action: "reportViolation",
      violation: violation
    });
  }
  
  // Check if this might be a CSP violation report
  if (init && init.method === 'POST' && init.body) {
    try {
      // Try to parse the body if it's a string
      if (typeof init.body === 'string') {
        try {
          const parsedBody = JSON.parse(init.body);
          
          // Check if it looks like a CSP report with trusted-types violations
          if (parsedBody && 
              parsedBody["csp-report"] && 
              parsedBody["csp-report"]["violated-directive"] && 
              parsedBody["csp-report"]["violated-directive"].includes("trusted-types")) {
            
            console.log("Trusted Types Monitor: Intercepted violation via fetch", parsedBody);
            
            // Extract the useful information and send to background script
            const report = parsedBody["csp-report"];
            const violation = {
              timestamp: new Date().toISOString(),
              url: report["document-uri"] || document.location.href,
              directive: report["violated-directive"] || "unknown",
              blockedUri: report["blocked-uri"] || "unknown",
              sourceFile: report["source-file"] || "unknown",
              lineNumber: report["line-number"] || "unknown",
              columnNumber: report["column-number"] || "unknown",
              sample: report["script-sample"] || "unknown"
            };
            
            // Send to background script for storage
            chrome.runtime.sendMessage({
              action: "reportViolation",
              violation: violation
            });
          }
        } catch (e) {
          // Not JSON, continue
        }
      }
    } catch (e) {
      // Error parsing or processing, just continue
      console.debug("Trusted Types Monitor: Error processing fetch", e);
    }
  }
  
  // Let the original call continue
  return originalFetch.call(window, resource, init);
};

// Add a specific listener for network requests to trusted-types-violation endpoints
const observer = new PerformanceObserver((entryList) => {
  for (const entry of entryList.getEntries()) {
    if (entry.initiatorType === 'fetch' || entry.initiatorType === 'xmlhttprequest') {
      // Check if this might be a violation report URL
      if (entry.name.includes('trusted-types-violation')) {
        console.log("Trusted Types Monitor: Detected violation via PerformanceObserver", entry);
        
        // Create a basic violation report from the URL
        const violation = {
          timestamp: new Date().toISOString(),
          url: document.location.href,
          directive: "trusted-types (resource timing)",
          observedRequest: entry.name,
          initiatorType: entry.initiatorType
        };
        
        // Send to background script
        chrome.runtime.sendMessage({
          action: "reportViolation",
          violation: violation
        });
      }
    }
  }
});

// Start observing resource timing entries
try {
  observer.observe({entryTypes: ['resource']});
  console.log("Trusted Types Monitor: PerformanceObserver started");
} catch (e) {
  console.error("Trusted Types Monitor: PerformanceObserver failed", e);
}

// Also inject a CSP header for trusted types
const meta = document.createElement('meta');
meta.httpEquiv = 'Content-Security-Policy-Report-Only';
meta.content = "require-trusted-types-for 'script'; report-uri /trusted-types-violation; report-to csp-endpoint";

// Also add a reporting endpoint
const reportingMeta = document.createElement('meta');
reportingMeta.httpEquiv = 'Reporting-Endpoints';
reportingMeta.content = "csp-endpoint=\"/trusted-types-violation\"";

// Try to inject as early as possible
if (document.head) {
  document.head.appendChild(meta);
  document.head.appendChild(reportingMeta);
} else {
  // If head doesn't exist yet, wait for it
  const observer = new MutationObserver(function(mutations) {
    if (document.head) {
      document.head.appendChild(meta);
      document.head.appendChild(reportingMeta);
      observer.disconnect();
    }
  });
  observer.observe(document.documentElement || document, { childList: true, subtree: true });
}

// Create a test helper function that can be called from the console to generate violations
window._generateTrustedTypesViolation = function() {
  console.log("Generating a Trusted Types violation for testing");
  try {
    // Try to create a violation by setting innerHTML
    const div = document.createElement('div');
    div.innerHTML = "<script>console.log('test');<\/script>";
    document.body.appendChild(div);
    return "Violation generated";
  } catch (e) {
    console.error("Error generating violation:", e);
    return "Error: " + e.message;
  }
};

// Simulate a trusted types violation when debugging mode is active
if (document.URL.includes('trusted-types-monitor-test') || document.URL.includes('test-page.html')) {
  console.log("Test mode detected, will generate test violations");
  setTimeout(() => {
    window._generateTrustedTypesViolation();
  }, 1000);
}

// Add a message listener for communication with the background script
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "checkTrustedTypesSupport") {
    const supported = typeof window.trustedTypes !== 'undefined';
    sendResponse({ supported: supported });
  }
  return true;
});

// Add a fallback mechanism to detect when extension is disabled/enabled
// This will help ensure data is cleared even if management API is not available
(function setupExtensionStateDetection() {
  // Create a storage key unique to this page to detect reloads
  const pageId = document.location.href + '_' + Date.now();
  const storageKey = 'ttm_page_' + btoa(pageId).replace(/=/g, '');
  
  // Check if this is a fresh load or a reload after extension was disabled/enabled
  chrome.storage.local.get(['extensionState'], function(result) {
    const storedState = result.extensionState || {};
    
    // If we find this page was previously active, extension was likely reloaded
    if (Object.keys(storedState).length > 0) {
      console.log("Trusted Types Monitor: Content script reloaded, extension likely re-enabled");
      chrome.runtime.sendMessage({
        action: "extensionEnabled"
      }).catch(() => {
        // Ignore errors if background script is not available
        console.log("Trusted Types Monitor: Could not send extensionEnabled message");
      });
    }
    
    // Store that this page is now active
    storedState[pageId] = new Date().getTime();
    
    // Clean up old entries (older than 1 hour)
    const oneHourAgo = new Date().getTime() - (60 * 60 * 1000);
    for (const key in storedState) {
      if (storedState[key] < oneHourAgo) {
        delete storedState[key];
      }
    }
    
    // Save the updated state
    chrome.storage.local.set({ extensionState: storedState });
  });
  
  // Listen for beforeunload to detect when page is closing
  // If extension is being disabled, this gives us a chance to clean up
  window.addEventListener('beforeunload', function() {
    try {
      // Try to notify the background script that we might be getting disabled
      chrome.runtime.sendMessage({
        action: "pageUnloading",
        pageId: pageId
      }).catch(() => {
        // Ignore errors if background script is not available
      });
    } catch (e) {
      // Ignore errors if runtime is not available
    }
  });
})();
