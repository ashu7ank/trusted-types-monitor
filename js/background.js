// Background service worker for handling CSP violations
let pendingReports = [];
const MAX_STORAGE_ITEMS = 1000;

// Create a unique fingerprint for each violation to identify duplicates
function createViolationFingerprint(violation) {
  return `${violation.url}|${violation.directive}|${violation.blockedUri}|${violation.sourceFile}|${violation.lineNumber}|${violation.columnNumber}|${violation.sample}`;
}

// Process and store violations
function processViolation(violation) {
  // Normalize the violation format
  const normalizedViolation = {
    timestamp: violation.timestamp || new Date().toISOString(),
    url: violation.url || "unknown",
    directive: violation.directive || "unknown",
    blockedUri: violation.blockedUri || "unknown",
    sourceFile: violation.sourceFile || "unknown",
    lineNumber: violation.lineNumber || "unknown",
    columnNumber: violation.columnNumber || "unknown",
    sample: violation.sample || "unknown",
    // Add fields for tracking duplicates
    firstSeen: violation.timestamp || new Date().toISOString(),
    lastSeen: violation.timestamp || new Date().toISOString(),
    occurrences: 1
  };
  
  console.log("Processing violation:", normalizedViolation);
  
  // Check for duplicates before adding to pending reports
  checkForDuplicateViolation(normalizedViolation);
}

// Check if this violation is a duplicate before adding to pending reports
function checkForDuplicateViolation(violation) {
  const fingerprint = createViolationFingerprint(violation);
  
  chrome.storage.local.get(['violations', 'violationFingerprints'], function(result) {
    let violations = result.violations || [];
    let fingerprints = result.violationFingerprints || {};
    
    // Check if we've seen this exact violation before
    if (fingerprint in fingerprints) {
      const index = fingerprints[fingerprint];
      
      // Make sure the index is valid
      if (index >= 0 && index < violations.length) {
        // Update the existing violation record
        violations[index].lastSeen = new Date().toISOString();
        violations[index].occurrences = (violations[index].occurrences || 1) + 1;
        
        // If this violation is not near the end of the array, move it there
        // to prevent it from being trimmed (prioritize frequent violations)
        if (violations.length - index > 100) {
          const existingViolation = violations.splice(index, 1)[0];
          violations.push(existingViolation);
          // Update the fingerprint index
          fingerprints[fingerprint] = violations.length - 1;
        }
        
        console.log(`Duplicate violation found. Updated count to ${violations[index].occurrences}`);
        
        // Store the updated violation data
        chrome.storage.local.set({ 
          violations: violations,
          violationFingerprints: fingerprints 
        }, function() {
          // Notify any open popup
          notifyViolationsUpdated(violations.length);
        });
      } else {
        // Invalid index - treat as new violation
        addNewViolation(violation, violations, fingerprints);
      }
    } else {
      // This is a new violation
      addNewViolation(violation, violations, fingerprints);
    }
  });
}

// Add a new violation to storage
function addNewViolation(violation, violations, fingerprints) {
  // Add to pending reports to use the existing batch mechanism
  pendingReports.push(violation);
  
  // Store in batches to avoid too many storage operations
  if (pendingReports.length >= 5) {
    storeViolations(violations, fingerprints);
  }
}

// Store violations in Chrome storage with deduplication tracking
function storeViolations(existingViolations, existingFingerprints) {
  if (pendingReports.length === 0) return;
  
  console.log("Storing violations:", pendingReports.length);
  
  // If we don't have existing data, get it from storage
  if (!existingViolations || !existingFingerprints) {
    chrome.storage.local.get(['violations', 'violationFingerprints'], function(result) {
      storeViolationsInternal(
        result.violations || [], 
        result.violationFingerprints || {}
      );
    });
  } else {
    storeViolationsInternal(existingViolations, existingFingerprints);
  }
}

// Internal function to store violations with fingerprint tracking
function storeViolationsInternal(violations, fingerprints) {
  // Add new violations
  const newViolations = [...violations];
  
  // Process each pending report
  for (const violation of pendingReports) {
    const fingerprint = createViolationFingerprint(violation);
    newViolations.push(violation);
    fingerprints[fingerprint] = newViolations.length - 1;
  }
  
  // Trim if exceeded storage limit
  if (newViolations.length > MAX_STORAGE_ITEMS) {
    const removedCount = newViolations.length - MAX_STORAGE_ITEMS;
    const removedViolations = newViolations.splice(0, removedCount);
    
    // Update fingerprints by removing deleted entries and adjusting indices
    for (const violation of removedViolations) {
      const fingerprint = createViolationFingerprint(violation);
      delete fingerprints[fingerprint];
    }
    
    // Adjust indices for remaining fingerprints
    Object.keys(fingerprints).forEach(key => {
      fingerprints[key] = Math.max(0, fingerprints[key] - removedCount);
    });
  }
  
  // Store updated violations and fingerprints
  chrome.storage.local.set({ 
    violations: newViolations,
    violationFingerprints: fingerprints 
  }, function() {
    console.log('Stored', pendingReports.length, 'violations. Total:', newViolations.length);
    pendingReports = [];
    
    // Notify any open popup
    notifyViolationsUpdated(newViolations.length);
  });
}

// Notify popup of updates
function notifyViolationsUpdated(count) {
  chrome.runtime.sendMessage({
    action: "violationsUpdated",
    count: count
  }).catch(() => {
    // Ignore errors if popup is not open
  });
}

// Set up a runtime listener for CSP violation reports from content script
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "reportViolation") {
    console.log("Received violation report from content script", request.violation);
    processViolation(request.violation);
    sendResponse({ success: true });
    return true;
  } else if (request.action === "getViolations") {
    chrome.storage.local.get(['violations'], function(result) {
      sendResponse({ violations: result.violations || [] });
    });
    return true; // Keep the message channel open for async response
  } else if (request.action === "clearViolations") {
    chrome.storage.local.set({ 
      violations: [],
      violationFingerprints: {} 
    }, function() {
      sendResponse({ success: true });
    });
    return true;
  } else if (request.action === "getViolationStats") {
    // New endpoint to get statistics about violations
    chrome.storage.local.get(['violations'], function(result) {
      const violations = result.violations || [];
      const stats = {
        totalViolations: violations.length,
        totalOccurrences: violations.reduce((sum, v) => sum + (v.occurrences || 1), 0),
        uniqueUrls: new Set(violations.map(v => v.url)).size,
        savedStorage: violations.reduce((sum, v) => sum + ((v.occurrences || 1) - 1), 0)
      };
      sendResponse({ stats: stats });
    });
    return true;
  }
});

console.log("Trusted Types Monitor: Background script initialized");

// Set up periodic storage of pending violations
setInterval(() => storeViolations(), 30000);  // Store every 30 seconds

// Clear old data occasionally
chrome.runtime.onStartup.addListener(function() {
  const monthAgo = new Date();
  monthAgo.setMonth(monthAgo.getMonth() - 1);
  
  chrome.storage.local.get(['violations', 'violationFingerprints'], function(result) {
    if (!result.violations) return;
    
    const oldViolations = result.violations;
    const fingerprints = result.violationFingerprints || {};
    
    // Filter out old violations
    const filtered = oldViolations.filter(v => 
      new Date(v.lastSeen || v.timestamp) >= monthAgo
    );
    
    if (filtered.length !== oldViolations.length) {
      // Rebuild fingerprints from scratch since indices have changed
      const newFingerprints = {};
      filtered.forEach((violation, index) => {
        const fingerprint = createViolationFingerprint(violation);
        newFingerprints[fingerprint] = index;
      });
      
      chrome.storage.local.set({ 
        violations: filtered,
        violationFingerprints: newFingerprints
      });
      
      console.log(`Removed ${oldViolations.length - filtered.length} old violations during cleanup`);
    }
  });
});