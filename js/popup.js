// Simplified popup JavaScript for Trusted Types Monitor

// Global state
let allViolations = [];
let currentPage = 1;
let itemsPerPage = 20;
let currentSort = { field: 'timestamp', ascending: false };

// DOM elements
const elements = {
  exportCsv: document.getElementById('export-csv'),
  clearAll: document.getElementById('clear-all'),
  refreshData: document.getElementById('refresh-data'),
  totalViolations: document.getElementById('total-violations'),
  uniqueUrls: document.getElementById('unique-urls'),
  tableHeaders: document.querySelectorAll('th[data-sort]'),
  violationsBody: document.getElementById('violations-body'),
  prevPage: document.getElementById('prev-page'),
  nextPage: document.getElementById('next-page'),
  pageInfo: document.getElementById('page-info'),
  detailPanel: document.getElementById('violation-detail'),
  closeDetail: document.getElementById('close-detail')
};

// Initialize the popup
document.addEventListener('DOMContentLoaded', function() {
  initializePopup();
  attachEventListeners();
  
  // Set up a listener for violation updates from the background script
  chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "violationsUpdated") {
      console.log("Received update notification, reloading violations");
      loadViolations();
    }
    return true;
  });
});

// Initialize the popup with data and setup
function initializePopup() {
  // First, check and clear the extensionDisabled flag if it exists
  // This ensures the extension properly reinitializes after being reenabled
  chrome.storage.local.get(['extensionDisabled'], function(result) {
    if (result.extensionDisabled === true) {
      console.log("Popup detected extensionDisabled flag, clearing data and reinitializing");
      chrome.runtime.sendMessage({
        action: "extensionEnabled"
      });
    }
  });
  
  // Load violations from storage
  loadViolations();
}

// Attach event listeners to UI elements
function attachEventListeners() {
  // Action buttons
  elements.exportCsv.addEventListener('click', exportToCsv);
  elements.clearAll.addEventListener('click', clearAllData);
  elements.refreshData.addEventListener('click', loadViolations);
  
  // Table sorting
  elements.tableHeaders.forEach(header => {
    header.addEventListener('click', () => handleSort(header.dataset.sort));
  });
  
  // Pagination
  elements.prevPage.addEventListener('click', goToPrevPage);
  elements.nextPage.addEventListener('click', goToNextPage);
  
  // Detail panel
  elements.closeDetail.addEventListener('click', closeDetailPanel);
  
  // Close detail panel with ESC key
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && !elements.detailPanel.classList.contains('hidden')) {
      closeDetailPanel();
    }
  });
  
  // Close detail panel when clicking outside
  elements.detailPanel.addEventListener('click', function(e) {
    if (e.target === elements.detailPanel) {
      closeDetailPanel();
    }
  });
}

// Close the detail panel
function closeDetailPanel() {
  elements.detailPanel.classList.add('hidden');
}

// Load violations from Chrome storage
function loadViolations() {
  chrome.runtime.sendMessage({ action: "getViolations" }, function(response) {
    allViolations = response.violations || [];
    sortViolations();
    renderViolationsTable();
    updatePagination();
    updateStats();
  });
}

// Sort violations based on current sort settings
function sortViolations() {
  allViolations.sort((a, b) => {
    const fieldA = a[currentSort.field];
    const fieldB = b[currentSort.field];
    
    let comparison = 0;
    if (fieldA < fieldB) {
      comparison = -1;
    } else if (fieldA > fieldB) {
      comparison = 1;
    }
    
    return currentSort.ascending ? comparison : -comparison;
  });
}

// Handle column sorting
function handleSort(field) {
  if (currentSort.field === field) {
    // Toggle direction if same field
    currentSort.ascending = !currentSort.ascending;
  } else {
    // New field, default to descending for timestamp, ascending for others
    currentSort.field = field;
    currentSort.ascending = field !== 'timestamp';
  }
  
  // Update header indicators
  elements.tableHeaders.forEach(header => {
    if (header.dataset.sort === currentSort.field) {
      header.innerHTML = header.textContent.replace(/[⬆⬇]/g, '') + 
        (currentSort.ascending ? ' ⬆' : ' ⬇');
    } else {
      header.innerHTML = header.textContent.replace(/[⬆⬇]/g, '');
    }
  });
  
  sortViolations();
  renderViolationsTable();
  updatePagination();
}

// Render the violations table with current page data
function renderViolationsTable() {
  elements.violationsBody.innerHTML = '';
  
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = Math.min(startIndex + itemsPerPage, allViolations.length);
  
  if (allViolations.length === 0) {
    const emptyRow = document.createElement('tr');
    emptyRow.innerHTML = '<td colspan="5" style="text-align: center;">No violations found</td>';
    elements.violationsBody.appendChild(emptyRow);
    return;
  }
  
  for (let i = startIndex; i < endIndex; i++) {
    const violation = allViolations[i];
    const row = document.createElement('tr');
    
    // Format timestamp
    const timestamp = new Date(violation.timestamp);
    const formattedTime = timestamp.toLocaleString();
    
    // Ensure URL is a string and truncate if too long
    const url = String(violation.url || '');
    const displayUrl = url.length > 40 
      ? url.substring(0, 37) + '...' 
      : url;
    
    row.innerHTML = `
      <td>${formattedTime}</td>
      <td title="${url}">${displayUrl}</td>
      <td>${violation.directive || 'N/A'}</td>
      <td title="${violation.sourceFile || 'N/A'}">${(violation.sourceFile || 'N/A').split('/').pop()}</td>
      <td class="actions-cell">
        <button class="action-button view-details" data-index="${i}">Details</button>
      </td>
    `;
    
    elements.violationsBody.appendChild(row);
  }
  
  // Attach event listeners to detail buttons
  document.querySelectorAll('.view-details').forEach(button => {
    button.addEventListener('click', () => {
      showViolationDetails(allViolations[button.dataset.index]);
    });
  });
}

// Show detailed information for a violation
function showViolationDetails(violation) {
  const detailContent = elements.detailPanel.querySelector('.detail-content');
  
  // Sort the entries to show important fields first
  const sortedEntries = Object.entries(violation).sort((a, b) => {
    const keyOrder = ['directive', 'blockedUri', 'url', 'sourceFile', 'lineNumber', 'columnNumber', 'sample', 'timestamp'];
    const indexA = keyOrder.indexOf(a[0]);
    const indexB = keyOrder.indexOf(b[0]);
    
    if (indexA !== -1 && indexB !== -1) return indexA - indexB;
    if (indexA !== -1) return -1;
    if (indexB !== -1) return 1;
    return a[0].localeCompare(b[0]);
  });
  
  let detailsHtml = '';
  for (const [key, value] of sortedEntries) {
    // Convert value to string and handle null/undefined values
    let displayValue = (value !== null && value !== undefined) 
      ? String(value) 
      : 'N/A';
    
    // Format the value for better display
    if (key === 'sample') {
      // Special handling for sample as it's often HTML/JS code
      displayValue = `<pre class="pre-wrap sample-code" style="max-height: 300px;">${escapeHtml(displayValue)}</pre>`;
    } else if (key === 'stackTrace' || key === 'stack' || (typeof value === 'string' && value.length > 100)) {
      // For other long text content, use pre-formatted text
      const maxHeight = '200px';
      displayValue = `<pre class="pre-wrap" style="max-height: ${maxHeight};">${escapeHtml(displayValue)}</pre>`;
    } else if (key === 'timestamp' && !isNaN(new Date(value).getTime())) {
      // Format timestamp as a readable date
      displayValue = new Date(value).toLocaleString();
    } else if (key === 'url' || key === 'blockedUri' || key === 'sourceFile') {
      // Format URLs to be clickable
      if (displayValue && displayValue !== 'N/A' && 
          (displayValue.startsWith('http') || displayValue.startsWith('/'))) {
        displayValue = `<a href="${displayValue}" target="_blank" title="${displayValue}">${displayValue}</a>`;
      } else {
        // Escape HTML to prevent XSS
        displayValue = escapeHtml(displayValue);
      }
    } else {
      // Escape HTML to prevent XSS
      displayValue = escapeHtml(displayValue);
    }
    
    // Add scrollable class for longer content that's not wrapped in pre
    const needsScrollClass = !displayValue.includes('<pre') && displayValue.length > 100;
    const scrollClass = needsScrollClass ? 'scrollable' : '';
    
    detailsHtml += `
      <div class="detail-row">
        <div class="detail-label">${key}:</div>
        <div class="detail-value ${scrollClass}">${displayValue}</div>
      </div>
    `;
  }
  
  detailContent.innerHTML = detailsHtml;
  elements.detailPanel.classList.remove('hidden');
  
  // Add event listeners to any links
  detailContent.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      chrome.tabs.create({ url: link.href });
      closeDetailPanel();
    });
  });
}

// Helper function to escape HTML
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Update pagination controls and info
function updatePagination() {
  const totalPages = Math.max(1, Math.ceil(allViolations.length / itemsPerPage));
  elements.pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
  
  elements.prevPage.disabled = currentPage <= 1;
  elements.nextPage.disabled = currentPage >= totalPages;
}

// Go to previous page
function goToPrevPage() {
  if (currentPage > 1) {
    currentPage--;
    renderViolationsTable();
    updatePagination();
  }
}

// Go to next page
function goToNextPage() {
  const totalPages = Math.ceil(allViolations.length / itemsPerPage);
  if (currentPage < totalPages) {
    currentPage++;
    renderViolationsTable();
    updatePagination();
  }
}

// Update statistics display
function updateStats() {
  // Total violations
  const oldTotal = parseInt(elements.totalViolations.textContent) || 0;
  const newTotal = allViolations.length;
  
  elements.totalViolations.textContent = newTotal;
  
  // Highlight if changed
  if (newTotal > oldTotal && oldTotal > 0) {
    elements.totalViolations.classList.add('highlight-change');
    setTimeout(() => {
      elements.totalViolations.classList.remove('highlight-change');
    }, 2000);
  }
  
  // Unique URLs (ensure we handle non-string URLs)
  const uniqueUrls = new Set();
  allViolations.forEach(violation => {
    if (violation.url) {
      uniqueUrls.add(String(violation.url));
    }
  });
  
  const oldUrlCount = parseInt(elements.uniqueUrls.textContent) || 0;
  const newUrlCount = uniqueUrls.size;
  
  elements.uniqueUrls.textContent = newUrlCount;
  
  // Highlight if changed
  if (newUrlCount > oldUrlCount && oldUrlCount > 0) {
    elements.uniqueUrls.classList.add('highlight-change');
    setTimeout(() => {
      elements.uniqueUrls.classList.remove('highlight-change');
    }, 2000);
  }
}

// Export violations to CSV
function exportToCsv() {
  if (allViolations.length === 0) {
    alert('No violations to export');
    return;
  }
  
  // Define the columns to include in the export
  const columns = [
    'timestamp',
    'url',
    'directive',
    'blockedUri',
    'sourceFile',
    'lineNumber',
    'columnNumber',
    'sample'
  ];
  
  // Create CSV header row
  let csvContent = columns.join(',') + '\n';
  
  // Add data rows
  allViolations.forEach(violation => {
    const row = columns.map(column => {
      // Convert to string and use empty string if null or undefined
      let value = (violation[column] !== null && violation[column] !== undefined) 
        ? String(violation[column]) 
        : '';
      
      // Escape quotes and wrap in quotes if contains comma or newline
      if (value.includes(',') || value.includes('\n') || value.includes('"')) {
        value = '"' + value.replace(/"/g, '""') + '"';
      }
      return value;
    });
    csvContent += row.join(',') + '\n';
  });
  
  // Create download link
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  
  // Generate filename with date
  const now = new Date().toISOString().split('T')[0];
  
  link.setAttribute('href', url);
  link.setAttribute('download', `trusted-types-violations_${now}.csv`);
  link.style.display = 'none';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  
  // Clean up
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 100);
}

// Clear all violation data
function clearAllData() {
  if (confirm('Are you sure you want to clear all violation data? This cannot be undone.')) {
    chrome.runtime.sendMessage({ action: "clearViolations" }, function(response) {
      allViolations = [];
      renderViolationsTable();
      updatePagination();
      updateStats();
      alert('All violation data has been cleared.');
    });
  }
}
