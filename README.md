# Trusted Types Monitor Extension

A Chrome extension that monitors Trusted Types CSP violations across browsed webpages.

## Features

1. **Content Security Policy Implementation**
   - Injects a Trusted Types CSP header in Report-Only mode
   - Works on all webpages being browsed
   - Specifically monitors Trusted Types violations

2. **Violation Detection & Storage**
   - Captures and filters CSP violation reports specific to Trusted Types
   - Stores violation data persistently using Chrome's storage API
   - Records timestamp, URL, violation details, and source information

3. **User Interface**
   - Provides a clean popup interface to display collected violations
   - Shows violations in a structured, tabular format
   - Displays key violation metrics and statistics
   - Features an interactive details panel with advanced content formatting

4. **Export Functionality**
   - CSV export for stored violation data
   - Includes all relevant violation fields in the export

## Installation

### Developer Mode Installation
1. Download the `trusted-types-monitor.zip` file and extract it
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" using the toggle in the top-right corner
4. Click "Load unpacked" and select the extracted `trusted-types-monitor` folder

### From Source
1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" using the toggle in the top-right corner
4. Click "Load unpacked" and select the `trusted-types-monitor` folder

### Testing Your Installation
After installation, you can verify the extension is working properly by opening the included `how-to-test.html` file in your browser. This page provides detailed instructions for generating and viewing test violations.

## Usage

1. **Browsing with Monitoring Active**
   - The extension automatically applies Trusted Types CSP in Report-Only mode to all pages
   - No configuration needed - monitoring begins immediately after installation

2. **Viewing Violations**
   - Click on the extension popup to view recorded violations
   - Violations are displayed in a table with time, URL, directive, and source information
   - Click "Details" to see full violation information in an interactive panel
   - Detailed view supports scrollable content, code formatting, and clickable URLs

3. **Exporting Data**
   - Click "Export CSV" to download all violations
   - The exported file includes timestamps and complete violation details
   - Useful for offline analysis or reporting

4. **Data Management**
   - Use "Clear All" to reset violation storage if needed
   - The extension automatically manages storage to prevent excessive usage

## Technical Details

- Built with Manifest V3
- Uses declarativeNetRequest for header modification
- Implements multiple methods to capture violations:
  - securitypolicyviolation event listener
  - CSP header injection
  - XHR/fetch interception
- Provides unobtrusive monitoring with minimal page impact
- Features responsive design with enhanced UI for violation details
- Optimized for handling large code samples and stack traces

## How It Works

The extension uses several techniques to capture Trusted Types violations:

1. It injects a Content Security Policy header via declarativeNetRequest rules
2. It adds a meta tag with CSP headers as a backup method
3. It listens for security policy violation events
4. It intercepts XHR and fetch requests to capture violation reports

When a violation is detected, it's stored in the extension's local storage and can be viewed in the popup UI.

## Troubleshooting

If no violations are being recorded:
1. Ensure the extension is enabled
2. Check that you're browsing pages that use JavaScript and might be attempting DOM operations
3. Verify that the extension has permissions for the sites you're visiting
4. Check the browser console for any error messages related to the extension
5. Try using the included test page (test-page.html) to generate sample violations
6. Consult the how-to-test.html guide for detailed testing instructions


## Privacy

This extension operates entirely locally. No data is sent to any server, and all violation reports are stored only in your browser's local storage.

## Extension Structure

```
trusted-types-monitor/
├── manifest.json         # Extension configuration
├── rules.json           # declarativeNetRequest rules
├── popup.html           # Main UI
├── how-to-test.html     # Testing guide
├── test-page.html       # Page for generating test violations
├── report-violation     # Endpoint for violation reports
├── css/
│   ├── popup.css               # Main UI styling
│   └── detail-enhancements.css # Specialized UI for violation details
└── js/
    ├── background.js    # Background service worker
    ├── content.js       # Content script for page injection
    └── popup.js         # UI interaction logic
```

## License

MIT License
