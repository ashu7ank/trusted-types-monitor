# Trusted Types Monitor

A Chrome (MV3) extension that monitors, analyzes, and helps fix Trusted Types CSP violations. It adds a dedicated DevTools panel for the full developer experience: live violation stream, clustering, fix guidance, policy generation (including “Perfect Types”), and optional AI-powered analysis.

**Important**: This runs Trusted Types in **Report-Only** mode by injecting a `Content-Security-Policy-Report-Only` header (and a matching `<meta http-equiv>` fallback). That means pages will attempt to POST CSP reports to `/trusted-types-violation`, which may show up as 404s in the target site’s network/server logs. The extension **observes** those reports; it does not send violation data to any external server unless you explicitly enable AI and provide your own API key.

## Architecture

The extension uses a **split UI** approach:

- **Popup** (extension icon): Lightweight dashboard showing stats, recent violations, and a prompt to use DevTools for the full experience.
- **DevTools Panel** (TT Monitor tab): The primary interface. Live violation stream, clustering, fix guidance, policy generator, and AI assistant. Persists as long as DevTools is open.

## Features

### Violation Detection
- Injects Trusted Types CSP headers in Report-Only mode via `declarativeNetRequest` (plus a `<meta http-equiv>` fallback added at `document_start`)
- Captures violations through `securitypolicyviolation` events and `ReportingObserver` (isolated world)
- Patches `XMLHttpRequest` and `fetch` in the page's MAIN world to parse and relay Trusted Types CSP report POST bodies
- Automatic type classification: TrustedHTML, TrustedScript, TrustedScriptURL
- Per-tab violation tracking with tab-aware filtering
- Deduplication within a 2-second window to prevent noise
- Auto-clears per-tab data on **real navigations** (origin/path change) so different pages don’t get mixed together

### DevTools Panel - Live Stream
- Real-time violation feed with instant updates via long-lived background connection
- Sortable columns (time, type, source)
- Full-text search/filter across all violation fields
- Detail sidebar with structured fields, stack traces, and source links
- Direct "Fix" and "Ask AI" actions from any violation
- Resilient reconnection if the MV3 service worker is suspended (panel auto-reconnects and rehydrates state)

### Violation Clustering
- Groups violations by root cause (stack trace analysis, source file + line)
- Sorted by occurrence count to highlight the most impactful issues
- Drill down to fix guidance from any cluster

### Fix Guidance Engine
- Context-aware recommendations based on violation type and content analysis
- Severity assessment (critical, high, medium) with danger explanations
- Step-by-step remediation instructions
- Copy-paste code examples for each fix pattern
- Special handling for: script injection, inline event handlers, iframes, eval patterns, dynamic URLs
- Reference links to MDN, web.dev, OWASP, W3C

### Policy Generator
- **Standard mode**: analyzes observed violations to generate a practical `trustedTypes.createPolicy('default', …)` implementation
  - HTML analysis: extracts tags and attributes from violation samples
  - URL analysis: builds origin allowlists from script URL patterns
  - Script analysis: catalogs eval-like patterns
  - Security warnings for dangerous patterns
- **Perfect Types mode**: generates a migration-oriented policy guide that pushes you toward **zero-policy** Trusted Types using:
  - `Element.setHTML()` + the **Sanitizer API** for HTML sinks (modern browsers)
  - “No escape hatch” guidance for script evaluation sinks
  - Optional named policy suggestions only where unavoidable (script/URL sinks)
- One-click copy (DevTools export is JSON; popup export is CSV)

### AI Assistant (Optional)
- Supports Claude (Anthropic), Gemini (Google), and GPT (OpenAI)
- Multi-turn conversation memory (maintains context across messages)
- API key stored locally, never shared with third parties
- Quick actions: full audit, policy generation, critical issue analysis
- Can be invoked from any violation or fix guide page
- Auto-detects provider from key format

### Performance
- Badge count on extension icon showing violation count per tab
- Global on/off toggle to pause monitoring
- Deduplication in background worker prevents duplicate storage
- Single `getFullState` API call for initial load (violations + clusters + keys)
- Incremental live updates pushed to DevTools panel via `chrome.runtime.connect`
- Periodic background flush to storage and capped storage size (keeps the newest items)

## Installation

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked** and select the project folder
5. Open DevTools on any page to find the **TT Monitor** tab

## Usage

### Quick Start
- The popup shows violation counts and recent items at a glance
- For full analysis, open DevTools (F12) and click the **TT Monitor** tab

### Fix Guidance
- Click **Fix** on any violation or cluster for targeted guidance
- Browse the Fix Guide tab for education on each violation type

### Generating Policies
1. Go to the **Policy Gen** tab in DevTools
2. Choose **Standard** or **Perfect Types** mode
3. Click **Generate**
4. Review code and warnings
5. Copy and adapt for your application

### AI Analysis
1. Open the **AI Assist** tab in DevTools
2. Enter your API key (Claude, Gemini, or GPT)
3. Use quick actions or ask questions in the chat
4. Multi-turn: follow up on previous responses

### Testing the Extension Quickly
- Load the extension, then open `test-page.html` from this repo in a browser tab
- Click the test buttons to generate violations
- Open **DevTools → TT Monitor** to see the live stream, clusters, and fix guidance

## File Structure

```
trusted-types-monitor/
├── manifest.json            # MV3 config: permissions, content scripts, devtools
├── rules.json               # declarativeNetRequest CSP injection rules
├── devtools.html            # DevTools entry point
├── panel.html               # Full DevTools panel UI
├── popup.html               # Lightweight popup dashboard
├── test-page.html           # Test page for generating violations
├── how-to-test.html         # Testing instructions
├── report-violation         # Legacy/diagnostic page (not used by default report interception)
├── css/
│   ├── panel.css            # DevTools panel styles (dark theme, full layout)
│   └── popup.css            # Popup styles (compact dashboard)
└── js/
    ├── background.js        # Service worker: storage, dedup, clustering, guidance, policy, badge
    ├── content.js           # Content script (isolated): CSP events, ReportingObserver
    ├── content-main.js      # Content script (MAIN world): XHR/fetch patching
    ├── devtools.js          # Creates the DevTools panel
    ├── panel.js             # DevTools panel controller: all tab logic, live stream, AI
    ├── popup.js             # Popup controller: stats, recent, export
    └── ai-assistant.js      # AI client: Claude, Gemini, GPT with multi-turn support
```

## Feature Placement

| Feature | Popup | DevTools Panel |
|---------|-------|---------------|
| Violation count (this tab / all) | Yes | Yes |
| Type breakdown bar | Yes | Yes (stats) |
| Recent violations (last 8) | Yes | - |
| Live violation stream | - | Yes |
| Search/filter | - | Yes |
| Violation detail sidebar | - | Yes |
| Clustering | - | Yes |
| Fix guidance | - | Yes |
| Policy generator | - | Yes |
| AI assistant | - | Yes |
| Export (CSV) | Yes | Yes (JSON) |
| Clear violations | Yes | Yes |
| On/off toggle | Yes | Yes |

## Privacy

- All data stored locally in `chrome.storage.local`
- No external server communication by default
- AI features are opt-in with your own API key
- Keys stored locally, sent only to the configured provider
- MAIN world content script only inspects Trusted Types report POST bodies (to `/trusted-types-violation`) to extract violation fields; it does not collect general browsing data

## License

MIT License
