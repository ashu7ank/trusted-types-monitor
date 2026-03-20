<p align="center">
  <img src="https://img.shields.io/badge/Chrome-MV3-4285F4?logo=googlechrome&logoColor=white" alt="Chrome MV3" />
  <img src="https://img.shields.io/badge/Trusted_Types-Monitor-E34F26?logo=w3c&logoColor=white" alt="Trusted Types" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License" />
  <img src="https://img.shields.io/badge/Version-3.0-blue" alt="Version 3.0" />
</p>

# Trusted Types Monitor

> A Chrome DevTools extension that **monitors, analyzes, and helps fix** [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API) CSP violations in real time — with clustering, one-click fix guidance, auto-generated policies, and optional AI-powered analysis.

---


## Why This Extension?

Trusted Types is the browser's built-in defense against DOM XSS — the most common class of web vulnerability. But adopting it is hard:

- **Discovery is painful** — violations are buried in console noise and CSP report endpoints.
- **Root-cause analysis is manual** — you have to map each violation back to source code yourself.
- **Migration is daunting** — rewriting every `innerHTML`, `eval`, and `document.write` call takes significant effort.

**Trusted Types Monitor** automates all three stages: it **captures** every violation the moment it fires, **clusters** them by root cause so you know what to fix first, and **generates** the exact policy code you need — all inside a dedicated DevTools panel.

---

## Features

### Violation Detection
- Injects `Content-Security-Policy-Report-Only` headers via `declarativeNetRequest` (using header **append** to avoid clobbering existing site headers, plus a `<meta>` fallback at `document_start`)
- Captures violations through `securitypolicyviolation` events and `ReportingObserver` (isolated world)
- Patches `XMLHttpRequest` and `fetch` in the MAIN world to intercept Trusted Types report POST bodies
- Automatic type classification: **TrustedHTML**, **TrustedScript**, **TrustedScriptURL**
- Per-tab tracking with deduplication (2-second window) and auto-clear on navigation

### DevTools Panel — Live Stream
- Real-time violation feed with instant push updates via long-lived background connection
- Sortable columns, full-text search/filter across all fields
- **Sink-to-source mapping**: extracts the exact DOM sink (e.g. `Element.innerHTML`, `eval()`, `HTMLScriptElement.src`) and shows it in the **Sink** column
- **First-party vs third-party**: origin badge per violation (**1st party / 3rd party**) based on the violation source file origin (supports user-configured aliases for internal CDNs)
- Detail sidebar with structured fields, stack traces, and source links
- Direct **Fix** and **Ask AI** actions from any row
- Resilient reconnection when the MV3 service worker suspends

### Violation Clustering
- Groups violations by root cause (stack trace + source file/line analysis)
- Sorted by occurrence count to surface the most impactful issues first
- One-click drill-down to fix guidance from any cluster

### Fix Guidance Engine
- Context-aware recommendations based on violation type and content
- Severity levels (critical / high / medium) with danger explanations
- Step-by-step remediation with copy-paste code examples
- Special handling for script injection, inline handlers, iframes, eval, dynamic URLs
- **Framework-aware suggestions**: detects common frameworks from violation sources/stack traces (React, Angular, Vue, jQuery, Svelte, Next.js, Nuxt, Webpack) and shows tailored fix patterns
- Reference links to MDN, web.dev, OWASP, and W3C specs

### Insights — Deep Analysis
- **Origin Analysis**: first-party vs third-party breakdown + top third-party origins
- **First-Party Domain Aliases**: treat organization-owned CDNs/asset hosts as first-party (with **Auto-Suggest** to detect likely internal CDNs from captured violations)
- **Sink Map**: groups violations by sink type and shows source locations (file:line:col) where available
- **Policy Scatter Detection**: counts distinct source files and origins; flags medium/high scatter and recommends centralization steps + module pattern
- **Named Policy Recommendations**: suggests 2–4 purpose-specific policy names (e.g. `app-rich-html`, `app-sanitize-html`, `app-script-url`, `app-script-eval`) and generates a centralized policy module you can copy
- **CSP Header Generator**: production-ready CSP headers (Report-Only first, enforcing, meta tag, Nginx, Apache) derived from recommended named policies

### Policy Generator
- **Standard mode** — analyzes observed violations to generate a practical `trustedTypes.createPolicy('default', ...)` with HTML tag/attribute extraction, URL origin allowlists, and script pattern cataloging
- **Perfect Types mode** — migration-oriented guide pushing toward **zero-policy** Trusted Types using `Element.setHTML()` + the Sanitizer API, with fallback named-policy suggestions only where unavoidable
- Security warnings for dangerous patterns, one-click copy

### AI Assistant (Optional)
- Supports **Claude** (Anthropic), **Gemini** (Google), and **GPT** (OpenAI)
- Multi-turn conversation with full context
- Quick actions: full audit, policy review, critical-issue analysis, third-party risk review, centralization strategy
- Uses the extension’s computed context (sinks, origin analysis, named policies, CSP output, detected frameworks, scatter severity, and configured first-party aliases) to keep suggestions consistent with what you see in the UI
- Invokable from any violation row or fix guide
- API key stored locally, never shared with third parties
- Requests have a client-side timeout (30s) with a clear error if the provider is slow/unreachable

### Performance & UX
- Badge count on extension icon per tab
- Global on/off toggle to pause monitoring
- Single `getFullState` API for initial load; incremental live pushes thereafter
- Background deduplication, periodic flush, and capped storage
- Debounced **Insights** refresh (when the Insights tab is active) to reduce UI churn during high-volume violation streams
- Panel performance safeguards: keeps the most recent 1000 violations and renders the first 200 rows by default (use search to narrow)

---

## Installation

### From Source

```bash
# git clone https://github.com/ashu7ank/trusted-types-monitor.git
```

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select the cloned folder
4. Open DevTools on any page → find the **TT Monitor** tab

### Quick Test

Open `test-page.html` from this repo in your browser, click **Run all unsafe tests**, then switch to the **TT Monitor** DevTools tab to see violations stream in.

---

## Usage

### Quick Start
1. The **Popup** shows violation counts and recent items at a glance
2. For full analysis, open DevTools (**F12**) and click the **TT Monitor** tab

### Fix Guidance
Click **Fix** on any violation or cluster for targeted, context-aware remediation steps with copy-paste code.

### Generating Policies
1. Open the **Policy Gen** tab
2. Choose **Standard** or **Perfect Types** mode
3. Click **Generate** → review code + warnings → copy

### Origin Aliases (Internal CDNs / Related Domains)
If your app loads scripts from organization-owned domains that don’t match the page origin (e.g. internal CDNs), you can prevent them from being treated as “third-party”:

1. Open **Insights** → **Origin Analysis**
2. Under **First-Party Domain Aliases**, click **Auto-Suggest** (recommended), or add domains manually
3. The Live Stream origin badges, Origin Analysis, Scatter Analysis, and AI context will refresh to match the new classification (debounced during rapid bursts to keep the panel responsive)
   - You can paste a bare hostname (e.g. `cdn.internal.example`) or a full URL — the host is normalized and validated
   - Existing captured violations are reclassified when state is refreshed, so you don’t need to wait for new violations to see the impact

### AI Analysis
1. Open the **AI Assist** tab
2. Enter your API key (Claude, Gemini, or GPT)
3. Use quick actions or ask questions — multi-turn context is maintained

### Exporting Data
- In the **DevTools panel**, click **Export** to download a JSON snapshot (violations + clusters metadata).
- In the **Popup**, click **Export** to download a CSV of violations for quick sharing.

---

## File Structure

```
trusted-types-monitor/
├── manifest.json            # MV3 config: permissions, content scripts, devtools
├── rules.json               # declarativeNetRequest CSP injection rules
├── devtools.html            # DevTools entry point
├── panel.html               # Full DevTools panel UI
├── popup.html               # Lightweight popup dashboard
├── test-page.html           # Test page for generating violations
├── how-to-test.html         # Testing guide
├── screenshots/             # README screenshots (9 images)
├── css/
│   ├── panel.css            # DevTools panel styles (dark theme)
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

---

## Feature Matrix

| Feature | Popup | DevTools Panel |
|---|:---:|:---:|
| Violation count (tab / all) | Yes | Yes |
| Type breakdown bar | Yes | Yes |
| Recent violations (last 8) | Yes | — |
| Live violation stream | — | Yes |
| Sink-to-source mapping (Sink column) | — | Yes |
| First-party vs third-party badges | — | Yes |
| Search / filter | — | Yes |
| Violation detail sidebar | — | Yes |
| Clustering by root cause | — | Yes |
| Fix guidance engine | — | Yes |
| Framework detection + tailored guidance | — | Yes |
| Origin analysis + alias configuration | — | Yes |
| Scatter analysis + centralization recommendation | — | Yes |
| Named policy recommendations + centralized module | — | Yes |
| CSP header generator | — | Yes |
| Policy generator | — | Yes |
| AI assistant | — | Yes |
| Export | CSV | JSON |
| Clear violations | Yes | Yes |
| On / off toggle | Yes | Yes |

---

## Privacy

- All data stored locally in `chrome.storage.local` — nothing leaves your machine by default
- AI features are **opt-in**: you provide your own API key, and requests go directly to the provider you choose
- MAIN world content script only inspects Trusted Types report POST bodies; it does not collect general browsing data
- The extension runs CSP in **Report-Only** mode, so it observes but never blocks page behavior

---

## Important Note

Running in Report-Only mode means pages will attempt to POST CSP reports to `/trusted-types-violation`, which may appear as 404s in the target site's network or server logs. This is expected behavior — the extension intercepts these reports locally.

---

## License

[MIT](LICENSE)
