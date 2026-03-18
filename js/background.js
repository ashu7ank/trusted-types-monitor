// Background service worker for Trusted Types Monitor
const MAX_STORAGE_ITEMS = 1000;
const DEDUP_WINDOW_MS = 2000;

let pendingReports = [];
let recentHashes = new Map();
let monitoringEnabled = true;
let storeInFlight = false;
const recentlyClearedTabs = new Set();

// ── Deduplication ──

function violationHash(v) {
  return `${v.tabId}|${v.url}|${v.sourceFile}|${v.lineNumber}|${v.directive}|${(v.sample || "").substring(0, 80)}`;
}

function isDuplicate(violation) {
  const hash = violationHash(violation);
  const now = Date.now();
  const prev = recentHashes.get(hash);
  if (prev && (now - prev) < DEDUP_WINDOW_MS) return true;
  recentHashes.set(hash, now);
  if (recentHashes.size > 500) {
    const cutoff = now - DEDUP_WINDOW_MS * 2;
    for (const [k, t] of recentHashes) {
      if (t < cutoff) recentHashes.delete(k);
    }
  }
  return false;
}

// ── Violation Processing ──

function processViolation(violation, tabId) {
  if (!monitoringEnabled) return;

  const normalized = {
    timestamp: violation.timestamp || new Date().toISOString(),
    url: violation.url || "unknown",
    directive: violation.directive || "unknown",
    blockedUri: violation.blockedUri || "unknown",
    sourceFile: violation.sourceFile || "unknown",
    lineNumber: violation.lineNumber || "unknown",
    columnNumber: violation.columnNumber || "unknown",
    sample: violation.sample || "unknown",
    stackTrace: violation.stackTrace || "",
    endpoint: violation.endpoint || "",
    tabId: tabId > 0 ? tabId : -1,
    violationType: inferViolationType(violation)
  };

  if (isDuplicate(normalized)) return;

  pendingReports.push(normalized);

  // Push ONLY to the DevTools panel watching this specific tab
  for (const [port, portTabId] of panelPorts.entries()) {
    if (portTabId === tabId && tabId > 0) {
      try { port.postMessage({ action: "newViolation", violation: normalized }); } catch {}
    }
  }

  if (pendingReports.length >= 5) storeViolations();

  updateBadge(tabId);
}

function inferViolationType(violation) {
  const directive = (violation.directive || "").toLowerCase();
  const sample = (violation.sample || "").toLowerCase();
  const rawSample = (violation.sample || "");
  const blockedUri = (violation.blockedUri || "").toLowerCase();

  // Browser violation samples often use "SinkType property|value" format,
  // e.g. "HTMLScriptElement src|https://..." or "Element innerHTML|<div>..."
  // Also: "Element.setAttribute|..." or "Function|code..."
  const pipeIdx = rawSample.indexOf("|");
  const sinkProperty = (pipeIdx >= 0 ? rawSample.substring(0, pipeIdx) : rawSample)
    .toLowerCase().trim();
  const sinkValue = pipeIdx >= 0 ? rawSample.substring(pipeIdx + 1) : "";

  if (directive !== "" && directive !== "unknown" &&
      !directive.includes("trusted-types")) {
    return "Unknown";
  }

  // ── TrustedScript ──
  // eval, setTimeout/setInterval with strings, new Function, script.text
  // Browser sink format: "Function|code..." or "eval|code..."
  if (sample.includes("eval(") || sample.includes("eval ") ||
      /\beval\b/.test(sample) || sample.includes("function(") || sample.includes("function (") ||
      sample.includes("settimeout") || sample.includes("setinterval") ||
      sample.includes("new function") ||
      sinkProperty.includes("eval") ||
      /^function\b/.test(sinkProperty) ||
      /htmlscriptelement\s+(text|textcontent|innertext)\b/.test(sinkProperty)) {
    return "TrustedScript";
  }

  // ── TrustedScriptURL ──
  // script.src, Worker(), import(), iframe.src, embed.src, object.data
  // Browser format: "HTMLScriptElement src|URL" or "Worker constructor|URL"
  const urlSinkPatterns = [
    "script src", "script.src", "scriptelement src",
    "worker constructor", "worker(",
    "import(", "importscripts",
    "embed src", "object data"
  ];
  const blockedIsScriptUrl = blockedUri.includes(".js") ||
      (blockedUri.startsWith("http") && !/<[a-zA-Z]/.test(sample));
  if (blockedIsScriptUrl || blockedUri.startsWith("data:") ||
      urlSinkPatterns.some(p => sinkProperty.includes(p)) ||
      /htmlscriptelement\b/.test(sinkProperty) ||
      /htmliframeelement\s+src\b/.test(sinkProperty) ||
      /\bsrc[=|]/.test(sinkProperty)) {
    return "TrustedScriptURL";
  }

  // ── TrustedHTML ──
  // innerHTML, outerHTML, insertAdjacentHTML, document.write, DOMParser, srcdoc
  // Browser format: "Element innerHTML|<markup...>" or "Element.insertAdjacentHTML|..."
  const htmlSinkPatterns = [
    "innerhtml", "outerhtml", "insertadjacenthtml",
    "document.write", "domparser", "createcontextualfragment",
    "srcdoc"
  ];
  if (/<[a-zA-Z]/.test(sample) ||
      htmlSinkPatterns.some(p => sinkProperty.includes(p) || sample.includes(p)) ||
      /\binnerhtml[=|]/.test(sample) || /\bouterhtml[=|]/.test(sample)) {
    return "TrustedHTML";
  }

  // ── Element.setAttribute ──
  // Browser format: "Element.setAttribute|<attrName, value>"
  // Type depends on which attribute: src-like → URL, srcdoc → HTML, else → Script
  if (sinkProperty.includes("setattribute")) {
    const attrMatch = sinkValue.match(/^<?\s*(\w[\w-]*)/);
    const attrName = attrMatch ? attrMatch[1].toLowerCase() : "";
    if (/^(src|href|action|formaction|codebase|data|poster|background)$/.test(attrName)) {
      return "TrustedScriptURL";
    }
    if (attrName === "srcdoc") return "TrustedHTML";
    if (/^on/.test(attrName)) return "TrustedScript";
    return "TrustedScriptURL";
  }

  // ── Fallback: element-based inference ──
  if (/^html\w*element\b/.test(sinkProperty) || /^element\b/.test(sinkProperty)) {
    if (/\bsrc\b/.test(sinkProperty)) return "TrustedScriptURL";
    if (/\bhtml\b/.test(sinkProperty)) return "TrustedHTML";
  }

  // ── Last resort: use blockedUri "trusted-types-sink" as a TT violation signal ──
  // If we get here, the browser confirmed it's a TT violation but the sample didn't
  // match specific patterns. Attempt classification from any remaining clues.
  if (blockedUri === "trusted-types-sink" || directive.includes("require-trusted-types")) {
    if (/<[a-zA-Z]/.test(rawSample)) return "TrustedHTML";
    if (/^https?:|^data:|\.js\b/i.test(sinkValue)) return "TrustedScriptURL";
    return "TrustedScript";
  }

  return "Unknown";
}

// ── Badge ──

function updateBadge(tabId) {
  chrome.storage.local.get(["violations"], (result) => {
    const all = [...(result.violations || []), ...pendingReports];

    if (tabId > 0) {
      const tabCount = all.filter(v => v.tabId === tabId).length;
      chrome.action.setBadgeText({ text: tabCount > 0 ? String(tabCount) : "", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
    }
  });
}

// ── Clustering (per-call, no global cache to avoid tabId mismatch) ──

function clusterViolations(violations) {
  const clusterMap = new Map();

  for (const v of violations) {
    const rootCause = computeRootCause(v);
    const key = rootCause + "|" + v.violationType;

    if (clusterMap.has(key)) {
      const c = clusterMap.get(key);
      c.count++;
      c.violations.push(v);
      if (v.timestamp > c.lastSeen) c.lastSeen = v.timestamp;
      if (v.timestamp < c.firstSeen) c.firstSeen = v.timestamp;
    } else {
      clusterMap.set(key, {
        id: key,
        rootCause,
        violationType: v.violationType,
        sourceFile: v.sourceFile,
        lineNumber: v.lineNumber,
        columnNumber: v.columnNumber,
        samplePreview: (v.sample || "").substring(0, 120),
        count: 1,
        firstSeen: v.timestamp,
        lastSeen: v.timestamp,
        violations: [v]
      });
    }
  }

  return [...clusterMap.values()].sort((a, b) => b.count - a.count);
}

function computeRootCause(violation) {
  if (violation.stackTrace) {
    const rootFrame = extractRootFrame(violation.stackTrace);
    if (rootFrame) return rootFrame;
  }
  if (violation.sourceFile && violation.sourceFile !== "unknown" &&
      violation.lineNumber && violation.lineNumber !== "unknown") {
    return `${violation.sourceFile}:${violation.lineNumber}:${violation.columnNumber || "?"}`;
  }
  return `${violation.url}|${violation.directive}|${(violation.sample || "").substring(0, 60)}`;
}

function extractRootFrame(stackTrace) {
  if (!stackTrace) return null;
  const lines = stackTrace.split("\n").map(l => l.trim()).filter(l => l.startsWith("at "));
  const meaningful = lines.slice(2);
  if (meaningful.length > 0) {
    const match = meaningful[0].match(/at\s+(?:(.+?)\s+)?\(?(https?:\/\/.+?):(\d+):(\d+)\)?/);
    if (match) {
      return `${match[1] || "<anonymous>"} (${match[2]}:${match[3]}:${match[4]})`;
    }
    return meaningful[0].replace(/^at\s+/, "");
  }
  return null;
}

// ── Policy Generation ──

function generatePolicy(violations) {
  const htmlSamples = new Set();
  const scriptSamples = new Set();
  const urlPatterns = new Set();

  for (const v of violations) {
    const type = v.violationType || inferViolationType(v);
    const sample = v.sample || "";
    if (sample === "unknown") continue;

    switch (type) {
      case "TrustedHTML":
        htmlSamples.add(sample);
        break;
      case "TrustedScript":
        scriptSamples.add(sample);
        break;
      case "TrustedScriptURL": {
        const urlStr = v.blockedUri !== "unknown" ? v.blockedUri : sample;
        if (urlStr && urlStr !== "unknown") {
          try { urlPatterns.add(new URL(urlStr).origin); }
          catch { urlPatterns.add(urlStr); }
        }
        break;
      }
    }
  }

  return buildPolicyCode(
    analyzeHtmlSamples([...htmlSamples]),
    [...scriptSamples],
    [...urlPatterns]
  );
}

function analyzeHtmlSamples(samples) {
  const tags = new Set(), attrs = new Set(), rawFragments = [];
  for (const s of samples) {
    (s.match(/<([a-zA-Z][a-zA-Z0-9]*)/g) || []).forEach(t => tags.add(t.substring(1).toLowerCase()));
    (s.match(/\s([a-zA-Z-]+)\s*=/g) || []).forEach(a => attrs.add(a.trim().replace("=", "").toLowerCase()));
    if (s.length <= 200) rawFragments.push(s);
  }
  return { tags: [...tags], attrs: [...attrs], rawFragments, totalSamples: samples.length };
}

function buildPolicyCode(htmlAnalysis, scriptList, urlList) {
  const l = [];
  l.push("// Auto-generated Trusted Types default policy");
  l.push("// Review and tighten before deploying to production\n");
  if (urlList.length > 0) {
    l.push("const urlAllowlist = [");
    urlList.forEach(u => l.push(`  "${u}",`));
    l.push("];\n");
  }
  if (scriptList.length > 0) {
    l.push("const scriptAllowlist = [");
    scriptList.forEach(s => l.push(`  ${JSON.stringify(s)},`));
    l.push("];\n");
  }
  l.push("if (window.trustedTypes && trustedTypes.createPolicy) {");
  l.push("  trustedTypes.createPolicy('default', {");
  l.push("    createHTML: (input) => {");
  if (htmlAnalysis.tags.length > 0) {
    l.push("      // Detected tags: " + htmlAnalysis.tags.join(", "));
    l.push("      // Consider: DOMPurify.sanitize(input, {");
    if (htmlAnalysis.tags.length) l.push("      //   ADD_TAGS: [" + htmlAnalysis.tags.map(t => `'${t}'`).join(", ") + "],");
    if (htmlAnalysis.attrs.length) l.push("      //   ADD_ATTR: [" + htmlAnalysis.attrs.map(a => `'${a}'`).join(", ") + "],");
    l.push("      // })");
  }
  l.push("      // WARNING: Returning raw input is insecure. Use a sanitizer.");
  l.push("      return input;");
  l.push("    },\n");
  l.push("    createScriptURL: (input) => {");
  if (urlList.length > 0) {
    l.push("      if (urlAllowlist.some(u => input.startsWith(u))) return input;");
    l.push("      throw new TypeError('Script URL not in allowlist: ' + input);");
  } else {
    l.push("      // WARNING: Add URL validation.");
    l.push("      return input;");
  }
  l.push("    },\n");
  l.push("    createScript: (input) => {");
  if (scriptList.length > 0) {
    l.push("      if (scriptAllowlist.includes(input)) return input;");
    l.push("      throw new TypeError('Script not in allowlist');");
  } else {
    l.push("      // WARNING: Avoid eval-like patterns.");
    l.push("      return input;");
  }
  l.push("    },");
  l.push("  });");
  l.push("}");
  return l.join("\n");
}

// ── Perfect Types Policy Generation ──

function generatePerfectTypesPolicy(violations) {
  const htmlSamples = new Set();
  const scriptSamples = new Set();
  const urlPatterns = new Set();
  const htmlSinkNames = new Set();

  for (const v of violations) {
    const type = v.violationType || inferViolationType(v);
    const sample = v.sample || "";
    if (sample === "unknown") continue;
    const sinkPart = sample.split("|")[0].trim();

    switch (type) {
      case "TrustedHTML":
        htmlSamples.add(sample);
        if (sinkPart) htmlSinkNames.add(sinkPart);
        break;
      case "TrustedScript":
        scriptSamples.add(sample);
        break;
      case "TrustedScriptURL": {
        const urlStr = v.blockedUri !== "unknown" ? v.blockedUri : sample;
        if (urlStr && urlStr !== "unknown") {
          try { urlPatterns.add(new URL(urlStr).origin); }
          catch { urlPatterns.add(urlStr); }
        }
        break;
      }
    }
  }

  const htmlAnalysis = analyzeHtmlSamples([...htmlSamples]);
  return buildPerfectTypesCode(htmlAnalysis, htmlSinkNames, [...scriptSamples], [...urlPatterns]);
}

function buildPerfectTypesCode(htmlAnalysis, htmlSinkNames, scriptList, urlList) {
  const l = [];

  l.push("// ═══════════════════════════════════════════════════════════════");
  l.push("// Perfect Types - Zero-Policy Trusted Types with setHTML()");
  l.push("// Reference: https://frederikbraun.de/perfect-types-with-sethtml.html");
  l.push("// ═══════════════════════════════════════════════════════════════\n");

  l.push("// ── Step 1: CSP Header ──");
  l.push("// Add this Content-Security-Policy header to your server response:");
  l.push("//");
  l.push("//   Content-Security-Policy: require-trusted-types-for 'script'; trusted-types 'none';");
  l.push("//");
  l.push("// This blocks ALL legacy HTML parsing sinks (innerHTML, document.write, etc.)");
  l.push("// and forbids creating any Trusted Types policy — the only way to insert HTML");
  l.push("// is via the safe Sanitizer API: setHTML() and Document.parseHTML().\n");

  if (htmlAnalysis.totalSamples > 0) {
    l.push("// ── Step 2: Migrate HTML Sinks to setHTML() ──");
    l.push("// " + htmlAnalysis.totalSamples + " HTML violation(s) detected. Replace each innerHTML/outerHTML/");
    l.push("// insertAdjacentHTML/document.write call with setHTML().\n");

    if (htmlSinkNames.size > 0) {
      l.push("// Observed sinks to migrate:");
      for (const name of htmlSinkNames) {
        l.push("//   - " + name);
      }
      l.push("");
    }

    l.push("// BEFORE (blocked by Perfect Types CSP):");
    l.push("//   element.innerHTML = htmlString;");
    l.push("//");
    l.push("// AFTER (safe — sanitizes automatically):");
    l.push("element.setHTML(htmlString);\n");

    if (htmlAnalysis.tags.length > 0) {
      l.push("// Your violations use these tags: " + htmlAnalysis.tags.join(", "));
      l.push("// If you need to preserve specific elements, provide a custom Sanitizer config:");
      const allowTags = htmlAnalysis.tags
        .filter(t => !["script", "object", "embed", "applet"].includes(t));
      if (allowTags.length > 0) {
        l.push("const sanitizerConfig = new Sanitizer({");
        l.push("  allowElements: [" + allowTags.map(t => `'${t}'`).join(", ") + "],");
        if (htmlAnalysis.attrs.length > 0) {
          const safeAttrs = htmlAnalysis.attrs
            .filter(a => !a.startsWith("on"));
          if (safeAttrs.length > 0) {
            l.push("  allowAttributes: {");
            for (const a of safeAttrs) {
              l.push(`    '${a}': ['*'],`);
            }
            l.push("  },");
          }
        }
        l.push("});\n");
        l.push("element.setHTML(htmlString, { sanitizer: sanitizerConfig });");
      }
    } else {
      l.push("// Default setHTML() strips all dangerous elements (<script>, event handlers,");
      l.push("// <object>, <embed>) while preserving safe markup. No config needed.");
    }

    l.push("\n// For fragments not inserted directly into the DOM:");
    l.push("// const doc = Document.parseHTML(htmlString);");
    l.push("// const content = doc.querySelector('.my-element').cloneNode(true);");
    l.push("// container.appendChild(content);");
  }

  if (scriptList.length > 0) {
    l.push("\n\n// ── Script Sinks (Not Covered by setHTML) ──");
    l.push("// " + scriptList.length + " eval-like violation(s) detected. These require refactoring —");
    l.push("// Perfect Types blocks all script evaluation sinks with no escape hatch.");
    l.push("//");
    l.push("// Refactoring guidance:");
    l.push("//   - Replace eval(jsonStr) with JSON.parse(jsonStr)");
    l.push("//   - Replace setTimeout('code', ms) with setTimeout(() => code, ms)");
    l.push("//   - Replace new Function('code') with a static function import");
  }

  if (urlList.length > 0) {
    l.push("\n\n// ── Script URL Sinks (Not Covered by setHTML) ──");
    l.push("// " + urlList.length + " script URL pattern(s) detected. Perfect Types blocks dynamic");
    l.push("// script loading — use static <script src=\"...\"> tags or import() instead.");
    l.push("//");
    l.push("// Detected origins:");
    for (const u of urlList) {
      l.push("//   - " + u);
    }
    l.push("//");
    l.push("// Migration: convert dynamic script.src assignments to static imports");
    l.push("// or bundled modules. If a runtime policy is unavoidable, Perfect Types");
    l.push("// cannot be used — fall back to Standard Policy mode.");
  }

  if (scriptList.length > 0 || urlList.length > 0) {
    l.push("\n\n// ── Hybrid Approach ──");
    l.push("// Since Script/URL sinks were detected, you may need a hybrid CSP that");
    l.push("// allows a named policy only for those sinks while blocking HTML sinks:");
    l.push("//");
    l.push("//   Content-Security-Policy: require-trusted-types-for 'script'; trusted-types 'my-script-policy';");
    l.push("//");
    l.push("// Use setHTML() for all HTML sinks and the named policy only for script/URL sinks:");

    if (urlList.length > 0) {
      l.push("\nconst urlAllowlist = [");
      urlList.forEach(u => l.push(`  "${u}",`));
      l.push("];\n");
    }

    l.push("if (window.trustedTypes && trustedTypes.createPolicy) {");
    l.push("  trustedTypes.createPolicy('my-script-policy', {");
    if (urlList.length > 0) {
      l.push("    createScriptURL: (input) => {");
      l.push("      if (urlAllowlist.some(u => input.startsWith(u))) return input;");
      l.push("      throw new TypeError('Script URL not in allowlist: ' + input);");
      l.push("    },");
    }
    if (scriptList.length > 0) {
      l.push("    createScript: (input) => {");
      l.push("      // Validate or reject — refactoring is preferred over allowing");
      l.push("      throw new TypeError('Blocked script evaluation: ' + input.slice(0, 50));");
      l.push("    },");
    }
    l.push("  });");
    l.push("}");
  }

  l.push("\n\n// ── Browser Support ──");
  l.push("// setHTML(): Chrome 124+, Firefox 130+, Safari 18.2+");
  l.push("// Trusted Types: Chrome 83+, Edge 83+ (Firefox/Safari behind flag)");
  l.push("// For older browsers, use DOMPurify as a fallback — see Standard Policy mode.");

  return l.join("\n");
}

// ── Fix Guidance ──

function getFixGuidance(violation) {
  const type = violation.violationType || inferViolationType(violation);
  const sample = violation.sample || "";
  const g = { violationType: type, severity: "high", title: "", explanation: "", fixSteps: [], codeExample: "", references: [], sinkType: "", dangerLevel: "" };
  switch (type) {
    case "TrustedHTML": return buildHtmlGuidance(g, sample, violation);
    case "TrustedScript": return buildScriptGuidance(g, sample, violation);
    case "TrustedScriptURL": return buildScriptUrlGuidance(g, sample, violation);
    default: return buildGenericGuidance(g, sample, violation);
  }
}

function buildHtmlGuidance(g, sample, v) {
  g.title = "Unsafe HTML Assignment Detected";
  g.sinkType = "HTML Sink (innerHTML, outerHTML, insertAdjacentHTML, document.write)";
  g.dangerLevel = "High - Can lead to XSS";
  const hasScript = /<script/i.test(sample), hasEvent = /\bon\w+\s*=/i.test(sample), hasIframe = /<iframe/i.test(sample), hasObj = /<(object|embed|applet)/i.test(sample);

  const setHtmlNote = "\n\n// BEST: Use the Sanitizer API (no library needed, Chrome 124+/Firefox 130+/Safari 18.2+):\nelement.setHTML(userContent);\n// With custom config:\nelement.setHTML(userContent, { sanitizer: new Sanitizer({\n  allowElements: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li']\n}) });";

  if (hasScript) {
    g.severity = "critical";
    g.explanation = "Raw string with <script> tag assigned to HTML sink - most dangerous XSS form.";
    g.fixSteps = [
      "BEST: Replace innerHTML with element.setHTML() (Sanitizer API) - strips <script> natively with zero config",
      "Remove <script> tags from HTML strings",
      "Use document.createElement('script') + .src for dynamic scripts",
      "Sanitize with DOMPurify inside a Trusted Types policy (legacy fallback)",
      "For zero-policy security, use Perfect Types CSP: trusted-types 'none'"
    ];
    g.codeExample = "// BEFORE:\nelement.innerHTML = userContent;\n\n// AFTER (DOMPurify + policy):\nimport DOMPurify from 'dompurify';\nconst policy = trustedTypes.createPolicy('sanitize-html', {\n  createHTML: (input) => DOMPurify.sanitize(input)\n});\nelement.innerHTML = policy.createHTML(userContent);" + setHtmlNote;
  } else if (hasEvent) {
    g.severity = "critical";
    g.explanation = "HTML with inline event handlers (onclick, onerror) - equivalent to script execution.";
    g.fixSteps = [
      "BEST: Replace innerHTML with element.setHTML() - strips event handlers natively",
      "Remove inline event handlers from HTML strings",
      "Use addEventListener() instead",
      "Sanitize with DOMPurify (strips handlers by default)"
    ];
    g.codeExample = "// BEFORE:\nel.innerHTML = '<button onclick=\"doStuff()\">Click</button>';\n\n// AFTER (DOM API):\nconst btn = document.createElement('button');\nbtn.textContent = 'Click';\nbtn.addEventListener('click', doStuff);\nel.appendChild(btn);" + setHtmlNote;
  } else if (hasIframe || hasObj) {
    g.severity = "critical";
    g.explanation = "HTML with <iframe>/<object>/<embed> - can load arbitrary content.";
    g.fixSteps = [
      "BEST: Replace innerHTML with element.setHTML() - blocks dangerous elements by default",
      "Create elements with document.createElement",
      "Validate src against origin allowlist",
      "Use sandbox attribute on iframes"
    ];
    g.codeExample = "// BEFORE:\ncontainer.innerHTML = '<iframe src=\"' + url + '\"></iframe>';\n\n// AFTER (DOM API):\nconst iframe = document.createElement('iframe');\nconst allowed = ['https://trusted.example.com'];\nconst parsed = new URL(url);\nif (allowed.includes(parsed.origin)) {\n  iframe.src = url;\n  iframe.sandbox = 'allow-scripts';\n  container.appendChild(iframe);\n}" + setHtmlNote;
  } else {
    g.explanation = "Raw string assigned to HTML sink. Can become exploitable if user-controlled data reaches it.";
    g.fixSteps = [
      "BEST: Replace innerHTML with element.setHTML() (Sanitizer API) - safe by default",
      "Use textContent/innerText for plain text",
      "Use DOM APIs (createElement) for structured content",
      "Sanitize with DOMPurify inside a Trusted Types policy (legacy fallback)",
      "For zero-policy security, use Perfect Types CSP: trusted-types 'none'"
    ];
    g.codeExample = "// OPTION 1: Plain text\nelement.textContent = data;\n\n// OPTION 2: DOM APIs\nconst p = document.createElement('p');\np.textContent = data;\ncontainer.appendChild(p);\n\n// OPTION 3: Trusted Types + DOMPurify\nconst policy = trustedTypes.createPolicy('my-component', {\n  createHTML: (input) => DOMPurify.sanitize(input)\n});\nelement.innerHTML = policy.createHTML(data);" + setHtmlNote;
  }
  g.references = [
    { title: "MDN: Element.setHTML()", url: "https://developer.mozilla.org/en-US/docs/Web/API/Element/setHTML" },
    { title: "MDN: Sanitizer API", url: "https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API" },
    { title: "Perfect Types with setHTML()", url: "https://frederikbraun.de/perfect-types-with-sethtml.html" },
    { title: "MDN: Trusted Types API", url: "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API" },
    { title: "web.dev: Trusted Types", url: "https://web.dev/articles/trusted-types" },
    { title: "DOMPurify", url: "https://github.com/cure53/DOMPurify" },
    { title: "OWASP XSS Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html" }
  ];
  return g;
}

function buildScriptGuidance(g, sample, v) {
  g.title = "Unsafe Script Evaluation Detected"; g.sinkType = "Script Sink (eval, setTimeout/setInterval string, new Function)"; g.dangerLevel = "Critical - Direct code execution"; g.severity = "critical";
  const hasEval = /\beval\b/i.test(sample) || (v.directive || "").includes("eval"), hasTimeout = /set(Timeout|Interval)/i.test(sample);
  if (hasEval) { g.explanation = "eval() used with raw string - allows arbitrary code execution."; g.fixSteps = ["Replace eval() with JSON.parse() for JSON", "Restructure logic to avoid dynamic evaluation", "Create named policy with strict validation if unavoidable", "Use Web Worker for sandboxed evaluation"]; g.codeExample = "// BEFORE:\neval(jsonString);\n\n// AFTER (JSON):\nconst data = JSON.parse(jsonString);\n\n// AFTER (policy):\nconst policy = trustedTypes.createPolicy('eval-guard', {\n  createScript: (input) => {\n    if (isKnownSafe(input)) return input;\n    throw new TypeError('Blocked: ' + input.slice(0, 50));\n  }\n});"; }
  else if (hasTimeout) { g.explanation = "setTimeout/setInterval called with string argument - evaluated as code."; g.fixSteps = ["Use arrow function or function reference instead", "Refactor if string comes from user input", "Policy only as last resort for legacy code"]; g.codeExample = "// BEFORE:\nsetTimeout(\"doSomething()\", 1000);\n\n// AFTER:\nsetTimeout(() => doSomething(), 1000);\nsetTimeout(doSomething, 1000);"; }
  else { g.explanation = "Raw string passed to script evaluation sink."; g.fixSteps = ["Identify the consuming API", "Refactor to avoid string-based evaluation", "Create strict policy with input validation", "Audit all callers"]; g.codeExample = "const policy = trustedTypes.createPolicy('script-guard', {\n  createScript: (input) => {\n    const allowed = ['expr1', 'expr2'];\n    if (allowed.includes(input)) return input;\n    throw new TypeError('Blocked: ' + input.slice(0, 50));\n  }\n});"; }
  g.references = [{ title: "MDN: Trusted Types API", url: "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API" }, { title: "MDN: eval() dangers", url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!" }, { title: "web.dev: Trusted Types", url: "https://web.dev/articles/trusted-types" }];
  return g;
}

function buildScriptUrlGuidance(g, sample, v) {
  g.title = "Unsafe Script URL Assignment"; g.sinkType = "Script URL Sink (script.src, Worker(), import())"; g.dangerLevel = "Critical - Can load arbitrary scripts"; g.severity = "critical";
  g.explanation = "Raw URL assigned to script-loading sink. Attacker could load arbitrary JS."; g.fixSteps = ["Validate URL against trusted origin allowlist", "Use policy checking protocol and hostname", "Prefer static script URLs", "Restrict to same-origin or specific CDNs", "Never build URLs from user input"]; g.codeExample = "const allowedOrigins = [\n  'https://cdn.example.com',\n  location.origin\n];\nconst policy = trustedTypes.createPolicy('script-url-guard', {\n  createScriptURL: (input) => {\n    try {\n      const url = new URL(input, location.href);\n      if (allowedOrigins.includes(url.origin)) return url.href;\n    } catch {}\n    throw new TypeError('Blocked: ' + input.slice(0, 100));\n  }\n});\nscript.src = policy.createScriptURL(dynamicUrl);";
  g.references = [{ title: "MDN: Trusted Types API", url: "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API" }, { title: "web.dev: Trusted Types", url: "https://web.dev/articles/trusted-types" }];
  return g;
}

function buildGenericGuidance(g) {
  g.title = "Trusted Types Violation Detected"; g.sinkType = "Unknown DOM sink"; g.dangerLevel = "Medium"; g.severity = "medium";
  g.explanation = "Violation detected but sink type could not be determined. Check stack trace."; g.fixSteps = ["Check stack trace for the triggering DOM API", "Determine sink type (HTML/Script/URL)", "Apply appropriate policy", "See references for complete sink list"]; g.codeExample = "if (window.trustedTypes && trustedTypes.createPolicy) {\n  const policy = trustedTypes.createPolicy('my-policy', {\n    createHTML: (input) => { /* sanitize */ return input; },\n    createScript: (input) => { /* validate */ return input; },\n    createScriptURL: (input) => { /* allowlist */ return input; }\n  });\n}";
  g.references = [{ title: "MDN: Trusted Types API", url: "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API" }, { title: "web.dev: Trusted Types", url: "https://web.dev/articles/trusted-types" }, { title: "W3C Spec", url: "https://w3c.github.io/trusted-types/dist/spec/" }];
  return g;
}

// ── Storage (with lock to prevent read-modify-write race) ──

function storeViolations() {
  if (pendingReports.length === 0) return;
  if (storeInFlight) return;
  storeInFlight = true;

  const batch = [...pendingReports];
  pendingReports = [];

  chrome.storage.local.get(["violations"], (result) => {
    // Drop any batch items whose tab was cleared while this write was in-flight
    const safeBatch = recentlyClearedTabs.size > 0
      ? batch.filter(v => !recentlyClearedTabs.has(v.tabId))
      : batch;
    recentlyClearedTabs.clear();

    let violations = [...(result.violations || []), ...safeBatch];
    if (violations.length > MAX_STORAGE_ITEMS) {
      violations = violations.slice(violations.length - MAX_STORAGE_ITEMS);
    }

    chrome.storage.local.set({ violations }, () => {
      storeInFlight = false;
      chrome.runtime.sendMessage({ action: "violationsUpdated", count: violations.length }).catch(() => {});
      const tabIds = new Set(safeBatch.map(v => v.tabId).filter(id => id > 0));
      tabIds.forEach(id => updateBadge(id));

      if (pendingReports.length > 0) storeViolations();
    });
  });
}

// ── Long-lived panel connections ──

const panelPorts = new Map(); // port -> tabId

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === "tt-panel") {
    panelPorts.set(port, -1);
    port.onDisconnect.addListener(() => panelPorts.delete(port));

    port.onMessage.addListener((msg) => {
      if (msg.action === "setTabId") {
        panelPorts.set(port, msg.tabId);
      }
    });
  }
});

// ── Helpers for message handlers ──

function getTabViolations(allViolations, tabId) {
  if (tabId > 0) return allViolations.filter(v => v.tabId === tabId);
  return allViolations;
}

// ── Message Handling ──

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case "reportViolation": {
      const tabId = sender.tab?.id || -1;
      processViolation(request.violation, tabId);
      sendResponse({ success: true });
      return true;
    }

    case "getFullState": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations", "aiApiKeys"], (result) => {
        const allViolations = result.violations || [];
        const tabViolations = getTabViolations(allViolations, reqTab);
        sendResponse({
          violations: tabViolations,
          clusters: clusterViolations(tabViolations),
          apiKeys: result.aiApiKeys || {},
          enabled: monitoringEnabled
        });
      });
      return true;
    }

    case "getViolations": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        sendResponse({ violations: getTabViolations(result.violations || [], reqTab) });
      });
      return true;
    }

    case "getClusters": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        sendResponse({ clusters: clusterViolations(tabViolations) });
      });
      return true;
    }

    case "getFixGuidance":
      sendResponse({ guidance: getFixGuidance(request.violation) });
      return true;

    case "generatePolicy": {
      const reqTab = request.tabId || -1;
      const mode = request.mode || "standard";
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        const policy = mode === "perfect-types"
          ? generatePerfectTypesPolicy(tabViolations)
          : generatePolicy(tabViolations);
        sendResponse({ policy });
      });
      return true;
    }

    case "clearViolations": {
      const reqTab = request.tabId || -1;
      if (reqTab > 0) {
        recentlyClearedTabs.add(reqTab);
        pendingReports = pendingReports.filter(v => v.tabId !== reqTab);
        for (const [hash] of recentHashes) {
          if (hash.startsWith(`${reqTab}|`)) recentHashes.delete(hash);
        }
        chrome.storage.local.get(["violations"], (result) => {
          const kept = (result.violations || []).filter(v => v.tabId !== reqTab);
          chrome.storage.local.set({ violations: kept }, () => {
            sendResponse({ success: true });
            updateBadge(reqTab);
          });
        });
      } else {
        pendingReports = [];
        recentHashes.clear();
        chrome.storage.local.set({ violations: [] }, () => {
          sendResponse({ success: true });
          chrome.action.setBadgeText({ text: "" });
        });
      }
      return true;
    }

    case "getApiKeys":
      chrome.storage.local.get(["aiApiKeys"], (result) => {
        sendResponse({ apiKeys: result.aiApiKeys || {} });
      });
      return true;

    case "saveApiKeys":
      chrome.storage.local.set({ aiApiKeys: request.apiKeys }, () => {
        sendResponse({ success: true });
      });
      return true;

    case "setEnabled":
      monitoringEnabled = request.enabled;
      chrome.storage.local.set({ monitoringEnabled: request.enabled });
      sendResponse({ success: true, enabled: monitoringEnabled });
      return true;

    case "getEnabled":
      sendResponse({ enabled: monitoringEnabled });
      return true;
  }
});

// ── Track current URL per tab & auto-clear on navigation ──

const tabCurrentUrl = new Map(); // tabId -> current page URL

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;

  const tabId = details.tabId;
  const newUrl = details.url;
  const prevUrl = tabCurrentUrl.get(tabId);

  tabCurrentUrl.set(tabId, newUrl);

  if (prevUrl) {
    // Same origin+pathname (hash/query change only) — no clear needed
    try {
      const prev = new URL(prevUrl);
      const next = new URL(newUrl);
      if (prev.origin === next.origin && prev.pathname === next.pathname) return;
    } catch { /* malformed URL — treat as changed */ }
  }

  // Either the URL changed, or prevUrl is unknown (SW restarted).
  // Clear the tab's data — the storage check ensures we only write when needed.
  clearTabOnNavigation(tabId, newUrl);
});

function clearTabOnNavigation(tabId, newUrl) {
  recentlyClearedTabs.add(tabId);

  storeViolations();

  pendingReports = pendingReports.filter(v => v.tabId !== tabId);

  for (const [hash] of recentHashes) {
    if (hash.startsWith(`${tabId}|`)) recentHashes.delete(hash);
  }

  chrome.storage.local.get(["violations"], (result) => {
    const all = result.violations || [];
    const kept = all.filter(v => v.tabId !== tabId);

    // Only write if there was actually data to clear
    if (kept.length !== all.length) {
      chrome.storage.local.set({ violations: kept }, () => {
        updateBadge(tabId);
      });
    }
  });

  for (const [port, portTabId] of panelPorts.entries()) {
    if (portTabId === tabId) {
      try { port.postMessage({ action: "navigationReset", url: newUrl }); } catch {}
    }
  }
}

chrome.tabs.onRemoved.addListener((tabId) => {
  tabCurrentUrl.delete(tabId);
});

// ── Init ──

chrome.storage.local.get(["monitoringEnabled"], (result) => {
  if (result.monitoringEnabled !== undefined) monitoringEnabled = result.monitoringEnabled;
});

setInterval(storeViolations, 15000);

chrome.runtime.onStartup.addListener(() => {
  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() - 1);
  chrome.storage.local.get(["violations"], (result) => {
    if (!result.violations) return;
    const filtered = result.violations.filter(v => new Date(v.timestamp) >= cutoff);
    if (filtered.length !== result.violations.length) {
      chrome.storage.local.set({ violations: filtered });
    }
  });
});

console.log("Trusted Types Monitor: Background initialized");
