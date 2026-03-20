// Background service worker for Trusted Types Monitor
const MAX_STORAGE_ITEMS = 1000;
const DEDUP_WINDOW_MS = 2000;

let pendingReports = [];
let recentHashes = new Map();
let monitoringEnabled = true;
let storeInFlight = false;
const recentlyClearedTabs = new Set();
let firstPartyAliases = [];
let aliasesReady = false;
let pendingViolationQueue = [];

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

  if (!aliasesReady) {
    pendingViolationQueue.push({ violation, tabId });
    return;
  }

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

  const sinkInfo = extractSinkInfo(normalized);
  normalized.sinkName = sinkInfo.sinkName;
  normalized.sinkCategory = sinkInfo.sinkCategory;
  normalized.sourceLocation = sinkInfo.sourceLocation;

  const originClass = classifyOrigin(normalized);
  normalized.party = originClass.party;
  normalized.sourceOrigin = originClass.sourceOrigin;

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

// ── Named Policy Recommendations ──

function recommendNamedPolicies(violations) {
  const htmlViolations = violations.filter(v => (v.violationType || inferViolationType(v)) === "TrustedHTML");
  const scriptViolations = violations.filter(v => (v.violationType || inferViolationType(v)) === "TrustedScript");
  const urlViolations = violations.filter(v => (v.violationType || inferViolationType(v)) === "TrustedScriptURL");

  const policies = [];
  const policyNames = [];

  if (htmlViolations.length > 0) {
    const richHtml = htmlViolations.filter(v => {
      const s = (v.sample || "").toLowerCase();
      return /<(img|video|iframe|table|div|p|h[1-6]|ul|ol|li|a|span|br|em|strong)\b/i.test(s);
    });
    const simpleHtml = htmlViolations.filter(v => {
      const s = (v.sample || "").toLowerCase();
      return !/<(img|video|iframe|table|div|p|h[1-6]|ul|ol|li|a|span|br|em|strong)\b/i.test(s);
    });

    if (richHtml.length > 0 && simpleHtml.length > 0) {
      policies.push({
        name: "app-rich-html",
        type: "TrustedHTML",
        description: "For rich content (WYSIWYG editors, blog posts, user-generated HTML)",
        violationCount: richHtml.length,
        code: buildNamedHtmlPolicy("app-rich-html", richHtml, true)
      });
      policies.push({
        name: "app-sanitize-html",
        type: "TrustedHTML",
        description: "For simple HTML insertion (notifications, UI fragments)",
        violationCount: simpleHtml.length,
        code: buildNamedHtmlPolicy("app-sanitize-html", simpleHtml, false)
      });
      policyNames.push("app-rich-html", "app-sanitize-html");
    } else {
      policies.push({
        name: "app-html",
        type: "TrustedHTML",
        description: "Sanitizes all HTML assignments using DOMPurify",
        violationCount: htmlViolations.length,
        code: buildNamedHtmlPolicy("app-html", htmlViolations, richHtml.length > 0)
      });
      policyNames.push("app-html");
    }
  }

  if (urlViolations.length > 0) {
    const origins = new Set();
    for (const v of urlViolations) {
      const urlStr = v.blockedUri !== "unknown" ? v.blockedUri : (v.sample || "");
      if (urlStr && urlStr !== "unknown") {
        try { origins.add(new URL(urlStr).origin); } catch {}
      }
    }
    policies.push({
      name: "app-script-url",
      type: "TrustedScriptURL",
      description: "Controls dynamic script loading with origin allowlist",
      violationCount: urlViolations.length,
      detectedOrigins: [...origins],
      code: buildNamedUrlPolicy("app-script-url", [...origins])
    });
    policyNames.push("app-script-url");
  }

  if (scriptViolations.length > 0) {
    policies.push({
      name: "app-script-eval",
      type: "TrustedScript",
      description: "Guards eval-like sinks — prefer refactoring over allowing",
      violationCount: scriptViolations.length,
      code: buildNamedScriptPolicy("app-script-eval", scriptViolations)
    });
    policyNames.push("app-script-eval");
  }

  const cspDirective = generateCspDirective(policyNames);

  return {
    policies,
    policyNames,
    cspDirective,
    totalPolicies: policies.length,
    centralizationModule: buildCentralizedModule(policies)
  };
}

function buildNamedHtmlPolicy(name, violations, isRich) {
  const analysis = analyzeHtmlSamples(violations.map(v => v.sample || "").filter(s => s !== "unknown"));
  const l = [];
  l.push(`const ${camelCase(name)} = trustedTypes.createPolicy('${name}', {`);
  l.push("  createHTML: (input) => {");
  if (isRich && analysis.tags.length > 0) {
    l.push("    return DOMPurify.sanitize(input, {");
    l.push("      ADD_TAGS: [" + analysis.tags.filter(t => !["script","object","embed","applet"].includes(t)).map(t => `'${t}'`).join(", ") + "],");
    if (analysis.attrs.length > 0) {
      l.push("      ADD_ATTR: [" + analysis.attrs.filter(a => !a.startsWith("on")).map(a => `'${a}'`).join(", ") + "],");
    }
    l.push("    });");
  } else {
    l.push("    return DOMPurify.sanitize(input);");
  }
  l.push("  }");
  l.push("});");
  return l.join("\n");
}

function buildNamedUrlPolicy(name, origins) {
  const l = [];
  l.push(`const allowedOrigins = [`);
  l.push(`  location.origin,`);
  origins.forEach(o => l.push(`  '${o}',`));
  l.push(`];\n`);
  l.push(`const ${camelCase(name)} = trustedTypes.createPolicy('${name}', {`);
  l.push("  createScriptURL: (input) => {");
  l.push("    const url = new URL(input, location.href);");
  l.push("    if (allowedOrigins.includes(url.origin)) return url.href;");
  l.push("    throw new TypeError('Blocked script URL: ' + input);");
  l.push("  }");
  l.push("});");
  return l.join("\n");
}

function buildNamedScriptPolicy(name, violations) {
  const l = [];
  l.push(`const ${camelCase(name)} = trustedTypes.createPolicy('${name}', {`);
  l.push("  createScript: (input) => {");
  l.push("    // WARNING: Prefer refactoring eval/new Function to avoid this policy entirely");
  l.push("    // If unavoidable, validate against a strict allowlist:");
  l.push("    // const allowed = ['expression1', 'expression2'];");
  l.push("    // if (allowed.includes(input)) return input;");
  l.push("    throw new TypeError('Blocked script evaluation: ' + input.slice(0, 50));");
  l.push("  }");
  l.push("});");
  return l.join("\n");
}

function camelCase(str) {
  return str.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

function buildCentralizedModule(policies) {
  if (policies.length === 0) return "";
  const l = [];
  l.push("// ══════════════════════════════════════════════════════════════════");
  l.push("// Centralized Trusted Types Policies");
  l.push("// Import this module wherever DOM sinks are used.");
  l.push("// Do NOT create policies anywhere else in the codebase.");
  l.push("// ══════════════════════════════════════════════════════════════════\n");
  l.push("import DOMPurify from 'dompurify';\n");
  l.push("const policies = {};\n");
  l.push("if (window.trustedTypes?.createPolicy) {");
  for (const p of policies) {
    l.push("");
    l.push(`  // ${p.description} (${p.violationCount} violation${p.violationCount !== 1 ? "s" : ""} observed)`);
    const indented = p.code.split("\n").map(line => "  " + line).join("\n");
    l.push(indented);
    l.push(`  policies['${p.name}'] = ${camelCase(p.name)};`);
  }
  l.push("\n}");
  l.push("\nexport default policies;");
  return l.join("\n");
}

// ── CSP Header Generator ──

function generateCspDirective(policyNames) {
  if (!policyNames || policyNames.length === 0) {
    return {
      enforcing: "Content-Security-Policy: require-trusted-types-for 'script';",
      reportOnly: "Content-Security-Policy-Report-Only: require-trusted-types-for 'script';",
      policyNames: [],
      explanation: "No named policies detected. This CSP enforces Trusted Types but allows any policy name."
    };
  }

  const names = policyNames.join(" ");
  return {
    enforcing: `Content-Security-Policy: require-trusted-types-for 'script'; trusted-types ${names};`,
    reportOnly: `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'; trusted-types ${names};`,
    withDefault: `Content-Security-Policy: require-trusted-types-for 'script'; trusted-types ${names} default;`,
    policyNames,
    explanation: `Allows only the named policies [${names}]. ` +
      `Any trustedTypes.createPolicy() call with a different name will throw. ` +
      `Use the report-only header first to verify no policies are missed.`,
    metaTag: `<meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'; trusted-types ${names};">`,
    nginxConfig: `add_header Content-Security-Policy "require-trusted-types-for 'script'; trusted-types ${names};" always;`,
    apacheConfig: `Header always set Content-Security-Policy "require-trusted-types-for 'script'; trusted-types ${names};"`
  };
}

function generateFullCspHeader(violations) {
  const rec = recommendNamedPolicies(violations);
  return rec.cspDirective;
}

// ── Sink-to-Source Mapping ──

function extractSinkInfo(violation) {
  const sample = violation.sample || "";
  const pipeIdx = sample.indexOf("|");
  const sinkPart = (pipeIdx >= 0 ? sample.substring(0, pipeIdx) : "").trim();
  const sinkValue = pipeIdx >= 0 ? sample.substring(pipeIdx + 1) : "";

  const SINK_MAP = {
    "innerhtml":             { sink: "Element.innerHTML",         api: "innerHTML",           category: "html" },
    "outerhtml":             { sink: "Element.outerHTML",         api: "outerHTML",           category: "html" },
    "insertadjacenthtml":    { sink: "Element.insertAdjacentHTML", api: "insertAdjacentHTML", category: "html" },
    "document.write":        { sink: "document.write",            api: "document.write",      category: "html" },
    "domparser":             { sink: "DOMParser.parseFromString", api: "DOMParser",           category: "html" },
    "createcontextualfragment": { sink: "Range.createContextualFragment", api: "createContextualFragment", category: "html" },
    "srcdoc":                { sink: "HTMLIFrameElement.srcdoc",  api: "srcdoc",              category: "html" },
    "eval":                  { sink: "eval()",                    api: "eval",                category: "script" },
    "function":              { sink: "new Function()",            api: "Function constructor", category: "script" },
    "settimeout":            { sink: "setTimeout(string)",        api: "setTimeout",          category: "script" },
    "setinterval":           { sink: "setInterval(string)",       api: "setInterval",         category: "script" },
    "htmlscriptelement src": { sink: "HTMLScriptElement.src",     api: "script.src",          category: "url" },
    "worker constructor":    { sink: "Worker()",                  api: "Worker constructor",  category: "url" },
    "import(":               { sink: "import()",                  api: "dynamic import",      category: "url" },
    "importscripts":         { sink: "importScripts()",           api: "importScripts",       category: "url" },
  };

  const sinkLower = sinkPart.toLowerCase();
  let matched = null;
  for (const [pattern, info] of Object.entries(SINK_MAP)) {
    if (sinkLower.includes(pattern)) { matched = info; break; }
  }

  if (!matched) {
    const sampleLower = sample.toLowerCase();
    for (const [pattern, info] of Object.entries(SINK_MAP)) {
      if (sampleLower.includes(pattern)) { matched = info; break; }
    }
  }

  const sourceLocation = buildSourceLocation(violation);

  return {
    sinkName: matched ? matched.sink : (sinkPart || "Unknown sink"),
    sinkApi: matched ? matched.api : "unknown",
    sinkCategory: matched ? matched.category : inferSinkCategory(violation),
    sinkValue: sinkValue.substring(0, 200),
    sourceLocation,
    sourceFile: violation.sourceFile || "unknown",
    lineNumber: violation.lineNumber || "unknown",
    columnNumber: violation.columnNumber || "unknown"
  };
}

function buildSourceLocation(violation) {
  const file = violation.sourceFile || "unknown";
  const line = violation.lineNumber || "unknown";
  const col = violation.columnNumber || "unknown";
  if (file === "unknown") return null;
  let loc = file;
  if (line !== "unknown") {
    loc += `:${line}`;
    if (col !== "unknown") loc += `:${col}`;
  }
  return loc;
}

function inferSinkCategory(violation) {
  const type = violation.violationType || inferViolationType(violation);
  switch (type) {
    case "TrustedHTML": return "html";
    case "TrustedScript": return "script";
    case "TrustedScriptURL": return "url";
    default: return "unknown";
  }
}

// ── Third-Party vs First-Party Classification ──

function isFirstPartyAlias(sourceHost) {
  return firstPartyAliases.some(alias =>
    sourceHost === alias || sourceHost.endsWith("." + alias)
  );
}

function classifyOrigin(violation) {
  const pageUrl = violation.url || "";
  const sourceFile = violation.sourceFile || "";

  if (!sourceFile || sourceFile === "unknown" || !pageUrl) {
    return { party: "unknown", pageOrigin: "", sourceOrigin: "" };
  }

  try {
    const pageOrigin = new URL(pageUrl).origin;
    const sourceOrigin = new URL(sourceFile).origin;
    const sourceHost = new URL(sourceFile).hostname;

    if (pageOrigin === sourceOrigin) {
      return { party: "first-party", pageOrigin, sourceOrigin };
    }

    if (isFirstPartyAlias(sourceHost)) {
      return { party: "first-party", pageOrigin, sourceOrigin };
    }

    return { party: "third-party", pageOrigin, sourceOrigin };
  } catch {
    if (sourceFile.startsWith("inline") || sourceFile.startsWith("eval")) {
      return { party: "first-party", pageOrigin: "", sourceOrigin: "inline" };
    }
    return { party: "unknown", pageOrigin: "", sourceOrigin: "" };
  }
}

function classifyAllViolations(violations) {
  const firstParty = [];
  const thirdParty = [];
  const unknown = [];
  const thirdPartyOrigins = new Map();

  for (const v of violations) {
    const cls = classifyOrigin(v);
    switch (cls.party) {
      case "first-party": firstParty.push(v); break;
      case "third-party":
        thirdParty.push(v);
        thirdPartyOrigins.set(cls.sourceOrigin,
          (thirdPartyOrigins.get(cls.sourceOrigin) || 0) + 1);
        break;
      default: unknown.push(v); break;
    }
  }

  return {
    firstParty: { count: firstParty.length, violations: firstParty },
    thirdParty: {
      count: thirdParty.length,
      violations: thirdParty,
      origins: Object.fromEntries(thirdPartyOrigins)
    },
    unknown: { count: unknown.length, violations: unknown },
    summary: {
      total: violations.length,
      firstPartyPct: violations.length ? Math.round((firstParty.length / violations.length) * 100) : 0,
      thirdPartyPct: violations.length ? Math.round((thirdParty.length / violations.length) * 100) : 0
    }
  };
}

function reclassifyParty(violations) {
  for (const v of violations) {
    const cls = classifyOrigin(v);
    v.party = cls.party;
    v.sourceOrigin = cls.sourceOrigin;
  }
}

// ── Auto-Suggest First-Party Aliases ──

function suggestAliases(violations) {
  const pageHosts = new Set();
  const sourceHostCounts = new Map();

  for (const v of violations) {
    try { pageHosts.add(new URL(v.url).hostname); } catch {}
    try {
      const host = new URL(v.sourceFile).hostname;
      if (host) sourceHostCounts.set(host, (sourceHostCounts.get(host) || 0) + 1);
    } catch {}
  }

  const pageOrigins = new Set();
  for (const v of violations) {
    try { pageOrigins.add(new URL(v.url).origin); } catch {}
  }

  const suggestions = [];
  const alreadyAlias = new Set(firstPartyAliases);

  for (const [host, count] of sourceHostCounts) {
    if (count < 2) continue;

    let matchesPage = false;
    for (const ph of pageHosts) {
      if (host === ph) { matchesPage = true; break; }
    }
    if (matchesPage) continue;
    if (alreadyAlias.has(host)) continue;

    const hostOrigin = [...sourceHostCounts.keys()]
      .filter(h => h === host)
      .map(h => { try { return new URL([...violations].find(v => { try { return new URL(v.sourceFile).hostname === h; } catch { return false; } })?.sourceFile).origin; } catch { return null; } })
      .filter(Boolean)[0];

    if (hostOrigin && pageOrigins.has(hostOrigin)) continue;

    const isCdnLike = /^(cdn|static|assets|media|img|js|css|scripts|resources)\b/i.test(host) ||
      /\b(cdn|static|assets|objects|cloud|storage)\b/i.test(host);

    const sharesTld = [...pageHosts].some(ph => {
      const pageParts = ph.split(".");
      const srcParts = host.split(".");
      if (pageParts.length >= 2 && srcParts.length >= 2) {
        return pageParts.slice(-2).join(".") === srcParts.slice(-2).join(".") ||
               pageParts.slice(-1)[0] === srcParts.slice(-1)[0];
      }
      return false;
    });

    let reason = "";
    if (isCdnLike && sharesTld) reason = "CDN pattern with shared domain";
    else if (isCdnLike) reason = "CDN-like hostname";
    else if (sharesTld) reason = "Shares top-level domain with page";
    else if (count >= 5) reason = "High-frequency source (possible CDN)";

    if (reason) {
      suggestions.push({ host, count, reason });
    }
  }

  suggestions.sort((a, b) => b.count - a.count);
  return suggestions.slice(0, 10);
}

// ── Framework Detection ──

function detectFrameworks(violations) {
  const detected = [];
  const allSources = new Set();
  const allSamples = [];

  for (const v of violations) {
    if (v.sourceFile && v.sourceFile !== "unknown") allSources.add(v.sourceFile.toLowerCase());
    if (v.stackTrace) allSamples.push(v.stackTrace.toLowerCase());
    if (v.sample) allSamples.push(v.sample.toLowerCase());
  }

  const combined = [...allSources].join(" ") + " " + allSamples.join(" ");

  const FRAMEWORK_SIGNALS = [
    { name: "React",   patterns: ["react-dom", "react.production", "react.development", "jsx-runtime", "__react", "reactdom", "_reactroot"], version: null },
    { name: "Angular", patterns: ["angular", "@angular/core", "zone.js", "ng-", "angular.min.js", "ngsanitize", "platformbrowser"], version: null },
    { name: "Vue",     patterns: ["vue.runtime", "vue.global", "vue.esm", "vue@", "vue.min.js", "__vue_", "vuejs"], version: null },
    { name: "jQuery",  patterns: ["jquery.min.js", "jquery-", "jquery.js", "jquery.slim"], version: null },
    { name: "Svelte",  patterns: ["svelte", "__svelte"], version: null },
    { name: "Next.js", patterns: ["_next/static", "next/dist", "__next"], version: null },
    { name: "Nuxt",    patterns: ["_nuxt/", "nuxt.js", "__nuxt"], version: null },
    { name: "Webpack", patterns: ["webpack", "__webpack_require__", "webpackjsonp"], version: null },
  ];

  for (const fw of FRAMEWORK_SIGNALS) {
    if (fw.patterns.some(p => combined.includes(p))) {
      detected.push({ name: fw.name, confidence: "high" });
    }
  }

  return detected;
}

function getFrameworkGuidance(frameworks) {
  const guidance = {};

  const FW_GUIDANCE = {
    "React": {
      tip: "React escapes HTML by default via JSX. Violations likely come from dangerouslySetInnerHTML or third-party libraries.",
      fixSteps: [
        "Replace dangerouslySetInnerHTML with sanitized content: use DOMPurify.sanitize() inside a Trusted Types policy",
        "For React 19+: use the built-in Sanitizer API integration if available",
        "Wrap policy creation in a single module (e.g., src/utils/trusted-types.ts) and import across components",
        "Use react-helmet or next/head for safe <script> injection"
      ],
      policyPattern: "// React: centralize in src/utils/tt-policy.ts\nimport DOMPurify from 'dompurify';\nexport const htmlPolicy = trustedTypes.createPolicy('react-html', {\n  createHTML: (input) => DOMPurify.sanitize(input)\n});\n// Usage: <div dangerouslySetInnerHTML={{__html: htmlPolicy.createHTML(content)}} />"
    },
    "Angular": {
      tip: "Angular has built-in Trusted Types support since v15. Use its DomSanitizer with bypassSecurityTrust* methods wrapped in a TT policy.",
      fixSteps: [
        "Enable Trusted Types in angular.json: set 'security.trustedTypes' configuration",
        "Use Angular's DomSanitizer.bypassSecurityTrustHtml() within a TT policy wrapper",
        "Register a custom TrustedTypesPolicy in your app.module.ts or main.ts",
        "Angular v16+ automatically creates TT policies for its template engine"
      ],
      policyPattern: "// Angular: register in main.ts or app.module.ts\nif (window.trustedTypes) {\n  trustedTypes.createPolicy('angular', {\n    createHTML: (s) => s,  // Angular DomSanitizer handles this\n    createScriptURL: (s) => s,\n    createScript: (s) => s,\n  });\n}"
    },
    "Vue": {
      tip: "Vue's v-html directive bypasses Trusted Types. Use a custom directive with sanitization instead.",
      fixSteps: [
        "Replace v-html with a custom v-safe-html directive that uses DOMPurify",
        "Create a Vue plugin that registers a Trusted Types policy globally",
        "Use setHTML() in custom directives for modern browsers",
        "For Nuxt: add the Trusted Types CSP header in nuxt.config.ts"
      ],
      policyPattern: "// Vue: plugin in src/plugins/trusted-types.ts\nimport DOMPurify from 'dompurify';\nconst policy = trustedTypes.createPolicy('vue-html', {\n  createHTML: (input) => DOMPurify.sanitize(input)\n});\nexport default {\n  install(app) {\n    app.directive('safe-html', (el, binding) => {\n      el.innerHTML = policy.createHTML(binding.value);\n    });\n  }\n};"
    },
    "jQuery": {
      tip: "jQuery's .html(), .append(), .prepend(), .after(), .before() all use innerHTML internally and trigger TT violations.",
      fixSteps: [
        "Replace $.html(content) with element.setHTML(content) where possible",
        "Create a default TT policy that wraps DOMPurify for jQuery's innerHTML calls",
        "Consider migrating from jQuery to modern DOM APIs",
        "Wrap jQuery in a TT-aware helper: $.safeHtml(selector, content)"
      ],
      policyPattern: "// jQuery: default policy (catches all jQuery innerHTML calls)\ntrustedTypes.createPolicy('default', {\n  createHTML: (input) => DOMPurify.sanitize(input),\n  createScriptURL: (input) => {\n    const url = new URL(input, location.href);\n    if (url.origin === location.origin) return input;\n    throw new TypeError('Blocked: ' + input);\n  }\n});"
    }
  };

  for (const fw of frameworks) {
    if (FW_GUIDANCE[fw.name]) {
      guidance[fw.name] = FW_GUIDANCE[fw.name];
    }
  }

  return guidance;
}

// ── Policy Scatter Detection & Centralization ──

function analyzeScatter(violations) {
  const sourceFiles = new Set();
  const sourceOrigins = new Set();
  const sinksBySource = new Map();

  for (const v of violations) {
    const src = v.sourceFile || "unknown";
    if (src !== "unknown") {
      sourceFiles.add(src);
      try {
        const host = new URL(src).hostname;
        if (!isFirstPartyAlias(host)) {
          sourceOrigins.add(new URL(src).origin);
        }
      } catch {}

      const sinks = sinksBySource.get(src) || new Set();
      const sinkInfo = extractSinkInfo(v);
      sinks.add(sinkInfo.sinkName);
      sinksBySource.set(src, sinks);
    }
  }

  const scattered = sourceFiles.size >= 5;
  const multiOrigin = sourceOrigins.size > 1;

  const recommendation = {
    isScattered: scattered,
    isMultiOrigin: multiOrigin,
    sourceFileCount: sourceFiles.size,
    sourceOriginCount: sourceOrigins.size,
    severity: scattered ? (sourceFiles.size >= 10 ? "high" : "medium") : "low",
    message: "",
    steps: [],
    modulePattern: ""
  };

  if (scattered) {
    recommendation.message = `Violations originate from ${sourceFiles.size} different source files. ` +
      `Sink usage is spread across the codebase, making security audits difficult.`;
    recommendation.steps = [
      "Create a single shared policy module (e.g., src/lib/tt-policies.ts)",
      "Export named policies for each trust domain (html, scriptUrl, script)",
      "Import the shared module wherever DOM sinks are used — never call trustedTypes.createPolicy() outside this module",
      "Add a CSP trusted-types directive listing only your centralized policy names",
      "Use eslint-plugin-trusted-types or code review to enforce the single-module rule"
    ];
    recommendation.modulePattern =
`// src/lib/tt-policies.ts — Single source of truth for all TT policies
import DOMPurify from 'dompurify';

const policies = {};

if (window.trustedTypes?.createPolicy) {
  policies.html = trustedTypes.createPolicy('app-html', {
    createHTML: (input) => DOMPurify.sanitize(input)
  });

  policies.scriptUrl = trustedTypes.createPolicy('app-script-url', {
    createScriptURL: (input) => {
      const url = new URL(input, location.href);
      const allowed = [location.origin /* add CDN origins */];
      if (allowed.includes(url.origin)) return url.href;
      throw new TypeError('Blocked script URL: ' + input);
    }
  });
}

export default policies;`;
  } else {
    recommendation.message = sourceFiles.size > 0
      ? `Violations come from ${sourceFiles.size} source file(s) — manageable scope.`
      : "No source file information available in violations.";
  }

  const sourceSummary = [];
  for (const [file, sinks] of sinksBySource.entries()) {
    sourceSummary.push({
      file,
      sinks: [...sinks],
      violationCount: violations.filter(v => v.sourceFile === file).length
    });
  }
  sourceSummary.sort((a, b) => b.violationCount - a.violationCount);

  return { ...recommendation, sourceSummary };
}

// ── Fix Guidance ──

function getFixGuidance(violation) {
  const type = violation.violationType || inferViolationType(violation);
  const sample = violation.sample || "";
  const g = { violationType: type, severity: "high", title: "", explanation: "", fixSteps: [], codeExample: "", references: [], sinkType: "", dangerLevel: "" };

  const sinkInfo = extractSinkInfo(violation);
  g.sinkMapping = sinkInfo;

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
        reclassifyParty(tabViolations);
        sendResponse({
          violations: tabViolations,
          clusters: clusterViolations(tabViolations),
          apiKeys: result.aiApiKeys || {},
          enabled: monitoringEnabled,
          originAnalysis: classifyAllViolations(tabViolations),
          frameworks: detectFrameworks(tabViolations),
          scatter: analyzeScatter(tabViolations),
          firstPartyAliases: firstPartyAliases
        });
      });
      return true;
    }

    case "getViolations": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        reclassifyParty(tabViolations);
        sendResponse({ violations: tabViolations });
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

    case "getFixGuidance": {
      const guidance = getFixGuidance(request.violation);
      const frameworks = detectFrameworks(request.violations || [request.violation]);
      if (frameworks.length > 0) {
        guidance.frameworkGuidance = getFrameworkGuidance(frameworks);
        guidance.detectedFrameworks = frameworks;
      }
      sendResponse({ guidance });
      return true;
    }

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

    case "getNamedPolicies": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        sendResponse({ result: recommendNamedPolicies(tabViolations) });
      });
      return true;
    }

    case "getCspHeader": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        sendResponse({ csp: generateFullCspHeader(tabViolations) });
      });
      return true;
    }

    case "getOriginAnalysis": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        sendResponse({ analysis: classifyAllViolations(tabViolations) });
      });
      return true;
    }

    case "getScatterAnalysis": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        sendResponse({ scatter: analyzeScatter(tabViolations) });
      });
      return true;
    }

    case "getFrameworkInfo": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        const frameworks = detectFrameworks(tabViolations);
        sendResponse({
          frameworks,
          guidance: getFrameworkGuidance(frameworks)
        });
      });
      return true;
    }

    case "getSinkMap": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        const sinkMap = tabViolations.map(v => ({
          violation: v,
          sink: extractSinkInfo(v),
          origin: classifyOrigin(v)
        }));
        sendResponse({ sinkMap });
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

    case "getFirstPartyAliases":
      sendResponse({ aliases: firstPartyAliases });
      return true;

    case "saveFirstPartyAliases":
      firstPartyAliases = (request.aliases || []).map(a => a.trim().toLowerCase()).filter(Boolean);
      chrome.storage.local.set({ firstPartyAliases });
      sendResponse({ success: true });
      return true;

    case "suggestAliases": {
      const reqTab = request.tabId || -1;
      chrome.storage.local.get(["violations"], (result) => {
        const tabViolations = getTabViolations(result.violations || [], reqTab);
        sendResponse({ suggestions: suggestAliases(tabViolations) });
      });
      return true;
    }
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

chrome.storage.local.get(["monitoringEnabled", "firstPartyAliases"], (result) => {
  if (result.monitoringEnabled !== undefined) monitoringEnabled = result.monitoringEnabled;
  if (Array.isArray(result.firstPartyAliases)) firstPartyAliases = result.firstPartyAliases;
  aliasesReady = true;
  for (const item of pendingViolationQueue) {
    processViolation(item.violation, item.tabId);
  }
  pendingViolationQueue = [];
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
