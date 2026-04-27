// AI Assistant - Supports Claude, Gemini, GPT with multi-turn conversation

const AI_PROVIDERS = {
  claude: { name: "Claude", endpoint: "https://api.anthropic.com/v1/messages", model: "claude-sonnet-4-20250514" },
  gemini: { name: "Gemini", endpoint: "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent", model: "gemini-flash-latest" },
  gpt: { name: "GPT", endpoint: "https://api.openai.com/v1/chat/completions", model: "gpt-4o-mini" }
};

const AI_REQUEST_TIMEOUT_MS = 120000;
const MODELS_REQUEST_TIMEOUT_MS = 15000;

async function fetchWithTimeout(url, options, timeoutMs) {
  const ms = timeoutMs || AI_REQUEST_TIMEOUT_MS;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error(`Request timed out after ${ms / 1000}s — the AI provider may be slow or unreachable.`);
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

function detectProvider(key) {
  if (!key) return null;
  if (key.startsWith("sk-ant-")) return "claude";
  if (key.startsWith("sk-proj-") || key.startsWith("sk-")) return "gpt";
  if (key.startsWith("AIza")) return "gemini";
  return "gemini";
}

async function fetchModels(apiKey, provider) {
  const det = provider || detectProvider(apiKey);
  if (!det || !apiKey) throw new Error("API key and provider are required.");

  switch (det) {
    case "gpt": {
      const r = await fetchWithTimeout("https://api.openai.com/v1/models", {
        method: "GET",
        headers: { "Authorization": `Bearer ${apiKey}` }
      }, MODELS_REQUEST_TIMEOUT_MS);
      if (r.status === 401 || r.status === 403) throw new Error("Invalid or expired API key.");
      if (r.status === 429) throw new Error("Rate limited — wait a moment and retry.");
      if (!r.ok) throw new Error(`OpenAI API error ${r.status}: ${(await r.text()).substring(0, 200)}`);
      const json = await r.json();
      return (json.data || [])
        .filter(m => !m.id.startsWith("embedding") && !m.id.includes("whisper") && !m.id.includes("tts") && !m.id.includes("dall-e"))
        .map(m => ({ id: m.id, name: m.id }))
        .sort((a, b) => a.name.localeCompare(b.name));
    }

    case "gemini": {
      const r = await fetchWithTimeout(
        `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`,
        { method: "GET" },
        MODELS_REQUEST_TIMEOUT_MS
      );
      if (r.status === 401 || r.status === 403) throw new Error("Invalid or expired API key.");
      if (r.status === 429) throw new Error("Rate limited — wait a moment and retry.");
      if (!r.ok) throw new Error(`Gemini API error ${r.status}: ${(await r.text()).substring(0, 200)}`);
      const json = await r.json();
      const BLOCK_PATTERNS = [
        "deep-research", "imagen", "veo", "lyria",
        "embedding", "aqa", "bison", "gecko"
      ];
      return (json.models || [])
        .filter(m => {
          if (!m.name) return false;
          const id = m.name.replace("models/", "").toLowerCase();
          if (BLOCK_PATTERNS.some(p => id.includes(p))) return false;
          if (!Array.isArray(m.supportedGenerationMethods)) return false;
          return m.supportedGenerationMethods.includes("generateContent");
        })
        .map(m => {
          const id = m.name.replace("models/", "");
          return { id, name: m.displayName || id };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
    }

    case "claude":
      return [
        { id: "claude-sonnet-4-20250514", name: "Claude Sonnet 4" },
        { id: "claude-3-5-sonnet-20241022", name: "Claude 3.5 Sonnet" },
        { id: "claude-3-5-haiku-20241022", name: "Claude 3.5 Haiku" },
        { id: "claude-3-opus-20240229", name: "Claude 3 Opus" },
        { id: "claude-3-haiku-20240307", name: "Claude 3 Haiku" }
      ];

    default:
      throw new Error(`Unknown provider: ${det}`);
  }
}

const SYSTEM = `You are a Trusted Types security expert embedded in the TT Monitor Chrome DevTools extension. Help developers fix Trusted Types violations using the analysis data this extension has already computed.

Knowledge: W3C Trusted Types spec, DOM XSS sinks (innerHTML, outerHTML, document.write, eval, setTimeout strings, script.src, Worker, import()), DOMPurify, Sanitizer API (setHTML), CSP headers (require-trusted-types-for, trusted-types directive), same-origin policy, named vs default policies, policy centralization patterns.

Rules:
1) Reference the exact DOM sink names from the analysis context (e.g. "Element.innerHTML", "eval()") — do not use generic descriptions when specific sink data is provided.
2) Use EXACTLY the named policy names from the analysis context (e.g. "app-rich-html", "app-sanitize-html", "app-script-url") — NEVER invent alternative policy names.
3) When recommending CSP headers, use the pre-computed CSP directives from the analysis context — do not compose your own trusted-types directive.
4) When frameworks are detected, provide framework-specific fix patterns matching the detected frameworks — do not suggest patterns for frameworks not listed.
5) When scatter severity is medium or high, recommend the centralized module approach and reference the source file count from the analysis.
6) Distinguish first-party vs third-party violations: prioritize fixing first-party code; for third-party, recommend library updates or wrapper policies.
7) Assess severity (critical/high/medium) and provide copy-paste code fixes. Prefer named policies over default. Prefer setHTML() for HTML sinks in modern browsers.
8) Be concise, precise, actionable. Ground every recommendation in the specific analysis data provided.`;

function buildViolationContext(violations) {
  const summarized = violations.slice(0, 20).map((v, i) => ({
    "#": i + 1,
    type: v.violationType || "Unknown",
    directive: v.directive,
    source: v.sourceFile ? `${v.sourceFile}:${v.lineNumber}` : "unknown",
    sample: (v.sample || "").substring(0, 200),
    url: v.url,
    sink: v.sinkName || "Unknown",
    sinkCategory: v.sinkCategory || "unknown",
    party: v.party || "unknown",
    sourceOrigin: v.sourceOrigin || ""
  }));
  let ctx = "Current Trusted Types violations:\n```json\n" + JSON.stringify(summarized, null, 2) + "\n```\n";
  if (violations.length > 20) ctx += `(${violations.length} total, showing 20)\n`;
  return ctx;
}

function buildAnalysisContext(analysis) {
  if (!analysis) return "";
  const sections = [];

  if (analysis.originAnalysis) {
    const oa = analysis.originAnalysis;
    let s = `\n--- Origin Analysis ---\n`;
    s += `Total: ${oa.summary.total} violations — ${oa.firstParty.count} first-party (${oa.summary.firstPartyPct}%), ${oa.thirdParty.count} third-party (${oa.summary.thirdPartyPct}%)`;
    if (oa.thirdParty.count > 0 && oa.thirdParty.origins) {
      const origins = Object.entries(oa.thirdParty.origins).sort((a, b) => b[1] - a[1]).slice(0, 8);
      s += `\nThird-party origins: ${origins.map(([o, c]) => `${o} (${c})`).join(", ")}`;
    }
    sections.push(s);
  }

  if (analysis.namedPolicies && analysis.namedPolicies.policies.length > 0) {
    const np = analysis.namedPolicies;
    let s = `\n--- Named Policy Recommendations ---\n`;
    s += `Recommended policies: ${np.policyNames.join(", ")}\n`;
    for (const p of np.policies) {
      s += `• ${p.name} (${p.type}): ${p.description} — covers ${p.violationCount} violation(s)\n`;
    }
    s += `IMPORTANT: Use ONLY these policy names in your suggestions. Do not invent new names.`;
    sections.push(s);
  }

  if (analysis.csp) {
    const csp = analysis.csp;
    let s = `\n--- CSP Header (pre-computed) ---\n`;
    s += `Report-Only: ${csp.reportOnly}\n`;
    s += `Enforcing: ${csp.enforcing}`;
    if (csp.withDefault) s += `\nWith default: ${csp.withDefault}`;
    s += `\nIMPORTANT: Reference these exact CSP directives. Do not compose your own.`;
    sections.push(s);
  }

  if (analysis.frameworks && analysis.frameworks.length > 0) {
    let s = `\n--- Detected Frameworks ---\n`;
    s += analysis.frameworks.map(f => f.name).join(", ");
    if (analysis.frameworkGuidance) {
      for (const fw of analysis.frameworks) {
        const g = analysis.frameworkGuidance[fw.name];
        if (g) {
          s += `\n${fw.name}: ${g.tip}`;
          s += `\nKey steps: ${g.fixSteps.slice(0, 2).join("; ")}`;
        }
      }
    }
    s += `\nOnly provide guidance for these detected frameworks.`;
    sections.push(s);
  }

  if (analysis.scatter) {
    const sc = analysis.scatter;
    let s = `\n--- Scatter Analysis ---\n`;
    s += `Severity: ${sc.severity} | ${sc.sourceFileCount} source files, ${sc.sourceOriginCount} origins\n`;
    s += sc.message;
    if (sc.isScattered) {
      s += `\nRecommend centralization into a single shared policy module.`;
    }
    sections.push(s);
  }

  if (analysis.firstPartyAliases && analysis.firstPartyAliases.length > 0) {
    let s = `\n--- First-Party Domain Aliases ---\n`;
    s += `User has configured these domains as first-party: ${analysis.firstPartyAliases.join(", ")}\n`;
    s += `Violations from these domains are classified as first-party in all analysis above. `;
    s += `Treat these origins as internal CDNs/assets, not as external third-party dependencies.`;
    sections.push(s);
  }

  return sections.length > 0 ? "\n" + sections.join("\n") : "";
}

async function queryAI(apiKey, provider, violations, question, analysis) {
  return queryAIMultiTurn(apiKey, provider, violations, [{ role: "user", content: question || "Analyze these violations." }], analysis);
}

async function queryAIMultiTurn(apiKey, provider, violations, history, analysis, model) {
  const det = provider || detectProvider(apiKey);
  if (!det) throw new Error("Cannot detect provider from key.");

  const ctx = buildViolationContext(violations);
  const analysisCtx = buildAnalysisContext(analysis);
  const sysWithCtx = SYSTEM + "\n\n" + ctx + analysisCtx;

  switch (det) {
    case "claude": return callClaude(apiKey, sysWithCtx, history, model);
    case "gemini": return callGemini(apiKey, sysWithCtx, history, model);
    case "gpt": return callGPT(apiKey, sysWithCtx, history, model);
    default: throw new Error(`Unknown provider: ${det}`);
  }
}

async function callClaude(apiKey, system, history, model) {
  const messages = history.map(m => ({ role: m.role === "assistant" ? "assistant" : "user", content: m.content }));
  const r = await fetchWithTimeout("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
    body: JSON.stringify({ model: model || AI_PROVIDERS.claude.model, max_tokens: 4096, system, messages })
  });
  if (r.status === 401 || r.status === 403) throw new Error("Invalid or expired API key.");
  if (r.status === 429) throw new Error("Rate limited — wait a moment and retry.");
  if (!r.ok) throw new Error(`Claude API ${r.status}: ${(await r.text()).substring(0, 200)}`);
  const json = await r.json();
  if (!json.content || !json.content[0] || !json.content[0].text) {
    throw new Error("Unexpected response format from Claude API.");
  }
  return json.content[0].text;
}

async function callGemini(apiKey, system, history, model) {
  const contents = history.map(m => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
  const modelId = model || AI_PROVIDERS.gemini.model;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${apiKey}`;
  const r = await fetchWithTimeout(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ system_instruction: { parts: [{ text: system }] }, contents, generationConfig: { maxOutputTokens: 4096 } })
  });
  if (r.status === 401 || r.status === 403) throw new Error("Invalid or expired API key.");
  if (r.status === 429) throw new Error("Rate limited — wait a moment and retry.");
  if (!r.ok) throw new Error(`Gemini API ${r.status}: ${(await r.text()).substring(0, 200)}`);
  const json = await r.json();
  if (!json.candidates || !json.candidates[0] || !json.candidates[0].content) {
    throw new Error("Unexpected response format from Gemini API.");
  }
  return json.candidates[0].content.parts[0].text;
}

async function callGPT(apiKey, system, history, model) {
  const messages = [{ role: "system", content: system }, ...history.map(m => ({ role: m.role, content: m.content }))];
  const r = await fetchWithTimeout("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
    body: JSON.stringify({ model: model || AI_PROVIDERS.gpt.model, max_tokens: 4096, messages })
  });
  if (r.status === 401 || r.status === 403) throw new Error("Invalid or expired API key.");
  if (r.status === 429) throw new Error("Rate limited — wait a moment and retry.");
  if (!r.ok) throw new Error(`OpenAI API ${r.status}: ${(await r.text()).substring(0, 200)}`);
  const json = await r.json();
  if (!json.choices || !json.choices[0] || !json.choices[0].message) {
    throw new Error("Unexpected response format from OpenAI API.");
  }
  return json.choices[0].message.content;
}

window.AIAssistant = { AI_PROVIDERS, detectProvider, fetchModels, queryAI, queryAIMultiTurn };
