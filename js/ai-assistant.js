// AI Assistant - Supports Claude, Gemini, GPT with multi-turn conversation

const AI_PROVIDERS = {
  claude: { name: "Claude", endpoint: "https://api.anthropic.com/v1/messages", model: "claude-sonnet-4-20250514" },
  gemini: { name: "Gemini", endpoint: "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent", model: "gemini-flash-latest" },
  gpt: { name: "GPT", endpoint: "https://api.openai.com/v1/chat/completions", model: "gpt-4o-mini" }
};

function detectProvider(key) {
  if (!key) return null;
  if (key.startsWith("sk-ant-")) return "claude";
  if (key.startsWith("sk-proj-") || key.startsWith("sk-")) return "gpt";
  if (key.startsWith("AIza")) return "gemini";
  return "gemini";
}

const SYSTEM = `You are a Trusted Types security expert in a Chrome DevTools extension. Help developers fix Trusted Types violations.

Knowledge: W3C Trusted Types spec, DOM XSS sinks (innerHTML, outerHTML, document.write, eval, setTimeout strings, script.src), DOMPurify, CSP headers, same-origin policy.

Rules: 1) Identify the DOM sink 2) Assess severity 3) Provide copy-paste code fixes 4) Suggest secure approach first 5) Prefer named policies over default. Be concise, precise, actionable.`;

function buildViolationContext(violations) {
  const summarized = violations.slice(0, 20).map((v, i) => ({
    "#": i + 1, type: v.violationType || "Unknown", directive: v.directive,
    source: v.sourceFile ? `${v.sourceFile}:${v.lineNumber}` : "unknown",
    sample: (v.sample || "").substring(0, 200), url: v.url
  }));
  let ctx = "Current Trusted Types violations:\n```json\n" + JSON.stringify(summarized, null, 2) + "\n```\n";
  if (violations.length > 20) ctx += `(${violations.length} total, showing 20)\n`;
  return ctx;
}

// Single-turn (for popup backward compat)
async function queryAI(apiKey, provider, violations, question) {
  return queryAIMultiTurn(apiKey, provider, violations, [{ role: "user", content: question || "Analyze these violations." }]);
}

// Multi-turn with conversation history
async function queryAIMultiTurn(apiKey, provider, violations, history) {
  const det = provider || detectProvider(apiKey);
  if (!det) throw new Error("Cannot detect provider from key.");

  const ctx = buildViolationContext(violations);
  const sysWithCtx = SYSTEM + "\n\n" + ctx;

  switch (det) {
    case "claude": return callClaude(apiKey, sysWithCtx, history);
    case "gemini": return callGemini(apiKey, sysWithCtx, history);
    case "gpt": return callGPT(apiKey, sysWithCtx, history);
    default: throw new Error(`Unknown provider: ${det}`);
  }
}

async function callClaude(apiKey, system, history) {
  const messages = history.map(m => ({ role: m.role === "assistant" ? "assistant" : "user", content: m.content }));
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
    body: JSON.stringify({ model: AI_PROVIDERS.claude.model, max_tokens: 4096, system, messages })
  });
  if (!r.ok) throw new Error(`Claude ${r.status}: ${await r.text()}`);
  return (await r.json()).content[0].text;
}

async function callGemini(apiKey, system, history) {
  const contents = history.map(m => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
  const r = await fetch(`${AI_PROVIDERS.gemini.endpoint}?key=${apiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ system_instruction: { parts: [{ text: system }] }, contents, generationConfig: { maxOutputTokens: 4096 } })
  });
  if (!r.ok) throw new Error(`Gemini ${r.status}: ${await r.text()}`);
  return (await r.json()).candidates[0].content.parts[0].text;
}

async function callGPT(apiKey, system, history) {
  const messages = [{ role: "system", content: system }, ...history.map(m => ({ role: m.role, content: m.content }))];
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
    body: JSON.stringify({ model: AI_PROVIDERS.gpt.model, max_tokens: 4096, messages })
  });
  if (!r.ok) throw new Error(`GPT ${r.status}: ${await r.text()}`);
  return (await r.json()).choices[0].message.content;
}

window.AIAssistant = { AI_PROVIDERS, detectProvider, queryAI, queryAIMultiTurn };
