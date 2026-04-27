// Extension Trusted Types default policy + safe DOM helpers.
// Loaded before all other extension scripts on panel.html and popup.html.
//
// The manifest CSP enforces `require-trusted-types-for 'script'` with
// `trusted-types default` on extension pages. This module:
//   1. Creates the sole "default" policy
//   2. Exposes window.safeHTML(el, html) — the ONLY path for setting innerHTML
//   3. Exposes window.safeClear(el) — clears element children without innerHTML
//
// All HTML passed to safeHTML MUST already be escaped via esc(). The policy
// exists so the extension dogfoods Trusted Types on itself.

(function () {
  "use strict";

  let policy = null;

  if (typeof window.trustedTypes !== "undefined" && trustedTypes.createPolicy) {
    try {
      policy = trustedTypes.createPolicy("default", {
        createHTML: function (input) {
          return input;
        },
        createScript: function (input) {
          return input;
        },
        createScriptURL: function (input) {
          return input;
        }
      });
    } catch (e) {
      console.warn("TT Monitor: Could not create default policy —", e.message);
    }
  }

  /**
   * Safely set innerHTML on an element, routing through the Trusted Types
   * default policy when available. This is the single authorized call-site
   * for innerHTML in the entire extension UI.
   */
  function safeHTML(el, html) {
    if (!el) return;
    if (policy) {
      el.innerHTML = policy.createHTML(html);
    } else {
      el.innerHTML = html;
    }
  }

  /**
   * Clear all children from an element without touching innerHTML.
   */
  function safeClear(el) {
    if (!el) return;
    while (el.firstChild) el.removeChild(el.firstChild);
  }

  window.safeHTML = safeHTML;
  window.safeClear = safeClear;
})();
