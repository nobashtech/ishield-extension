'use strict';
(() => {
  const API = globalThis.browser ?? globalThis.chrome;
  const LIMITS = Object.freeze({ maxScriptErrors: 64, maxResourceErrors: 128, maxTextChars: 20000, probeDelayMs: 6000 });
  let scriptErrors = 0; let resourceErrors = 0; let sent = false;
  function bumpScript() { scriptErrors = Math.min(LIMITS.maxScriptErrors, scriptErrors + 1); }
  function onError(event) {
    const tag = event?.target?.tagName?.toLowerCase?.();
    if (tag && ['script', 'link', 'img', 'iframe', 'video', 'audio', 'source'].includes(tag)) resourceErrors = Math.min(LIMITS.maxResourceErrors, resourceErrors + 1);
    else bumpScript();
  }
  function visibleTextChars() {
    const text = document.body?.innerText ?? ''; return Math.min(LIMITS.maxTextChars, text.length);
  }
  async function sendProbe() {
    if (sent || !API?.runtime?.sendMessage) return; sent = true;
    const body = document.body;
    const probe = {
      scriptErrors, resourceErrors, visibleTextChars: visibleTextChars(),
      bodyChildCount: Math.min(10000, body?.childElementCount ?? 0),
      interactiveCount: Math.min(5000, document.querySelectorAll?.('a[href],button,input,select,textarea,[role="button"]').length ?? 0),
      readyState: document.readyState,
    };
    try {
      const response = await API.runtime.sendMessage({ type: 'recovery:probe', probe });
      if (response?.ok && response.recovery?.activated === true) globalThis.location.reload();
    } catch { /* Breakage signal is strictly best-effort and local. */ }
  }
  globalThis.addEventListener?.('error', onError, true);
  globalThis.addEventListener?.('unhandledrejection', bumpScript, true);
  const schedule = () => globalThis.setTimeout(sendProbe, LIMITS.probeDelayMs);
  if (document.readyState === 'complete') schedule(); else globalThis.addEventListener?.('load', schedule, { once: true });
})();
