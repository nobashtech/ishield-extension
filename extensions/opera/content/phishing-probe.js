'use strict';

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const MAX_FORMS = 32;
  const MAX_INPUTS = 64;
  let completed = false;

  function send(dom) {
    try {
      const maybePromise = api.runtime.sendMessage({ type: 'phishing:probe', dom });
      if (maybePromise?.catch) maybePromise.catch(() => undefined);
    } catch {
      // Protection must fail open if the extension context is unavailable during navigation.
    }
  }

  function boundedSignals() {
    let passwordFields = 0;
    let credentialFields = 0;
    let externalFormActions = 0;
    let insecureFormAction = false;
    let redirectCount = 0;
    try {
      const navigation = performance.getEntriesByType('navigation')[0];
      if (Number.isFinite(navigation?.redirectCount)) redirectCount = Math.min(8, Math.max(0, Math.trunc(navigation.redirectCount)));
    } catch {
      redirectCount = 0;
    }
    const currentOrigin = location.origin;

    const inputs = document.querySelectorAll('input');
    const inputLimit = Math.min(inputs.length, MAX_INPUTS);
    for (let index = 0; index < inputLimit; index += 1) {
      const input = inputs[index];
      const type = String(input.getAttribute('type') || 'text').toLowerCase();
      const autocomplete = String(input.getAttribute('autocomplete') || '').toLowerCase();
      if (type === 'password') passwordFields = Math.min(8, passwordFields + 1);
      if (type === 'password' || type === 'email' || autocomplete.includes('username') || autocomplete.includes('password')) {
        credentialFields = Math.min(16, credentialFields + 1);
      }
    }

    const forms = document.forms;
    const formLimit = Math.min(forms.length, MAX_FORMS);
    for (let index = 0; index < formLimit; index += 1) {
      const form = forms[index];
      const rawAction = form.getAttribute('action');
      if (!rawAction) continue;
      let action;
      try { action = new URL(rawAction, location.href); } catch { continue; }
      if (action.protocol !== 'http:' && action.protocol !== 'https:') continue;
      if (action.origin !== currentOrigin) externalFormActions = Math.min(8, externalFormActions + 1);
      if (location.protocol === 'https:' && action.protocol === 'http:') insecureFormAction = true;
    }

    return { passwordFields, credentialFields, externalFormActions, insecureFormAction, redirectCount };
  }

  // URL-only evaluation happens immediately; no page content is sent.
  send({ passwordFields: 0, credentialFields: 0, externalFormActions: 0, insecureFormAction: false, redirectCount: 0 });

  function complete() {
    if (completed) return;
    completed = true;
    send(boundedSignals());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', complete, { once: true });
  } else {
    complete();
  }
})();
