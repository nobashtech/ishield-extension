// iShield Extension clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
// This documentation-only header does not change runtime behavior.

'use strict';

const api = globalThis.browser ?? globalThis.chrome;
const token = location.hash.startsWith('#') ? location.hash.slice(1) : '';
const host = document.querySelector('#host');
const title = document.querySelector('#title');
const explanation = document.querySelector('#explanation');
const signals = document.querySelector('#signals');
const status = document.querySelector('#status');
const back = document.querySelector('#back');
const proceed = document.querySelector('#proceed');

const LABELS = Object.freeze({
  'known-phishing': 'Known phishing reputation evidence',
  'url-credentials': 'Suspicious credentials embedded in the URL',
  'punycode-host': 'Internationalized/punycode hostname needs extra caution',
  'brand-impersonation': 'Possible brand impersonation in the hostname',
  'brand-confusable': 'Possible look-alike brand spelling in the hostname',
  'credential-lure': 'Login/account lure pattern in the navigation',
  'ip-credential-surface': 'Credential form hosted directly on an IP address',
  'password-field': 'Password entry detected on the page',
  'cross-origin-form': 'Credential form submits to a different origin',
  'insecure-form-action': 'Form submission downgrades to insecure HTTP',
  'http-password-page': 'Password entry is served over insecure HTTP',
  'deep-host': 'Unusually deep hostname structure',
  'suspicious-infrastructure': 'Suspicious infrastructure reputation evidence',
  'redirect-chain': 'Multiple redirects occurred before this page loaded',
});

async function call(message) {
  const response = await api.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || 'Request failed');
  return response;
}

async function load() {
  try {
    const response = await call({ type: 'phishing:warning:get', token });
    const warning = response.warning;
    if (!warning) throw new Error('This warning has expired');
    host.textContent = warning.host;
    if (warning.action === 'block') {
      title.textContent = 'Dangerous website blocked';
      explanation.textContent = 'iShield Extension found strong local evidence that this site may be trying to steal credentials or impersonate a trusted service.';
    } else {
      title.textContent = 'Suspicious website';
      explanation.textContent = 'iShield Extension found multiple local phishing signals. Review the address carefully before continuing.';
    }
    signals.replaceChildren(...warning.reasons.map((reason) => {
      const li = document.createElement('li');
      li.textContent = LABELS[reason] ?? 'Suspicious phishing signal';
      return li;
    }));
  } catch (error) {
    title.textContent = 'Phishing warning expired';
    explanation.textContent = 'The temporary local warning state is no longer available.';
    proceed.hidden = true;
    status.textContent = error?.message ?? 'Expired';
  }
}

back.addEventListener('click', () => {
  if (history.length > 2) history.go(-2);
  else location.replace('about:blank');
});

proceed.addEventListener('click', async () => {
  proceed.disabled = true;
  status.textContent = 'Continuing with a temporary local bypass…';
  try {
    await call({ type: 'phishing:warning:continue', token });
  } catch (error) {
    proceed.disabled = false;
    status.textContent = error?.message ?? 'Could not continue';
  }
});

void load();
