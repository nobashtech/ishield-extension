// iShield Extension clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
// This documentation-only header does not change runtime behavior.

'use strict';

const api = globalThis.browser ?? globalThis.chrome;
const token = location.hash.startsWith('#') ? location.hash.slice(1) : '';
const host = document.querySelector('#host');
const title = document.querySelector('#title');
const explanation = document.querySelector('#explanation');
const category = document.querySelector('#category');
const signals = document.querySelector('#signals');
const status = document.querySelector('#status');
const back = document.querySelector('#back');
const proceed = document.querySelector('#proceed');

const CATEGORY_LABELS = Object.freeze({
  'general-scam': 'Known scam/fraud',
  'tech-support': 'Tech-support scam',
  investment: 'Investment scam',
  crypto: 'Crypto scam',
  'giveaway-prize': 'Fake giveaway or prize',
  'fake-shopping': 'Suspicious shopping store',
  'fake-support': 'Fake support page',
  impersonation: 'Impersonation scam',
  'fake-download': 'Fake download/update',
  payment: 'Payment scam',
  subscription: 'Fraudulent subscription/renewal',
  'suspicious-checkout': 'Suspicious checkout',
  'deceptive-alert': 'Deceptive browser/system alert',
  'fake-antivirus': 'Fake antivirus warning',
});

const LABELS = Object.freeze({
  'known-scam': 'Known scam reputation evidence',
  'suspicious-infrastructure': 'Suspicious infrastructure reputation evidence',
  'punycode-host': 'Internationalized/punycode hostname needs extra caution',
  'ip-host': 'Page is hosted directly on an IP address',
  'deep-host': 'Unusually deep hostname structure',
  'scam-url-lure': 'Scam-related lure pattern in the navigation',
  'tech-support-lure': 'Tech-support scam language detected locally',
  'investment-lure': 'Guaranteed/high-return investment language detected locally',
  'crypto-lure': 'Crypto scam/payment language detected locally',
  'giveaway-prize-lure': 'Prize or giveaway lure language detected locally',
  'shopping-lure': 'Suspicious store/clearance lure language detected locally',
  'support-lure': 'Support/helpdesk lure language detected locally',
  'impersonation-lure': 'Possible organization/authority impersonation language',
  'fake-download-lure': 'Required/fake update or download lure language',
  'payment-lure': 'Fee/payment-demand language detected locally',
  'subscription-lure': 'Suspicious renewal/subscription language detected locally',
  'deceptive-alert': 'Deceptive browser/system warning language detected locally',
  'antivirus-scare': 'Fake antivirus/malware scare language detected locally',
  'urgency-pressure': 'Urgency or pressure language detected locally',
  'remote-access-request': 'Remote-access software/request language detected locally',
  'irreversible-payment': 'Gift card, wire, crypto, or other irreversible payment language',
  'cross-origin-payment-form': 'Payment-like form submits to a different origin',
  'payment-fields': 'Payment-like fields detected on the page',
  'phone-contact': 'Phone-contact path co-occurs with scam signals',
  'download-link': 'Executable/download path co-occurs with scam signals',
  'dialog-overlay': 'Dialog/alert overlay co-occurs with scare signals',
  'redirect-chain': 'Multiple redirects occurred before this page loaded',
  'informational-context': 'Scam-awareness or security-education context reduced the local risk score',
});

async function call(message) {
  const response = await api.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || 'Request failed');
  return response;
}

async function load() {
  try {
    const response = await call({ type: 'scam:warning:get', token });
    const warning = response.warning;
    if (!warning) throw new Error('This warning has expired');
    host.textContent = warning.host;
    category.textContent = CATEGORY_LABELS[warning.category] ?? 'Possible scam';
    if (warning.action === 'block') {
      title.textContent = 'Possible scam blocked';
      explanation.textContent = 'iShield Extension found strong local evidence associated with scam or fraud tactics on this site.';
    } else {
      title.textContent = 'Possible scam warning';
      explanation.textContent = 'iShield Extension found multiple local scam signals. Verify the site independently before paying, calling, downloading, or granting remote access.';
    }
    signals.replaceChildren(...warning.reasons.map((reason) => {
      const li = document.createElement('li');
      li.textContent = LABELS[reason] ?? 'Suspicious scam signal';
      return li;
    }));
  } catch (error) {
    title.textContent = 'Scam warning expired';
    explanation.textContent = 'The temporary local warning state is no longer available.';
    category.textContent = '';
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
    await call({ type: 'scam:warning:continue', token });
  } catch (error) {
    proceed.disabled = false;
    status.textContent = error?.message ?? 'Could not continue';
  }
});

void load();
