'use strict';

export const PHISHING_ENGINE_VERSION = 1;
export const MAX_PASSWORD_FIELDS = 8;
export const MAX_CREDENTIAL_FIELDS = 16;
export const MAX_EXTERNAL_FORM_ACTIONS = 8;
export const MAX_REDIRECT_COUNT = 8;
export const KNOWN_PHISHING_BLOCK_CONFIDENCE = 85;
export const KNOWN_PHISHING_SIGNAL_CONFIDENCE = 65;

const MODES = Object.freeze({
  balanced: Object.freeze({ warn: 65, block: 90 }),
  strong: Object.freeze({ warn: 50, block: 80 }),
  maximum: Object.freeze({ warn: 40, block: 70 }),
});

const BRANDS = Object.freeze([
  Object.freeze({ token: 'paypal', official: Object.freeze(['paypal.com', 'paypalobjects.com']) }),
  Object.freeze({ token: 'microsoft', official: Object.freeze(['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'outlook.com']) }),
  Object.freeze({ token: 'google', official: Object.freeze(['google.com', 'gmail.com', 'youtube.com']) }),
  Object.freeze({ token: 'apple', official: Object.freeze(['apple.com', 'icloud.com']) }),
  Object.freeze({ token: 'amazon', official: Object.freeze(['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.in', 'amazon.com.au', 'amazon.co.jp', 'amazon.fr', 'amazon.it', 'amazon.es']) }),
  Object.freeze({ token: 'facebook', official: Object.freeze(['facebook.com', 'fb.com', 'meta.com']) }),
  Object.freeze({ token: 'instagram', official: Object.freeze(['instagram.com']) }),
  Object.freeze({ token: 'netflix', official: Object.freeze(['netflix.com']) }),
]);

const LURE_KEYWORDS = Object.freeze([
  'login', 'signin', 'sign-in', 'verify', 'verification', 'account', 'password',
  'credential', 'secure', 'wallet', 'payment', 'billing', 'invoice', 'unlock',
]);

const HIGH_VALUE_REASONS = new Set([
  'known-phishing', 'brand-impersonation', 'brand-confusable', 'url-credentials',
  'cross-origin-form', 'insecure-form-action',
]);

function boundedInteger(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`invalid ${name}`);
  return value;
}

function normalizeDom(candidate = {}) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) throw new TypeError('invalid dom signals');
  return Object.freeze({
    passwordFields: boundedInteger(candidate.passwordFields ?? 0, 0, MAX_PASSWORD_FIELDS, 'passwordFields'),
    credentialFields: boundedInteger(candidate.credentialFields ?? 0, 0, MAX_CREDENTIAL_FIELDS, 'credentialFields'),
    externalFormActions: boundedInteger(candidate.externalFormActions ?? 0, 0, MAX_EXTERNAL_FORM_ACTIONS, 'externalFormActions'),
    insecureFormAction: candidate.insecureFormAction === true,
    redirectCount: boundedInteger(candidate.redirectCount ?? 0, 0, MAX_REDIRECT_COUNT, 'redirectCount'),
  });
}

function hostIsDomainOrSubdomainOf(host, base) {
  return host === base || host.endsWith(`.${base}`);
}

function asciiSkeleton(value) {
  let output = '';
  for (const char of value.toLowerCase()) {
    if (char === '0') output += 'o';
    else if (char === '1') output += 'l';
    else if (char === '3') output += 'e';
    else if (char === '5') output += 's';
    else output += char;
  }
  return output;
}

function brandSignal(host) {
  let confusable = false;
  for (const profile of BRANDS) {
    if (profile.official.some((base) => hostIsDomainOrSubdomainOf(host, base))) continue;
    for (const label of host.split('.')) {
      if (label.includes(profile.token)) return 'brand-impersonation';
      for (const piece of label.split('-')) {
        if (Math.abs(piece.length - profile.token.length) > 1) continue;
        if (asciiSkeleton(piece) === profile.token) confusable = true;
      }
    }
  }
  return confusable ? 'brand-confusable' : null;
}

function isIpLiteral(host) {
  if (host.includes(':')) return true;
  const parts = host.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
}

function hasCredentialLure(parsed) {
  const path = parsed.pathname.toLowerCase();
  if (LURE_KEYWORDS.some((keyword) => path.includes(keyword))) return true;
  const raw = parsed.search.startsWith('?') ? parsed.search.slice(1) : parsed.search;
  for (const pair of raw.split('&').slice(0, 16)) {
    if (!pair) continue;
    const key = pair.split('=', 1)[0];
    if (key.length > 64) continue;
    const lower = key.toLowerCase();
    if (LURE_KEYWORDS.some((keyword) => lower.includes(keyword))) return true;
  }
  return false;
}

function addScore(score, amount) {
  return Math.min(100, score + amount);
}

function validateWebUrl(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 65536) throw new TypeError('invalid phishing URL');
  const parsed = new URL(value);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new TypeError('unsupported phishing URL scheme');
  if (!parsed.hostname || parsed.hostname.length > 253) throw new TypeError('invalid phishing host');
  return parsed;
}

/**
 * Evaluate one navigation using local-only evidence.
 * Returned verdicts deliberately omit URL/host/page content.
 */
export function evaluatePhishing(urlValue, options = {}) {
  const parsed = validateWebUrl(urlValue);
  const mode = typeof options.mode === 'string' && MODES[options.mode] ? options.mode : 'strong';
  const thresholds = MODES[mode];
  const dom = normalizeDom(options.dom ?? {});
  const nowMs = Number.isSafeInteger(options.nowMs) && options.nowMs >= 0 ? options.nowMs : Date.now();
  const reasons = [];
  let score = 0;
  let reputationConfidence = null;
  let reputationStale = false;

  const reputationIndex = options.reputationIndex ?? null;
  if (reputationIndex && typeof reputationIndex.lookup === 'function') {
    const lookup = reputationIndex.lookup(parsed.hostname, nowMs, 1);
    reputationStale = lookup?.datasetStatus === 'stale';
    const matched = reputationStale ? null : lookup?.matched;
    if (matched?.category === 'phishing') {
      reputationConfidence = matched.confidence;
      reasons.push('known-phishing');
      if (matched.confidence >= KNOWN_PHISHING_BLOCK_CONFIDENCE) {
        return Object.freeze({ action: 'block', score: 100, reasons: Object.freeze(reasons), reputationConfidence, reputationStale: false });
      }
      if (matched.confidence >= KNOWN_PHISHING_SIGNAL_CONFIDENCE) score = addScore(score, 50);
    } else if (matched?.category === 'suspicious' && matched.confidence >= 80) {
      reputationConfidence = matched.confidence;
      reasons.push('suspicious-infrastructure');
      score = addScore(score, 15);
    }
  }

  if (parsed.username || parsed.password) {
    reasons.push('url-credentials');
    score = addScore(score, 30);
  }

  const host = parsed.hostname.toLowerCase().replace(/\.$/u, '');
  const ipLiteral = isIpLiteral(host);
  if (!ipLiteral) {
    if (host.split('.').some((label) => label.startsWith('xn--'))) {
      reasons.push('punycode-host');
      score = addScore(score, 20);
    }
    const brand = brandSignal(host);
    if (brand) {
      reasons.push(brand);
      score = addScore(score, brand === 'brand-impersonation' ? 40 : 35);
    }
    if (host.split('.').length >= 7) {
      reasons.push('deep-host');
      score = addScore(score, 5);
    }
  }

  if (hasCredentialLure(parsed)) {
    reasons.push('credential-lure');
    score = addScore(score, 15);
  }
  if (dom.passwordFields > 0) {
    reasons.push('password-field');
    score = addScore(score, 15);
  }
  if (dom.externalFormActions > 0) {
    reasons.push('cross-origin-form');
    score = addScore(score, 30);
  }
  if (dom.insecureFormAction) {
    reasons.push('insecure-form-action');
    score = addScore(score, 20);
  }
  if (parsed.protocol === 'http:' && dom.passwordFields > 0) {
    reasons.push('http-password-page');
    score = addScore(score, 20);
  }
  if (dom.redirectCount >= 2) {
    reasons.push('redirect-chain');
    score = addScore(score, 10);
  }
  if (ipLiteral && (dom.passwordFields > 0 || dom.credentialFields > 1)) {
    reasons.push('ip-credential-surface');
    score = addScore(score, 25);
  }

  const highValue = reasons.some((reason) => HIGH_VALUE_REASONS.has(reason));
  const action = score >= thresholds.block && highValue ? 'block' : (score >= thresholds.warn ? 'warn' : 'allow');
  return Object.freeze({
    action,
    score,
    reasons: Object.freeze([...new Set(reasons)].slice(0, 16)),
    reputationConfidence,
    reputationStale,
  });
}

export function phishingBrandProfileCount() {
  return BRANDS.length;
}
