'use strict';

export const MAX_LEXICAL_HITS = 8;
export const MAX_PAYMENT_FIELDS = 16;
export const MAX_EXTERNAL_PAYMENT_FORMS = 8;
export const MAX_PHONE_LINKS = 16;
export const MAX_DOWNLOAD_LINKS = 32;
export const MAX_DIALOG_OVERLAYS = 8;
export const MAX_REDIRECT_COUNT = 8;
export const KNOWN_SCAM_BLOCK_CONFIDENCE = 85;
export const KNOWN_SCAM_SIGNAL_CONFIDENCE = 65;

const MODES = Object.freeze({
  balanced: Object.freeze({ warn: 70, block: 95 }),
  strong: Object.freeze({ warn: 55, block: 85 }),
  maximum: Object.freeze({ warn: 45, block: 75 }),
});

const CATEGORY_NAMES = Object.freeze([
  'general-scam', 'tech-support', 'investment', 'crypto', 'giveaway-prize', 'fake-shopping',
  'fake-support', 'impersonation', 'fake-download', 'payment', 'subscription',
  'suspicious-checkout', 'deceptive-alert', 'fake-antivirus',
]);

const HIGH_VALUE_REASONS = new Set([
  'known-scam', 'remote-access-request', 'irreversible-payment', 'cross-origin-payment-form',
  'deceptive-alert', 'antivirus-scare', 'impersonation-lure',
]);

function boundedInteger(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`invalid ${name}`);
  return value;
}

function normalizePage(candidate) {
  const input = candidate && typeof candidate === 'object' && !Array.isArray(candidate) ? candidate : {};
  const lexicalFields = [
    'techSupportHits', 'investmentHits', 'cryptoHits', 'giveawayHits', 'shoppingHits', 'supportHits',
    'impersonationHits', 'downloadHits', 'paymentHits', 'subscriptionHits', 'alertHits', 'antivirusHits',
    'urgencyHits', 'remoteAccessHits', 'irreversiblePaymentHits', 'informationalHits',
  ];
  const out = {};
  for (const name of lexicalFields) out[name] = boundedInteger(input[name] ?? 0, 0, MAX_LEXICAL_HITS, name);
  out.paymentFields = boundedInteger(input.paymentFields ?? 0, 0, MAX_PAYMENT_FIELDS, 'paymentFields');
  out.externalPaymentForms = boundedInteger(input.externalPaymentForms ?? 0, 0, MAX_EXTERNAL_PAYMENT_FORMS, 'externalPaymentForms');
  out.phoneLinks = boundedInteger(input.phoneLinks ?? 0, 0, MAX_PHONE_LINKS, 'phoneLinks');
  out.downloadLinks = boundedInteger(input.downloadLinks ?? 0, 0, MAX_DOWNLOAD_LINKS, 'downloadLinks');
  out.dialogOverlays = boundedInteger(input.dialogOverlays ?? 0, 0, MAX_DIALOG_OVERLAYS, 'dialogOverlays');
  out.redirectCount = boundedInteger(input.redirectCount ?? 0, 0, MAX_REDIRECT_COUNT, 'redirectCount');
  return Object.freeze(out);
}

function validateWebUrl(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 65536) throw new TypeError('invalid scam URL');
  const parsed = new URL(value);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new TypeError('unsupported scam URL scheme');
  if (!parsed.hostname || parsed.hostname.length > 253) throw new TypeError('invalid scam host');
  return parsed;
}

function isIpLiteral(host) {
  if (host.startsWith('[') && host.endsWith(']')) return true;
  const parts = host.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
}

function hasScamUrlLure(parsed) {
  const tokens = [
    'support', 'helpdesk', 'prize', 'winner', 'giveaway', 'claim', 'investment', 'crypto', 'wallet',
    'download', 'update', 'billing', 'checkout', 'payment', 'subscription', 'renewal', 'antivirus',
    'virus', 'security-alert', 'refund',
  ];
  const path = parsed.pathname.toLowerCase();
  if (tokens.some((token) => path.includes(token))) return true;
  const pairs = parsed.search.startsWith('?') ? parsed.search.slice(1).split('&').slice(0, 16) : [];
  for (const pair of pairs) {
    const key = pair.split('=')[0] ?? '';
    if (key.length > 64) continue;
    const lower = key.toLowerCase();
    if (tokens.some((token) => lower.includes(token))) return true;
  }
  return false;
}

function addScore(score, amount) {
  return Math.min(100, score + amount);
}

function lexicalScore(hits, base, extra) {
  if (hits === 0) return 0;
  return Math.min(255, base + Math.min(2, hits - 1) * extra);
}

function addCategory(scores, category, amount) {
  const index = CATEGORY_NAMES.indexOf(category);
  if (index < 0) throw new TypeError('unknown scam category');
  scores[index] = Math.min(65535, scores[index] + amount);
}

function strongestCategory(scores) {
  let bestIndex = -1;
  let bestScore = 0;
  for (let index = 0; index < scores.length; index += 1) {
    if (scores[index] > bestScore) {
      bestScore = scores[index];
      bestIndex = index;
    }
  }
  return bestIndex >= 0 ? CATEGORY_NAMES[bestIndex] : null;
}

function pushReason(reasons, reason) {
  if (!reasons.includes(reason) && reasons.length < 32) reasons.push(reason);
}

function applyLexical(page, reasons, categories, score) {
  let value = score;
  const items = [
    ['techSupportHits', 'tech-support-lure', 'tech-support', 20, 5, 3, 8],
    ['investmentHits', 'investment-lure', 'investment', 20, 5, 3, 8],
    ['cryptoHits', 'crypto-lure', 'crypto', 15, 4, 3, 6],
    ['giveawayHits', 'giveaway-prize-lure', 'giveaway-prize', 20, 5, 3, 8],
    ['shoppingHits', 'shopping-lure', 'fake-shopping', 10, 3, 3, 4],
    ['supportHits', 'support-lure', 'fake-support', 15, 4, 3, 6],
    ['impersonationHits', 'impersonation-lure', 'impersonation', 20, 5, 4, 8],
    ['downloadHits', 'fake-download-lure', 'fake-download', 15, 4, 3, 6],
    ['paymentHits', 'payment-lure', 'payment', 15, 4, 3, 6],
    ['subscriptionHits', 'subscription-lure', 'subscription', 15, 4, 4, 6],
    ['alertHits', 'deceptive-alert', 'deceptive-alert', 25, 5, 4, 10],
    ['antivirusHits', 'antivirus-scare', 'fake-antivirus', 25, 5, 4, 10],
  ];
  for (const [field, reason, category, base, extra, multiplier, categoryBase] of items) {
    const hits = page[field];
    if (hits <= 0) continue;
    pushReason(reasons, reason);
    value = addScore(value, lexicalScore(hits, base, extra));
    addCategory(categories, category, hits * multiplier + categoryBase);
  }
  if (page.urgencyHits > 0) {
    pushReason(reasons, 'urgency-pressure');
    value = addScore(value, lexicalScore(page.urgencyHits, 10, 3));
  }
  if (page.remoteAccessHits > 0) {
    pushReason(reasons, 'remote-access-request');
    value = addScore(value, lexicalScore(page.remoteAccessHits, 25, 5));
    addCategory(categories, 'tech-support', page.remoteAccessHits * 4 + 12);
  }
  if (page.irreversiblePaymentHits > 0) {
    pushReason(reasons, 'irreversible-payment');
    value = addScore(value, lexicalScore(page.irreversiblePaymentHits, 30, 5));
    addCategory(categories, 'payment', page.irreversiblePaymentHits * 4 + 12);
    addCategory(categories, 'crypto', page.irreversiblePaymentHits * 2);
  }
  return value;
}

function applyStructural(page, reasons, categories, score) {
  let value = score;
  if (page.externalPaymentForms > 0) {
    pushReason(reasons, 'cross-origin-payment-form');
    value = addScore(value, 25);
    addCategory(categories, 'suspicious-checkout', page.externalPaymentForms * 4 + 12);
  }
  if (page.paymentFields > 0) {
    pushReason(reasons, 'payment-fields');
    value = addScore(value, 5);
    addCategory(categories, 'suspicious-checkout', Math.min(4, page.paymentFields));
  }
  if (page.phoneLinks > 0 && (page.techSupportHits > 0 || page.supportHits > 0 || page.antivirusHits > 0 || page.alertHits > 0)) {
    pushReason(reasons, 'phone-contact');
    value = addScore(value, 5);
    addCategory(categories, 'fake-support', 3);
    addCategory(categories, 'tech-support', 3);
  }
  if (page.downloadLinks > 0 && (page.downloadHits > 0 || page.alertHits > 0 || page.antivirusHits > 0)) {
    pushReason(reasons, 'download-link');
    value = addScore(value, 5);
    addCategory(categories, 'fake-download', 5);
  }
  if (page.dialogOverlays > 0 && (page.alertHits > 0 || page.antivirusHits > 0)) {
    pushReason(reasons, 'dialog-overlay');
    value = addScore(value, 5);
    addCategory(categories, 'deceptive-alert', 4);
    addCategory(categories, 'fake-antivirus', 4);
  }
  if (page.redirectCount >= 2) {
    pushReason(reasons, 'redirect-chain');
    value = addScore(value, 10);
  }
  return value;
}

function applyCombinations(page, categories, score) {
  let value = score;
  if (page.techSupportHits > 0 && page.remoteAccessHits > 0) {
    value = addScore(value, 20); addCategory(categories, 'tech-support', 20);
  }
  if (page.alertHits > 0 && page.antivirusHits > 0) {
    value = addScore(value, 20); addCategory(categories, 'fake-antivirus', 14); addCategory(categories, 'deceptive-alert', 8);
  }
  if (page.investmentHits > 0 && (page.irreversiblePaymentHits > 0 || page.cryptoHits > 0)) {
    value = addScore(value, 15); addCategory(categories, 'investment', 12);
  }
  if (page.giveawayHits > 0 && (page.paymentHits > 0 || page.irreversiblePaymentHits > 0)) {
    value = addScore(value, 15); addCategory(categories, 'giveaway-prize', 12);
  }
  if (page.shoppingHits > 0 && page.externalPaymentForms > 0) {
    value = addScore(value, 15); addCategory(categories, 'fake-shopping', 10); addCategory(categories, 'suspicious-checkout', 8);
  }
  if (page.supportHits > 0 && page.impersonationHits > 0) {
    value = addScore(value, 10); addCategory(categories, 'impersonation', 10); addCategory(categories, 'fake-support', 6);
  }
  if (page.subscriptionHits > 0 && page.urgencyHits > 0) {
    value = addScore(value, 10); addCategory(categories, 'subscription', 8);
  }
  if (page.downloadHits > 0 && (page.alertHits > 0 || page.antivirusHits > 0)) {
    value = addScore(value, 10); addCategory(categories, 'fake-download', 8);
  }
  if (page.paymentHits > 0 && page.urgencyHits > 0) {
    value = addScore(value, 10); addCategory(categories, 'payment', 8);
  }
  return value;
}

function applyFalsePositiveMitigation(page, reasons, score) {
  if (page.informationalHits >= 2
      && page.urgencyHits === 0
      && page.paymentHits === 0
      && page.irreversiblePaymentHits === 0
      && page.externalPaymentForms === 0
      && page.phoneLinks === 0) {
    pushReason(reasons, 'informational-context');
    return Math.max(0, score - 30);
  }
  return score;
}

/**
 * Evaluate one navigation using local reputation + privacy-minimized page evidence.
 * Returned values never contain URL, hostname, raw text, phone numbers, form values, or link targets.
 */
export function evaluateScam(urlValue, options = {}) {
  const parsed = validateWebUrl(urlValue);
  const mode = typeof options.mode === 'string' && MODES[options.mode] ? options.mode : 'strong';
  const thresholds = MODES[mode];
  const page = normalizePage(options.page ?? {});
  const nowMs = Number.isSafeInteger(options.nowMs) && options.nowMs >= 0 ? options.nowMs : Date.now();
  const reasons = [];
  const categoryScores = new Array(CATEGORY_NAMES.length).fill(0);
  let score = 0;
  let reputationConfidence = null;
  let reputationStale = false;

  const reputationIndex = options.reputationIndex ?? null;
  if (reputationIndex && typeof reputationIndex.lookup === 'function') {
    const lookup = reputationIndex.lookup(parsed.hostname, nowMs, 1);
    reputationStale = lookup?.datasetStatus === 'stale';
    const matched = reputationStale ? null : lookup?.matched;
    if (matched?.category === 'scam' && matched.confidence >= KNOWN_SCAM_SIGNAL_CONFIDENCE) {
      reputationConfidence = matched.confidence;
      pushReason(reasons, 'known-scam');
      addCategory(categoryScores, 'general-scam', 80);
      if (matched.confidence >= KNOWN_SCAM_BLOCK_CONFIDENCE) {
        return Object.freeze({
          action: 'block', score: 100, category: 'general-scam', reasons: Object.freeze([...reasons]),
          reputationConfidence, reputationStale: false,
        });
      }
      score = addScore(score, 55);
    } else if (matched?.category === 'suspicious' && matched.confidence >= 80) {
      reputationConfidence = matched.confidence;
      pushReason(reasons, 'suspicious-infrastructure');
      score = addScore(score, 15);
    }
  }

  const host = parsed.hostname.toLowerCase().replace(/\.$/u, '');
  if (isIpLiteral(host)) {
    pushReason(reasons, 'ip-host');
    score = addScore(score, 5);
  } else {
    if (host.split('.').some((label) => label.startsWith('xn--'))) {
      pushReason(reasons, 'punycode-host');
      score = addScore(score, 10);
    }
    if (host.split('.').length >= 7) {
      pushReason(reasons, 'deep-host');
      score = addScore(score, 5);
    }
  }

  if (hasScamUrlLure(parsed)) {
    pushReason(reasons, 'scam-url-lure');
    score = addScore(score, 10);
  }

  score = applyLexical(page, reasons, categoryScores, score);
  score = applyStructural(page, reasons, categoryScores, score);
  score = applyCombinations(page, categoryScores, score);
  score = applyFalsePositiveMitigation(page, reasons, score);

  const category = strongestCategory(categoryScores);
  const highValue = reasons.some((reason) => HIGH_VALUE_REASONS.has(reason));
  const action = score >= thresholds.block && highValue ? 'block' : (score >= thresholds.warn ? 'warn' : 'allow');
  return Object.freeze({
    action,
    score,
    category,
    reasons: Object.freeze([...reasons].slice(0, 32)),
    reputationConfidence,
    reputationStale,
  });
}

export function scamCategoryNames() {
  return CATEGORY_NAMES;
}
