// iShield clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
// This documentation-only header does not change runtime behavior.

'use strict';

export const PHISHING_SESSION_KEY = 'ishield.phishing.session.v1';
export const INTERVENTION_CAP = 16;
export const BYPASS_CAP = 16;
export const INTERVENTION_TTL_MS = 10 * 60 * 1000;
export const BYPASS_TTL_MS = 5 * 60 * 1000;
const TOKEN_RE = /^[0-9a-f]{32}$/u;
const ALLOWED_ACTIONS = new Set(['warn', 'block']);
const ALLOWED_REASONS = new Set([
  'known-phishing', 'url-credentials', 'punycode-host', 'brand-impersonation', 'brand-confusable',
  'credential-lure', 'ip-credential-surface', 'password-field', 'cross-origin-form',
  'insecure-form-action', 'http-password-page', 'deep-host', 'suspicious-infrastructure', 'redirect-chain',
]);

function defaultState() {
  return { interventions: [], bypasses: [] };
}

function tokenFromCrypto() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
}

function normalizeUrl(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 65536) throw new TypeError('invalid intervention URL');
  const parsed = new URL(value);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new TypeError('unsupported intervention URL');
  parsed.hash = '';
  return parsed.href;
}

function normalizeVerdict(verdict) {
  if (!verdict || typeof verdict !== 'object' || !ALLOWED_ACTIONS.has(verdict.action)) throw new TypeError('invalid phishing verdict');
  if (!Number.isInteger(verdict.score) || verdict.score < 0 || verdict.score > 100) throw new TypeError('invalid phishing score');
  const reasons = Array.isArray(verdict.reasons) ? [...new Set(verdict.reasons.filter((reason) => ALLOWED_REASONS.has(reason)))].slice(0, 16) : [];
  return { action: verdict.action, score: verdict.score, reasons };
}

function prune(state, now) {
  const candidate = state && typeof state === 'object' && !Array.isArray(state) ? state : defaultState();
  const interventions = (Array.isArray(candidate.interventions) ? candidate.interventions : [])
    .filter((item) => item && TOKEN_RE.test(item.token) && typeof item.url === 'string' && Number.isSafeInteger(item.expiresAt) && item.expiresAt > now)
    .slice(-INTERVENTION_CAP);
  const bypasses = (Array.isArray(candidate.bypasses) ? candidate.bypasses : [])
    .filter((item) => item && typeof item.url === 'string' && Number.isSafeInteger(item.expiresAt) && item.expiresAt > now)
    .slice(-BYPASS_CAP);
  return { interventions, bypasses };
}

export class PhishingSessionStore {
  constructor(storageArea, tokenFactory = tokenFromCrypto) {
    if (!storageArea?.get || !storageArea?.set) throw new TypeError('session storage unavailable');
    this.storageArea = storageArea;
    this.tokenFactory = tokenFactory;
    this.queue = Promise.resolve();
  }

  exclusive(operation) {
    const run = this.queue.then(operation, operation);
    this.queue = run.catch(() => undefined);
    return run;
  }

  async load(now = Date.now()) {
    const stored = await this.storageArea.get(PHISHING_SESSION_KEY);
    return prune(stored?.[PHISHING_SESSION_KEY], now);
  }

  async save(state, now = Date.now()) {
    const normalized = prune(state, now);
    await this.storageArea.set({ [PHISHING_SESSION_KEY]: normalized });
    return normalized;
  }

  hasBypass(url, now = Date.now()) {
    return this.exclusive(async () => {
      const normalizedUrl = normalizeUrl(url);
      const state = await this.load(now);
      return state.bypasses.some((item) => item.url === normalizedUrl && item.expiresAt > now);
    });
  }

  create(url, verdict, now = Date.now()) {
    return this.exclusive(async () => {
      const normalizedUrl = normalizeUrl(url);
      const safeVerdict = normalizeVerdict(verdict);
      const state = await this.load(now);
      let token = this.tokenFactory();
      if (!TOKEN_RE.test(token)) throw new TypeError('invalid intervention token');
      for (let attempts = 0; attempts < 3 && state.interventions.some((item) => item.token === token); attempts += 1) token = this.tokenFactory();
      if (state.interventions.some((item) => item.token === token)) throw new Error('intervention token collision');
      state.interventions.push({ token, url: normalizedUrl, verdict: safeVerdict, expiresAt: now + INTERVENTION_TTL_MS });
      await this.save(state, now);
      return token;
    });
  }

  view(token, now = Date.now()) {
    return this.exclusive(async () => {
      if (!TOKEN_RE.test(token)) return null;
      const state = await this.load(now);
      const item = state.interventions.find((entry) => entry.token === token);
      if (!item) return null;
      const parsed = new URL(item.url);
      return Object.freeze({
        action: item.verdict.action,
        score: item.verdict.score,
        reasons: Object.freeze([...item.verdict.reasons]),
        host: parsed.hostname,
      });
    });
  }

  continue(token, now = Date.now()) {
    return this.exclusive(async () => {
      if (!TOKEN_RE.test(token)) return null;
      const state = await this.load(now);
      const index = state.interventions.findIndex((entry) => entry.token === token);
      if (index < 0) return null;
      const [item] = state.interventions.splice(index, 1);
      state.bypasses = state.bypasses.filter((entry) => entry.url !== item.url);
      state.bypasses.push({ url: item.url, expiresAt: now + BYPASS_TTL_MS });
      await this.save(state, now);
      return item.url;
    });
  }

  discard(token, now = Date.now()) {
    return this.exclusive(async () => {
      if (!TOKEN_RE.test(token)) return false;
      const state = await this.load(now);
      const before = state.interventions.length;
      state.interventions = state.interventions.filter((entry) => entry.token !== token);
      await this.save(state, now);
      return state.interventions.length !== before;
    });
  }
}
