'use strict';

import { canonicalizeSiteHost } from './domain.js';

export const STRICT_POLICY_KEY = 'ishield.strict.v1';
export const STRICT_SCHEMA_VERSION = 1;
export const STRICT_POLICY_CAP = 2048;
export const STRICT_TARGET_MAX_BYTES = 512;
export const STRICT_CATEGORY_MAX_BYTES = 64;
export const STRICT_APPLICATION_MAX_BYTES = 256;
const TEXT_ENCODER = new TextEncoder();

function byteLength(value) { return TEXT_ENCODER.encode(value).length; }
function validCategory(value) { return /^[a-z0-9][a-z0-9_-]{0,63}$/u.test(value); }
function validApplication(value) { return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value); }

function normalizeDomain(value) {
  if (typeof value !== 'string' || !value || value.includes('/') || value.includes('@')) return null;
  return canonicalizeSiteHost(`https://${value}/`);
}

function normalizePathPrefix(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.includes('?') || value.includes('#') || value.includes('\\')) return null;
  const prefix = value.endsWith('*') ? value.slice(0, -1) : value;
  if (!prefix.startsWith('/') || byteLength(prefix) > STRICT_TARGET_MAX_BYTES || prefix.includes('*') || /[\u0000-\u0020]/u.test(prefix)) return null;
  return prefix;
}

export function parseStrictTarget(raw) {
  if (typeof raw !== 'string') throw new TypeError('Strict Mode target must be text');
  const value = raw.trim();
  if (!value) throw new TypeError('Strict Mode target is empty');
  if (byteLength(value) > STRICT_TARGET_MAX_BYTES) throw new RangeError('Strict Mode target too long');

  if (value.startsWith('category:')) {
    const category = value.slice(9).trim().toLowerCase();
    if (!validCategory(category) || byteLength(category) > STRICT_CATEGORY_MAX_BYTES) throw new TypeError('invalid category target');
    return Object.freeze({ kind: 'category', target: `category:${category}`, category });
  }
  if (value.startsWith('app:')) {
    const application = value.slice(4).trim();
    if (!validApplication(application) || byteLength(application) > STRICT_APPLICATION_MAX_BYTES) throw new TypeError('invalid application target');
    return Object.freeze({ kind: 'application', target: `app:${application}`, application });
  }
  if (value.includes('://') || value.includes('?') || value.includes('#') || value.includes('@') || value.includes(':')) throw new TypeError('enter a host/path without URL credentials, query, or fragment');

  let scope = 'domainTree';
  let body = value;
  if (body.startsWith('=')) { scope = 'exact'; body = body.slice(1); }
  if (body.startsWith('*.')) { scope = 'wildcardSubdomains'; body = body.slice(2); }
  const slash = body.indexOf('/');
  const hostText = slash === -1 ? body : body.slice(0, slash);
  const host = normalizeDomain(hostText);
  if (!host) throw new TypeError('invalid Strict Mode domain');

  if (slash !== -1) {
    const prefix = normalizePathPrefix(body.slice(slash));
    if (!prefix) throw new TypeError('invalid Strict Mode path prefix');
    const targetPrefix = scope === 'exact' ? '=' : (scope === 'wildcardSubdomains' ? '*.' : '');
    return Object.freeze({ kind: 'pathPrefix', scope, host, prefix, target: `${targetPrefix}${host}${prefix}*` });
  }
  if (scope === 'exact') return Object.freeze({ kind: 'exactDomain', host, target: `=${host}` });
  if (scope === 'wildcardSubdomains') return Object.freeze({ kind: 'wildcardSubdomains', host, target: `*.${host}` });
  return Object.freeze({ kind: 'domainTree', host, target: host });
}

// Whether a policy blocks navigations to this page. DNR only affects new requests, so the extension
// uses this to reload tabs that are already open on a site the user has just blocked.
export function strictPolicyMatchesUrl(policy, url) {
  let parsed;
  try { parsed = new URL(url); } catch { return false; }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  const host = parsed.hostname.toLowerCase();
  const subdomain = host.endsWith(`.${policy.host}`);
  switch (policy.kind) {
    case 'domainTree': return host === policy.host || subdomain;
    case 'exactDomain': return host === policy.host;
    case 'wildcardSubdomains': return subdomain;
    case 'pathPrefix': {
      const hostMatches = policy.scope === 'exact' ? host === policy.host : (policy.scope === 'wildcardSubdomains' ? subdomain : (host === policy.host || subdomain));
      return hostMatches && parsed.pathname.startsWith(policy.prefix);
    }
    default: return false;
  }
}

export function defaultStrictState() {
  return { schemaVersion: STRICT_SCHEMA_VERSION, nextId: 1, policies: [] };
}

export function normalizeStrictState(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return defaultStrictState();
  const policies = [];
  const seenIds = new Set();
  const seenTargets = new Set();
  for (const raw of Array.isArray(candidate.policies) ? candidate.policies.slice(0, STRICT_POLICY_CAP * 2) : []) {
    if (!Number.isSafeInteger(raw?.id) || raw.id < 1 || seenIds.has(raw.id)) continue;
    let parsed;
    try { parsed = parseStrictTarget(raw.target); } catch { continue; }
    if (seenTargets.has(parsed.target)) continue;
    seenIds.add(raw.id); seenTargets.add(parsed.target);
    policies.push(Object.freeze({ id: raw.id, ...parsed }));
    if (policies.length >= STRICT_POLICY_CAP) break;
  }
  const maxId = policies.reduce((max, policy) => Math.max(max, policy.id), 0);
  const requested = Number.isSafeInteger(candidate.nextId) && candidate.nextId > maxId ? candidate.nextId : maxId + 1;
  return { schemaVersion: STRICT_SCHEMA_VERSION, nextId: Math.min(Number.MAX_SAFE_INTEGER, requested), policies };
}

export function strictCapabilities() {
  return Object.freeze({
    browserDomainPathEnforcement: true,
    categoryResolverReady: true,
    applicationResolverReady: false,
    persistsAcrossBrowserRestart: true,
    overridesRegularSitePause: true,
    storesVisitedUrls: false,
  });
}

export class StrictPolicyStore {
  constructor(storageArea) {
    if (!storageArea?.get || !storageArea?.set) throw new TypeError('storage API unavailable');
    this.storageArea = storageArea;
    this.queue = Promise.resolve();
  }
  exclusive(operation) {
    const run = this.queue.then(operation, operation);
    this.queue = run.catch(() => undefined);
    return run;
  }
  async load() {
    const stored = await this.storageArea.get(STRICT_POLICY_KEY);
    return normalizeStrictState(stored?.[STRICT_POLICY_KEY]);
  }
  async persist(state) {
    const normalized = normalizeStrictState(state);
    await this.storageArea.set({ [STRICT_POLICY_KEY]: normalized });
    return normalized;
  }
  add(target) {
    return this.exclusive(async () => {
      const parsed = parseStrictTarget(target);
      const state = await this.load();
      if (state.policies.some((policy) => policy.target === parsed.target)) return state;
      if (state.policies.length >= STRICT_POLICY_CAP || state.nextId >= Number.MAX_SAFE_INTEGER) throw new RangeError('Strict Mode policy capacity exceeded');
      state.policies.push(Object.freeze({ id: state.nextId, ...parsed }));
      state.nextId += 1;
      return this.persist(state);
    });
  }
  remove(id) {
    return this.exclusive(async () => {
      if (!Number.isSafeInteger(id) || id < 1) throw new TypeError('invalid Strict Mode policy id');
      const state = await this.load();
      state.policies = state.policies.filter((policy) => policy.id !== id);
      return this.persist(state);
    });
  }
}
