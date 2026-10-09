'use strict';

export const SITE_ALLOWLIST_CAP = 1000;
export const SITE_COMPATIBILITY_CAP = 512;

export function hostToExcludeMatch(host) {
  if (typeof host !== 'string' || !host || host.length > 253 || /[\s/]/u.test(host)) throw new TypeError('invalid allowlist host');
  if (host.includes(':')) return `*://[${host}]/*`;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(host) || !host.includes('.')) return `*://${host}/*`;
  return `*://*.${host}/*`;
}

export function allowlistToExcludeMatches(allowlist) {
  if (!Array.isArray(allowlist)) return [];
  const out = [];
  const seen = new Set();
  for (const host of allowlist.slice(0, SITE_ALLOWLIST_CAP)) {
    const pattern = hostToExcludeMatch(host);
    if (!seen.has(pattern)) { seen.add(pattern); out.push(pattern); }
  }
  return out;
}

export function normalizeCompatibilityExcludeMatches(values) {
  if (!Array.isArray(values)) return [];
  const out = [];
  const seen = new Set();
  const re = /^\*:\/\/(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\/\*$/u;
  for (const value of values.slice(0, SITE_COMPATIBILITY_CAP)) {
    if (typeof value !== 'string' || !re.test(value)) continue;
    if (!seen.has(value)) { seen.add(value); out.push(value); }
  }
  return out;
}

export function combinedSiteExcludeMatches(state, compatibilityExcludeMatches = []) {
  return [...new Set([
    ...allowlistToExcludeMatches(state?.allowlist),
    ...normalizeCompatibilityExcludeMatches(compatibilityExcludeMatches),
  ])];
}
