'use strict';

const MAX_HOST_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;

function isAscii(value) {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0x7f) return false;
  }
  return true;
}

function isValidDnsHost(host) {
  if (!host || host.length > MAX_HOST_LENGTH || !isAscii(host)) return false;
  if (host === 'localhost' || host.includes(':')) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host)) return false;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  return labels.every((label) => {
    if (!label || label.length > MAX_LABEL_LENGTH) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    return /^[a-z0-9-]+$/u.test(label);
  });
}

/**
 * Canonicalizes a URL or DNS host for DNR domain conditions.
 * Returns null for browser-internal URLs, IP literals, localhost, and malformed values.
 */
export function canonicalizeSiteHost(input) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 4096) return null;

  let parsed;
  try {
    parsed = trimmed.includes('://') ? new URL(trimmed) : new URL(`https://${trimmed}`);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  const host = parsed.hostname.toLowerCase().replace(/\.$/u, '');
  return isValidDnsHost(host) ? host : null;
}

export function normalizeAllowlist(values, cap) {
  if (!Array.isArray(values)) return [];
  const unique = new Set();
  for (const value of values) {
    const host = canonicalizeSiteHost(value);
    if (host) unique.add(host);
    if (unique.size >= cap) break;
  }
  return [...unique].sort();
}
