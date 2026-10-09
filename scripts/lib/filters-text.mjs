// iShield clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
//
// Parses the plain-text filter list you publish (update/filters.txt) into the host-level
// `network-rules` payload the signed update system understands. Only host rules are supported,
// because that is what the extension will accept from a remote source (see update-runtime.js).
//
//   ! or # ...             comment
//   ||ads.example.com^     block the host and its subdomains for page resources
//   tracker.example.net    bare domain: same as ||tracker.example.net^
//   =only.example.org      exact host only (no subdomains)
//   ||bad.example.com^$all also block opening the site itself; $document blocks only navigation

import { domainToASCII } from 'node:url';

export const SUBRESOURCE_TYPES = Object.freeze(['sub_frame', 'script', 'image', 'stylesheet', 'xmlhttprequest', 'font', 'media', 'websocket', 'ping', 'object', 'other']);
export const MAX_RULES = 10_000;

export function normalizeHost(value) {
  const ascii = domainToASCII(value.toLowerCase());
  const labels = ascii.split('.');
  const valid = ascii.length > 0 && ascii.length <= 253 && labels.length >= 2
    && !/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(ascii)
    && labels.every((label) => label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label));
  return valid ? ascii : null;
}

export function parseFiltersText(text) {
  const rules = [];
  const errors = [];
  const seen = new Set();
  text.split(/\r?\n/u).forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('!') || line.startsWith('#')) return;
    const lineNumber = index + 1;
    const [pattern, modifier, ...extra] = line.split('$');
    if (extra.length > 0) { errors.push(`line ${lineNumber}: only one $modifier is supported`); return; }
    let scope = 'host-and-subdomains';
    let host = pattern.trim();
    if (host.startsWith('=')) { scope = 'exact'; host = host.slice(1); }
    else if (host.startsWith('||')) host = host.slice(2).replace(/\^$/u, '');
    if (host.includes('/') || host.includes('*') || host.includes('^') || host.includes('|') || host.includes(':')) {
      errors.push(`line ${lineNumber}: paths, wildcards and ports are not supported (host rules only): ${line}`);
      return;
    }
    const normalized = normalizeHost(host);
    if (normalized === null) { errors.push(`line ${lineNumber}: not a valid DNS host: ${line}`); return; }
    let resourceTypes = [...SUBRESOURCE_TYPES];
    if (modifier !== undefined) {
      const option = modifier.trim().toLowerCase();
      if (option === 'all') resourceTypes = ['main_frame', ...SUBRESOURCE_TYPES];
      else if (option === 'document') resourceTypes = ['main_frame'];
      else { errors.push(`line ${lineNumber}: unsupported modifier $${modifier}`); return; }
    }
    const key = `${scope}|${normalized}|${resourceTypes.join(',')}`;
    if (seen.has(key)) return;
    seen.add(key);
    rules.push({ host: normalized, scope, resourceTypes });
  });
  if (rules.length > MAX_RULES) errors.push(`too many rules: ${rules.length} (limit ${MAX_RULES})`);
  return { rules, errors };
}
