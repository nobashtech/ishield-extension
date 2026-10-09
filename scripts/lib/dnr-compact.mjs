// iShield clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
//
// Lossless compaction of declarativeNetRequest rules. Chrome/Firefox budget *rules*, not
// domains, and imported filter lists are dominated by one-domain rules ("||host^"). A rule
// whose only URL condition is a pure host anchor matches exactly the same requests as a
// `requestDomains: [host]` rule (host and its subdomains), so rules that agree on everything
// else (action, priority, other conditions) are merged into shared `requestDomains` lists.
// Anything that is not provably equivalent is passed through untouched.

const PURE_HOST_ANCHOR = /^\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\^$/u;

// Conditions that may accompany the host anchor and are copied verbatim into the merged rule.
// isUrlFilterCaseSensitive is deliberately absent: it only has meaning with urlFilter/regexFilter.
const MERGEABLE_CONDITION_KEYS = new Set([
  'urlFilter', 'resourceTypes', 'excludedResourceTypes', 'domainType',
  'initiatorDomains', 'excludedInitiatorDomains', 'requestMethods', 'excludedRequestMethods',
]);

export const MAX_DOMAINS_PER_RULE = 1000;

function hostOf(condition) {
  if (typeof condition?.urlFilter !== 'string') return null;
  if (Object.keys(condition).some((key) => !MERGEABLE_CONDITION_KEYS.has(key))) return null;
  const match = PURE_HOST_ANCHOR.exec(condition.urlFilter);
  return match && !match[1].includes('..') ? match[1] : null;
}

export function compactRules(rules, { maxDomainsPerRule = MAX_DOMAINS_PER_RULE } = {}) {
  if (!Array.isArray(rules)) throw new TypeError('rules must be an array');
  if (!Number.isInteger(maxDomainsPerRule) || maxDomainsPerRule < 1) throw new RangeError('invalid maxDomainsPerRule');
  const passthrough = [];
  const groups = new Map();
  for (const rule of rules) {
    const host = hostOf(rule.condition);
    if (host === null) { passthrough.push(rule); continue; }
    const { urlFilter, ...rest } = rule.condition;
    const key = JSON.stringify([rule.action, rule.priority ?? null, rest]);
    let group = groups.get(key);
    if (!group) { group = { action: rule.action, priority: rule.priority, rest, hosts: new Set() }; groups.set(key, group); }
    group.hosts.add(host);
  }
  const merged = [];
  for (const group of groups.values()) {
    const hosts = [...group.hosts].sort();
    for (let start = 0; start < hosts.length; start += maxDomainsPerRule) {
      const rule = { action: group.action, condition: { requestDomains: hosts.slice(start, start + maxDomainsPerRule), ...group.rest } };
      if (group.priority !== undefined) rule.priority = group.priority;
      merged.push(rule);
    }
  }
  // Rule order never affects matching, so exception rules are placed last: they then occupy one
  // contiguous id block, which lets consumers recognise them with a single range check.
  const isException = (rule) => rule.action?.type === 'allow' || rule.action?.type === 'allowAllRequests';
  // A single upstream rule can carry thousands of domains (host lists); split those at the same
  // cap so no rule exceeds it. The pieces are identical apart from their domain slice.
  const bounded = [...passthrough, ...merged].flatMap((rule) => {
    const domains = rule.condition?.requestDomains;
    if (!Array.isArray(domains) || domains.length <= maxDomainsPerRule) return [rule];
    const pieces = [];
    for (let start = 0; start < domains.length; start += maxDomainsPerRule) {
      pieces.push({ ...rule, condition: { ...rule.condition, requestDomains: domains.slice(start, start + maxDomainsPerRule) } });
    }
    return pieces;
  });
  const all = bounded;
  return [...all.filter((rule) => !isException(rule)), ...all.filter(isException)].map(({ id: _upstreamId, ...rule }, index) => ({ id: index + 1, ...rule }));
}
