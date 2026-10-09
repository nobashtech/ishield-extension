'use strict';

import { STRICT_POLICY_CAP, normalizeStrictState } from './strict-policy.js';
import { CategoryIndex } from './category-index.js';

export const STRICT_RULE_ID_START = 1_200_000;
export const STRICT_RULE_ID_END = STRICT_RULE_ID_START + STRICT_POLICY_CAP - 1;
export const STRICT_CATEGORY_RULE_ID_START = 1_300_000;
export const STRICT_CATEGORY_RULE_CAP = 512;
export const STRICT_CATEGORY_DOMAINS_PER_RULE = 250;
export const STRICT_RULE_PRIORITY = 2_000_000;
const NAVIGATION_TYPES = Object.freeze(['main_frame', 'sub_frame']);

function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'); }

function domainRegex(host, scope) {
  const base = escapeRegex(host);
  if (scope === 'exact') return `^https?://${base}(?::[0-9]{1,5})?(?:/|$)`;
  if (scope === 'wildcardSubdomains') return `^https?://(?:[^./]+\\.)+${base}(?::[0-9]{1,5})?(?:/|$)`;
  return `^https?://(?:[^./]+\\.)*${base}(?::[0-9]{1,5})?(?:/|$)`;
}

function pathRegex(policy) {
  const base = escapeRegex(policy.host);
  const prefix = escapeRegex(policy.prefix);
  const hostPart = policy.scope === 'exact'
    ? base
    : (policy.scope === 'wildcardSubdomains' ? `(?:[^./]+\\.)+${base}` : `(?:[^./]+\\.)*${base}`);
  return `^https?://${hostPart}(?::[0-9]{1,5})?${prefix}`;
}

function compileCategoryRules(categoryPolicies, categoryIndex, nowMs) {
  if (!(categoryIndex instanceof CategoryIndex) || categoryIndex.status(nowMs) !== 'current') {
    return { rules: [], unresolvedCategoryCount: categoryPolicies.length, resolvedCategoryCount: 0, resolvedCategoryDomainCount: 0 };
  }
  const treeHosts = [];
  const exactHosts = [];
  const emitted = new Set();
  let unresolvedCategoryCount = 0;
  let resolvedCategoryCount = 0;

  for (const policy of categoryPolicies) {
    const records = categoryIndex.domainsForCategory(policy.category, nowMs, 80);
    if (records.length === 0) { unresolvedCategoryCount += 1; continue; }
    resolvedCategoryCount += 1;
    for (const record of records) {
      const identity = `${record.scope}\0${record.host}`;
      if (emitted.has(identity)) continue;
      emitted.add(identity);
      if (record.scope === 'exact') exactHosts.push(record.host);
      else treeHosts.push(record.host);
    }
  }

  const rules = [];
  for (let offset = 0; offset < treeHosts.length; offset += STRICT_CATEGORY_DOMAINS_PER_RULE) {
    if (rules.length >= STRICT_CATEGORY_RULE_CAP) throw new RangeError('Strict Mode category DNR capacity exceeded');
    rules.push(Object.freeze({
      id: STRICT_CATEGORY_RULE_ID_START + rules.length,
      priority: STRICT_RULE_PRIORITY,
      action: { type: 'block' },
      condition: { requestDomains: treeHosts.slice(offset, offset + STRICT_CATEGORY_DOMAINS_PER_RULE), resourceTypes: NAVIGATION_TYPES },
    }));
  }
  for (const host of exactHosts) {
    if (rules.length >= STRICT_CATEGORY_RULE_CAP) throw new RangeError('Strict Mode category DNR capacity exceeded');
    rules.push(Object.freeze({
      id: STRICT_CATEGORY_RULE_ID_START + rules.length,
      priority: STRICT_RULE_PRIORITY,
      action: { type: 'block' },
      condition: { regexFilter: domainRegex(host, 'exact'), isUrlFilterCaseSensitive: true, resourceTypes: NAVIGATION_TYPES },
    }));
  }
  return { rules, unresolvedCategoryCount, resolvedCategoryCount, resolvedCategoryDomainCount: emitted.size };
}

export function buildStrictDnrRules(candidate, categoryIndex = null, nowMs = Date.now()) {
  const state = normalizeStrictState(candidate);
  const domainRules = [];
  const categoryPolicies = [];
  let unresolvedApplicationCount = 0;
  for (const policy of state.policies) {
    if (policy.kind === 'category') { categoryPolicies.push(policy); continue; }
    if (policy.kind === 'application') { unresolvedApplicationCount += 1; continue; }
    if (domainRules.length >= STRICT_POLICY_CAP) break;
    const condition = { resourceTypes: NAVIGATION_TYPES };
    if (policy.kind === 'domainTree') condition.urlFilter = `||${policy.host}^`;
    else if (policy.kind === 'exactDomain') { condition.regexFilter = domainRegex(policy.host, 'exact'); condition.isUrlFilterCaseSensitive = true; }
    else if (policy.kind === 'wildcardSubdomains') { condition.regexFilter = domainRegex(policy.host, 'wildcardSubdomains'); condition.isUrlFilterCaseSensitive = true; }
    else if (policy.kind === 'pathPrefix') { condition.regexFilter = pathRegex(policy); condition.isUrlFilterCaseSensitive = true; }
    else continue;
    domainRules.push({ id: STRICT_RULE_ID_START + domainRules.length, priority: STRICT_RULE_PRIORITY, action: { type: 'block' }, condition });
  }
  const category = compileCategoryRules(categoryPolicies, categoryIndex, nowMs);
  return {
    rules: [...domainRules, ...category.rules],
    managedDomainRuleCount: domainRules.length,
    managedCategoryRuleCount: category.rules.length,
    unresolvedCategoryCount: category.unresolvedCategoryCount,
    resolvedCategoryCount: category.resolvedCategoryCount,
    resolvedCategoryDomainCount: category.resolvedCategoryDomainCount,
    unresolvedApplicationCount,
  };
}

export function isStrictDynamicRuleId(id) {
  return Number.isInteger(id) && (
    (id >= STRICT_RULE_ID_START && id <= STRICT_RULE_ID_END)
    || (id >= STRICT_CATEGORY_RULE_ID_START && id < STRICT_CATEGORY_RULE_ID_START + STRICT_CATEGORY_RULE_CAP)
  );
}

async function validateStrictRegexRules(dnrApi, rules) {
  if (typeof dnrApi?.isRegexSupported !== 'function') return;
  for (const rule of rules) {
    const regex = rule?.condition?.regexFilter;
    if (typeof regex !== 'string') continue;
    const result = await dnrApi.isRegexSupported({ regex, isCaseSensitive: rule.condition.isUrlFilterCaseSensitive === true, requireCapturing: false });
    if (result?.isSupported !== true) throw new Error('Strict Mode regex capability rejected');
  }
}

function stableRuleView(rules) { return [...rules].sort((a, b) => a.id - b.id).map((rule) => JSON.stringify(rule)); }

export async function reconcileStrictRules(dnrApi, candidate, categoryIndex = null, nowMs = Date.now()) {
  const current = (await dnrApi.getDynamicRules()).filter((rule) => isStrictDynamicRuleId(rule?.id));
  const desired = buildStrictDnrRules(candidate, categoryIndex, nowMs);
  let changed = false;
  if (JSON.stringify(stableRuleView(current)) !== JSON.stringify(stableRuleView(desired.rules))) {
    await validateStrictRegexRules(dnrApi, desired.rules);
    await dnrApi.updateDynamicRules({ removeRuleIds: current.map((rule) => rule.id), addRules: desired.rules });
    changed = true;
  }
  return {
    changed,
    managedStrictRuleCount: desired.rules.length,
    managedStrictDomainRuleCount: desired.managedDomainRuleCount,
    managedStrictCategoryRuleCount: desired.managedCategoryRuleCount,
    unresolvedCategoryCount: desired.unresolvedCategoryCount,
    resolvedCategoryCount: desired.resolvedCategoryCount,
    resolvedCategoryDomainCount: desired.resolvedCategoryDomainCount,
    unresolvedApplicationCount: desired.unresolvedApplicationCount,
  };
}
