'use strict';

import {
  ALLOWLIST_RULE_CAP,
  ALLOWLIST_RULE_ID_START,
  ALLOWLIST_RULE_PRIORITY,
  FILTER_LISTS,
  REGEX_VALIDATION_CAP,
  RULESET_IDS,
} from './constants.js';
import { canonicalizeSiteHost, normalizeAllowlist } from './domain.js';
import { reconcileStrictRules } from './strict-manager.js';
import { compileSignedNetworkRules, isSignedUpdateRuleId } from './update-runtime.js';

const ALLOWLIST_RULE_ID_END = ALLOWLIST_RULE_ID_START + ALLOWLIST_RULE_CAP - 1;
const MAIN_FRAME = Object.freeze(['main_frame']);

// Order is priority order: if the browser's budget cannot hold every ruleset,
// reconcileStaticRulesets enables them front-to-back and skips what doesn't fit.
// A list loads when its protection layer is on and its own switch is on (default per FILTER_LISTS).
export function desiredStaticRulesets(state) {
  if (!state.protectionEnabled) return [];
  const layerOn = (layer) => state.features?.[layer] !== false;
  const listOn = (list) => layerOn(list.layer) && (typeof state.lists?.[list.key] === 'boolean' ? state.lists[list.key] : list.defaultOn);
  const ads = layerOn('ads');
  const strong = state.mode === 'strong' || state.mode === 'maximum';
  const desired = [];
  if (ads) desired.push(RULESET_IDS.core);
  for (const list of FILTER_LISTS) {
    if (listOn(list)) desired.push(list.rulesetId);
    if (list.key === 'tracking') {
      if (ads && strong) desired.push(RULESET_IDS.strong);
      if (ads && state.mode === 'maximum') desired.push(RULESET_IDS.maximum);
    }
  }
  return desired;
}

export function buildAllowlistRules(values) {
  const domains = normalizeAllowlist(values, ALLOWLIST_RULE_CAP);
  return domains.map((domain, index) => ({
    id: ALLOWLIST_RULE_ID_START + index,
    priority: ALLOWLIST_RULE_PRIORITY,
    action: { type: 'allowAllRequests' },
    condition: { requestDomains: [domain], resourceTypes: MAIN_FRAME },
  }));
}

function isAllowlistRule(rule) { return Number.isInteger(rule?.id) && rule.id >= ALLOWLIST_RULE_ID_START && rule.id <= ALLOWLIST_RULE_ID_END; }
function stableRuleView(rules) { return [...rules].sort((a, b) => a.id - b.id).map((rule) => JSON.stringify(rule)); }

function withCachedDynamicRules(dnrApi, dynamicRules) {
  // One reconcile pass operates on disjoint managed ID ranges. Reuse a single native
  // getDynamicRules() snapshot to avoid four browser IPC reads and repeated cloning.
  return new Proxy(dnrApi, {
    get(target, property, receiver) {
      if (property === 'getDynamicRules') return async () => dynamicRules;
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}


/**
 * Preserve Firefox's capability-driven regex validation contract. Signed/Strict
 * generated regex rules are validated separately before activation, while this
 * helper remains available to older rule pipelines and Phase 8 callers.
 */
export async function validateRegexCandidates(dnrApi, rules, cap = REGEX_VALIDATION_CAP) {
  if (!Array.isArray(rules)) throw new TypeError('rules must be an array');
  if (!Number.isInteger(cap) || cap < 1 || cap > REGEX_VALIDATION_CAP) throw new RangeError('invalid regex validation cap');
  const candidates = rules.filter((rule) => typeof rule?.condition?.regexFilter === 'string');
  if (candidates.length > cap) throw new RangeError('regex candidate capacity exceeded');
  if (typeof dnrApi?.isRegexSupported !== 'function') {
    return { supportedRuleIds: [], rejected: candidates.slice(0, cap).map((rule) => ({ id: rule.id, reason: 'capability_unavailable' })) };
  }
  const supportedRuleIds = []; const rejected = [];
  for (const rule of candidates) {
    const regex = rule.condition.regexFilter;
    if (!regex || regex.length > 4096 || !/^[\x00-\x7F]+$/u.test(regex)) { rejected.push({ id: rule.id, reason: 'invalid_local_candidate' }); continue; }
    try {
      const result = await dnrApi.isRegexSupported({ regex, isCaseSensitive: rule.condition.isUrlFilterCaseSensitive === true, requireCapturing: false });
      if (result?.isSupported === true) supportedRuleIds.push(rule.id); else rejected.push({ id: rule.id, reason: result?.reason ?? 'unsupported' });
    } catch { rejected.push({ id: rule.id, reason: 'validation_failed' }); }
  }
  return { supportedRuleIds, rejected };
}

async function reconcileRuleRange(dnrApi, currentPredicate, desired) {
  const current = (await dnrApi.getDynamicRules()).filter(currentPredicate);
  if (JSON.stringify(stableRuleView(current)) !== JSON.stringify(stableRuleView(desired))) {
    await dnrApi.updateDynamicRules({ removeRuleIds: current.map((rule) => rule.id), addRules: desired });
  }
  return desired.length;
}

export async function reconcileStaticRulesets(dnrApi, state) {
  const current = new Set(await dnrApi.getEnabledRulesets());
  const desired = desiredStaticRulesets(state);
  const managedIds = new Set(Object.values(RULESET_IDS));
  const enableRulesetIds = desired.filter((id) => !current.has(id));
  const disableRulesetIds = [...current].filter((id) => managedIds.has(id) && !desired.includes(id));
  if (!enableRulesetIds.length && !disableRulesetIds.length) return [...desired];
  try {
    await dnrApi.updateEnabledRulesets({ enableRulesetIds, disableRulesetIds });
    return [...desired];
  } catch {
    // A bulk update is all-or-nothing, and the browser rejects it when the enabled static
    // rules exceed its shared budget. Apply disables first, then enable one ruleset at a
    // time so the essential lists still activate and only the ones that don't fit are skipped.
    if (disableRulesetIds.length) await dnrApi.updateEnabledRulesets({ disableRulesetIds });
    const enabled = desired.filter((id) => current.has(id));
    for (const id of enableRulesetIds) {
      try { await dnrApi.updateEnabledRulesets({ enableRulesetIds: [id] }); enabled.push(id); } catch { /* does not fit the current budget */ }
    }
    return enabled;
  }
}

export async function reconcileAllowlistRules(dnrApi, state) {
  return reconcileRuleRange(dnrApi, isAllowlistRule, buildAllowlistRules(state.allowlist));
}

export async function reconcileSignedRules(dnrApi, updateSnapshot) {
  const desired = compileSignedNetworkRules(updateSnapshot);
  if (typeof dnrApi?.isRegexSupported === 'function') {
    for (const rule of desired) {
      const regex = rule?.condition?.regexFilter;
      if (typeof regex !== 'string') continue;
      const result = await dnrApi.isRegexSupported({ regex, isCaseSensitive: rule.condition.isUrlFilterCaseSensitive === true, requireCapturing: false });
      if (result?.isSupported !== true) throw new Error('signed update regex capability rejected');
    }
  }
  return reconcileRuleRange(dnrApi, (rule) => isSignedUpdateRuleId(rule?.id), desired);
}


export async function reconcileDnr(dnrApi, state, strictState, { categoryIndex = null, updateSnapshot = null, nowMs = Date.now() } = {}) {
  // The user's own rules (Strict Mode blocks, allowlist) come first and do not depend on the large
  // lists: if enabling a static ruleset is slow or fails, "Block youtube.com" must still take effect.
  const dynamicRules = await dnrApi.getDynamicRules();
  const cachedDnrApi = withCachedDynamicRules(dnrApi, dynamicRules);
  const strict = await reconcileStrictRules(cachedDnrApi, strictState, categoryIndex, nowMs);
  const allowlistRuleCount = await reconcileAllowlistRules(cachedDnrApi, state);
  let enabledRulesets = [];
  let staticError = null;
  try { enabledRulesets = await reconcileStaticRulesets(dnrApi, state); } catch (error) { staticError = error; }
  const signedRuleCount = await reconcileSignedRules(cachedDnrApi, updateSnapshot);
  if (staticError) throw staticError;
  return {
    enabledRulesets,
    allowlistRuleCount,
    signedRuleCount,
    strictRulesChanged: strict.changed === true,
    managedStrictRuleCount: strict.managedStrictRuleCount,
    managedStrictDomainRuleCount: strict.managedStrictDomainRuleCount,
    managedStrictCategoryRuleCount: strict.managedStrictCategoryRuleCount,
    managedDynamicRuleCount: allowlistRuleCount + signedRuleCount + strict.managedStrictRuleCount,
    unresolvedCategoryCount: strict.unresolvedCategoryCount,
    resolvedCategoryCount: strict.resolvedCategoryCount,
    resolvedCategoryDomainCount: strict.resolvedCategoryDomainCount,
    unresolvedApplicationCount: strict.unresolvedApplicationCount,
  };
}

export function assertAllowedSiteInput(value) {
  const host = canonicalizeSiteHost(value);
  if (!host) throw new TypeError('site must be a valid HTTP(S) DNS host');
  return host;
}
