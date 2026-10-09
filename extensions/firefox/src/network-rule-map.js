'use strict';

import { PRODUCTION_ALLOW_RULE_RANGES } from './production-allow-rules.js';

export const NETWORK_RULE_CATEGORIES = Object.freeze({
  1001: 'ads', 1002: 'ads', 1003: 'ads', 1004: 'ads', 1005: 'ads', 1006: 'ads', 1007: 'ads', 1008: 'ads',
  2001: 'ads', 2002: 'ads', 2003: 'trackers', 2004: 'trackers', 2005: 'trackers', 2006: 'ads', 2007: 'ads', 2008: 'ads', 2009: 'trackers',
  3001: 'ads', 3002: 'trackers', 3003: 'trackers', 3004: 'ads', 3005: 'ads', 3006: 'ads',
});

// Production rulesets (see import_production_filters.mjs) are homogeneous by
// source filter -- every rule in a given ruleset belongs to the same category --
// so they are classified by rulesetId rather than by individual rule ID. This is
// what lets the activity counters scale to a ~190k-rule production import without
// a per-rule lookup table.
const PRODUCTION_SUFFIX_CATEGORIES = Object.freeze({
  production_base: 'ads', production_ublock: 'ads', production_easylist: 'ads', production_mobile: 'ads',
  production_tracking: 'trackers', production_pgl: 'trackers', production_easyprivacy: 'trackers', production_urltracking: 'trackers',
  production_urlhaus: 'malware', production_badware: 'malware',
});

export const PRODUCTION_RULESET_CATEGORIES = Object.freeze(Object.fromEntries(
  Object.entries(PRODUCTION_SUFFIX_CATEGORIES).flatMap(([suffix, category]) => [[`ishield_${suffix}`, category], [`ishield_fx_${suffix}`, category]]),
));

export const MANAGED_STATIC_RULESETS = Object.freeze(new Set([
  'ishield_core', 'ishield_strong', 'ishield_maximum',
  'ishield_fx_core', 'ishield_fx_strong', 'ishield_fx_maximum',
  ...Object.keys(PRODUCTION_RULESET_CATEGORIES),
]));

// Phase 22 dedicated dynamic rule partition. Keep this numeric boundary here so the
// privacy-safe activity classifier stays byte-identical across browsers (its only import is a generated table).
export const STRICT_DYNAMIC_RULE_ID_START = 1_200_000;
export const STRICT_DYNAMIC_RULE_ID_END = STRICT_DYNAMIC_RULE_ID_START + 2_048 - 1;

// Exception (allow) rules are reported as "matched" by the browser but block nothing.
function isProductionExceptionRule(rulesetId, ruleId) {
  const ranges = PRODUCTION_ALLOW_RULE_RANGES[rulesetId];
  return Array.isArray(ranges) && ranges.some(([start, end]) => ruleId >= start && ruleId <= end);
}

export function classifyMatchedRule(info) {
  const rule = info?.rule;
  if (!rule || !Number.isInteger(rule.ruleId)) return null;
  if (rule.ruleId >= STRICT_DYNAMIC_RULE_ID_START && rule.ruleId <= STRICT_DYNAMIC_RULE_ID_END) return 'strictPolicy';
  if (!MANAGED_STATIC_RULESETS.has(rule.rulesetId)) return null;
  if (rule.rulesetId in PRODUCTION_RULESET_CATEGORIES) return isProductionExceptionRule(rule.rulesetId, rule.ruleId) ? null : PRODUCTION_RULESET_CATEGORIES[rule.rulesetId];
  return NETWORK_RULE_CATEGORIES[rule.ruleId] ?? null;
}
