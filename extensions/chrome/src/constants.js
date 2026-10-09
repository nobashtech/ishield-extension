'use strict';

export const STATE_KEY = 'ishield.state.v1';
export const HEALTH_KEY = 'ishield.health.v1';
export const STRICT_POLICY_KEY = 'ishield.strict.v1';
export const STATE_SCHEMA_VERSION = 1;

export const MODES = Object.freeze(['balanced', 'strong', 'maximum']);
export const DEFAULT_MODE = 'strong';

// User-controllable protection layers (each can be switched off independently of the master
// switch): ads = ad/annoyance network rules + cosmetic + scriptlets, privacy = tracker rules
// + fingerprint hardening, phishing = phishing and malware page warnings, scam = scam warnings.
export const FEATURE_KEYS = Object.freeze(['ads', 'privacy', 'phishing', 'scam']);

export const RULESET_IDS = Object.freeze({
  core: 'ishield_core',
  strong: 'ishield_strong',
  maximum: 'ishield_maximum',
  productionBase: 'ishield_production_base',
  productionTracking: 'ishield_production_tracking',
  productionUblock: 'ishield_production_ublock',
  productionPgl: 'ishield_production_pgl',
  productionUrlhaus: 'ishield_production_urlhaus',
  productionBadware: 'ishield_production_badware',
  productionEasylist: 'ishield_production_easylist',
  productionEasyprivacy: 'ishield_production_easyprivacy',
  productionMobile: 'ishield_production_mobile',
  productionUrlTracking: 'ishield_production_urltracking',
});

// Imported filter lists in load-priority order (if the browser cannot hold every enabled list they
// load front to back). `layer` is the FEATURE_KEYS switch that governs the list; `defaultOn` is
// its out-of-the-box state, chosen so the default set fits the guaranteed 30,000-rule budget.
export const FILTER_LISTS = Object.freeze([
  Object.freeze({ key: 'base', rulesetId: RULESET_IDS.productionBase, layer: 'ads', defaultOn: true }),
  Object.freeze({ key: 'tracking', rulesetId: RULESET_IDS.productionTracking, layer: 'privacy', defaultOn: true }),
  Object.freeze({ key: 'ublock', rulesetId: RULESET_IDS.productionUblock, layer: 'ads', defaultOn: true }),
  Object.freeze({ key: 'pgl', rulesetId: RULESET_IDS.productionPgl, layer: 'privacy', defaultOn: true }),
  Object.freeze({ key: 'urlhaus', rulesetId: RULESET_IDS.productionUrlhaus, layer: 'phishing', defaultOn: true }),
  Object.freeze({ key: 'badware', rulesetId: RULESET_IDS.productionBadware, layer: 'phishing', defaultOn: true }),
  Object.freeze({ key: 'easylist', rulesetId: RULESET_IDS.productionEasylist, layer: 'ads', defaultOn: false }),
  Object.freeze({ key: 'easyprivacy', rulesetId: RULESET_IDS.productionEasyprivacy, layer: 'privacy', defaultOn: false }),
  Object.freeze({ key: 'mobile', rulesetId: RULESET_IDS.productionMobile, layer: 'ads', defaultOn: false }),
  Object.freeze({ key: 'urltracking', rulesetId: RULESET_IDS.productionUrlTracking, layer: 'privacy', defaultOn: false }),
]);
export const LIST_KEYS = Object.freeze(FILTER_LISTS.map((list) => list.key));

// Dynamic rules are intentionally partitioned so future rule classes cannot collide.
export const ALLOWLIST_RULE_ID_START = 1_000_000;
export const ALLOWLIST_RULE_CAP = 1_000;
// Must outrank every imported production rule (highest is 1,100,201) so "Pause on this
// site" really pauses them, yet stay below STRICT_RULE_PRIORITY so Strict Mode still wins.
export const ALLOWLIST_RULE_PRIORITY = 1_500_000;
export const RECONCILE_MAX_PASSES = 4;
