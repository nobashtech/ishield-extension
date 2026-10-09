// iShield clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
// This documentation-only header does not change runtime behavior.

'use strict';

import {
  ALLOWLIST_RULE_CAP,
  DEFAULT_MODE,
  FEATURE_KEYS,
  FILTER_LISTS,
  LIST_KEYS,
  MODES,
  STATE_SCHEMA_VERSION,
} from './constants.js';
import { normalizeAllowlist } from './domain.js';

export function defaultFeatures() {
  return Object.fromEntries(FEATURE_KEYS.map((key) => [key, true]));
}

export function defaultLists() {
  return Object.fromEntries(FILTER_LISTS.map((list) => [list.key, list.defaultOn]));
}

// Per-list switches: an explicit boolean is respected; anything else (missing, older stored state,
// malformed) falls back to the list's default.
function normalizeLists(candidate) {
  const source = candidate && typeof candidate === 'object' && !Array.isArray(candidate) ? candidate : {};
  return Object.fromEntries(FILTER_LISTS.map((list) => [list.key, typeof source[list.key] === 'boolean' ? source[list.key] : list.defaultOn]));
}

// A missing or malformed flag means "on": older stored state predates per-layer switches.
function normalizeFeatures(candidate) {
  const source = candidate && typeof candidate === 'object' && !Array.isArray(candidate) ? candidate : {};
  return Object.fromEntries(FEATURE_KEYS.map((key) => [key, source[key] !== false]));
}

export function defaultState() {
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    protectionEnabled: true,
    mode: DEFAULT_MODE,
    allowlist: [],
    features: defaultFeatures(),
    lists: defaultLists(),
  };
}

export function normalizeState(candidate) {
  const fallback = defaultState();
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return fallback;
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    protectionEnabled: candidate.protectionEnabled !== false,
    mode: MODES.includes(candidate.mode) ? candidate.mode : DEFAULT_MODE,
    allowlist: normalizeAllowlist(candidate.allowlist, ALLOWLIST_RULE_CAP),
    features: normalizeFeatures(candidate.features),
    lists: normalizeLists(candidate.lists),
  };
}

export function withProtectionEnabled(state, enabled) {
  return normalizeState({ ...state, protectionEnabled: enabled === true });
}

export function withMode(state, mode) {
  if (!MODES.includes(mode)) throw new TypeError('unsupported protection mode');
  return normalizeState({ ...state, mode });
}

export function withFeature(state, feature, enabled) {
  if (!FEATURE_KEYS.includes(feature)) throw new TypeError('unsupported protection feature');
  return normalizeState({ ...state, features: { ...normalizeFeatures(state?.features), [feature]: enabled === true } });
}

export function withList(state, list, enabled) {
  if (!LIST_KEYS.includes(list)) throw new TypeError('unsupported filter list');
  return normalizeState({ ...state, lists: { ...normalizeLists(state?.lists), [list]: enabled === true } });
}

export function withAllowedSite(state, host) {
  const normalizedHost = normalizeAllowlist([host], 1)[0];
  if (!normalizedHost) throw new TypeError('invalid allowlist host');
  if (state.allowlist.includes(normalizedHost)) return normalizeState(state);
  if (state.allowlist.length >= ALLOWLIST_RULE_CAP) throw new RangeError('allowlist capacity exceeded');
  const allowlist = normalizeAllowlist([...state.allowlist, normalizedHost], ALLOWLIST_RULE_CAP);
  return normalizeState({ ...state, allowlist });
}

export function withoutAllowedSite(state, host) {
  return normalizeState({
    ...state,
    allowlist: state.allowlist.filter((entry) => entry !== host),
  });
}
