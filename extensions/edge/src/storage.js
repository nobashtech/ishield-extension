'use strict';

import { HEALTH_KEY, STATE_KEY } from './constants.js';
import { normalizeState } from './state.js';

export async function readState(storageArea = chrome.storage.local) {
  const stored = await storageArea.get(STATE_KEY);
  return normalizeState(stored?.[STATE_KEY]);
}

export async function writeState(state, storageArea = chrome.storage.local) {
  const normalized = normalizeState(state);
  await storageArea.set({ [STATE_KEY]: normalized });
  return normalized;
}

export async function readHealth(storageArea = chrome.storage.local) {
  const stored = await storageArea.get(HEALTH_KEY);
  return stored?.[HEALTH_KEY] ?? null;
}

export async function writeHealth(health, storageArea = chrome.storage.local) {
  // Health records deliberately contain no visited URL or site/domain fields.
  const sanitized = {
    status: health.status === 'healthy' ? 'healthy' : 'degraded',
    reason: typeof health.reason === 'string' ? health.reason.slice(0, 64) : 'unknown',
    checkedAt: Number.isFinite(health.checkedAt) ? health.checkedAt : Date.now(),
    enabledRulesetCount: Number.isInteger(health.enabledRulesetCount)
      ? Math.max(0, health.enabledRulesetCount)
      : 0,
    managedDynamicRuleCount: Number.isInteger(health.managedDynamicRuleCount)
      ? Math.max(0, health.managedDynamicRuleCount)
      : 0,
    managedStrictRuleCount: Number.isInteger(health.managedStrictRuleCount) ? Math.max(0, health.managedStrictRuleCount) : 0,
    managedStrictDomainRuleCount: Number.isInteger(health.managedStrictDomainRuleCount) ? Math.max(0, health.managedStrictDomainRuleCount) : 0,
    managedStrictCategoryRuleCount: Number.isInteger(health.managedStrictCategoryRuleCount) ? Math.max(0, health.managedStrictCategoryRuleCount) : 0,
    unresolvedStrictCategoryCount: Number.isInteger(health.unresolvedStrictCategoryCount) ? Math.max(0, health.unresolvedStrictCategoryCount) : 0,
    resolvedStrictCategoryCount: Number.isInteger(health.resolvedStrictCategoryCount) ? Math.max(0, health.resolvedStrictCategoryCount) : 0,
    resolvedStrictCategoryDomainCount: Number.isInteger(health.resolvedStrictCategoryDomainCount) ? Math.max(0, health.resolvedStrictCategoryDomainCount) : 0,
    unresolvedStrictApplicationCount: Number.isInteger(health.unresolvedStrictApplicationCount) ? Math.max(0, health.unresolvedStrictApplicationCount) : 0,
    signedRuleCount: Number.isInteger(health.signedRuleCount) ? Math.max(0, health.signedRuleCount) : 0,
    youtubeAdsRegistrationActive: health.youtubeAdsRegistrationActive === true,
    pageCleanupActive: health.pageCleanupActive === true,
    pageCleanupRulesetCount: Number.isInteger(health.pageCleanupRulesetCount) ? Math.max(0, health.pageCleanupRulesetCount) : 0,
    fingerprintRegistrationActive: health.fingerprintRegistrationActive === true,
    fingerprintMode: ['balanced','strong','maximum'].includes(health.fingerprintMode) ? health.fingerprintMode : null,
    actionCountAvailable: health.actionCountAvailable === true,
  };
  await storageArea.set({ [HEALTH_KEY]: sanitized });
  return sanitized;
}
