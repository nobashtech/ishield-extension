import {createMatchQuery} from './match-query.js';
import {websiteExclusions, clearLocalExtensionData} from './data-controls.js';
import {createAdguardContentManager} from './adguard-content-manager.js';
'use strict';

import { ActivityStore, DNR_LOOKBACK_MS, EVENT_COUNT_CAP } from './activity-store.js';
import {createBadgeCounter} from './badge-counter.js';
import { PageActivityStore, pageNetworkCounts, pageSnapshot, PAGE_ACTIVITY_KEY, PAGE_CATEGORIES } from './page-activity.js';
import { CategoryIndex, emptyCategoryDataset } from './category-index.js';
import { RECONCILE_MAX_PASSES, STATE_KEY, STRICT_POLICY_KEY } from './constants.js';
import { assertAllowedSiteInput, reconcileDnr } from './dnr-manager.js';
import { canonicalizeSiteHost } from './domain.js';
import { classifyMatchedRule } from './network-rule-map.js';
import { evaluatePhishing } from './phishing-engine.js';
import { PhishingSessionStore } from './phishing-session.js';
import { evaluateScam } from './scam-engine.js';
import { ScamSessionStore } from './scam-session.js';
import { evaluateMalware } from './malware-engine.js';
import { LocalMalwareFeedIndex } from './malware-feed.js';
import { MalwareSessionStore } from './malware-session.js';
import { LocalReputationIndex } from './reputation-index.js';
import { combinedSiteExcludeMatches } from './site-exclusions.js';
import { reconcileYoutubeAds } from './youtube-ads-manager.js';
import { PAGE_CLEANUP_CATALOG } from './page-cleanup-catalog.js';
import { handlePageCleanupMessage, isPageCleanupMessage, packagedJsonLoader, reconcilePageCleanup } from './page-cleanup-manager.js';
import { reconcileFingerprintProtection } from './fingerprint-manager.js';
import { readHealth, readState, writeHealth, writeState } from './storage.js';
import { withAllowedSite, withMode, withProtectionEnabled, withoutAllowedSite, withFeature, withList } from './state.js';
import { StrictPolicyStore, strictCapabilities, strictPolicyMatchesUrl } from './strict-policy.js';
import { buildStrictDnrRules, isStrictDynamicRuleId } from './strict-manager.js';
import { SignedUpdateStore, UPDATE_STATE_KEY } from './signed-update.js';
import { SignedUpdateClient } from './update-client.js';
import { UPDATE_CHANNEL, UPDATE_TRUST_STORE } from './trust-store.js';
import { BreakageRecoveryStore, RECOVERY_STATE_KEY, normalizeRecoveryHost, resolveEffectiveCompatibility } from './breakage-recovery.js';

const activityStore = new ActivityStore(chrome.storage.local);
const pageActivityStore = new PageActivityStore(chrome.storage.session);
const queryMatchedRules = createMatchQuery(chrome.declarativeNetRequest, chrome.storage.session);
const badgeCounter = createBadgeCounter(chrome, pageActivityStore, readState);
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') void pageActivityStore.reset(tabId).then(() => publishPageBadge(tabId)).catch(() => undefined);
  else if (changeInfo.url || changeInfo.status === 'complete') void publishPageBadge(tabId);
});
chrome.tabs.onActivated?.addListener(({tabId}) => { void publishPageBadge(tabId); });
chrome.tabs.onRemoved.addListener((tabId) => { void pageActivityStore.remove(tabId).catch(() => undefined); void badgeCounter.remove(tabId).catch(() => undefined); });
const strictPolicyStore = new StrictPolicyStore(chrome.storage.local);
const signedUpdateStore = new SignedUpdateStore(chrome.storage.local);
const signedUpdateClient = new SignedUpdateClient({ storageArea: chrome.storage.local, trustStore: UPDATE_TRUST_STORE });
const breakageRecoveryStore = new BreakageRecoveryStore(chrome.storage.local);
const phishingSessionStore = chrome.storage.session ? new PhishingSessionStore(chrome.storage.session) : null;
const scamSessionStore = chrome.storage.session ? new ScamSessionStore(chrome.storage.session) : null;
const malwareSessionStore = chrome.storage.session ? new MalwareSessionStore(chrome.storage.session) : null;
const THREAT_INTERVENTION_GUARD_MS = 5_000;
const THREAT_INTERVENTION_GUARD_CAP = 128;
const threatInterventionUntil = new Map();
const BOOTSTRAP_REPUTATION_DATASET = Object.freeze({
  metadata: { schemaVersion: 1, datasetVersion: 1, generatedAtMs: 0, expiresAtMs: Number.MAX_SAFE_INTEGER, declaredSourceCount: 0, declaredRecordCount: 0 },
  sources: [],
  records: [],
});
const BOOTSTRAP_MALWARE_DATASET = Object.freeze({
  metadata: { schemaVersion: 1, datasetVersion: 1, generatedAtMs: 0, expiresAtMs: Number.MAX_SAFE_INTEGER, declaredSourceCount: 0, declaredRecordCount: 0 },
  sources: [],
  records: [],
});
let activeCategoryIndex = new CategoryIndex(emptyCategoryDataset());
let activeReputationIndex = new LocalReputationIndex(BOOTSTRAP_REPUTATION_DATASET);
let activeMalwareFeedIndex = new LocalMalwareFeedIndex(BOOTSTRAP_MALWARE_DATASET);
let activeUpdateSnapshot = null;
let reconcileRunning = false;
let fullResetRunning = false;
let reconcileRequested = false;

async function refreshSignedUpdateSnapshot() {
  const loaded = await signedUpdateStore.loadActive();
  activeUpdateSnapshot = loaded.snapshot;
  return loaded.state;
}


async function compatibilityPolicyForHost(host) {
  const localSite = await breakageRecoveryStore.status(host);
  return resolveEffectiveCompatibility(host, localSite, Date.now());
}

async function compatibilityScriptletExcludeMatches() {
  return breakageRecoveryStore.activeScriptletExcludeMatches();
}



async function pageCompatibilityPolicy(sender) {
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0 || typeof sender?.url !== 'string') throw new TypeError('content-script sender required');
  const host = canonicalizeSiteHost(sender.url);
  if (!host) return Object.freeze({ active: false, disabledLayers: Object.freeze([]), localRecovery: false });
  return compatibilityPolicyForHost(host);
}

async function handleBreakageProbe(message, sender) {
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0 || typeof sender?.url !== 'string') throw new TypeError('content-script sender required');
  const host = canonicalizeSiteHost(sender.url);
  if (!host) return { accepted: false, reason: 'unsupported_navigation' };
  const state = await readState();
  if (!state.protectionEnabled || hostIsAllowed(host, state.allowlist)) return { accepted: false, reason: 'protection_inactive' };
  const recovery = await breakageRecoveryStore.recordProbe(host, message.probe);
  if (recovery.activated) await performReconcile();
  return { accepted: true, recovery };
}

async function activateManualRecovery(message, sender) {
  requireExtensionPageSender(sender);
  const host = normalizeRecoveryHost(message.host);
  const site = await breakageRecoveryStore.activateManual(host);
  await performReconcile();
  return { site, compatibility: await compatibilityPolicyForHost(host) };
}

async function clearRecovery(message, sender) {
  requireExtensionPageSender(sender);
  const host = normalizeRecoveryHost(message.host);
  const result = await breakageRecoveryStore.clear(host);
  await performReconcile();
  return { ...result, compatibility: await compatibilityPolicyForHost(host) };
}

const UPDATE_CHECK_KEY = 'ishield.update.check.v1';
const UPDATE_ALARM = 'ishield-update-check';
const UPDATE_CHECK_PERIOD_MINUTES = 360;

async function signedUpdateStatus() {
  const loaded = await signedUpdateStore.loadActive();
  const stored = await chrome.storage.local.get(UPDATE_CHECK_KEY);
  const network = loaded.snapshot?.resources?.find((item) => item.kind === 'network-rules');
  return {
    state: loaded.state,
    resources: Array.isArray(loaded.snapshot?.resources) ? loaded.snapshot.resources.map((item) => ({ kind: item.kind, version: item.version })) : [],
    networkRuleCount: Array.isArray(network?.payload?.rules) ? network.payload.rules.length : 0,
    lastCheck: stored?.[UPDATE_CHECK_KEY] ?? null,
  };
}

async function checkSignedUpdates() {
  if (UPDATE_CHANNEL.enabled !== true || typeof UPDATE_CHANNEL.manifestUrl !== 'string') return { checked: false, reason: 'channel_disabled' };
  if (Object.keys(UPDATE_TRUST_STORE).length < 1) throw new Error('signed update trust store is not provisioned');
  const updateState = await signedUpdateClient.fetchAndApply(UPDATE_CHANNEL.manifestUrl);
  await refreshSignedUpdateSnapshot();
  requestReconcile();
  return { checked: true, updateState };
}

async function recordUpdateCheck(result) {
  try { await chrome.storage.local.set({ [UPDATE_CHECK_KEY]: result }); } catch { /* Status only. */ }
}

// A manifest that is not newer than what is applied is rejected as a replay/downgrade; from the
// user's point of view that simply means "already up to date".
async function runUpdateCheck() {
  const checkedAt = Date.now();
  try {
    const outcome = await checkSignedUpdates();
    if (outcome.checked === true) await recordUpdateCheck({ checkedAt, ok: true, upToDate: false, sequence: outcome.updateState?.sequence ?? null });
    return outcome;
  } catch (error) {
    if (/replay or downgrade/u.test(String(error?.message))) {
      await recordUpdateCheck({ checkedAt, ok: true, upToDate: true });
      return { checked: true, upToDate: true };
    }
    await recordUpdateCheck({ checkedAt, ok: false, upToDate: false });
    throw error;
  }
}

async function ensureUpdateAlarm() {
  if (UPDATE_CHANNEL.enabled !== true || Object.keys(UPDATE_TRUST_STORE).length < 1) return;
  if (!(await chrome.alarms.get(UPDATE_ALARM))) chrome.alarms.create(UPDATE_ALARM, { delayInMinutes: 1, periodInMinutes: UPDATE_CHECK_PERIOD_MINUTES });
}

function requireExtensionPageSender(sender) {
  if (sender?.tab) throw new TypeError('update control requires an extension page');
}

const ICON_SIZES = Object.freeze([16, 32, 48, 128]);

// Toolbar icon mirrors the master switch: violet shield when protecting, amber with a pause mark when paused.
async function configureActionIcon(state) {
  const prefix = state.protectionEnabled === true ? 'icon' : 'paused';
  try { await chrome.action.setIcon({ path: Object.fromEntries(ICON_SIZES.map((size) => [size, `icons/${prefix}-${size}.png`])) }); } catch { /* Cosmetic only. */ }
}

const BADGE_OFF_COLOR = '#b45309';

// While paused, "OFF" replaces the blocked-count badge so the state is obvious at a glance.
async function configureActionBadge(state) {
  try {
    if (state.protectionEnabled === true) {
      if ((await chrome.action.getBadgeText({})) === 'OFF') await chrome.action.setBadgeText({ text: '' });
      await configureActionCount(state);
    } else {
      await configureActionCount(state);
      await chrome.action.setBadgeBackgroundColor({ color: BADGE_OFF_COLOR });
      await chrome.action.setBadgeText({ text: 'OFF' });
    }
  } catch { /* Cosmetic only. */ }
}

// Applied the moment the state changes and whenever the worker wakes -- not at the end of a full
// reconcile, which can take a while with large rule sets -- and icons set at runtime do not survive a restart.
async function syncActionAppearance(state) {
  await Promise.all([configureActionIcon(state), configureActionBadge(state)]);
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.filter(tab => Number.isInteger(tab.id)).map(tab => publishPageBadge(tab.id)));
}
async function syncActionAppearanceFromStorage() { try { await syncActionAppearance(await readState()); } catch { /* Cosmetic only. */ } }

async function configureActionCount(state) {
  if (typeof chrome.declarativeNetRequest?.setExtensionActionOptions !== 'function') return false;
  try {
    await chrome.declarativeNetRequest.setExtensionActionOptions({
      displayActionCountAsBadgeText: false,
    });
    return true;
  } catch {
    return false;
  }
}

async function performReconcile() {
  const state = await readState();
  const strictState = await strictPolicyStore.load();
  let updateSnapshotFailed = false;
  try { await refreshSignedUpdateSnapshot(); } catch (error) {
    updateSnapshotFailed = true;
    activeUpdateSnapshot = null;
    activeCategoryIndex = new CategoryIndex(emptyCategoryDataset());
    activeReputationIndex = new LocalReputationIndex(BOOTSTRAP_REPUTATION_DATASET);
    activeMalwareFeedIndex = new LocalMalwareFeedIndex(BOOTSTRAP_MALWARE_DATASET);
    console.error('iShield signed update snapshot rejected', error?.name ?? 'Error');
  }
  let dnrResult = null;
  let fingerprintResult = null;
  let dnrFailed = false;
  let youtubeResult = null;
  let youtubeFailed = false;
  let pageCleanupResult = null;
  let pageCleanupFailed = false;
  let adguardContentFailed = false;
  let fingerprintFailed = false;
  try {
    dnrResult = await reconcileDnr(chrome.declarativeNetRequest, state, strictState, { categoryIndex: activeCategoryIndex, updateSnapshot: activeUpdateSnapshot, nowMs: Date.now() });
  } catch (error) {
    dnrFailed = true;
    console.error('iShield DNR reconciliation failed', error?.name ?? 'Error');
  }
  if (dnrResult?.strictRulesChanged) void reloadTabsBlockedByStrict(strictState);
  const siteScriptExcludes = combinedSiteExcludeMatches(state, await compatibilityScriptletExcludeMatches());
  try {
    // Allowed sites and compatibility recovery switch page-level filtering off too.
    youtubeResult = await reconcileYoutubeAds(chrome.scripting, state, siteScriptExcludes);
  } catch (error) {
    youtubeFailed = true;
    console.error('iShield YouTube ad defence reconciliation failed', error?.name ?? 'Error');
  }
  try {
    // Register uBO/EasyList cosmetic filtering, Facebook cleanup and page scriptlets first.
    // This must not depend on the optional AdGuard content engine successfully parsing its lists.
    pageCleanupResult = await reconcilePageCleanup({
      scriptingApi: chrome.scripting,
      storageArea: chrome.storage.local,
      fetchJson: packagedJsonLoader((relativePath) => chrome.runtime.getURL(relativePath), globalThis.fetch),
      state,
      catalog: PAGE_CLEANUP_CATALOG,
      excludeMatches: siteScriptExcludes,
      allowlistHostnames: state.allowlist,
    });
  } catch (error) {
    pageCleanupFailed = true;
    console.error('iShield page cleanup reconciliation failed', error?.name ?? 'Error');
  }
  try {
    // AdGuard is an additional content-filtering engine. Keep its failure domain separate so
    // Facebook and cosmetic filtering remain active even if this parser/runtime fails.
    await adguardContentManager.configure(state);
  } catch (error) {
    adguardContentFailed = true;
    console.error('iShield AdGuard content engine configuration failed', error?.name ?? 'Error');
  }
  try {
    fingerprintResult = await reconcileFingerprintProtection(chrome.scripting, state, []);
  } catch (error) {
    fingerprintFailed = true;
    console.error('iShield fingerprint reconciliation failed', error?.name ?? 'Error');
  }
  void syncActionAppearance(state);
  const actionCountAvailable = await configureActionCount(state);
  await writeHealth({
    status: updateSnapshotFailed || dnrFailed || youtubeFailed || pageCleanupFailed || adguardContentFailed || fingerprintFailed ? 'degraded' : 'healthy',
    reason: updateSnapshotFailed ? 'signed_update_snapshot_invalid' : (dnrFailed ? 'dnr_reconcile_failed' : (youtubeFailed ? 'youtube_ads_reconcile_failed' : (pageCleanupFailed ? 'page_cleanup_reconcile_failed' : (adguardContentFailed ? 'adguard_content_failed' : (fingerprintFailed ? 'fingerprint_reconcile_failed' : 'ok'))))),
    checkedAt: Date.now(),
    enabledRulesetCount: dnrResult?.enabledRulesets?.length ?? 0,
    managedDynamicRuleCount: dnrResult?.managedDynamicRuleCount ?? 0,
    managedStrictRuleCount: dnrResult?.managedStrictRuleCount ?? 0,
    managedStrictDomainRuleCount: dnrResult?.managedStrictDomainRuleCount ?? 0,
    managedStrictCategoryRuleCount: dnrResult?.managedStrictCategoryRuleCount ?? 0,
    unresolvedStrictCategoryCount: dnrResult?.unresolvedCategoryCount ?? 0,
    resolvedStrictCategoryCount: dnrResult?.resolvedCategoryCount ?? 0,
    resolvedStrictCategoryDomainCount: dnrResult?.resolvedCategoryDomainCount ?? 0,
    unresolvedStrictApplicationCount: dnrResult?.unresolvedApplicationCount ?? 0,
    signedRuleCount: dnrResult?.signedRuleCount ?? 0,
    youtubeAdsRegistrationActive: youtubeResult?.active === true,
    pageCleanupActive: pageCleanupResult?.active === true,
    pageCleanupRulesetCount: pageCleanupResult?.rulesetCount ?? 0,
    fingerprintRegistrationActive: fingerprintResult?.active === true,
    fingerprintMode: fingerprintResult?.mode ?? null,
    actionCountAvailable,
  });
}

function requestReconcile() {
  if (fullResetRunning) return;
  reconcileRequested = true;
  if (reconcileRunning) return;
  reconcileRunning = true;
  void (async () => {
    let passes = 0;
    try {
      while (reconcileRequested && passes < RECONCILE_MAX_PASSES) {
        reconcileRequested = false;
        passes += 1;
        await performReconcile();
      }
    } finally { reconcileRunning = false; }
  })();
}

// DNR rules only affect new requests, so a page that is already open on a site the user has blocked keeps
// working until it is reloaded. Whenever the installed Strict rules actually change, reload those tabs.
// (A tab that is already showing the block page is reloaded too, which is harmless.)
async function reloadTabsBlockedByStrict(strictState) {
  try {
    for (const tab of await chrome.tabs.query({})) {
      if (Number.isInteger(tab.id) && typeof tab.url === 'string' && strictState.policies.some((policy) => strictPolicyMatchesUrl(policy, tab.url))) void chrome.tabs.reload(tab.id).catch(() => undefined);
    }
  } catch { /* Best effort: the rules are already active for every new navigation. */ }
}

// What the popup shows next to the rule list: how many Strict rules should exist versus how many the browser holds.
async function strictEnforcement(strict) {
  try {
    const expected = buildStrictDnrRules(strict, activeCategoryIndex).rules.length;
    const installed = (await chrome.declarativeNetRequest.getDynamicRules()).filter((rule) => isStrictDynamicRuleId(rule?.id)).length;
    return { expected, installed };
  } catch { return null; }
}

chrome.runtime.onInstalled.addListener(() => { void ensureUpdateAlarm(); requestReconcile(); });
chrome.runtime.onStartup.addListener(() => { void ensureUpdateAlarm(); requestReconcile(); });
chrome.storage.onChanged.addListener((changes, areaName) => { if (areaName === 'local' && Object.prototype.hasOwnProperty.call(changes, STATE_KEY)) void syncActionAppearanceFromStorage(); });
void syncActionAppearanceFromStorage();
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === UPDATE_ALARM) void runUpdateCheck().catch(() => undefined); });
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && (Object.prototype.hasOwnProperty.call(changes, STATE_KEY) || Object.prototype.hasOwnProperty.call(changes, STRICT_POLICY_KEY) || Object.prototype.hasOwnProperty.call(changes, UPDATE_STATE_KEY) || Object.prototype.hasOwnProperty.call(changes, RECOVERY_STATE_KEY))) requestReconcile();
});

function publishPageBadge(tabId) {
  return badgeCounter.publish(Number(tabId)).catch(() => undefined);
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'session' || !changes[PAGE_ACTIVITY_KEY]) return;
  const oldPages = changes[PAGE_ACTIVITY_KEY].oldValue ?? {};
  const pages = changes[PAGE_ACTIVITY_KEY].newValue ?? {};
  for (const [tabId, page] of Object.entries(pages)) {
    if (JSON.stringify(page) !== JSON.stringify(oldPages[tabId])) void publishPageBadge(tabId, page);
  }
});

async function syncTabActivity(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) throw new TypeError('invalid tab id');
  const local = await pageActivityStore.snapshot(tabId);
  const fallback = { ...pageSnapshot(local), reason: 'active_tab_match_history_unavailable', acceptedCount: 0 };
  await publishPageBadge(tabId, local);
  if (typeof chrome.declarativeNetRequest?.getMatchedRules !== 'function') return fallback;
  try {
    const now = Date.now();
    const result = await queryMatchedRules({ tabId });
    const matches = Array.isArray(result?.rulesMatchedInfo) ? result.rulesMatchedInfo : [];
    const recent = matches.filter((info) => Number(info?.timeStamp) >= now - DNR_LOOKBACK_MS);
    const ingested = await activityStore.ingestMatchedRules(recent, classifyMatchedRule, now);
    const network = pageNetworkCounts(matches, classifyMatchedRule, local.startedAt, tabId);
    const page = await pageActivityStore.network(tabId, network, local.startedAt);
    await publishPageBadge(tabId, page);
    return { ...pageSnapshot(page), reason: 'ok', acceptedCount: ingested.acceptedCount };
  } catch { return fallback; }
}

async function recordCosmeticActivity(message, sender) {
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0) throw new TypeError('content-script sender required');
  if (message.category !== 'ads' || message.source !== 'cosmetic-collapse') throw new TypeError('unsupported activity source');
  if (!Number.isInteger(message.count) || message.count < 1 || message.count > EVENT_COUNT_CAP) throw new RangeError('activity count out of bounds');
  await activityStore.record({ category: 'ads', source: 'cosmetic-collapse', count: message.count });
  await pageActivityStore.record(sender.tab.id, 'ads', message.count);
  await publishPageBadge(sender.tab.id);
  return { recorded: message.count };
}

function hostIsAllowed(host, allowlist) {
  return Array.isArray(allowlist) && allowlist.some((entry) => host === entry || host.endsWith(`.${entry}`));
}

function reserveThreatIntervention(tabId, now = Date.now()) {
  for (const [id, expiresAt] of threatInterventionUntil.entries()) {
    if (expiresAt <= now) threatInterventionUntil.delete(id);
  }
  if ((threatInterventionUntil.get(tabId) ?? 0) > now) return false;
  if (threatInterventionUntil.size >= THREAT_INTERVENTION_GUARD_CAP) {
    const oldest = threatInterventionUntil.keys().next().value;
    if (oldest !== undefined) threatInterventionUntil.delete(oldest);
  }
  threatInterventionUntil.delete(tabId);
  threatInterventionUntil.set(tabId, now + THREAT_INTERVENTION_GUARD_MS);
  return true;
}

function releaseThreatIntervention(tabId) {
  threatInterventionUntil.delete(tabId);
}

async function handlePhishingProbe(message, sender) {
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0) throw new TypeError('content-script sender required');
  if (typeof sender.url !== 'string') throw new TypeError('sender URL unavailable');
  const host = canonicalizeSiteHost(sender.url);
  if (!host) return { evaluated: false, reason: 'unsupported_navigation' };
  const state = await readState();
  if (!state.protectionEnabled || state.features?.phishing === false) return { evaluated: false, reason: 'protection_disabled' };
  if (hostIsAllowed(host, state.allowlist)) return { evaluated: false, reason: 'allowlisted' };
  if (phishingSessionStore && await phishingSessionStore.hasBypass(sender.url)) {
    return { evaluated: true, reason: 'temporary_bypass', action: 'allow' };
  }

  const verdict = evaluatePhishing(sender.url, {
    mode: state.mode,
    dom: message.dom ?? {},
    reputationIndex: activeReputationIndex,
    nowMs: Date.now(),
  });
  if (verdict.action === 'allow') return { evaluated: true, reason: 'allow', action: 'allow', score: verdict.score };
  if (!phishingSessionStore) return { evaluated: true, reason: 'session_storage_unavailable', action: 'allow', score: verdict.score };
  if (!reserveThreatIntervention(sender.tab.id)) return { evaluated: true, reason: 'other_threat_intervention', action: 'allow', score: verdict.score };

  let token;
  try {
    token = await phishingSessionStore.create(sender.url, verdict);
  } catch (error) {
    releaseThreatIntervention(sender.tab.id);
    throw error;
  }
  const warningUrl = chrome.runtime.getURL(`warning/phishing.html#${token}`);
  try {
    await chrome.tabs.update(sender.tab.id, { url: warningUrl });
  } catch {
    await phishingSessionStore.discard(token);
    releaseThreatIntervention(sender.tab.id);
    return { evaluated: true, reason: 'warning_navigation_failed', action: 'allow', score: verdict.score };
  }
  await activityStore.record({ category: 'phishing', source: 'threat-engine', count: 1 });
  await pageActivityStore.record(sender.tab.id, 'phishing', 1);
  await publishPageBadge(sender.tab.id);
  return { evaluated: true, reason: 'intervened', action: verdict.action, score: verdict.score };
}

async function getPhishingWarning(message, sender) {
  if (typeof sender?.url !== 'string' || !sender.url.startsWith(chrome.runtime.getURL('warning/phishing.html'))) throw new TypeError('warning page sender required');
  if (!phishingSessionStore) return { warning: null };
  return { warning: await phishingSessionStore.view(message.token) };
}

async function continuePhishingWarning(message, sender) {
  if (!phishingSessionStore) throw new Error('session storage unavailable');
  if (typeof sender?.url !== 'string' || !sender.url.startsWith(chrome.runtime.getURL('warning/phishing.html'))) throw new TypeError('warning page sender required');
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0) throw new TypeError('warning tab required');
  const url = await phishingSessionStore.continue(message.token);
  if (!url) throw new Error('warning expired');
  await chrome.tabs.update(sender.tab.id, { url });
  return { continued: true };
}

async function handleScamProbe(message, sender) {
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0) throw new TypeError('content-script sender required');
  if (typeof sender.url !== 'string') throw new TypeError('sender URL unavailable');
  const host = canonicalizeSiteHost(sender.url);
  if (!host) return { evaluated: false, reason: 'unsupported_navigation' };
  const state = await readState();
  if (!state.protectionEnabled || state.features?.scam === false) return { evaluated: false, reason: 'protection_disabled' };
  if (hostIsAllowed(host, state.allowlist)) return { evaluated: false, reason: 'allowlisted' };
  if (scamSessionStore && await scamSessionStore.hasBypass(sender.url)) {
    return { evaluated: true, reason: 'temporary_bypass', action: 'allow' };
  }

  const verdict = evaluateScam(sender.url, {
    mode: state.mode,
    page: message.page ?? {},
    reputationIndex: activeReputationIndex,
    nowMs: Date.now(),
  });
  if (verdict.action === 'allow') return { evaluated: true, reason: 'allow', action: 'allow', score: verdict.score, category: verdict.category };
  if (!scamSessionStore) return { evaluated: true, reason: 'session_storage_unavailable', action: 'allow', score: verdict.score, category: verdict.category };
  if (!reserveThreatIntervention(sender.tab.id)) return { evaluated: true, reason: 'other_threat_intervention', action: 'allow', score: verdict.score, category: verdict.category };

  let token;
  try {
    token = await scamSessionStore.create(sender.url, verdict);
  } catch (error) {
    releaseThreatIntervention(sender.tab.id);
    throw error;
  }
  const warningUrl = chrome.runtime.getURL(`warning/scam.html#${token}`);
  try {
    await chrome.tabs.update(sender.tab.id, { url: warningUrl });
  } catch {
    await scamSessionStore.discard(token);
    releaseThreatIntervention(sender.tab.id);
    return { evaluated: true, reason: 'warning_navigation_failed', action: 'allow', score: verdict.score, category: verdict.category };
  }
  await activityStore.record({ category: 'scams', source: 'threat-engine', count: 1 });
  await pageActivityStore.record(sender.tab.id, 'scams', 1);
  await publishPageBadge(sender.tab.id);
  return { evaluated: true, reason: 'intervened', action: verdict.action, score: verdict.score, category: verdict.category };
}

async function getScamWarning(message, sender) {
  if (typeof sender?.url !== 'string' || !sender.url.startsWith(chrome.runtime.getURL('warning/scam.html'))) throw new TypeError('warning page sender required');
  if (!scamSessionStore) return { warning: null };
  return { warning: await scamSessionStore.view(message.token) };
}

async function continueScamWarning(message, sender) {
  if (!scamSessionStore) throw new Error('session storage unavailable');
  if (typeof sender?.url !== 'string' || !sender.url.startsWith(chrome.runtime.getURL('warning/scam.html'))) throw new TypeError('warning page sender required');
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0) throw new TypeError('warning tab required');
  const url = await scamSessionStore.continue(message.token);
  if (!url) throw new Error('warning expired');
  await chrome.tabs.update(sender.tab.id, { url });
  return { continued: true };
}

async function handleMalwareProbe(message, sender) {
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0) throw new TypeError('content-script sender required');
  if (typeof sender.url !== 'string') throw new TypeError('sender URL unavailable');
  const host = canonicalizeSiteHost(sender.url);
  if (!host) return { evaluated: false, reason: 'unsupported_navigation' };
  const state = await readState();
  if (!state.protectionEnabled || state.features?.phishing === false) return { evaluated: false, reason: 'protection_disabled' };
  if (hostIsAllowed(host, state.allowlist)) return { evaluated: false, reason: 'allowlisted' };
  if (malwareSessionStore && await malwareSessionStore.hasBypass(sender.url)) return { evaluated: true, reason: 'temporary_bypass', action: 'allow' };
  const verdict = evaluateMalware(sender.url, { mode: state.mode, redirectCount: message.redirectCount ?? 0, reputationIndex: activeReputationIndex, threatIndex: activeMalwareFeedIndex, nowMs: Date.now() });
  if (verdict.action === 'allow') return { evaluated: true, reason: 'allow', action: 'allow', score: verdict.score, category: verdict.category };
  if (!malwareSessionStore) return { evaluated: true, reason: 'session_storage_unavailable', action: 'allow', score: verdict.score, category: verdict.category };
  if (!reserveThreatIntervention(sender.tab.id)) return { evaluated: true, reason: 'other_threat_intervention', action: 'allow', score: verdict.score, category: verdict.category };
  let token;
  try { token = await malwareSessionStore.create(sender.url, verdict); } catch (error) { releaseThreatIntervention(sender.tab.id); throw error; }
  const warningUrl = chrome.runtime.getURL(`warning/malware.html#${token}`);
  try { await chrome.tabs.update(sender.tab.id, { url: warningUrl }); } catch { await malwareSessionStore.discard(token); releaseThreatIntervention(sender.tab.id); return { evaluated: true, reason: 'warning_navigation_failed', action: 'allow', score: verdict.score, category: verdict.category }; }
  await activityStore.record({ category: 'malware', source: 'threat-engine', count: 1 });
  await pageActivityStore.record(sender.tab.id, 'malware', 1);
  await publishPageBadge(sender.tab.id);
  return { evaluated: true, reason: 'intervened', action: verdict.action, score: verdict.score, category: verdict.category };
}

async function getMalwareWarning(message, sender) {
  if (typeof sender?.url !== 'string' || !sender.url.startsWith(chrome.runtime.getURL('warning/malware.html'))) throw new TypeError('warning page sender required');
  if (!malwareSessionStore) return { warning: null };
  return { warning: await malwareSessionStore.view(message.token) };
}

async function continueMalwareWarning(message, sender) {
  if (!malwareSessionStore) throw new Error('session storage unavailable');
  if (typeof sender?.url !== 'string' || !sender.url.startsWith(chrome.runtime.getURL('warning/malware.html'))) throw new TypeError('warning page sender required');
  if (!Number.isInteger(sender?.tab?.id) || sender.tab.id < 0) throw new TypeError('warning tab required');
  const url = await malwareSessionStore.continue(message.token);
  if (!url) throw new Error('warning expired');
  await chrome.tabs.update(sender.tab.id, { url });
  return { continued: true };
}

const adguardContentManager = createAdguardContentManager(async (relativePath) => {
  const response=await fetch(chrome.runtime.getURL(relativePath));
  if(!response.ok) throw Error('Bundled AdGuard filters unavailable');
  return response.text();
});

async function fullReset(sender) {
  requireExtensionPageSender(sender);
  if (fullResetRunning) throw new Error('Reset already running');
  fullResetRunning = true;
  try {
    const deadline=Date.now()+30000;
    while(reconcileRunning && Date.now()<deadline) await new Promise(resolve=>setTimeout(resolve,50));
    if(reconcileRunning) throw new Error('Filtering is busy; retry reset');
    await Promise.all([activityStore.queue, pageActivityStore.tail, breakageRecoveryStore.queue, strictPolicyStore.queue]);
    await clearLocalExtensionData(chrome);
    activeUpdateSnapshot = null;
    await performReconcile();
    await ensureUpdateAlarm();
    return {reset:true};
  } finally { fullResetRunning=false; }
}

async function handleMessage(message, sender) {
  if (!message || typeof message !== 'object') throw new TypeError('invalid message');
  if (isPageCleanupMessage(message)) { await handlePageCleanupMessage(message, sender, chrome.scripting); return {}; }
  if (fullResetRunning && !['state:get','data:reset'].includes(message.type)) throw new Error('Reset in progress');
  switch (message.type) {
    case 'content:adguard': {
      const policy=await pageCompatibilityPolicy(sender);
      return adguardContentManager.serve(message,sender,await readState(),policy.disabledLayers.includes('cosmetic'));
    }
    case 'data:reset': return fullReset(sender);
    case 'data:exclusions': { requireExtensionPageSender(sender); return {exclusions:websiteExclusions(await readState(), await breakageRecoveryStore.load())}; }
    case 'data:exclusion:remove': {
      requireExtensionPageSender(sender);
      const host=normalizeRecoveryHost(message.host);
      const state=await writeState(withoutAllowedSite(await readState(),host));
      await breakageRecoveryStore.clear(host);
      const deadline=Date.now()+15000;
      while(reconcileRunning && Date.now()<deadline) await new Promise(resolve=>setTimeout(resolve,50));
      if(reconcileRunning) throw new Error('Filtering is busy; retry');
      await performReconcile();
      return {state,exclusions:websiteExclusions(state,await breakageRecoveryStore.load())};
    }
    case 'state:get': return { state: await readState(), health: await readHealth() };
    case 'protection:set': return { state: await writeState(withProtectionEnabled(await readState(), message.enabled === true)) };
    case 'feature:set': return { state: await writeState(withFeature(await readState(), message.feature, message.enabled === true)) };
    case 'list:set': return { state: await writeState(withList(await readState(), message.list, message.enabled === true)) };
    case 'mode:set': return { state: await writeState(withMode(await readState(), message.mode)) };
    case 'site:allow': return { state: await writeState(withAllowedSite(await readState(), assertAllowedSiteInput(message.host))) };
    case 'site:protect': return { state: await writeState(withoutAllowedSite(await readState(), assertAllowedSiteInput(message.host))) };
    case 'strict:get': { const strict = await strictPolicyStore.load(); return { strict, capabilities: strictCapabilities(), enforcement: await strictEnforcement(strict) }; }
    case 'strict:add': { const strict = await strictPolicyStore.add(message.target); requestReconcile(); return { strict, capabilities: strictCapabilities(), enforcement: await strictEnforcement(strict) }; }
    case 'strict:remove': { const strict = await strictPolicyStore.remove(message.id); requestReconcile(); return { strict, capabilities: strictCapabilities(), enforcement: await strictEnforcement(strict) }; }
    case 'update:status': return { update: await signedUpdateStatus(), channel: { enabled: UPDATE_CHANNEL.enabled === true, host: UPDATE_CHANNEL.enabled === true && typeof UPDATE_CHANNEL.manifestUrl === 'string' ? new URL(UPDATE_CHANNEL.manifestUrl).host : null } };
    case 'update:check': { requireExtensionPageSender(sender); return { update: await runUpdateCheck() }; }
    case 'update:rollback': { requireExtensionPageSender(sender); const state = await signedUpdateStore.rollback(); await refreshSignedUpdateSnapshot(); requestReconcile(); return { updateState: state }; }
    case 'recovery:page-policy': return { compatibility: await pageCompatibilityPolicy(sender) };
    case 'recovery:probe': return handleBreakageProbe(message, sender);
    case 'recovery:status': { requireExtensionPageSender(sender); const host = normalizeRecoveryHost(message.host); return { compatibility: await compatibilityPolicyForHost(host), localSite: await breakageRecoveryStore.status(host) }; }
    case 'recovery:activate-manual': return activateManualRecovery(message, sender);
    case 'recovery:clear': return clearRecovery(message, sender);
    case 'activity:record': return recordCosmeticActivity(message, sender);
    case 'activity:sync-tab': return { networkSync: await syncTabActivity(message.tabId) };
    case 'activity:get': return { activity: await activityStore.snapshot(message.period, message.limit, Date.now(), message.query) };
    case 'activity:retention:set': return { activityState: await activityStore.setRetention(message.days) };
    case 'activity:clear-history': return { activityState: await activityStore.clearHistory() };
    case 'phishing:probe': return handlePhishingProbe(message, sender);
    case 'phishing:warning:get': return getPhishingWarning(message, sender);
    case 'phishing:warning:continue': return continuePhishingWarning(message, sender);
    case 'scam:probe': return handleScamProbe(message, sender);
    case 'scam:warning:get': return getScamWarning(message, sender);
    case 'scam:warning:continue': return continueScamWarning(message, sender);
    case 'malware:probe': return handleMalwareProbe(message, sender);
    case 'malware:warning:get': return getMalwareWarning(message, sender);
    case 'malware:warning:continue': return continueMalwareWarning(message, sender);
    default: throw new TypeError('unsupported message type');
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  void handleMessage(message, sender).then((payload) => sendResponse({ ok: true, ...payload })).catch((error) => sendResponse({ ok: false, error: error?.name ?? 'Error' }));
  return true;
});
