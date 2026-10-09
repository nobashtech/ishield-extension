'use strict';

import { restoreLegacyFacebookRecovery } from './recovery-migration.js';

import { parseStrictTarget } from '../src/strict-policy.js';
import { createPopupClient } from '../src/popup-client.js';
import { activityPage } from '../src/activity-query.js';
import { pageSnapshot, PAGE_ACTIVITY_KEY } from '../src/page-activity.js';
import { CONTENT_FILTER_COUNTS } from '../src/adguard-catalog.js';
import { canonicalizeSiteHost } from '../src/domain.js';
import { FILTER_CATALOG } from '../src/filter-catalog.js';
import { PAGE_CLEANUP_CATALOG } from '../src/page-cleanup-catalog.js';
import { enabledRulesets as enabledPageCleanupRulesets } from '../src/page-cleanup-manager.js';

const API = globalThis.browser ?? globalThis.chrome;
const $ = (selector) => document.querySelector(selector);

const content = $('#content');
const banner = $('#statusBanner');
const bannerTitle = $('#bannerTitle');
const statusText = $('#statusText');
const bannerEyebrow = $('#bannerEyebrow');
const bannerScope = $('#bannerScope');
const siteConnection = $('#siteConnection');
const pageCountsNote = $('#pageCountsNote');
const protectionToggle = $('#protectionToggle');
const globalProtectionToggle = $('#globalProtectionToggle');
const globalProtectionStatus = $('#globalProtectionStatus');
const sitePill = $('#sitePill');
const sitePillText = $('#sitePillText');
const siteHost = $('#siteHost');
const allowlistButton = $('#allowlistButton');
const fixSiteButton = $('#fixSiteButton');
const toast = $('#toast');
const toastText = $('#toastText');
const toastAction = $('#toastAction');
const layersNote = $('#layersNote');
const strictMeta = $('#strictMeta');
const tabActionCount = $('#tabActionCount');
const networkSyncPill = $('#networkSyncPill');
const retentionSelect = $('#retentionSelect');
const clearHistory = $('#clearHistory');
const activityTotal = $('#activityTotal');
const activityPeriodLabel = $('#activityPeriodLabel');
const chartWrap = $('#chartWrap');
const activityChart = $('#activityChart');
const composeBar = $('#composeBar');
const filtersLists = $('#filtersLists');
const filtersRules = $('#filtersRules');
const filtersRuleCount = $('#filtersRuleCount');
const filtersRuleNote = $('#filtersRuleNote');
const pageCleanupNote = $('#pageCleanupNote');
const filtersFootnote = $('#filtersFootnote');
const filterGroups = $('#filterGroups');
const budgetFill = $('#budgetFill');
const budgetNote = $('#budgetNote');
const updateHost = $('#updateHost');
const updateButton = $('#updateButton');
const updateLabel = $('#updateLabel');
const updateStatus = $('#updateStatus');
const ruleHint = $('#ruleHint');
const allowCount = $('#allowCount');
const activityCoverage = $('#activityCoverage');
const strictTarget = $('#strictTarget');
const strictAdd = $('#strictAdd');
const strictList = $('#strictList');
const strictCount = $('#strictCount');
const strictStatus = $('#strictStatus');
const strictError = $('#strictError');
const allowlistList = $('#allowlistList');
const recoveryStatus = $('#recoveryStatus');
const recoveryReport = $('#recoveryReport');
const recoveryClear = $('#recoveryClear');
const privacyModeStatus = $('#privacyModeStatus');
const versionText = $('#versionText');

const VIEWS = Object.freeze({
  overview: $('#overviewView'),
  site: $('#siteView'),
  activity: $('#activityView'),
  strict: $('#strictView'),
  settings: $('#settingsView'),
  appearance: $('#appearanceView'),
  privacy: $('#privacyView'),
  social: $('#socialView'),
  cosmetic: $('#cosmeticView'),
  security: $('#securityView'),
  data: $('#dataView'),
});

const SVG_NS = 'http://www.w3.org/2000/svg';
const DAY_MS = 86_400_000;
const PERIOD_LABELS = Object.freeze({ today: 'Today', week: 'Last 7 days', month: 'Last 30 days', all: 'All time' });
const UPDATE_DEFAULT_TEXT = 'Automatic filter updates are not enabled in this build. Filters are refreshed with every iShield Extension release.';
const RULE_KINDS = Object.freeze({
  block: { placeholder: 'facebook.com or example.com/path/*', hint: 'Use a domain or path. A warning explains the scope before you add a permanent block.' },
  allow: { placeholder: 'example.com', hint: 'Pauses filtering and warnings on this site. Blocked rules still apply.' },
});

// Filter lists are grouped by the protection layer that governs them; each list has its own switch
// (state.lists) and only loads while its layer is on.
const LAYER_UI = Object.freeze({
  ads: { title: 'Ads & annoyances', layerName: 'Ad Blocking', tone: 'tone-blue', icon: [['path', { d: 'M3 10v4a1 1 0 0 0 1 1h2l5 4V5L6 9H4a1 1 0 0 0-1 1Z', fill: 'currentColor' }], ['path', { d: 'M15.5 8.6c1.2 1.1 1.2 5.7 0 6.8' }]] },
  privacy: { title: 'Tracking & privacy', layerName: 'Privacy', tone: 'tone-teal', icon: [['path', { d: 'M9.9 5.2A9.8 9.8 0 0 1 12 5c5.2 0 8.6 4.4 9.5 7-.4 1.1-1.4 2.7-2.9 4' }], ['path', { d: 'M6.4 7.4C4.3 8.8 3 10.7 2.5 12c.9 2.6 4.3 7 9.5 7 1.4 0 2.7-.3 3.8-.8' }], ['path', { d: 'M3.5 3.5l17 17' }]] },
  phishing: { title: 'Threats & malware', layerName: 'Anti-Phishing', tone: 'tone-red', icon: [['path', { d: 'M12 3 5 5.8v5.1c0 4.6 2.9 8 7 9.1 4.1-1.1 7-4.5 7-9.1V5.8L12 3Z' }], ['path', { d: 'M12 8.4v4.3M12 15.3h.01' }]] },
});
const FILTER_ICONS = Object.freeze({
  base: [['path',{d:'M4 9v6h4l7 4V5L8 9Z',fill:'currentColor'}],['path',{d:'M18 8c2 2 2 6 0 8'}]],
  ublock: [['path',{d:'M3 3l18 18M3 12c4-9 14-9 18 0-4 9-14 9-18 0Z'}],['circle',{cx:12,cy:12,r:3}]],
  tracking: [['path',{d:'M3 3l18 18M3 12c4-9 14-9 18 0-4 9-14 9-18 0Z'}],['circle',{cx:12,cy:12,r:3}]],
  easylist: [['path',{d:'M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6Z'}]],
  urlhaus: [['circle',{cx:12,cy:12,r:9}],['ellipse',{cx:12,cy:12,rx:4,ry:9}],['path',{d:'M3 12h18'}]],
  pgl: [['circle',{cx:12,cy:12,r:9}],['ellipse',{cx:12,cy:12,rx:4,ry:9}],['path',{d:'M3 12h18'}]],
  badware: [['path',{d:'M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6Z M9 10l6 6m0-6-6 6'}]],
  mobile: [['circle',{cx:12,cy:6,r:3,fill:'currentColor'}],['circle',{cx:5,cy:9,r:2}],['circle',{cx:19,cy:9,r:2}],['path',{d:'M7 21v-4a5 5 0 0 1 10 0v4M2 20v-4m20 4v-4'}]],
});
const LAYER_ORDER = Object.freeze(['ads', 'privacy', 'phishing']);
const BUILTIN_RULES = Object.freeze({ core: 8, strong: 9, maximum: 6 });
const STATIC_RULE_GUARANTEE = 30_000;

let currentHost = null;
let currentTabId = null;
let currentIsSecure = false;
let currentState = null;
let currentHealth = null;
let currentPeriod = 'week';
let activityScope = 'all';
let activityMetricCounts = {};
let activityEvents = [];
let showOptionalFilters = false;
let activityPageIndex = 0;
let activityPagination = null;
let activityLoadRevision = 0;
let networkSyncAvailable = null;
let recoveryActive = false;
let protectionMutationPending = false;
let strictPolicies = [];
let syncedPageBlocked = null;
let syncedPageCounts = null;
let ruleKind = 'block';
let refreshTimer = 0;
let messageTimer = 0;

const ids = Object.freeze({
  pageAds: $('#pageAds'),
  pageTrackers: $('#pageTrackers'),
  pageScams: $('#pageScams'),
  pageThreats: $('#pageThreats'),
  statsAds: $('#statsAds'),
  statsTrackers: $('#statsTrackers'),
  statsScams: $('#statsScams'),
  statsThreats: $('#statsThreats'),
  statsPhishing: $('#statsPhishing'),
  statsMalware: $('#statsMalware'),
  statsPrivacy: $('#statsPrivacy'),
  statsStrict: $('#statsStrict'),
});

const FEATURE_LABELS = Object.freeze({ ads: 'Ad Blocking', privacy: 'Privacy', phishing: 'Anti-Phishing', scam: 'Anti-Scam' });

const THEME_KEY = 'ishield.popup.theme';
const THEMES = Object.freeze(['light', 'dark', 'system']);

function applyTheme(choice) {
  const theme = THEMES.includes(choice) ? choice : 'dark';
  document.documentElement.dataset.theme = theme;
  for (const button of document.querySelectorAll('#themeControl [data-theme-choice]')) {
    const selected = button.dataset.themeChoice === theme;
    button.classList.toggle('is-active', selected);
    button.setAttribute('aria-checked', String(selected));
  }
}
// Adopt the requested dark default once; subsequent explicit theme choices are remembered.
try {
  if (localStorage.getItem('ishield.popup.dark-default.v1') !== 'applied') {
    localStorage.setItem(THEME_KEY, 'dark');
    localStorage.setItem('ishield.popup.dark-default.v1', 'applied');
  }
  applyTheme(localStorage.getItem(THEME_KEY));
} catch { applyTheme('dark'); }
for (const button of document.querySelectorAll('#themeControl [data-theme-choice]')) {
  button.addEventListener('click', () => {
    applyTheme(button.dataset.themeChoice);
    try { localStorage.setItem(THEME_KEY, button.dataset.themeChoice); } catch { /* Preference simply is not remembered. */ }
  });
}

const MOTION_KEY = 'ishield.popup.motion';
const DENSITY_KEY = 'ishield.popup.density';
function applyMotion(enabled) {
  const on = enabled !== false;
  document.documentElement.dataset.motion = on ? 'on' : 'off';
  const toggle = $('#motionToggle');
  if (toggle) toggle.setAttribute('aria-checked', String(on));
}
function applyDensity(value) {
  const density = value === 'compact' ? 'compact' : 'comfortable';
  document.documentElement.dataset.density = density;
  const select = $('#densitySelect');
  if (select) select.value = density;
}
try { applyMotion(localStorage.getItem(MOTION_KEY) !== 'off'); } catch { applyMotion(true); }
try { applyDensity(localStorage.getItem(DENSITY_KEY)); } catch { applyDensity('comfortable'); }
$('#motionToggle')?.addEventListener('click', () => {
  const next = $('#motionToggle').getAttribute('aria-checked') !== 'true';
  applyMotion(next);
  try { localStorage.setItem(MOTION_KEY, next ? 'on' : 'off'); } catch { /* Preference simply is not remembered. */ }
});
$('#densitySelect')?.addEventListener('change', (event) => {
  applyDensity(event.target.value);
  try { localStorage.setItem(DENSITY_KEY, event.target.value); } catch { /* Preference simply is not remembered. */ }
});

const delay = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
const safeCount = (value) => (Number.isSafeInteger(value) && value >= 0 ? value : 0);

const popupClient = createPopupClient(API.runtime);
const send = message => popupClient.request(message);

function formatCount(value) {
  const number = safeCount(value);
  return new Intl.NumberFormat(undefined, { notation: number >= 10_000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(number);
}

function formatFull(value) { return new Intl.NumberFormat().format(safeCount(value)); }

function hideToast() { toast.hidden = true; }

function showToast(text, action = null, ms = 5000) {
  clearTimeout(messageTimer);
  toastText.textContent = text;
  toastAction.hidden = action === null;
  toastAction.onclick = action === null ? null : () => { hideToast(); action.run(); };
  if (action !== null) toastAction.textContent = action.label;
  toast.hidden = false;
  messageTimer = setTimeout(hideToast, ms);
}

function renderPageCount() {
  const counts = syncedPageCounts;
  const complete = networkSyncAvailable === true;
  const display = (value) => {
    if (!currentHost || !counts) return '—';
    return complete ? formatCount(value) : (safeCount(value) > 0 ? `${formatCount(value)}+` : '—');
  };
  ids.pageAds.textContent = display(counts?.ads);
  ids.pageTrackers.textContent = display(counts?.trackers);
  ids.pageScams.textContent = display(counts?.scams);
  ids.pageThreats.textContent = display(safeCount(counts?.phishing) + safeCount(counts?.malware));
  const observed = counts ? Object.values(counts).reduce((total, value) => total + safeCount(value), 0) : 0;
  tabActionCount.textContent = display(Number.isSafeInteger(syncedPageBlocked) ? syncedPageBlocked : observed);
  const pageTotal = display(Number.isSafeInteger(syncedPageBlocked) ? syncedPageBlocked : observed);
  $('#homePageTotal').textContent = pageTotal + ' total';
  const other = safeCount(counts?.privacy) + safeCount(counts?.strictPolicy);
  const extras = safeCount(counts?.scams) + other;
  $('#homeOtherActions').hidden = extras === 0;
  $('#homeOtherActions').textContent = [safeCount(counts?.scams) ? `${formatCount(counts.scams)} scam actions` : '', other ? `${formatCount(other)} other protection actions` : ''].filter(Boolean).join(' · ');
  if ($('#sitePageTotal')) $('#sitePageTotal').textContent = pageTotal + ' total' + (other ? ` · ${formatCount(other)} other protection actions` : '');
  pageCountsNote.textContent = !currentHost ? 'Open a website to see page activity' : (complete ? 'Blocked on this page · Resets when the page reloads' : 'Observed on this page · Network counts unavailable');
  const siteTotal = $('#siteTotalBlocked');
  if (siteTotal) siteTotal.textContent = tabActionCount.textContent;
  if ($('#siteAdsBlocked')) $('#siteAdsBlocked').textContent = ids.pageAds.textContent;
  if ($('#siteTrackersBlocked')) $('#siteTrackersBlocked').textContent = ids.pageTrackers.textContent;
  if ($('#siteScamsBlocked')) $('#siteScamsBlocked').textContent = ids.pageScams.textContent;
  if ($('#siteThreatsBlocked')) $('#siteThreatsBlocked').textContent = ids.pageThreats.textContent;
  renderSiteRecentActivity();
  refreshSiteDetails();
  if (activityScope === 'page') { renderActivityPage(); renderRecentActivity(); }
  const recent = $('#recentPageSummary');
  if (recent) recent.textContent = currentHost && Number.isFinite(syncedPageBlocked) ? `${formatCount(syncedPageBlocked)} items blocked on this page` : 'No activity on this page yet';
}

// This Site uses the existing ephemeral page counters; no fabricated event times or history.
function renderSiteRecentActivity() {
  const list = $('#siteRecentActivity');
  list.replaceChildren();
  const labels = { ads: 'Blocked ad activity', trackers: 'Blocked tracking requests', scams: 'Scam protection', phishing: 'Phishing protection', malware: 'Malware protection', privacy: 'Privacy protection', strictPolicy: 'Custom rules enforced' };
  const entries = currentHost ? Object.entries(syncedPageCounts ?? {}).filter(([, count]) => safeCount(count) > 0).slice(0, 5) : [];
  for (const [category, count] of entries) {
    const row = document.createElement('div'); row.className = `site-activity-row site-event-${category}`;
    const icon = document.createElement('span'); icon.className = 'site-activity-icon';
    activityIcon(category, icon); icon.classList.add('site-activity-icon'); icon.setAttribute('aria-hidden', 'true');
    const label = document.createElement('span'); label.className = 'site-activity-label'; label.textContent = labels[category] ?? 'Protection activity';
    const amount = document.createElement('span'); amount.className = 'site-activity-time'; amount.textContent = `${formatCount(count)} on this page`;
    row.append(icon, label, amount); list.append(row);
  }
  if (!entries.length) {
    const empty = document.createElement('p'); empty.className = 'site-activity-empty'; empty.textContent = currentHost ? 'No activity recorded on this page yet.' : 'Open a website to see its activity.'; list.append(empty);
  }
}

function setBanner(tone, title, sub) {
  banner.dataset.tone = tone;
  bannerEyebrow.textContent = 'BROWSING PROTECTION';
  bannerTitle.dataset.active = String(tone === 'active');
  bannerTitle.textContent = title;
  statusText.textContent = sub;
}

function emptyRow(text) {
  const empty = document.createElement('div');
  empty.className = 'empty';
  empty.textContent = text;
  return empty;
}

function renderState(state, health) {
  currentState = state;
  if (health) currentHealth = health;
  const enabled = state.protectionEnabled === true;
  const healthy = currentHealth?.status !== 'degraded';

  if (!enabled) setBanner('paused', 'Protection Paused', 'Filtering is off on every site');
  else if (currentHost && state.allowlist.some((host) => currentHost === host || currentHost.endsWith(`.${host}`))) setBanner('paused', 'Paused on This Site', 'Other websites stay protected');
  else if (!currentHost) setBanner('active', 'Protection active', 'Open a website to view its protection.');
  else if (!healthy) setBanner('warn', 'Needs Attention', 'Some protections are still starting up');
  else setBanner('active', 'Protection active', 'Ads, trackers and threats are filtered.');
  bannerScope.textContent = !enabled ? 'Globally paused' : healthy && currentHost && !state.allowlist.some(host => currentHost === host || currentHost.endsWith(`.${host}`)) ? 'All systems active' : 'Applies to this website only';
  const switchLabel = $('#protectionSwitchLabel');
  if (switchLabel) switchLabel.textContent = enabled && !state.allowlist.some(host => currentHost === host || currentHost.endsWith(`.${host}`)) ? 'Protection On' : 'Protection Off';
  globalProtectionToggle.setAttribute('aria-checked', String(enabled));
  globalProtectionToggle.disabled = protectionMutationPending;
  $('#filterGlobalProtectionToggle').disabled = protectionMutationPending;
  $('#filterGlobalProtectionToggle').setAttribute('aria-checked', String(enabled));
  $('#filterGlobalProtectionToggle').classList.toggle('is-on', enabled);
  globalProtectionStatus.textContent = enabled ? 'On for all websites except your allowed sites.' : 'Off for all websites. Turn on to resume protection.';

  $('#filterGlobalProtectionStatus').textContent = globalProtectionStatus.textContent;
  const fpActive = currentHealth?.fingerprintRegistrationActive === true;
  const fpMode = ['balanced', 'strong', 'maximum'].includes(currentHealth?.fingerprintMode) ? currentHealth.fingerprintMode : state.mode;
  privacyModeStatus.textContent = enabled && fpActive
    ? `${fpMode[0].toUpperCase()}${fpMode.slice(1)} fingerprint hardening active`
    : (enabled ? 'Fingerprint hardening is reconciling' : 'Fingerprint hardening paused');

  $('#privacyModeSelect').value = state.mode;
  $('#engineHealthBadge').textContent = !enabled ? 'Paused' : currentHealth?.status === 'healthy' ? 'Ready' : currentHealth?.status === 'degraded' ? 'Needs attention' : 'Checking';
  $('#engineHealthBadge').dataset.tone = currentHealth?.status === 'healthy' ? 'on' : 'warn';
  $('#engineHealthSummary').textContent = !enabled ? 'Automatic protection is paused globally. Your saved Strict rules remain enforced.' : currentHealth?.status === 'healthy' ? 'Browser filtering is ready. Your selected lists and protection layers are applied.' : 'Some protection modules are starting or unavailable. Refresh to check their status.';
  renderSite();
  renderFeatures();
  renderSettingsFeatures();
  renderAllowlist();
  void renderFilterCards();
}

function renderSite() {
  const enabled = currentState?.protectionEnabled === true;
  const setPill = (tone, text) => { sitePill.dataset.tone = tone; sitePillText.textContent = text; };
  if (!currentState) return;
  if (!currentHost) {
    siteHost.textContent = 'No website selected';
    $('#siteViewHost').textContent = 'No website selected';
    $('#siteViewStatus').textContent = 'Open a website to view activity.';
    $('#siteViewStatus').dataset.tone = 'off';
    setPill('off', 'Not filtered');
    protectionToggle.disabled = true;
    protectionToggle.setAttribute('aria-checked', 'false');
    protectionToggle.setAttribute('aria-label', 'Protection unavailable on this page');
    fixSiteButton.disabled = true;
    allowlistButton.disabled = true;
    for (const id of ['siteAllowAction', 'siteBlockAction']) $(`#${id}`).disabled = true;
    return;
  }
  siteHost.textContent = currentHost;
  siteConnection.textContent = currentIsSecure ? 'Secure connection' : 'HTTP connection';
  const allowedHost = currentState.allowlist.find((host) => currentHost === host || currentHost.endsWith(`.${host}`));
  const paused = Boolean(allowedHost);
  if (!enabled) setPill('off', 'Protection off');
  else if (paused) setPill('paused', 'Paused');
  else setPill('safe', 'Safe');
  protectionToggle.setAttribute('aria-checked', String(enabled && !paused));
  protectionToggle.setAttribute('aria-label', !enabled ? 'Protection off globally. Enable it in Settings' : (paused ? `Resume protection on ${currentHost}` : `Pause protection on ${currentHost} only`));
  protectionToggle.title = !enabled ? 'Turn on global protection in Settings' : (allowedHost && allowedHost !== currentHost ? `Paused by ${allowedHost}. Manage this exception in Allowlist.` : 'Applies only to this website');
  protectionToggle.disabled = !enabled || protectionMutationPending;
  fixSiteButton.disabled = !enabled || paused || recoveryActive;
  allowlistButton.disabled = !enabled || paused || protectionMutationPending;
  const siteViewHost = $('#siteViewHost');
  if (siteViewHost) siteViewHost.textContent = currentHost || 'No website selected';
  const siteViewStatus = $('#siteViewStatus');
  if (siteViewStatus) {
    siteViewStatus.textContent = !enabled ? 'Protection is off' : paused ? 'Protection paused on this site' : 'Protection active';
    siteViewStatus.dataset.tone = !enabled ? 'off' : paused ? 'paused' : 'active';
  }
  const siteViewConnection = $('#siteViewConnection');
  if (siteViewConnection) siteViewConnection.textContent = currentHost ? (currentIsSecure ? 'Secure connection' : 'HTTP connection') : 'No website';
  const siteControlText = $('#siteControlText');
  if (siteControlText) siteControlText.textContent = !enabled ? 'Global protection is currently turned off.' : paused ? 'Automatic filtering is paused for this website.' : 'iShield Extension is actively protecting this website.';
  const siteAllowAction = $('#siteAllowAction');
  if (siteAllowAction) {
    siteAllowAction.disabled = !enabled || protectionMutationPending;
    const title = siteAllowAction.querySelector('strong');
    const help = siteAllowAction.querySelector('small');
    if (title) title.textContent = paused ? 'Enable iShield Extension' : 'Disable iShield Extension';
    if (help) help.textContent = paused ? 'Turn on for this website' : 'Turn off on this website';
  }
  $('#siteBlockAction').disabled = protectionMutationPending;
  for (const row of document.querySelectorAll('[data-site-feature]')) {
    const feature = row.dataset.siteFeature;
    const flag = feature === 'cosmetic' ? currentState?.features?.ads !== false : currentState?.features?.[feature] !== false;
    const on = enabled && !paused && flag;
    const stateLabel = row.querySelector('b');
    if (stateLabel) stateLabel.textContent = on ? 'On' : 'Off';
    row.dataset.enabled = String(on);
  }
  refreshSiteDetails();
  if (activityScope === 'page') renderActivityPage();
}

function renderFeatures() {
  const enabled = currentState?.protectionEnabled === true;
  const sitePaused = currentHost && currentState?.allowlist.some((host) => currentHost === host || currentHost.endsWith(`.${host}`));
  const flags = currentState?.features ?? {};
  let active = 0;
  for (const node of document.querySelectorAll('#featureGrid [role="switch"]')) {
    const on = enabled && !sitePaused && flags[node.dataset.feature] !== false;
    if (on) active += 1;
    node.classList.toggle('is-on', on);
    node.setAttribute('aria-checked', String(on));
    node.disabled = !enabled || Boolean(sitePaused);
  }
  layersNote.textContent = sitePaused && enabled ? 'Paused on this site' : enabled ? `${active} of ${Object.keys(FEATURE_LABELS).length} on` : 'Protection paused';
  strictMeta.textContent = `${strictPolicies.length} ${strictPolicies.length === 1 ? 'rule' : 'rules'}`;
}

function renderAllowlist() {
  allowlistList.replaceChildren();
  const hosts = currentState?.allowlist ?? [];
  allowCount.textContent = `${hosts.length} ${hosts.length === 1 ? 'site' : 'sites'}`;
  if (hosts.length === 0) { allowlistList.appendChild(emptyRow('No allowed sites. Pause a site or add one above.')); return; }
  for (const host of hosts) {
    const row = document.createElement('div');
    row.className = 'strict-item';
    row.setAttribute('role', 'listitem');
    const copy = document.createElement('div');
    copy.className = 'strict-copy';
    const target = document.createElement('div');
    target.className = 'strict-target';
    target.textContent = host;
    const meta = document.createElement('div');
    meta.className = 'activity-meta';
    meta.textContent = 'Filtering and warnings paused';
    const resume = document.createElement('button');
    resume.className = 'text-button strict-remove';
    resume.type = 'button';
    resume.textContent = 'Resume';
    resume.addEventListener('click', async () => {
      resume.disabled = true;
      try {
        const { state } = await send({ type: 'site:protect', host });
        renderState(state);
        scheduleRefresh();
      } catch { await recoverFromMutationFailure(); }
    });
    copy.append(target, meta);
    row.append(copy, resume);
    allowlistList.appendChild(row);
  }
}

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
  return node;
}

function dayLabel(day, options) { return new Date(day * DAY_MS).toLocaleDateString(undefined, { ...options, timeZone: 'UTC' }); }

const ACTIVITY_METRICS = Object.freeze({
  ads: {name: 'Ads blocked', tag: 'Ad', description: 'Ad requests and elements hidden by the active filtering rules.'},
  trackers: {name: 'Trackers blocked', tag: 'Tracker', description: 'Tracking requests stopped by the privacy filters.'},
  scams: {name: 'Scams blocked', tag: 'Scam', description: 'Scam-related protection events recorded by iShield Extension.'},
  threats: {name: 'Threats blocked', tag: 'Threat', description: 'Phishing and malware protection events combined.'},
});
const activityMetric = category => ['phishing', 'malware'].includes(category) ? 'threats' : category === 'privacy' ? 'trackers' : ACTIVITY_METRICS[category] ? category : 'threats';
function activityIcon(category, node) {
  const metric = activityMetric(category);
  node.className = `event-icon event-${category} metric-${metric}`;
  node.replaceChildren();
  const glyph = $(`#activityView .stat-${metric} .stat-icon svg`)?.cloneNode?.(true);
  if (glyph) node.appendChild(glyph);
  else node.textContent = metric === 'ads' ? 'AD' : '•';
}
function activityDetails(category, count, time, description) {
  const metric = activityMetric(category);
  $('#activityDetailsTitle').textContent = category === 'privacy' ? 'Privacy actions' : category === 'strictPolicy' ? 'Custom rules enforced' : ACTIVITY_METRICS[metric].name;
  $('#activityDetailsDescription').textContent = description || ACTIVITY_METRICS[metric].description;
  $('#activityDetailsCount').textContent = formatFull(count);
  $('#activityDetailsTime').textContent = time;
  activityIcon(category, $('#activityDetailsIcon'));
  $('#activityDetailsDialog').showModal();
}
function relativeActivityTime(timestamp) {
  if (!timestamp) return 'This page';
  const minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60_000));
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return new Date(timestamp).toLocaleDateString(undefined, {month: 'short', day: 'numeric'});
}
function renderActivityVisuals(counts, series) {
  const threats = safeCount(counts.phishing) + safeCount(counts.malware);
  const values = {ads: safeCount(counts.ads), trackers: safeCount(counts.trackers), scams: safeCount(counts.scams), threats};
  const historical = Array.isArray(series) && series.length > 0;
  for (const node of document.querySelectorAll('[data-sparkline]')) {
    node.replaceChildren();
    const metric = node.dataset.sparkline;
    const samples = historical ? series.map(bucket => safeCount(bucket[metric === 'threats' ? 'securityThreats' : metric])) : [values[metric]];
    const max = Math.max(1, ...samples);
    const gap = samples.length > 14 ? 2 : 3;
    const barWidth = Math.min(6, (100 - gap * (samples.length - 1)) / samples.length);
    samples.forEach((value, index) => {
      const height = value > 0 ? Math.max(2, value / max * 20) : 1;
      const rect = svgEl('rect', {x: index * (barWidth + gap), y: 22 - height, width: barWidth, height, rx: 1.5, opacity: value ? .7 : .16});
      const title = svgEl('title'); title.textContent = `${formatFull(value)} ${ACTIVITY_METRICS[metric].name.toLowerCase()}`; rect.appendChild(title); node.appendChild(rect);
    });
    node.setAttribute('aria-label', `${ACTIVITY_METRICS[metric].name}: ${historical ? (series[0]?.hour === undefined ? 'daily recorded totals' : 'retained hourly events') : formatFull(values[metric]) + ' in this scope'}`);
  }
}
function renderChart(series, counts = {}) {
  const historical = Array.isArray(series) && series.length > 0;
  const buckets = historical ? series : [{...counts, label: activityScope === 'page' ? 'This page' : 'Recorded'}];
  chartWrap.hidden = false;
  activityChart.replaceChildren();
  activityChart.setAttribute('viewBox', '0 0 340 155');
  $('#activityChartTooltip').hidden = true;
  $('#activityChartCaption').textContent = historical ? 'Recorded activity for the selected period' : 'Recorded totals by type';
  const values = buckets.map(entry => {
    const ads = safeCount(entry.ads), trackers = safeCount(entry.trackers);
    const total = Number.isSafeInteger(entry.total) ? safeCount(entry.total) : ['ads', 'trackers', 'scams', 'phishing', 'malware', 'privacy', 'strictPolicy'].reduce((sum, key) => sum + safeCount(entry[key]), 0);
    return {ads, trackers, other: Math.max(0, total - ads - trackers), total};
  });
  const maximum = Math.max(1, ...values.map(entry => entry.total));
  const roughStep = maximum / 4;
  const magnitude = 10 ** Math.floor(Math.log10(roughStep));
  const step = Math.max(1, Math.ceil(roughStep / magnitude) * magnitude);
  const ceiling = step * 4;
  const left = 28, right = 333, top = 9, bottom = 117, height = bottom - top;
  for (let tick = 0; tick <= 4; tick += 1) {
    const y = bottom - tick / 4 * height;
    activityChart.append(svgEl('line', {x1:left, x2:right, y1:y, y2:y, class:'statistics-gridline'}));
    const label = svgEl('text', {x:left - 6, y:y + 3, class:'statistics-y-label'});
    label.textContent = new Intl.NumberFormat(undefined, {notation:'compact', maximumFractionDigits:1}).format(tick * step); activityChart.append(label);
  }
  const spacing = (right - left) / buckets.length;
  const barWidth = Math.min(19, spacing * .46);
  buckets.forEach((entry, index) => {
    const value = values[index];
    const x = left + spacing * index + (spacing - barWidth) / 2;
    const labelText = entry.label ?? (entry.hour === undefined ? dayLabel(entry.day, {month:'short', day:'numeric'}) : `${entry.hour % 12 || 12}${entry.hour < 12 ? 'AM' : 'PM'}`);
    let accumulated = 0;
    const group = svgEl('g', {tabindex:0, 'aria-label':`${labelText}: ${formatFull(value.total)} blocked`});
    const title = svgEl('title'); title.textContent = `${labelText}: ${formatFull(value.ads)} ads, ${formatFull(value.trackers)} trackers, ${formatFull(value.other)} other`; group.append(title);
    for (const category of ['ads', 'trackers', 'other']) {
      const segmentHeight = value[category] / ceiling * height;
      if (segmentHeight > 0) group.append(svgEl('rect', {x, y:bottom - accumulated - segmentHeight, width:barWidth, height:segmentHeight, class:`statistics-stack-${category}`}));
      accumulated += segmentHeight;
    }
    const show = () => { $('#activityChartTooltip').textContent = title.textContent; $('#activityChartTooltip').hidden = false; };
    const hide = () => { $('#activityChartTooltip').hidden = true; };
    for (const event of ['pointerenter', 'focus']) group.addEventListener(event, show);
    for (const event of ['pointerleave', 'blur']) group.addEventListener(event, hide);
    activityChart.append(group);
    if (buckets.length <= 7 || index === 0 || index === buckets.length - 1 || index % (entry.hour === undefined ? 7 : 6) === 0) {
      const label = svgEl('text', {x:x + barWidth / 2, y:136, class:'statistics-x-label'}); label.textContent = labelText; activityChart.append(label);
    }
  });
  renderActivityVisuals(counts, series);
}

function renderCompose(counts, threats) {
  composeBar.replaceChildren();
  for (const [className, value] of [['c-ads', counts.ads], ['c-trackers', counts.trackers], ['c-scams', counts.scams], ['c-threats', threats]]) {
    if (safeCount(value) === 0) continue;
    const segment = document.createElement('i');
    segment.className = className;
    segment.style.flex = `${safeCount(value)} 1 0`;
    composeBar.appendChild(segment);
  }
}

function renderBars(counts) {
  const values = { barPhishing: safeCount(counts.phishing), barMalware: safeCount(counts.malware), barPrivacy: safeCount(counts.privacy), barStrict: safeCount(counts.strictPolicy) };
  const max = Math.max(1, ...Object.values(values));
  for (const [id, value] of Object.entries(values)) $(`#${id}`).style.width = value === 0 ? '0' : `${Math.max(6, (value / max) * 100)}%`;
}

function renderSummary(summary, target = 'activity', series = []) {
  const counts = summary?.counts ?? {};
  const threats = safeCount(counts.phishing) + safeCount(counts.malware);
  activityMetricCounts = {ads:safeCount(counts.ads),trackers:safeCount(counts.trackers),scams:safeCount(counts.scams),threats};
  ids.statsAds.textContent = formatCount(counts.ads);
  ids.statsTrackers.textContent = formatCount(counts.trackers);
  ids.statsScams.textContent = formatCount(counts.scams);
  ids.statsThreats.textContent = formatCount(threats);
  ids.statsPhishing.textContent = formatCount(counts.phishing);
  ids.statsMalware.textContent = formatCount(counts.malware);
  ids.statsPrivacy.textContent = formatCount(counts.privacy);
  ids.statsStrict.textContent = formatCount(counts.strictPolicy);
  const total = ['ads', 'trackers', 'scams', 'phishing', 'malware', 'privacy', 'strictPolicy'].reduce((sum, key) => sum + safeCount(counts[key]), 0);
  activityTotal.textContent = formatCount(total);
  activityPeriodLabel.textContent = PERIOD_LABELS[currentPeriod] ?? '';
  renderCompose(counts, threats);
  renderBars(counts);
  renderChart(series, counts);
}

async function resolveCurrentTab() {
  const [tab] = await API.tabs.query({ active: true, currentWindow: true });
  currentTabId = Number.isInteger(tab?.id) ? tab.id : null;
  currentHost = canonicalizeSiteHost(tab?.url ?? '');
  currentIsSecure = tab?.url?.startsWith('https://') === true;
  for (const image of document.querySelectorAll('.site-favicon')) {
    const icon = tab?.favIconUrl;
    if (typeof icon === 'string' && /^(https?:|data:image\/|chrome-extension:|moz-extension:)/u.test(icon)) { image.src = icon; image.hidden = false; image.onerror = () => { image.hidden = true; }; }
    else image.hidden = true;
  }
  renderPageCount();
}

async function reloadCurrentTab() {
  if (currentTabId === null) return;
  try { await API.tabs.reload(currentTabId); } catch { /* The tab may have been closed. */ }
}

// Static-ruleset and dynamic-rule changes are applied asynchronously by the background
// reconciler, so wait (bounded) for the browser to reflect them before reloading the page.
async function waitForRulesets(expectActive) {
  if (typeof API.declarativeNetRequest?.getEnabledRulesets !== 'function') return;
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    try {
      const enabled = await API.declarativeNetRequest.getEnabledRulesets();
      if (enabled.some((id) => id.startsWith('ishield_')) === expectActive) return;
    } catch { return; }
    await delay(150);
  }
}

async function waitForSiteScripts(host, paused) {
  if (currentState?.features?.ads === false || !API.scripting?.getRegisteredContentScripts) return;
  const ids = ['ishield_pc_css_specific'];
  if (host === 'facebook.com' || host.endsWith('.facebook.com')) ids.push('ishield_pc_facebook_ads');
  const deadline = Date.now() + 12000;
  const excludesHost = pattern => {
    const excluded = /^\*:\/\/(?:\*\.)?([^/]+)\/\*$/.exec(pattern)?.[1];
    return excluded && (host === excluded || host.endsWith('.' + excluded));
  };
  while (Date.now() < deadline) {
    const scripts = await API.scripting.getRegisteredContentScripts({ids});
    if (ids.every(id => {
      const script = scripts.find(item => item.id === id);
      return Boolean(script) && (script.excludeMatches ?? []).some(excludesHost) === paused;
    })) return;
    await delay(150);
  }
  throw new Error('Site filtering scripts are still updating');
}

async function waitForAllowlist(host, expectPresent) {
  if (typeof API.declarativeNetRequest?.getDynamicRules !== 'function') return;
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    try {
      const rules = await API.declarativeNetRequest.getDynamicRules();
      const present = rules.some((rule) => rule.action?.type === 'allowAllRequests' && rule.condition?.requestDomains?.includes(host));
      if (present !== expectPresent) { await delay(150); continue; }
    } catch { return; }
    await waitForSiteScripts(host, expectPresent);
    return;
  }
  throw new Error('Site exception is still updating');
}

let pageRefreshRunning = false;
let pageCountRevision = 0;
async function syncCurrentTabActivity() {
  if (currentTabId === null || pageRefreshRunning) return;
  pageRefreshRunning = true;
  const revision = pageCountRevision;
  try {
    const { networkSync } = await send({ type: 'activity:sync-tab', tabId: currentTabId });
    if (revision !== pageCountRevision) return;
    networkSyncAvailable = networkSync?.available === true;
    syncedPageBlocked = Number.isSafeInteger(networkSync?.pageBlocked) ? networkSync.pageBlocked : null;
    syncedPageCounts = networkSync?.pageCounts ?? null;
  } catch {
    // Keep the last snapshot when a refresh is deferred or fails.
  } finally { pageRefreshRunning = false; }
  renderPageCount();
  networkSyncPill.textContent = networkSyncAvailable ? 'Synced' : 'Local';
  activityCoverage.textContent = networkSyncAvailable
    ? 'Network matches refresh while iShield Extension is open. URLs and domains are not stored.'
    : 'Current-tab network match history is unavailable in this browser session. No DNR debug permission is requested.';
}

function renderRecovery(payload) {
  const compatibility = payload?.compatibility ?? { active: false, disabledLayers: [] };
  const local = payload?.localSite ?? null;
  recoveryActive = compatibility.active === true;
  if (!currentHost) { recoveryStatus.textContent = 'Unavailable on this tab.'; recoveryReport.disabled = true; recoveryClear.hidden = true; renderSite(); return; }
  if (!compatibility.active) { recoveryStatus.textContent = 'No compatibility recovery is active for this site.'; recoveryReport.disabled = false; recoveryClear.hidden = true; renderSite(); return; }
  const layers = Array.isArray(compatibility.disabledLayers) ? compatibility.disabledLayers.join(' + ') : 'compatibility';
  const source = local?.source === 'automatic' ? 'Automatic recovery' : 'Manual recovery';
  recoveryStatus.textContent = `${source} active · ${layers}`;
  recoveryReport.disabled = true;
  recoveryClear.hidden = !local;
  renderSite();
}

async function loadRecovery() {
  if (!currentHost) return renderRecovery(null);
  renderRecovery(await send({ type: 'recovery:status', host: currentHost }));
}

function renderActivityPage() {
  renderSummary({ counts: syncedPageCounts ?? {} });
  ids.statsAds.textContent = ids.pageAds.textContent; ids.statsTrackers.textContent = ids.pageTrackers.textContent; ids.statsScams.textContent = ids.pageScams.textContent; ids.statsThreats.textContent = ids.pageThreats.textContent;
  activityTotal.textContent = tabActionCount.textContent;
  activityPeriodLabel.textContent = networkSyncAvailable === true ? 'Current page · resets on reload' : 'Observed on this page · network counts unavailable';
  chartWrap.hidden = false;
  if ($('.periods')) $('.periods').hidden = false;
}
function renderRecentActivity() {
  $('#recentActivityTitle').textContent = 'Recent activity';
  $('#activityListNote').textContent = activityScope === 'page' ? 'Grouped totals for this page · resets on reload' : 'Recorded protection events · ' + (PERIOD_LABELS[currentPeriod] ?? '');
  const list = $('#recentActivity');
  if (!list?.replaceChildren) return;
  list.replaceChildren();
  const events = activityScope === 'page' ? Object.entries(syncedPageCounts ?? {}).filter(([, count]) => count > 0).map(([category, count]) => ({ category, count, source: 'current-page' })) : activityEvents;
  const matches = events;
  const paged = activityScope === 'page' || !activityPagination ? activityPage(matches, {page: activityPageIndex, size: 6}) : {items: matches, pagination: activityPagination};
  activityPageIndex = paged.pagination.page;
  $('#activityPageLabel').textContent = `Page ${activityPageIndex + 1} of ${paged.pagination.pages} · ${paged.pagination.total} items`;
  $('#activityPrevious').disabled = activityPageIndex === 0;
  $('#activityNext').disabled = activityPageIndex + 1 >= paged.pagination.pages;
  $('#clearActivity').hidden = activityScope === 'page';
  const visible = paged.items;
  for (const event of visible) {
    const metric = activityMetric(event.category);
    const row = document.createElement('div'); row.className = `recent-event metric-${metric}`;
    const icon = document.createElement('span'); activityIcon(event.category, icon); icon.setAttribute('aria-hidden','true');
    const copy = document.createElement('div'); copy.className = 'activity-event-copy';
    const heading = document.createElement('div'); heading.className = 'activity-event-heading';
    const name = document.createElement('strong'); name.textContent = ({ads:'Blocked ad activity',trackers:'Blocked tracking activity',scams:'Scam protection',phishing:'Phishing protection',malware:'Malware protection',privacy:'Privacy protection',strictPolicy:'Custom rule enforced'})[event.category] ?? 'Protection event';
    const tag = document.createElement('span'); tag.className='activity-event-tag';tag.textContent=ACTIVITY_METRICS[metric].tag;
    heading.append(name,tag);
    const meta = document.createElement('small'); meta.textContent = ({'network-filter':'Network filtering','cosmetic-collapse':'Page cleanup','privacy-engine':'Privacy engine','threat-engine':'Threat protection','strict-policy':'Permanent custom rule','current-page':'Observed on this page'})[event.source] ?? event.source.replaceAll('-',' ');
    const tail = document.createElement('div'); tail.className='activity-event-tail';
    const time = document.createElement('time');time.textContent=relativeActivityTime(event.timestamp);if(event.timestamp) time.dateTime=new Date(event.timestamp).toISOString();
    const amount = document.createElement('span');amount.className='activity-event-count';amount.textContent=`×${formatCount(event.count)}`;amount.title=`${formatFull(event.count)} recorded items`;
    const details = document.createElement('button');details.type='button';details.className='activity-event-menu';details.textContent='⋯';details.setAttribute('aria-label',`Details for ${name.textContent.toLowerCase()}`);details.addEventListener('click',()=>activityDetails(event.category,event.count,event.timestamp?new Date(event.timestamp).toLocaleString():'Current page · resets on reload',`${meta.textContent}. This record stores only the type, time and count. Website URLs are not retained.`));
    tail.append(time,amount);copy.append(heading,meta);row.append(icon,copy,tail,details);list.append(row);
  }
  if (!visible.length) { const empty = document.createElement('p'); empty.className = 'empty-state'; empty.textContent = 'No activity recorded yet.'; list.append(empty); }
}
async function loadActivity() {
  const revision = ++activityLoadRevision;
  const { activity: selected } = await send({ type: 'activity:get', period: currentPeriod, limit: 6, query: {page: activityPageIndex} });
  if (revision !== activityLoadRevision) return;
  activityPagination = selected.pagination ?? null;
  const firstDay = new Date(); firstDay.setHours(0, 0, 0, 0); firstDay.setDate(firstDay.getDate() - ({ today: 0, week: 6, month: 29 })[currentPeriod]);
  activityEvents = (selected.recent ?? []).filter(event => currentPeriod === 'all' || event.timestamp >= firstDay.getTime());
  if (activityScope === 'page') renderActivityPage();
  else { renderSummary(selected.summary, 'activity', currentPeriod === 'today' ? (selected.hourlySeries ?? selected.series) : selected.series); if ($('.periods')) $('.periods').hidden = false; }
  for (const button of document.querySelectorAll('.period')) {button.disabled = activityScope === 'page';button.title = activityScope === 'page' ? 'Choose All websites to view historical periods. This page resets on reload.' : '';}
  $('#statisticsPeriodSelect').value = currentPeriod;
  $('#statisticsPeriodSelect').disabled = activityScope === 'page';
  retentionSelect.value = String(selected.retentionDays ?? 7);
  renderRecentActivity();
}
$('#activityScope')?.addEventListener('change', async event => { activityScope = event.target.value; activityPageIndex = 0; await loadActivity(); });
API.storage?.onChanged?.addListener((changes, area) => {
  const page = changes[PAGE_ACTIVITY_KEY]?.newValue?.[currentTabId];
  if (area === 'session' && changes[PAGE_ACTIVITY_KEY]) {
    pageCountRevision++;
    const snapshot = pageSnapshot(page);
    syncedPageCounts = snapshot.pageCounts; syncedPageBlocked = snapshot.pageBlocked; networkSyncAvailable = snapshot.available;
    renderPageCount();
    if (activityScope === 'page') { renderActivityPage(); renderRecentActivity(); }
  }
  if (area === 'local' && changes['ishield.activity.v1']) void loadActivity().catch(() => undefined);
});

for (const [id, step] of [['activityPrevious', -1], ['activityNext', 1]]) $(`#${id}`)?.addEventListener('click', async () => {
  activityPageIndex += step;
  try { if (activityScope === 'page') renderRecentActivity(); else await loadActivity(); } catch { showToast('Could not load activity.'); }
});
$('#clearActivity')?.addEventListener('click', () => { $('#clearActivityPrompt').hidden = false; });
$('#cancelClearActivity')?.addEventListener('click', () => { $('#clearActivityPrompt').hidden = true; });
$('#confirmClearActivity')?.addEventListener('click', async () => {
  const button = $('#confirmClearActivity'); button.disabled = true;
  try { await send({type:'activity:clear-history'}); activityPageIndex = 0; $('#clearActivityPrompt').hidden = true; await loadActivity(); showToast('Event history cleared. Totals kept.'); }
  catch { showToast('Could not clear history. Please try again.'); }
  finally { button.disabled = false; }
});

function iconNode(shapes) {
  const svg = svgEl('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.9, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' });
  for (const [tag, attrs] of shapes) svg.appendChild(svgEl(tag, attrs));
  return svg;
}

function timeAgo(timestamp) {
  const delta = Math.max(0, Date.now() - timestamp);
  if (!Number.isFinite(delta) || delta < 60_000) return 'just now';
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)} min ago`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)} h ago`;
  return `${Math.floor(delta / 86_400_000)} d ago`;
}

async function availableRuleBudget() {
  try { return typeof API.declarativeNetRequest?.getAvailableStaticRuleCount === 'function' ? await API.declarativeNetRequest.getAvailableStaticRuleCount() : null; } catch { return null; }
}

async function renderFilterCards() {
  let enabledIds = null;
  try { enabledIds = await API.declarativeNetRequest.getEnabledRulesets(); } catch { enabledIds = null; }
  if (!currentState) return;
  const known = Array.isArray(enabledIds);
  const protectionOn = currentState.protectionEnabled === true;
  const flags = currentState.features ?? {};
  const lists = currentState.lists ?? {};
  filterGroups.replaceChildren();
  let activeRules = 0;
  let activeLists = 0;

  for (const layer of LAYER_ORDER) {
    const ui = LAYER_UI[layer];
    const layerOn = flags[layer] !== false;
    for (const list of FILTER_CATALOG.lists.filter((item) => item.layer === layer)) {
      const loaded = known && enabledIds.some((id) => id.endsWith(list.suffix));
      const switchedOn = typeof lists[list.id] === 'boolean' ? lists[list.id] : list.default;
      if (loaded) { activeRules += list.ruleCount; activeLists += 1; }
      if (!showOptionalFilters && !list.default && list.id !== 'easylist') continue;

      let tone = '';
      let status = 'Off';
      let hint = '';
      if (!protectionOn) status = 'Paused';
      else if (!layerOn) status = `Needs ${ui.layerName}`;
      else if (!switchedOn) status = 'Off';
      else if (!known) status = 'Unknown';
      else if (loaded) { tone = 'on'; status = 'Active'; }
      else { tone = 'warn'; status = 'Not loaded'; hint = ' The browser did not load this list; its shared filter-rule budget may be used up by other extensions.'; }

      const card = document.createElement('div');
      card.className = 'filter-card';
      card.title = `${list.description}. Source: ${list.source} (${list.provider}). License: ${list.license}.${hint}`;
      const badge = document.createElement('span');
      badge.className = `catalog-icon ${list.id === 'easylist' ? 'tone-orange' : ['urlhaus','badware'].includes(list.id) ? 'tone-red' : list.layer === 'privacy' || list.id === 'ublock' ? 'tone-teal' : 'tone-blue'}`;
      badge.appendChild(iconNode(FILTER_ICONS[list.id] ?? ui.icon));
      const copy = document.createElement('div');
      copy.className = 'filter-copy';
      const name = document.createElement('div');
      name.className = 'filter-name';
      name.textContent = list.name;
      if (list.default) { const tag = document.createElement('span'); tag.className = 'tag'; tag.textContent = 'Default'; name.appendChild(tag); }
      const meta = document.createElement('div');
      meta.className = 'filter-meta';
      const state = document.createElement('span');
      state.className = 'filter-status';
      state.dataset.tone = tone;
      state.textContent = status;
      meta.textContent = list.description;
      const ruleCount = document.createElement('span'); ruleCount.className = 'catalog-rule-count'; ruleCount.textContent = `${formatCount(list.ruleCount)} rules`; ruleCount.title = `${formatFull(list.ruleCount)} network rules`;
      copy.append(name, meta);

      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = `filter-switch${switchedOn && protectionOn && layerOn ? ' is-on' : ''}`;
      toggle.setAttribute('role', 'switch');
      toggle.setAttribute('aria-checked', String(switchedOn));
      toggle.setAttribute('aria-label', list.name);
      toggle.disabled = !protectionOn || !layerOn;
      const knob = document.createElement('span');
      knob.className = 'switch-visual';
      knob.setAttribute('aria-hidden', 'true');
      toggle.appendChild(knob);
      toggle.addEventListener('click', () => { void setFilterSwitch(list, !switchedOn, toggle); });
      const details = document.createElement('button'); details.type = 'button'; details.className = 'catalog-chevron'; details.setAttribute('aria-label', `About ${list.name}`); details.appendChild(iconNode([['path',{d:'m9 5 7 7-7 7'}]])); details.addEventListener('click', () => { $('#filterDetailsName').textContent = list.name; $('#filterDetailsDescription').textContent = list.description; $('#filterDetailsCount').textContent = `${formatFull(list.ruleCount)} network rules. ${status}. ${hint}`; $('#filterDetailsDialog').showModal(); });
      card.append(badge, copy, ruleCount, state, toggle, details);
      filterGroups.appendChild(card);
    }
  }

  filtersRuleCount.textContent = known ? formatFull(activeRules) : '—';
  $('#filterUsedRules').textContent = filtersRuleCount.textContent;
  $('#filterUsedLists').textContent = known ? `${activeLists} active lists` : 'List status unavailable';
  filtersRuleNote.textContent = known ? `rules across ${activeLists} ${activeLists === 1 ? 'list' : 'lists'}` : 'rule count unavailable';
  const adguardRules = currentState?.protectionEnabled === false ? 0 : Object.entries(CONTENT_FILTER_COUNTS).filter(([layer]) => currentState?.features?.[layer] !== false && currentState?.lists?.[layer === 'ads' ? 'base' : 'tracking'] !== false).reduce((sum, [, count]) => sum + count, 0);
  const cleanup = enabledPageCleanupRulesets(currentState ?? {}, PAGE_CLEANUP_CATALOG);
  const hidingRules = cleanup.reduce((sum, ruleset) => sum + ruleset.genericCount + ruleset.specificCount, 0);
  const scriptletLists = cleanup.filter((ruleset) => Object.keys(ruleset.scriptletWorlds).length > 0).length;
  pageCleanupNote.textContent = cleanup.length === 0
    ? 'Page cleanup is off. Turn on the Ad Blocking layer to hide ad containers and run scriptlets.'
    : `+ content engine: ${formatFull(adguardRules)} rules · page cleanup: ${formatFull(hidingRules)} hiding rules and scriptlets from ${scriptletLists} ${scriptletLists === 1 ? 'list' : 'lists'}`;
  $('#prebuiltListCount').textContent = `${FILTER_CATALOG.lists.length} lists`;
  $('#browseFilterLists').setAttribute('aria-expanded', String(showOptionalFilters));
  $('#browseFilterLabel').textContent = showOptionalFilters ? 'Show fewer filter lists' : 'Browse and add more filter lists';
  const builtin = known ? enabledIds.reduce((sum, id) => sum + (Object.entries(BUILTIN_RULES).find(([key]) => id.endsWith(`_${key}`))?.[1] ?? 0), 0) : 0;
  const available = await availableRuleBudget();
  const used = activeRules + builtin;
  const capacity = Number.isSafeInteger(available) ? used + available : STATIC_RULE_GUARANTEE;
  const share = capacity > 0 ? Math.min(1, used / capacity) : 0;
  budgetFill.style.width = `${Math.max(known && used > 0 ? 2 : 0, share * 100)}%`;
  budgetFill.dataset.tone = share >= 1 ? 'bad' : (share >= 0.97 ? 'warn' : '');
  budgetNote.textContent = known
    ? `${formatFull(used)} of ${formatFull(capacity)} browser rules used${Number.isSafeInteger(available) ? ` · room for ${formatFull(available)} more` : ''}`
    : '';

  const fresh = FILTER_CATALOG.importedAt ? new Date(FILTER_CATALOG.importedAt) : null;
  const freshText = fresh && !Number.isNaN(fresh.getTime()) ? fresh.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '';
  filtersFootnote.textContent = `Bundled filters${freshText ? ` · ${freshText}` : ''}. Source licenses are available in Settings.`;

}

async function setFilterSwitch(list, enable, node) {
  if (!currentState) return;
  if (enable) {
    // Optional lists compete for the browser's static-rule budget; refuse one that cannot load.
    const available = await availableRuleBudget();
    if (Number.isSafeInteger(available) && list.ruleCount > available) {
      showToast(`Not enough browser rule budget for ${list.name} (${formatFull(list.ruleCount)} rules needed, ${formatFull(available)} free).`);
      return;
    }
  }
  node.disabled = true;
  try {
    const { state } = await send({ type: 'list:set', list: list.id, enabled: enable });
    renderState(state);
    showToast(`${list.name} ${enable ? 'on' : 'off'}. Reload the page to apply.`, { label: 'Reload', run: () => { void reloadCurrentTab(); } });
    scheduleRefresh();
  } catch { await recoverFromMutationFailure(); }
}

function setUpdateStatus(tone, text) {
  updateStatus.dataset.tone = tone;
  updateStatus.textContent = text;
}

function describeUpdate({ update, channel }) {
  updateButton.hidden = channel?.enabled !== true;
  $('#updateTitle').textContent = channel?.enabled === true ? 'Filter lists update' : 'Bundled filter lists';
  if (channel?.enabled !== true) { updateHost.textContent = 'bundled'; return ['', UPDATE_DEFAULT_TEXT]; }
  updateHost.textContent = channel.host ?? 'server';
  const last = update?.lastCheck ?? null;
  const rules = update?.networkRuleCount ?? 0;
  const applied = rules > 0 ? `${formatFull(rules)} of your own rules are active. ` : '';
  if (last === null) return ['', `${applied}Checks ${channel.host} automatically every 6 hours. Nothing has been checked yet.`];
  if (last.ok !== true) return ['warn', `${applied}Could not reach ${channel.host} (${timeAgo(last.checkedAt)}). iShield Extension will retry automatically.`];
  return ['good', `${applied}${last.upToDate ? 'Up to date' : 'Updated'} · checked ${timeAgo(last.checkedAt)}. Signed by your key; checks every 6 hours.`];
}

async function loadUpdateStatus() {
  try { setUpdateStatus(...describeUpdate(await send({ type: 'update:status' }))); } catch { setUpdateStatus('', UPDATE_DEFAULT_TEXT); }
}

async function checkForUpdates() {
  updateButton.disabled = true;
  updateLabel.textContent = 'Checking…';
  try {
    const { update } = await send({ type: 'update:check' });
    if (update?.checked === true) scheduleRefresh();
    else if (update?.reason !== 'channel_disabled') setUpdateStatus('warn', 'Could not check for updates right now.');
    await loadUpdateStatus();
  } catch {
    await loadUpdateStatus();
    if (updateStatus.dataset.tone !== 'warn') setUpdateStatus('warn', 'Could not check for updates. Check your connection and try again.');
  } finally { updateButton.disabled = false; updateLabel.textContent = 'Check for updates'; }
}

function setRuleKind(kind) {
  ruleKind = kind;
  for (const button of document.querySelectorAll('#ruleKind .seg')) {
    const selected = button.dataset.ruleKind === kind;
    button.classList.toggle('is-active', selected);
    button.setAttribute('aria-checked', String(selected));
  }
  strictTarget.placeholder = RULE_KINDS[kind].placeholder;
  ruleHint.textContent = RULE_KINDS[kind].hint;
  strictError.textContent = '';
}

function setView(name) {
  if (!VIEWS[name]) name = 'overview';
  for (const [key, section] of Object.entries(VIEWS)) section.hidden = key !== name;
  for (const item of document.querySelectorAll('.nav-item')) {
    const navView = ['strict', 'appearance', 'privacy', 'social', 'cosmetic', 'security', 'data'].includes(name) ? 'settings' : name;
    const selected = item.dataset.view === navView;
    item.classList.toggle('is-active', selected);
    if (selected) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
  }
  document.body.dataset.view = name;
  const siteSlot = $('#siteToggleSlot');
  if (name === 'site' && siteSlot) siteSlot.append?.(protectionToggle);
  else if (!$('#siteDetailsDialog')?.open) banner.append?.(protectionToggle);
  content.scrollTop = 0;
}

function setFiltersTab(name) {
  document.body.dataset.filterTab = name;
  $('#filtersScreenTitle').textContent = name === 'rules' ? 'Whitelists & Rules' : 'Filter Lists';
  filtersLists.hidden = name !== 'lists';
  filtersRules.hidden = name !== 'rules';
  for (const button of document.querySelectorAll('#filtersTabs .seg')) {
    const selected = button.dataset.filtersTab === name;
    button.classList.toggle('is-active', selected);
    button.setAttribute('aria-selected', String(selected));
  }
}

function strictKindLabel(policy) {
  return {
    domainTree: 'Domain + subdomains', exactDomain: 'Exact domain', wildcardSubdomains: 'Subdomains',
    pathPrefix: 'Path prefix', category: 'Category policy', application: 'Application policy',
  }[policy.kind] ?? 'Strict policy';
}

function renderStrict(payload) {
  const policies = Array.isArray(payload?.strict?.policies) ? payload.strict.policies : [];
  strictPolicies = policies;
  $('#customRulesCount').textContent = `${policies.length} rules`;
  strictCount.textContent = `${policies.length} ${policies.length === 1 ? 'rule' : 'rules'}`;
  renderStrictEnforcement(payload?.enforcement);
  strictList.replaceChildren();
  if (policies.length === 0) strictList.appendChild(emptyRow('No permanent rules yet.'));
  for (const policy of policies) {
    const row = document.createElement('div'); row.className = 'strict-item'; row.setAttribute('role', 'listitem');
    const copy = document.createElement('div'); copy.className = 'strict-copy';
    const target = document.createElement('div'); target.className = 'strict-target'; target.textContent = policy.target;
    const meta = document.createElement('div'); meta.className = 'activity-meta'; meta.textContent = strictKindLabel(policy);
    const remove = document.createElement('button'); remove.className = 'text-button strict-remove'; remove.type = 'button'; remove.textContent = 'Remove';
    remove.addEventListener('click', async () => {
      remove.disabled = true; strictError.textContent = '';
      try { strictPollsLeft = 8; renderStrict(await send({ type: 'strict:remove', id: policy.id })); } catch { strictError.textContent = 'Could not remove the permanent rule.'; }
      finally { remove.disabled = false; }
    });
    copy.append(target, meta); row.append(copy, remove); strictList.appendChild(row);
  }
  renderFeatures();
}

// Shows whether the browser is really enforcing the saved rules. A rule is applied a moment after it is added,
// so while it is pending the list is re-read a few times.
let strictPollsLeft = 0;
let strictPollTimer = 0;
function renderStrictEnforcement(enforcement) {
  clearTimeout(strictPollTimer);
  if (!enforcement || !(enforcement.expected > 0)) { strictStatus.hidden = true; return; }
  const live = enforcement.installed >= enforcement.expected;
  strictStatus.hidden = false;
  strictStatus.dataset.tone = live ? 'on' : 'warn';
  strictStatus.textContent = live ? 'Active in browser' : 'Applying\u2026';
  strictStatus.title = live ? 'The browser is enforcing these rules now.' : 'Saved, but the browser has not applied it yet. If this stays, reload iShield Extension in chrome://extensions.';
  if (!live && strictPollsLeft > 0) {
    strictPollsLeft -= 1;
    strictPollTimer = setTimeout(() => { send({ type: 'strict:get' }).then(renderStrict).catch(() => undefined); }, 1200);
  }
}

async function loadStrict() { strictPollsLeft = 8; renderStrict(await send({ type: 'strict:get' })); }

function scheduleRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(async () => {
    try {
      const { state, health } = await send({ type: 'state:get' });
      renderState(state, health);
      await syncCurrentTabActivity();
    } catch { /* Keep the current view. */ }
  }, 0);
}

async function recoverFromMutationFailure() {
  showToast('Could not apply that change. Please try again.');
  try {
    const { state, health } = await send({ type: 'state:get' });
    renderState(state, health);
  } catch { setBanner('off', 'Status unavailable', 'Reload the extension and try again'); }
}

async function toggleGlobalProtection() {
  if (!currentState || protectionMutationPending) return;
  const enable = currentState.protectionEnabled !== true;
  protectionMutationPending = true;
  globalProtectionToggle.disabled = true;
  $('#filterGlobalProtectionToggle').disabled = true;
  renderSite();
  try {
    const { state } = await send({ type: 'protection:set', enabled: enable });
    renderState(state);
    showToast(enable ? 'Protection resumed globally. Allowed sites stay paused. Reloading this page…' : 'Protection paused on every site. Reloading this page…');
    await waitForRulesets(enable);
    await reloadCurrentTab();
  } catch { await recoverFromMutationFailure(); }
  finally { protectionMutationPending = false; renderState(currentState); scheduleRefresh(); }
}
globalProtectionToggle.addEventListener('click', toggleGlobalProtection);
$('#filterGlobalProtectionToggle').addEventListener('click', toggleGlobalProtection);

async function toggleCurrentSiteProtection() {
  if (!currentHost || !currentState || !currentState.protectionEnabled || protectionMutationPending) return;
  const inheritedHost = currentState.allowlist.find((host) => host !== currentHost && currentHost.endsWith(`.${host}`));
  if (inheritedHost) {
    setView('strict');
    setRuleKind('allow');
    closeSiteDetails();
  $('#allowlistCard').scrollIntoView({ block: 'start' });
    showToast(`This site is paused by ${inheritedHost}. Resume that entry in Allowlist.`);
    return;
  }
  protectionMutationPending = true;
  globalProtectionToggle.disabled = true;
  $('#filterGlobalProtectionToggle').disabled = true;
  renderSite();
  const wasPaused = currentState.allowlist.includes(currentHost);
  try {
    const { state } = await send({ type: wasPaused ? 'site:protect' : 'site:allow', host: currentHost });
    renderState(state);
    showToast(wasPaused ? `Protection resumed on ${currentHost}. Reloading…` : `Paused on ${currentHost}. Reloading…`);
    await waitForAllowlist(currentHost, !wasPaused);
    await reloadCurrentTab();
  } catch { await recoverFromMutationFailure(); }
  finally { protectionMutationPending = false; renderState(currentState); scheduleRefresh(); }
}

protectionToggle.addEventListener('click', toggleCurrentSiteProtection);

for (const node of document.querySelectorAll('#featureGrid [role="switch"]')) {
  node.addEventListener('click', async () => {
    if (!currentState || currentState.protectionEnabled !== true) return;
    const feature = node.dataset.feature;
    const enable = currentState.features?.[feature] === false;
    node.disabled = true;
    try {
      const { state } = await send({ type: 'feature:set', feature, enabled: enable });
      renderState(state);
      showToast(`${node.querySelector(".feature-label").textContent} ${enable ? 'on' : 'off'}. Reload the page to apply.`, { label: 'Reload', run: () => { void reloadCurrentTab(); } });
    } catch { await recoverFromMutationFailure(); }
    finally { renderFeatures(); scheduleRefresh(); }
  });
}

allowlistButton.addEventListener('click', async () => {
  if (!currentHost || !currentState?.protectionEnabled) return;
  allowlistButton.disabled = true;
  try {
    const {state} = await send({type:'site:allow', host:currentHost});
    renderState(state);
    await waitForAllowlist(currentHost, true);
    await reloadCurrentTab();
  } catch { await recoverFromMutationFailure(); }
  finally { renderSite(); }
});

async function activateSiteRecovery() {
  if (!currentHost) return;
  fixSiteButton.disabled = true;
  recoveryReport.disabled = true;
  try {
    await send({ type: 'recovery:activate-manual', host: currentHost });
    await loadRecovery();
    showToast(`Compatibility recovery enabled for ${currentHost}. Reloading…`);
    await reloadCurrentTab();
  } catch {
    recoveryStatus.textContent = 'Compatibility recovery could not be enabled.';
    showToast('Compatibility recovery could not be enabled.');
    recoveryReport.disabled = false;
    renderSite();
  }
}
fixSiteButton.addEventListener('click', activateSiteRecovery);
recoveryReport.addEventListener('click', activateSiteRecovery);

recoveryClear.addEventListener('click', async () => {
  if (!currentHost) return; recoveryClear.disabled = true;
  try { await send({ type: 'recovery:clear', host: currentHost }); await loadRecovery(); await reloadCurrentTab(); }
  catch { recoveryStatus.textContent = 'Compatibility recovery could not be cleared.'; }
  finally { recoveryClear.disabled = false; }
});

$('#settingsButton')?.addEventListener('click', () => { setView('settings'); });

async function openFilters() {
  void renderFilterCards();
  void loadUpdateStatus();
  try { await loadStrict(); } catch { strictError.textContent = 'Custom rules are temporarily unavailable.'; }
}

for (const button of document.querySelectorAll('.nav-item')) {
  button.addEventListener('click', async () => {
    setView(button.dataset.view);
    if (button.dataset.view === 'site') { renderSite(); renderPageCount(); }
    if (button.dataset.view === 'activity') await loadActivity();
  });
}

for (const button of document.querySelectorAll('#filtersTabs .seg')) {
  button.addEventListener('click', () => { setFiltersTab(button.dataset.filtersTab); });
}
for (const button of document.querySelectorAll('#ruleKind .seg')) {
  button.addEventListener('click', () => { setRuleKind(button.dataset.ruleKind); strictTarget.focus(); });
}
for (const item of document.querySelectorAll('[data-goto]')) {
  item.addEventListener('click', async () => {
    const target = item.dataset.goto;
    $('#advancedSettingsDialog')?.close();
    setView(target);
    if (item.dataset.ruleKindChoice) setRuleKind(item.dataset.ruleKindChoice);
    if (target === 'strict') {
      setFiltersTab(item.dataset.openFilterTab || 'rules');
      await openFilters();
    }
  });
}
updateButton.addEventListener('click', () => { void checkForUpdates(); });

let pendingRule = null;
function cancelPendingRule() { pendingRule = null; $('#ruleWarningDialog').close(); strictAdd.disabled = false; }
strictAdd.addEventListener('click', () => {
  const target = strictTarget.value.trim();
  if (!target) { strictError.textContent = 'Enter a domain or path first.'; strictTarget.focus(); return; }
  strictError.textContent = '';
  try {
    if (ruleKind === 'allow') {
      const host = canonicalizeSiteHost(/^[a-z][a-z0-9+.-]*:\/\//iu.test(target) ? target : `https://${target}`);
      if (!host) throw new TypeError('invalid site');
      pendingRule = {kind:'allow', target:host};
      $('#ruleWarningTitle').textContent = 'Allow this website?';
      $('#ruleWarningText').textContent = `Automatic ads, tracking and warning protection will pause on ${host} and its subdomains. Other websites stay protected.`;
      $('#ruleWarningPersistence').textContent = 'The exception is saved on this device. Permanent Strict rules still apply.';
      $('#confirmRuleWarning').textContent = 'Allow website';
    } else {
      const parsed = parseStrictTarget(target);
      if (['category', 'application'].includes(parsed.kind)) throw new TypeError('Use a domain or path in this editor');
      pendingRule = {kind:'block', target:parsed.target};
      const scope = parsed.kind === 'exactDomain' || parsed.scope === 'exact' ? 'this exact hostname only' : parsed.kind === 'wildcardSubdomains' || parsed.scope === 'wildcardSubdomains' ? 'subdomains only (the main domain stays available)' : 'this domain and all its subdomains';
      $('#ruleWarningTitle').textContent = 'Confirm permanent block';
      $('#ruleWarningText').textContent = parsed.kind === 'pathPrefix' ? `Blocks addresses starting with ${parsed.prefix} on ${scope}. Matching requests and pages will fail to load.` : `Blocks ${scope}. The website and matching requests from other websites may stop working.`;
      $('#ruleWarningPersistence').textContent = 'This rule stays active after a restart and while protection is paused. It overrides site exceptions.';
      $('#confirmRuleWarning').textContent = 'Add permanent block';
    }
    $('#ruleWarningTarget').textContent = pendingRule.target;
    $('#ruleWarningDialog .recovery-guide span').textContent = pendingRule.kind === 'allow' ? 'Go to Filters → My rules → Allowed sites and choose Resume. Then reload the website.' : 'Go to Filters → My rules → Blocked and choose Remove. Then reload the affected website.';
    strictAdd.disabled = true;
    $('#ruleWarningDialog').showModal();
  } catch { pendingRule = null; strictError.textContent = ruleKind === 'allow' ? 'Enter a valid website, like example.com.' : 'Use example.com, =example.com, *.example.com or example.com/path/*. Full URLs and query strings are not supported.'; }
});
$('#cancelRuleWarning').addEventListener('click', cancelPendingRule);
$('#ruleWarningDialog').addEventListener('cancel', event => { event.preventDefault(); if (!$('#confirmRuleWarning').disabled) cancelPendingRule(); });
$('#confirmRuleWarning').addEventListener('click', async () => {
  if (!pendingRule) return;
  const draft = pendingRule; const button = $('#confirmRuleWarning');
  button.disabled = true; $('#cancelRuleWarning').disabled = true;
  try {
    if (draft.kind === 'allow') {
      const {state} = await send({type:'site:allow', host:draft.target});
      renderState(state); showToast(`Filtering paused on ${draft.target}.`);
    } else {
      strictPollsLeft = 8; renderStrict(await send({type:'strict:add', target:draft.target}));
      showToast('Permanent block saved. Remove it from My rules to undo.');
    }
    strictTarget.value = ''; cancelPendingRule(); scheduleRefresh();
  } catch { cancelPendingRule(); strictError.textContent = 'Could not save this rule. Check the target and try again.'; }
  finally { button.disabled = false; $('#cancelRuleWarning').disabled = false; strictAdd.disabled = false; }
});
strictTarget.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); strictAdd.click(); } });

for (const button of document.querySelectorAll('.period')) {
  button.addEventListener('click', async () => {
    currentPeriod = button.dataset.period; activityPageIndex = 0;
    for (const item of document.querySelectorAll('.period')) item.classList.toggle('is-active', item === button);
    try { await loadActivity(); } catch { activityCoverage.textContent = 'Activity data is temporarily unavailable.'; }
  });
}

retentionSelect.addEventListener('change', async () => {
  retentionSelect.disabled = true;
  try {
    await send({ type: 'activity:retention:set', days: Number(retentionSelect.value) });
    await loadActivity();
  } catch { /* Leave previous bounded state intact. */ }
  finally { retentionSelect.disabled = false; }
});

clearHistory.addEventListener('click', () => $('#historyWarningDialog').showModal());
$('#cancelHistoryWarning').addEventListener('click', () => $('#historyWarningDialog').close());
$('#confirmHistoryWarning').addEventListener('click', async () => {
  const button = $('#confirmHistoryWarning'); button.disabled = true;
  try { await send({type:'activity:clear-history'}); activityPageIndex = 0; await loadActivity(); $('#historyWarningDialog').close(); showToast('Detailed history cleared. Totals kept.'); }
  catch { showToast('Could not clear history. Please try again.'); }
  finally { button.disabled = false; }
});
$('#browseFilterLists').addEventListener('click', async () => { showOptionalFilters = !showOptionalFilters; await renderFilterCards(); });
$('#customRulesRow').addEventListener('click', () => { setFiltersTab('rules'); });
$('#closeFilterDetails').addEventListener('click', () => $('#filterDetailsDialog').close());
$('#refreshSettings').addEventListener('click', async () => {
  const button = $('#refreshSettings'); button.disabled = true;
  try { const {state, health} = await send({type:'state:get'}); renderState(state, health); await loadRecovery(); showToast('Protection status refreshed.'); } catch { showToast('Could not refresh protection status.'); } finally { button.disabled = false; }
});
$('#privacyModeSelect').addEventListener('change', async event => {
  const control = event.target; control.disabled = true;
  try { const {state} = await send({type:'mode:set', mode:control.value}); renderState(state); scheduleRefresh(); showToast('Strength saved. Reload open websites to apply it.'); }
  catch { control.value = currentState?.mode ?? 'strong'; showToast('Could not change protection strength.'); }
  finally { control.disabled = false; }
});
$('#manageAllowedSites').addEventListener('click', async () => { setView('strict'); setFiltersTab('rules'); await openFilters(); $('#allowlistCard').scrollIntoView({block:'start'}); });

setRuleKind('block');

async function bootstrap() {
  try {
    const manifest = API.runtime.getManifest();
    versionText.textContent = manifest.version_name ?? manifest.version ?? '—';
  } catch { versionText.textContent = '—'; }
  await resolveCurrentTab();
  const restoredFacebookHosts = await restoreLegacyFacebookRecovery(API.storage.local, send).catch(() => []);
  if (restoredFacebookHosts.includes(currentHost)) {
    await reloadCurrentTab();
    showToast('Facebook ad filtering restored. Reloading this website…');
  }
  const { state, health } = await send({ type: 'state:get' });
  renderState(state, health);
  await syncCurrentTabActivity();
  const refreshTimer = setInterval(() => { if (!document.hidden) void syncCurrentTabActivity(); }, 2000);
  window.addEventListener('pagehide', () => clearInterval(refreshTimer), {once:true});
  await resolveCurrentTab();
  await Promise.allSettled([
    loadActivity().catch(() => { activityCoverage.textContent = 'Activity data is temporarily unavailable.'; }),
    loadStrict().catch(() => { strictError.textContent = 'Custom rules are temporarily unavailable.'; }),
    loadRecovery(),
  ]);
}


function refreshSiteDetails() {
  const title = $('#siteDetailsTitle');
  if (!title) return;
  title.textContent = currentHost || 'No website selected';
  $('#detailConnection').textContent = currentHost ? (currentIsSecure ? 'Connection is secure' : 'Connection uses HTTP') : 'Open a website to see its details';
  $('#detailProtection').textContent = banner.dataset.tone === 'active' ? 'Protection on this site' : bannerTitle.textContent;
  $('#detailStatusText').textContent = statusText.textContent;
  $('#detailSafety').textContent = sitePillText.textContent;
  $('#detailSafety').dataset.tone = sitePill.dataset.tone;
  $('#detailTotal').textContent = `${tabActionCount.textContent} items`;
  for (const [target, source] of [['detailAds','pageAds'],['detailTrackers','pageTrackers'],['detailScams','pageScams'],['detailThreats','pageThreats']]) $(`#${target}`).textContent = ids[source].textContent;
  $('#detailCountNote').textContent = pageCountsNote.textContent;
}
function closeSiteDetails() { $('#siteDetailsDialog').close(); banner.append?.(protectionToggle); }
$('#siteDetailsButton').addEventListener('click', () => { refreshSiteDetails(); setView('site'); renderSite(); renderPageCount(); });
$('#siteDetailsDialog').addEventListener('close', () => banner.append?.(protectionToggle));
$('#closeSiteDetails').addEventListener('click', closeSiteDetails);
$('#dismissSiteDetails').addEventListener('click', closeSiteDetails);
for (const id of ['detailSiteSettings']) $(`#${id}`).addEventListener('click', () => { closeSiteDetails(); setView('settings'); });
for (const id of ['detailBlock']) $(`#${id}`).addEventListener('click', async () => { closeSiteDetails(); setView('strict'); setFiltersTab('rules'); setRuleKind('block'); strictTarget.value = currentHost || ''; await openFilters(); });


$('#siteAllowAction')?.addEventListener('click', () => {
  const paused = currentHost && currentState?.allowlist.some(host => currentHost === host || currentHost.endsWith(`.${host}`));
  if (paused) void toggleCurrentSiteProtection();
  else allowlistButton.click();
});
$('#siteBlockAction')?.addEventListener('click', async () => { setView('strict'); setFiltersTab('rules'); setRuleKind('block'); strictTarget.value = currentHost || ''; await openFilters(); });
$('#filtersBack')?.addEventListener('click', () => setView('settings'));
$('#appearanceBack')?.addEventListener('click', () => setView('settings'));

function renderSettingsFeatures() {
  for (const node of document.querySelectorAll('[data-settings-feature]')) {
    const on = currentState?.protectionEnabled === true && currentState?.features?.[node.dataset.settingsFeature] !== false;
    node.setAttribute('aria-checked', String(on)); node.classList.toggle('is-on', on);
    node.disabled = currentState?.protectionEnabled !== true;
  }
}
for (const node of document.querySelectorAll('[data-settings-feature]')) node.addEventListener('click', async () => {
  if (!currentState?.protectionEnabled) return;
  const feature = node.dataset.settingsFeature;
  node.disabled = true;
  try {
    const {state} = await send({type:'feature:set', feature, enabled:currentState.features?.[feature] === false});
    renderState(state); showToast('Protection preference saved. Reload the page to apply.');
  } catch { await recoverFromMutationFailure(); }
  finally { renderSettingsFeatures(); scheduleRefresh(); }
});
async function loadExclusions() {
  const {exclusions} = await send({type:'data:exclusions'});
  const list=$('#exclusionsList');list.replaceChildren();
  if(!exclusions?.length) {list.append(emptyRow('No excluded websites.'));return;}
  for(const entry of exclusions) {
    const row=document.createElement('div');row.className='exclusion-row';
    const copy=document.createElement('div');const host=document.createElement('strong');host.textContent=entry.host;
    const detail=document.createElement('small');detail.textContent=[entry.allowed?'Protection paused':null,entry.recovery?(entry.source==='automatic'?'Automatic recovery':'Manual recovery'):null].filter(Boolean).join(' · ');
    const remove=document.createElement('button');remove.type='button';remove.className='text-button';remove.textContent='Remove';remove.setAttribute('aria-label',`Remove exclusion for ${entry.host}`);
    remove.addEventListener('click',async()=>{
      remove.disabled=true;$('#exclusionsError').textContent='';
      try {
        const {state}=await send({type:'data:exclusion:remove',host:entry.host});renderState(state);await loadRecovery();await loadExclusions();
        if(currentHost===entry.host || currentHost?.endsWith('.'+entry.host)) await reloadCurrentTab();
        showToast(`Exclusion removed for ${entry.host}. Reload that website to apply.`);
      }catch {$('#exclusionsError').textContent='Could not remove this exclusion. Please try again.';remove.disabled=false;}
    });
    copy.append(host,detail);row.append(copy,remove);list.append(row);
  }
}
$('#manageExclusions').addEventListener('click',async()=>{
  $('#exclusionsError').textContent='';$('#exclusionsDialog').showModal();
  try {await loadExclusions();} catch {$('#exclusionsError').textContent='Could not load excluded websites.';}
});
$('#closeExclusions').addEventListener('click',()=>$('#exclusionsDialog').close());
$('#fullResetButton').addEventListener('click',()=>{$('#fullResetError').textContent='';$('#fullResetDialog').showModal();});
$('#cancelFullReset').addEventListener('click',()=>$('#fullResetDialog').close());
$('#confirmFullReset').addEventListener('click',async()=>{
  const button=$('#confirmFullReset');button.disabled=true;$('#cancelFullReset').disabled=true;
  try {
    await send({type:'data:reset'});
    localStorage.clear();
    $('#fullResetDialog').close();
    API.runtime.reload();
  }catch {$('#fullResetError').textContent='Reset could not finish. Please try again.';button.disabled=false;$('#cancelFullReset').disabled=false;}
});

$('#brandHomeButton').addEventListener('click', () => setView('overview'));
$('#closeAdvancedSettings').addEventListener('click', () => $('#advancedSettingsDialog').close());

$('#statisticsPeriodSelect').addEventListener('change', event => {
  $(`.period[data-period="${event.target.value}"]`)?.click();
});
$('#headerMoreButton').addEventListener('click', () => $('#advancedSettingsDialog').showModal());
function renderLicenseNotices(container, text) {
  const lines = text.split('\n');
  // Put attribution detail after the mockup's introduction and filter table.
  const copyright = lines.findIndex(line => line.startsWith('iShield Extension is copyright'));
  if (copyright >= 0) lines.push(lines.splice(copyright, 1)[0]);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line === '# Third-party notices') continue;
    if (line.startsWith('|')) {
      const table = document.createElement('table');
      const head = document.createElement('thead'); const body = document.createElement('tbody');
      let header = true; let defaultColumn = -1;
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        const cells = lines[i].trim().split('|').slice(1, -1).map(value => value.trim());
        i++;
        if (cells.every(value => /^[-: ]+$/.test(value))) continue;
        if (header) defaultColumn = cells.indexOf('Default');
        if (defaultColumn >= 0) cells.splice(defaultColumn, 1);
        const row = document.createElement('tr');
        for (const value of cells) {
          const cell = document.createElement(header ? 'th' : 'td');
          if (header) cell.scope = 'col';
          if (/^https:\/\//.test(value)) {
            const link = document.createElement('a'); link.href = value; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = '↗ ' + new URL(value).hostname.replace(/^www\./, ''); cell.append(link);
          } else cell.textContent = value;
          row.append(cell);
        }
        (header ? head : body).append(row); header = false;
      }
      i--; table.append(head, body);
      const wrap = document.createElement('div'); wrap.className = 'license-table-scroll'; wrap.tabIndex = 0; wrap.setAttribute('aria-label', 'License attribution table'); wrap.append(table); container.append(wrap);
    } else if (line.startsWith('## ')) {
      const heading = document.createElement('h3'); heading.textContent = line.slice(3); container.append(heading);
    } else {
      const paragraph = document.createElement('p'); paragraph.textContent = line.replace(/`([^`]+)`/g, '$1'); container.append(paragraph);
    }
  }
}
$('#openLicense').addEventListener('click', async () => {
  $('#advancedSettingsDialog').close();
  $('#licenseDialog').showModal();
  const contents = $('#licenseContents');
  if (contents.dataset.loaded) return;
  contents.textContent = 'Loading licenses…';
  try {
    const response = await fetch(new URL('license-texts.json', import.meta.url));
    if (!response.ok) throw new Error('License file unavailable');
    const licenses = await response.json();
    contents.replaceChildren();
    for (const [index, license] of licenses.entries()) {
      const section = document.createElement('details');
      section.open = index === 0 || index === 2;
      const title = document.createElement('summary');
      const chevron = document.createElement('span'); chevron.className = 'license-chevron'; chevron.textContent = '›'; chevron.setAttribute('aria-hidden', 'true');
      const name = document.createElement('strong'); name.textContent = license.title;
      const badge = document.createElement('span'); badge.className = 'license-section-badge'; badge.textContent = index === 2 ? 'Includes filter lists' : 'Open source';
      title.append(chevron, name, badge);
      const body = document.createElement('div'); body.className = 'license-section-body'; body.tabIndex = 0; body.setAttribute('aria-label', license.title + ' text');
      if (index === 2) renderLicenseNotices(body, license.text);
      else { const text = document.createElement('pre'); text.textContent = index < 2 ? license.text.split(/\n\s*\n/).map(paragraph => paragraph.replace(/\n/g, ' ')).join('\n\n') : license.text; body.append(text); }
      section.append(title, body); contents.append(section);
    }
    contents.dataset.loaded = 'true';
  } catch { contents.textContent = 'Could not load licenses. Close and reopen to try again.'; }
});
$('#backFromLicense').addEventListener('click', () => { $('#licenseDialog').close(); $('#advancedSettingsDialog').showModal(); });
$('#closeLicense').addEventListener('click', () => $('#licenseDialog').close());

$('#closeStatisticsOptions').addEventListener('click', () => $('#statisticsOptionsDialog').close());

$('#closeActivityDetails').addEventListener('click', () => $('#activityDetailsDialog').close());
for (const button of document.querySelectorAll('[data-activity-metric]')) button.addEventListener('click', () => {
  const metric=button.dataset.activityMetric;
  const value=activityScope==='page'?(metric==='threats'?safeCount(syncedPageCounts?.phishing)+safeCount(syncedPageCounts?.malware):safeCount(syncedPageCounts?.[metric])):activityMetricCounts[metric];
  activityDetails(metric,value ?? 0,activityScope==='page'?'Current page · resets on reload':(PERIOD_LABELS[currentPeriod]??'All time')+' · all websites');
});

setView('overview');
void bootstrap().catch(() => {
  setBanner('off', 'Status unavailable', 'Reload the extension and try again');
  activityCoverage.textContent = 'Activity data is temporarily unavailable.';
});
