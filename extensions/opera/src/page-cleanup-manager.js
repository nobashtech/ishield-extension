'use strict';

// Page cleanup: the half of ad blocking that happens inside the page, next to the network rules.
//   * cosmetic filtering: hides the containers ads are drawn in (generic selectors, and selectors for specific sites);
//   * scriptlets: small scripts, run in the page or in the extension's isolated world, that neutralise ad and
//     anti-adblock code (they are the uBlock Origin scriptlets).
// The data and the content-script runtime come from uBlock Origin Lite (GPL-3.0); see scripts/import_page_cleanup.mjs.
// This module decides what to register (from the protection layers, the allowlist and the catalog), keeps the
// site-specific data in extension storage where the content scripts read it, and serves their "inject this CSS"
// requests. It only touches http(s) pages.

import {adguardRegistrations} from './adguard-content-manager.js';

export const PAGE_CLEANUP_PREFIX = 'ishield_pc_';
export const HTTP_MATCHES = Object.freeze(['http://*/*', 'https://*/*']);
export const SPECIFIC_DATA_MARKER = 'ishield.pagecleanup.data.v1';
const SPECIFIC_KEY = (id) => `css.specific.${id}`;
const MAX_CSS_BYTES = 2_000_000;
const RUNTIME = Object.freeze({
  api: ['content/cosmetic-activity.js', 'content/ubol/css-api.js', 'content/ubol/isolated-api.js'],
  generic: 'content/ubol/css-generic.js',
  specific: 'content/ubol/css-specific.js',
  procedural: 'content/ubol/css-procedural-api.js',
});

const matchFromHostname = (hostname) => `*://*.${hostname}/*`;
const unique = (values) => [...new Set(values)];

export function enabledRulesets(state, catalog) {
  if (!state || state.protectionEnabled === false) return [];
  return catalog.rulesets.filter((ruleset) => state.features?.[ruleset.layer] !== false);
}

export function desiredPageCleanup(state, catalog, excludeMatches = []) {
  const rulesets = enabledRulesets(state, catalog);
  const excluded = unique(excludeMatches);
  const registrations = [...adguardRegistrations(state, excluded)];
  const base = { allFrames: true, persistAcrossSessions: true };
  if (state && state.protectionEnabled !== false && state.features?.ads !== false) {
    registrations.push({
      id: `${PAGE_CLEANUP_PREFIX}facebook_ads`,
      matches: ['*://*.facebook.com/*'],
      runAt: 'document_idle', allFrames: false, persistAcrossSessions: true,
      js: ['content/facebook-ads.js'],
      ...(excluded.length ? { excludeMatches: excluded } : {}),
    });
  }
  const withExcludes = (registration, extra = []) => {
    const all = unique([...excluded, ...extra]);
    return all.length ? { ...registration, excludeMatches: all } : registration;
  };

  const generic = rulesets.filter((ruleset) => ruleset.genericCount > 0);
  if (generic.length) {
    // Sites where a list switches generic hiding off.
    const unhide = unique(generic.flatMap((ruleset) => ruleset.unhide)).map(matchFromHostname);
    registrations.push(withExcludes({
      ...base, id: `${PAGE_CLEANUP_PREFIX}css_generic`, matches: [...HTTP_MATCHES], runAt: 'document_idle',
      js: [...RUNTIME.api, ...generic.map((ruleset) => `rules/scripting/generic/${ruleset.id}.js`), RUNTIME.generic],
    }, unhide));
  }

  const specific = rulesets.filter((ruleset) => ruleset.specificCount > 0);
  if (specific.length) {
    registrations.push(withExcludes({
      ...base, id: `${PAGE_CLEANUP_PREFIX}css_specific`, matches: [...HTTP_MATCHES], runAt: 'document_start',
      js: [...RUNTIME.api, ...specific.map((ruleset) => `rules/scripting/specific/${ruleset.id}.js`), RUNTIME.specific],
    }));
  }

  for (const ruleset of rulesets) {
    for (const [world, hostnames] of Object.entries(ruleset.scriptletWorlds)) {
      registrations.push(withExcludes({
        ...base, id: `${PAGE_CLEANUP_PREFIX}${ruleset.id}_${world.toLowerCase()}`, runAt: 'document_start', world, matchOriginAsFallback: true,
        matches: hostnames.includes('*') ? [...HTTP_MATCHES] : hostnames.map(matchFromHostname),
        js: [`rules/scripting/scriptlet/${world.toLowerCase()}/${ruleset.id}.js`],
      }));
    }
  }
  return { registrations, specificIds: specific.map((ruleset) => ruleset.id), rulesets };
}

// Reads a JSON file that ships inside the extension package. The fetch implementation is passed in, like the update
// clients do, and the address is always built from the extension's own base URL, never from page or network input.
export function packagedJsonLoader(getUrl, fetchImpl) {
  return async (relativePath) => {
    const response = await fetchImpl(getUrl(relativePath));
    if (!response.ok) throw new Error(`packaged file ${relativePath} unavailable`);
    return response.json();
  };
}

async function syncSpecificData({ storageArea, fetchJson, catalog, specificIds, allowlistHostnames }) {
  const marker = `${catalog.source.commit}:${specificIds.join(',')}`;
  const allIds = catalog.rulesets.filter((ruleset) => ruleset.specificCount > 0).map((ruleset) => ruleset.id);
  const stored = await storageArea.get([SPECIFIC_DATA_MARKER, ...allIds.map(SPECIFIC_KEY)]);
  const complete = stored[SPECIFIC_DATA_MARKER] === marker && specificIds.every((id) => typeof stored[SPECIFIC_KEY(id)] === 'object' && stored[SPECIFIC_KEY(id)] !== null);
  if (!complete) {
    const entries = {};
    for (const id of specificIds) entries[SPECIFIC_KEY(id)] = await fetchJson(`rules/scripting/specific/${id}.json`);
    await storageArea.remove(allIds.filter((id) => !specificIds.includes(id)).map(SPECIFIC_KEY));
    await storageArea.set({ ...entries, [SPECIFIC_DATA_MARKER]: marker });
  }
  // The site-specific runtime skips the sites in `none`, the sites the user has allowed.
  await storageArea.set({ filteringModeDetails: { none: [...allowlistHostnames], basic: [], optimal: [], complete: ['all-urls'] } });
}

export async function reconcilePageCleanup({ scriptingApi, storageArea, fetchJson, state, catalog, excludeMatches = [], allowlistHostnames = [] }) {
  if (!scriptingApi?.getRegisteredContentScripts || !scriptingApi?.registerContentScripts || !scriptingApi?.updateContentScripts || !scriptingApi?.unregisterContentScripts) throw new TypeError('scripting API unavailable');
  const desired = desiredPageCleanup(state, catalog, excludeMatches);
  const existing = (await scriptingApi.getRegisteredContentScripts()).filter((item) => typeof item?.id === 'string' && item.id.startsWith(PAGE_CLEANUP_PREFIX));
  const present = new Set(existing.map((item) => item.id));
  const wanted = new Set(desired.registrations.map((item) => item.id));
  const stale = [...present].filter((id) => !wanted.has(id));
  if (stale.length) await scriptingApi.unregisterContentScripts({ ids: stale });
  if (desired.specificIds.length) await syncSpecificData({ storageArea, fetchJson, catalog, specificIds: desired.specificIds, allowlistHostnames });
  const update = desired.registrations.filter((item) => present.has(item.id));
  const create = desired.registrations.filter((item) => !present.has(item.id));
  if (update.length) await scriptingApi.updateContentScripts(update.map(item => ({...item, excludeMatches: item.excludeMatches ?? []})));
  if (create.length) await scriptingApi.registerContentScripts(create);
  return { active: desired.registrations.length > 0, registrationCount: desired.registrations.length, rulesetCount: desired.rulesets.length };
}

// Requests from the page-cleanup content scripts. Returns null for any other message so the caller can carry on.
export function isPageCleanupMessage(message) {
  return message !== null && typeof message === 'object' && (message.what === 'insertCSS' || message.what === 'removeCSS' || message.what === 'injectCSSProceduralAPI');
}

export async function handlePageCleanupMessage(message, sender, scriptingApi) {
  const tabId = sender?.tab?.id;
  const frameId = sender?.frameId;
  if (!Number.isInteger(tabId) || tabId < 0 || !Number.isInteger(frameId) || frameId < 0) throw new TypeError('page cleanup requests come from page content scripts');
  if (typeof sender.url !== 'string' || !/^https?:\/\//u.test(sender.url)) throw new TypeError('page cleanup only serves http(s) pages');
  const target = { tabId, frameIds: [frameId] };
  if (message.what === 'injectCSSProceduralAPI') return scriptingApi.executeScript({ files: [RUNTIME.procedural], target, injectImmediately: true });
  if (typeof message.css !== 'string' || message.css.length === 0 || message.css.length > MAX_CSS_BYTES) throw new RangeError('css payload out of bounds');
  const details = { css: message.css, origin: 'USER', target };
  return message.what === 'insertCSS' ? scriptingApi.insertCSS(details) : scriptingApi.removeCSS(details);
}
