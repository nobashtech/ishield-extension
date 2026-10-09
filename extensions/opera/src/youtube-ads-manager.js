'use strict';

// Registers the YouTube ad defence: a script in the page's own world (so it can reach the player data before YouTube's
// code does) and a stylesheet. Both are on while protection and the Ads layer are on, and off on allowed sites.
export const YOUTUBE_SCRIPT_ID = 'ishield_youtube_ads_v1';
export const YOUTUBE_STYLE_ID = 'ishield_youtube_ads_css_v1';
export const YOUTUBE_MATCHES = Object.freeze(['*://*.youtube.com/*', '*://*.youtube-nocookie.com/*']);

export function desiredYoutubeRegistrations(state, excludeMatches = []) {
  if (!state || state.protectionEnabled === false || state.features?.ads === false) return [];
  const base = { matches: [...YOUTUBE_MATCHES], runAt: 'document_start', allFrames: true, persistAcrossSessions: true };
  const excluded = [...new Set(excludeMatches)];
  if (excluded.length) base.excludeMatches = excluded;
  return [
    { ...base, id: YOUTUBE_SCRIPT_ID, js: ['content/youtube-ads-main.js'], world: 'MAIN' },
    { ...base, id: YOUTUBE_STYLE_ID, css: ['content/youtube-ads.css'] },
  ];
}

export async function reconcileYoutubeAds(scriptingApi, state, excludeMatches = []) {
  if (!scriptingApi?.getRegisteredContentScripts || !scriptingApi?.registerContentScripts || !scriptingApi?.updateContentScripts || !scriptingApi?.unregisterContentScripts) {
    throw new TypeError('scripting API unavailable');
  }
  const ids = [YOUTUBE_SCRIPT_ID, YOUTUBE_STYLE_ID];
  const existing = await scriptingApi.getRegisteredContentScripts({ ids });
  const present = new Set((Array.isArray(existing) ? existing : []).map((item) => item?.id));
  const desired = desiredYoutubeRegistrations(state, excludeMatches);
  const wanted = new Set(desired.map((item) => item.id));
  const stale = ids.filter((id) => present.has(id) && !wanted.has(id));
  if (stale.length) await scriptingApi.unregisterContentScripts({ ids: stale });
  const update = desired.filter((item) => present.has(item.id));
  const create = desired.filter((item) => !present.has(item.id));
  if (update.length) await scriptingApi.updateContentScripts(update.map(item => ({...item, excludeMatches: item.excludeMatches ?? []})));
  if (create.length) await scriptingApi.registerContentScripts(create);
  return { active: desired.length > 0, excludeMatchCount: desired[0]?.excludeMatches?.length ?? 0 };
}
