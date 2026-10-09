'use strict';
// The badge uses the same classified page snapshot as Home and This Site.
// Browser-native action counts also include non-blocking matches, so do not mix them.
import {pageSnapshot} from './page-activity.js';
export const BADGE_LOCAL_KEY = 'ishield.badge.local.v1';
export function createBadgeCounter(api, pageStore, readState) {
  let tail = Promise.resolve();
  const publish = tabId => {
    const task = tail.catch(() => undefined).then(async () => {
      const state = await readState();
      let paused = state.protectionEnabled === false;
      if (!paused && typeof api.tabs?.get === 'function') {
        const tab = await api.tabs.get(tabId);
        try {
          const url = new URL(tab.url ?? tab.pendingUrl ?? '');
          const host = url.hostname.toLowerCase().replace(/\.$/u, '');
          paused = ['http:', 'https:'].includes(url.protocol) && (state.allowlist ?? []).some(site => host === site || host.endsWith(`.${site}`));
        } catch { /* Browser-internal pages are not site exceptions. */ }
      }
      if (paused) {
        await api.action.setBadgeBackgroundColor({tabId, color:'#b45309'});
        await api.action.setBadgeText({tabId, text:'OFF'});
        return;
      }
      await api.action.setBadgeBackgroundColor({tabId, color:'#6d28d9'});
      const page = await pageStore.snapshot(tabId);
      const snapshot = pageSnapshot(page);
      const total = snapshot.pageBlocked;
      const text = total > 0 ? `${total}${snapshot.available ? '' : '+'}` : '';
      await api.action.setBadgeText({tabId, text});
    });
    tail = task;
    return task;
  };
  const remove = tabId => api.action.setBadgeText({tabId, text:''}).catch(() => undefined);
  return {publish, remove};
}
