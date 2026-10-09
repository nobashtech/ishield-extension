'use strict';

// Ephemeral current-document counters, keyed only by tab id. No URL, hostname,
// history or network payload is retained. Network counts are read on popup open.
export const PAGE_ACTIVITY_KEY = 'ishield.page.activity.v1';
export const PAGE_CATEGORIES = Object.freeze(['ads', 'trackers', 'scams', 'phishing', 'malware', 'privacy', 'strictPolicy']);
const zero = () => Object.fromEntries(PAGE_CATEGORIES.map((key) => [key, 0]));
const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const normalize = (value) => ({ startedAt: count(value?.startedAt), available: value?.available === true, network: Object.fromEntries(PAGE_CATEGORIES.map((key) => [key, count(value?.network?.[key])])), counts: Object.fromEntries(PAGE_CATEGORIES.map((key) => [key, count(value?.counts?.[key])])) });
const validTab = (id) => Number.isInteger(id) && id >= 0;

export function pageNetworkCounts(matches, classifyRule, startedAt = 0, tabId = null) {
  const counts = zero();
  for (const info of Array.isArray(matches) ? matches : []) {
    if (tabId !== null && info.tabId !== tabId) continue;
    if (!Number.isFinite(info.timeStamp) || info.timeStamp < startedAt) continue;
    const category = classifyRule(info);
    if (Object.hasOwn(counts, category)) counts[category] += 1;
  }
  return counts;
}

export class PageActivityStore {
  constructor(storageArea) { this.storageArea = storageArea; this.memory = {}; this.tail = Promise.resolve(); this.networkSeen = new Map(); this.networkSyncedAt = new Map(); }
  run(operation, write = true) {
    const result = this.tail.then(async () => {
      const stored = this.storageArea ? (await this.storageArea.get(PAGE_ACTIVITY_KEY))[PAGE_ACTIVITY_KEY] : this.memory;
      const pages = stored && typeof stored === 'object' && !Array.isArray(stored) ? { ...stored } : {};
      const result = await operation(pages);
      this.memory = pages;
      if (write && this.storageArea) await this.storageArea.set({ [PAGE_ACTIVITY_KEY]: pages });
      return result;
    });
    this.tail = result.catch(() => undefined);
    return result;
  }
  reset(tabId, now = Date.now()) {
    this.networkSeen.delete(tabId); this.networkSyncedAt.delete(tabId);
    if (!validTab(tabId)) return Promise.resolve();
    return this.run((pages) => { pages[tabId] = { startedAt: count(now), counts: zero() }; });
  }
  remove(tabId) { this.networkSeen.delete(tabId); this.networkSyncedAt.delete(tabId); return this.run((pages) => { delete pages[tabId]; }); }
  record(tabId, category, amount) {
    if (!validTab(tabId) || !PAGE_CATEGORIES.includes(category) || !Number.isSafeInteger(amount) || amount < 1 || amount > 64) return Promise.reject(new TypeError('invalid page activity'));
    return this.run((pages) => {
      const page = normalize(pages[tabId]);
      page.counts[category] = Math.min(Number.MAX_SAFE_INTEGER, page.counts[category] + amount);
      pages[tabId] = page;
      // Bound abandoned session records; tabs.onRemoved normally deletes these.
      const keys = Object.keys(pages);
      if (keys.length > 512) for (const key of keys.slice(0, keys.length - 512)) if (key !== String(tabId)) delete pages[key];
      return page;
    });
  }
  recordNetworkMatch(tabId, category, key, startedAt, observedAt = Date.now()) {
    if (!validTab(tabId) || !PAGE_CATEGORIES.includes(category) || typeof key !== 'string') return Promise.reject(new TypeError('invalid network match'));
    return this.run(pages => {
      const page = normalize(pages[tabId]);
      if (page.startedAt !== startedAt) return page;
      let seen = this.networkSeen.get(tabId);
      if (!seen || seen.startedAt !== startedAt) { seen = {startedAt, keys:new Set()}; this.networkSeen.set(tabId, seen); }
      if (seen.keys.has(key)) return page;
      seen.keys.add(key);
      const synced = this.networkSyncedAt.get(tabId);
      if (synced?.startedAt === startedAt && observedAt <= synced.time) return page;
      if (seen.keys.size > 5000) seen.keys.delete(seen.keys.values().next().value);
      page.network[category] = Math.min(Number.MAX_SAFE_INTEGER, page.network[category] + 1);
      pages[tabId] = page; return page;
    });
  }
  network(tabId, counts, startedAt, available = true) {
    return this.run((pages) => {
      const page = normalize(pages[tabId]);
      if (page.startedAt !== startedAt) return page;
      page.network = Object.fromEntries(PAGE_CATEGORIES.map((key) => [key, Math.max(page.network[key], count(counts?.[key]))]));
      page.available = available;
      this.networkSyncedAt.set(tabId, {startedAt, time:Date.now()});
      pages[tabId] = page;
      return page;
    });
  }
  snapshot(tabId) {
    if (!validTab(tabId)) return Promise.reject(new TypeError('invalid tab id'));
    return this.run((pages) => normalize(pages[tabId]), false);
  }
}

export function pageSnapshot(page) {
  const normalized = normalize(page);
  const pageCounts = Object.fromEntries(PAGE_CATEGORIES.map((key) => [key, Math.min(Number.MAX_SAFE_INTEGER, normalized.counts[key] + normalized.network[key])]));
  return { available: normalized.available, pageCounts, pageBlocked: PAGE_CATEGORIES.reduce((total, key) => total + pageCounts[key], 0) };
}
