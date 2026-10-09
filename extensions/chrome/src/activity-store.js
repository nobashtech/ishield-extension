// iShield clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
// This documentation-only header does not change runtime behavior.

'use strict';
import {activityPage} from './activity-query.js';

export const ACTIVITY_KEY = 'ishield.activity.v1';
export const ACTIVITY_SCHEMA_VERSION = 1;
export const ACTIVITY_EVENT_CAP = 256;
export const DAILY_BUCKET_CAP = 31;
export const SEEN_MATCH_CAP = 1024;
export const EVENT_COUNT_CAP = 64;
export const DEFAULT_RETENTION_DAYS = 7;
export const RETENTION_OPTIONS = Object.freeze([1, 7, 30]);
export const DNR_LOOKBACK_MS = 5 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

// Days are counted in the user's local time so "Today" starts at local midnight
// (a UTC day boundary would reset the counters mid-morning in UTC+ zones).
export function localDayIndex(timestamp) {
  const ts = Math.max(0, timestamp);
  return Math.floor((ts - new Date(ts).getTimezoneOffset() * 60_000) / DAY_MS);
}

export const CATEGORIES = Object.freeze([
  'ads', 'trackers', 'scams', 'phishing', 'malware', 'privacy', 'strictPolicy',
]);
export const SOURCES = Object.freeze([
  'network-filter', 'cosmetic-collapse', 'privacy-engine', 'threat-engine', 'strict-policy',
]);
const CATEGORY_SET = new Set(CATEGORIES);
const SOURCE_SET = new Set(SOURCES);

function emptyCounts() {
  return { ads: 0, trackers: 0, scams: 0, phishing: 0, malware: 0, privacy: 0, strictPolicy: 0 };
}

function boundedInteger(value, min, max, fallback = 0) {
  return Number.isSafeInteger(value) && value >= min && value <= max ? value : fallback;
}

function saturatingAdd(left, right) {
  const a = boundedInteger(left, 0, MAX_SAFE, 0);
  const b = boundedInteger(right, 0, MAX_SAFE, 0);
  return Math.min(MAX_SAFE, a + b);
}

function normalizeCounts(candidate) {
  const out = emptyCounts();
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return out;
  for (const category of CATEGORIES) out[category] = boundedInteger(candidate[category], 0, MAX_SAFE, 0);
  return out;
}

function normalizeEvent(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
  if (!CATEGORY_SET.has(candidate.category) || !SOURCE_SET.has(candidate.source)) return null;
  const timestamp = boundedInteger(candidate.timestamp, 0, MAX_SAFE, -1);
  const count = boundedInteger(candidate.count, 1, EVENT_COUNT_CAP, 0);
  if (timestamp < 0 || count === 0) return null;
  return Object.freeze({ timestamp, category: candidate.category, source: candidate.source, count });
}

function normalizeDay(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
  const day = boundedInteger(candidate.day, 0, MAX_SAFE, -1);
  if (day < 0) return null;
  return { day, counts: normalizeCounts(candidate.counts) };
}

function normalizeSeen(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
  if (typeof candidate.key !== 'string' || !/^[0-9a-f]{8}$/u.test(candidate.key)) return null;
  const multiplicity = boundedInteger(candidate.multiplicity, 1, EVENT_COUNT_CAP, 0);
  const seenAt = boundedInteger(candidate.seenAt, 0, MAX_SAFE, -1);
  if (!multiplicity || seenAt < 0) return null;
  return { key: candidate.key, multiplicity, seenAt };
}

function retentionValue(value) {
  return RETENTION_OPTIONS.includes(value) ? value : DEFAULT_RETENTION_DAYS;
}

export function defaultActivityState() {
  return {
    schemaVersion: ACTIVITY_SCHEMA_VERSION,
    retentionDays: DEFAULT_RETENTION_DAYS,
    allTime: emptyCounts(),
    days: [],
    events: [],
    seenMatches: [],
  };
}

export function normalizeActivityState(candidate, now = Date.now()) {
  const fallback = defaultActivityState();
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return fallback;
  const currentDay = localDayIndex(now);
  const firstDay = Math.max(0, currentDay - (DAILY_BUCKET_CAP - 1));
  const retentionDays = retentionValue(candidate.retentionDays);
  const historyFloor = Math.max(0, now - retentionDays * DAY_MS);
  const seenFloor = Math.max(0, now - DNR_LOOKBACK_MS * 3);

  const daysByNumber = new Map();
  for (const raw of Array.isArray(candidate.days) ? candidate.days.slice(-DAILY_BUCKET_CAP * 2) : []) {
    const item = normalizeDay(raw);
    if (!item || item.day < firstDay || item.day > currentDay) continue;
    daysByNumber.set(item.day, item);
  }
  const days = [...daysByNumber.values()].sort((a, b) => a.day - b.day).slice(-DAILY_BUCKET_CAP);

  const events = (Array.isArray(candidate.events) ? candidate.events : [])
    .map(normalizeEvent).filter(Boolean)
    .filter((event) => event.timestamp >= historyFloor && event.timestamp <= now + 60_000)
    .sort((a, b) => a.timestamp - b.timestamp)
    .slice(-ACTIVITY_EVENT_CAP);

  const seenMap = new Map();
  for (const raw of Array.isArray(candidate.seenMatches) ? candidate.seenMatches.slice(-SEEN_MATCH_CAP * 2) : []) {
    const item = normalizeSeen(raw);
    if (!item || item.seenAt < seenFloor || item.seenAt > now + 60_000) continue;
    seenMap.set(item.key, item);
  }

  return {
    schemaVersion: ACTIVITY_SCHEMA_VERSION,
    retentionDays,
    allTime: normalizeCounts(candidate.allTime),
    days,
    events,
    seenMatches: [...seenMap.values()].sort((a, b) => a.seenAt - b.seenAt).slice(-SEEN_MATCH_CAP),
  };
}

function addCount(counts, category, count) {
  counts[category] = saturatingAdd(counts[category], count);
}

function appendEventMutable(state, rawEvent, now) {
  const event = normalizeEvent(rawEvent);
  if (!event) throw new TypeError('invalid activity event');
  if (event.timestamp > now + 60_000) throw new RangeError('future activity event rejected');

  addCount(state.allTime, event.category, event.count);
  const day = localDayIndex(event.timestamp);
  let bucket = state.days.find((item) => item.day === day);
  if (!bucket) {
    bucket = { day, counts: emptyCounts() };
    state.days.push(bucket);
  }
  addCount(bucket.counts, event.category, event.count);
  state.events.push(event);
  return event;
}

function pruneMutable(state, now) {
  const normalized = normalizeActivityState(state, now);
  state.schemaVersion = normalized.schemaVersion;
  state.retentionDays = normalized.retentionDays;
  state.allTime = normalized.allTime;
  state.days = normalized.days;
  state.events = normalized.events;
  state.seenMatches = normalized.seenMatches;
  return state;
}

function fnv1a32(text) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

function matchedKey(info) {
  const ruleId = info?.rule?.ruleId;
  const rulesetId = info?.rule?.rulesetId;
  const tabId = info?.tabId;
  const timeStamp = Math.round(Number(info?.timeStamp));
  if (!Number.isInteger(ruleId) || typeof rulesetId !== 'string' || !Number.isInteger(tabId) || !Number.isSafeInteger(timeStamp) || timeStamp < 0) return null;
  return fnv1a32(`${tabId}|${rulesetId}|${ruleId}|${timeStamp}`);
}

function periodDays(period) {
  if (period === 'today') return 1;
  if (period === 'week') return 7;
  if (period === 'month') return 30;
  if (period === 'all') return null;
  throw new TypeError('unsupported statistics period');
}

export function summarizeActivity(candidate, period = 'today', now = Date.now()) {
  const state = normalizeActivityState(candidate, now);
  let counts = emptyCounts();
  const days = periodDays(period);
  if (days === null) {
    counts = { ...state.allTime };
  } else {
    const currentDay = localDayIndex(now);
    const firstDay = Math.max(0, currentDay - (days - 1));
    for (const bucket of state.days) {
      if (bucket.day < firstDay || bucket.day > currentDay) continue;
      for (const category of CATEGORIES) addCount(counts, category, bucket.counts[category]);
    }
  }
  return Object.freeze({
    period,
    counts: Object.freeze(counts),
    threatsPrevented: Math.min(MAX_SAFE, counts.scams + counts.phishing + counts.malware),
    estimatedBandwidthSaved: null,
  });
}

// One entry per local day in the period (zeros included so charts stay aligned). Only week and
// month have a per-day breakdown; "today" is a single bucket and "all" spans more than the
// retained daily buckets.
export function activitySeries(candidate, period = 'week', now = Date.now()) {
  const days = periodDays(period);
  if (days === null || days < 2) return Object.freeze([]);
  const state = normalizeActivityState(candidate, now);
  const currentDay = localDayIndex(now);
  const byDay = new Map(state.days.map((bucket) => [bucket.day, bucket.counts]));
  const series = [];
  for (let day = currentDay - (days - 1); day <= currentDay; day += 1) {
    const counts = byDay.get(day) ?? emptyCounts();
    series.push(Object.freeze({
      day,
      ads: counts.ads,
      trackers: counts.trackers,
      scams: counts.scams,
      securityThreats: Math.min(MAX_SAFE, counts.phishing + counts.malware),
      threats: Math.min(MAX_SAFE, counts.scams + counts.phishing + counts.malware),
      total: CATEGORIES.reduce((sum, category) => saturatingAdd(sum, counts[category]), 0),
    }));
  }
  return Object.freeze(series);
}

// Presentation-only breakdown of retained events, independent of pagination.
// Daily totals may exceed retained history; the dashboard labels this explicitly.
export function activityHourlySeries(candidate, now = Date.now()) {
  const state = normalizeActivityState(candidate, now);
  const today = localDayIndex(now);
  const buckets = Array.from({length: 24}, (_, hour) => ({hour, ads:0, trackers:0, scams:0, securityThreats:0, total:0}));
  for (const event of state.events) {
    if (localDayIndex(event.timestamp) !== today) continue;
    const bucket = buckets[new Date(event.timestamp).getHours()];
    const metric = ['ads','trackers','scams'].includes(event.category) ? event.category : ['phishing','malware'].includes(event.category) ? 'securityThreats' : null;
    if (metric) bucket[metric] = saturatingAdd(bucket[metric], event.count);
    bucket.total = saturatingAdd(bucket.total, event.count);
  }
  return buckets.map(bucket => Object.freeze(bucket));
}

export class ActivityStore {
  constructor(storageArea) {
    if (!storageArea?.get || !storageArea?.set) throw new TypeError('storage API unavailable');
    this.storageArea = storageArea;
    this.queue = Promise.resolve();
  }

  exclusive(operation) {
    const run = this.queue.then(operation, operation);
    this.queue = run.catch(() => undefined);
    return run;
  }

  async load(now = Date.now()) {
    const stored = await this.storageArea.get(ACTIVITY_KEY);
    return normalizeActivityState(stored?.[ACTIVITY_KEY], now);
  }

  async persist(state, now = Date.now()) {
    const normalized = normalizeActivityState(state, now);
    await this.storageArea.set({ [ACTIVITY_KEY]: normalized });
    return normalized;
  }

  record(rawEvent, now = Date.now()) {
    return this.exclusive(async () => {
      const state = await this.load(now);
      appendEventMutable(state, { ...rawEvent, timestamp: now }, now);
      return this.persist(pruneMutable(state, now), now);
    });
  }

  ingestMatchedRules(matches, classifyRule, now = Date.now()) {
    return this.exclusive(async () => {
      const state = await this.load(now);
      const previous = new Map(state.seenMatches.map((entry) => [entry.key, entry]));
      const currentMultiplicity = new Map();
      const accepted = [];
      const list = Array.isArray(matches) ? matches.slice(0, SEEN_MATCH_CAP) : [];
      list.sort((left, right) => Number(left?.timeStamp ?? 0) - Number(right?.timeStamp ?? 0));

      for (const info of list) {
        const category = classifyRule(info);
        const key = matchedKey(info);
        const timestamp = boundedInteger(Math.round(Number(info?.timeStamp)), 0, MAX_SAFE, -1);
        if (!CATEGORY_SET.has(category) || !key || timestamp < now - DNR_LOOKBACK_MS || timestamp > now + 60_000) continue;
        const multiplicity = (currentMultiplicity.get(key) ?? 0) + 1;
        currentMultiplicity.set(key, multiplicity);
        const priorMultiplicity = previous.get(key)?.multiplicity ?? 0;
        if (multiplicity <= priorMultiplicity) continue;
        appendEventMutable(state, { timestamp, category, source: 'network-filter', count: 1 }, now);
        accepted.push({ category, timestamp });
      }

      for (const [key, multiplicity] of currentMultiplicity.entries()) {
        previous.set(key, { key, multiplicity: Math.min(EVENT_COUNT_CAP, multiplicity), seenAt: now });
      }
      state.seenMatches = [...previous.values()].sort((a, b) => a.seenAt - b.seenAt).slice(-SEEN_MATCH_CAP);
      const persisted = await this.persist(pruneMutable(state, now), now);
      return { state: persisted, acceptedCount: accepted.length };
    });
  }

  snapshot(period = 'today', limit = 24, now = Date.now(), query = null) {
    return this.exclusive(async () => {
      const state = await this.load(now);
      const eventLimit = boundedInteger(limit, 1, 64, 24);
      let page = null;
      if (query) {
        const days = periodDays(period);
        const first = days === null ? 0 : localDayIndex(now) - (days - 1);
        page = activityPage(state.events.filter(event => localDayIndex(event.timestamp) >= first).slice().reverse(), {...query, size: eventLimit});
      }
      return {
        ...(page ? {pagination: page.pagination} : {}),
        summary: summarizeActivity(state, period, now),
        series: activitySeries(state, period, now),
        hourlySeries: period === 'today' ? activityHourlySeries(state, now) : [],
        recent: page ? page.items : state.events.slice(-eventLimit).reverse(),
        retentionDays: state.retentionDays,
        privacy: Object.freeze({ storesUrls: false, storesDomains: false, storesPageContent: false }),
      };
    });
  }

  setRetention(days, now = Date.now()) {
    if (!RETENTION_OPTIONS.includes(days)) return Promise.reject(new TypeError('unsupported retention'));
    return this.exclusive(async () => {
      const state = await this.load(now);
      state.retentionDays = days;
      return this.persist(pruneMutable(state, now), now);
    });
  }

  clearHistory(now = Date.now()) {
    return this.exclusive(async () => {
      const state = await this.load(now);
      state.events = [];
      // Keep de-duplication keys: clearing history must not re-import network matches.
      return this.persist(state, now);
    });
  }
}
