'use strict';

export const CATEGORY_SCHEMA_VERSION = 1;
export const MAX_CATEGORY_RECORDS = 100000;
export const MAX_CATEGORIES_PER_RECORD = 8;
export const MAX_CATEGORY_DOMAINS_PER_QUERY = 20000;
export const CATEGORY_NAMES = Object.freeze([
  'adult', 'gambling', 'dating', 'social-media', 'streaming', 'games', 'drugs',
  'malware', 'scam', 'phishing', 'crypto-scam', 'proxy-vpn', 'file-sharing',
  'newly-observed-suspicious',
]);
const CATEGORY_SET = new Set(CATEGORY_NAMES);
const SCOPES = new Set(['exact', 'host-and-subdomains']);

function integer(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`invalid ${name}`);
}

function normalizeHost(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 253) throw new TypeError('invalid category host');
  let parsed;
  try { parsed = new URL(`https://${value}/`); } catch { throw new TypeError('invalid category host'); }
  const host = parsed.hostname.toLowerCase().replace(/\.$/u, '');
  const labels = host.split('.');
  if (!host || host.includes(':') || labels.length < 2 || /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host) || labels.some((label) => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) throw new TypeError('category host must be a DNS hostname');
  return host;
}

function normalizeCategory(value) {
  if (typeof value !== 'string') throw new TypeError('invalid category');
  const category = value.trim().toLowerCase();
  if (!CATEGORY_SET.has(category)) throw new TypeError('unsupported category');
  return category;
}

export function emptyCategoryDataset(nowMs = 0) {
  return Object.freeze({
    metadata: Object.freeze({
      schemaVersion: CATEGORY_SCHEMA_VERSION,
      datasetVersion: 1,
      generatedAtMs: nowMs,
      expiresAtMs: Number.MAX_SAFE_INTEGER,
      declaredRecordCount: 0,
    }),
    records: Object.freeze([]),
  });
}

export function normalizeCategoryDataset(dataset) {
  if (!dataset || typeof dataset !== 'object' || Array.isArray(dataset)) throw new TypeError('invalid category dataset');
  const metadata = dataset.metadata;
  if (!metadata || typeof metadata !== 'object') throw new TypeError('missing category metadata');
  if (metadata.schemaVersion !== CATEGORY_SCHEMA_VERSION) throw new TypeError('unsupported category schema');
  integer(metadata.datasetVersion, 1, Number.MAX_SAFE_INTEGER, 'category datasetVersion');
  integer(metadata.generatedAtMs, 0, Number.MAX_SAFE_INTEGER, 'category generatedAtMs');
  integer(metadata.expiresAtMs, 1, Number.MAX_SAFE_INTEGER, 'category expiresAtMs');
  if (metadata.expiresAtMs <= metadata.generatedAtMs) throw new TypeError('invalid category dataset expiry');
  if (!Array.isArray(dataset.records) || dataset.records.length > MAX_CATEGORY_RECORDS) throw new RangeError('category record cap exceeded');
  if (metadata.declaredRecordCount !== dataset.records.length) throw new TypeError('declared category count mismatch');

  const identities = new Set();
  const records = [];
  for (const raw of dataset.records) {
    const host = normalizeHost(raw?.host);
    if (!SCOPES.has(raw?.scope)) throw new TypeError('invalid category scope');
    integer(raw?.confidence, 1, 100, 'category confidence');
    integer(raw?.observedAtMs, 0, Number.MAX_SAFE_INTEGER, 'category observedAtMs');
    integer(raw?.expiresAtMs, 1, Number.MAX_SAFE_INTEGER, 'category expiresAtMs');
    if (raw.expiresAtMs <= raw.observedAtMs) throw new TypeError('invalid category record expiry');
    if (!Array.isArray(raw.categories) || raw.categories.length < 1 || raw.categories.length > MAX_CATEGORIES_PER_RECORD) throw new TypeError('invalid category list');
    const categories = [...new Set(raw.categories.map(normalizeCategory))].sort();
    const identity = `${host}\0${raw.scope}`;
    if (identities.has(identity)) throw new TypeError('duplicate category host/scope record');
    identities.add(identity);
    records.push(Object.freeze({ host, scope: raw.scope, confidence: raw.confidence, observedAtMs: raw.observedAtMs, expiresAtMs: raw.expiresAtMs, categories: Object.freeze(categories) }));
  }
  records.sort((a, b) => a.host.localeCompare(b.host) || a.scope.localeCompare(b.scope));
  return Object.freeze({
    metadata: Object.freeze({
      schemaVersion: CATEGORY_SCHEMA_VERSION,
      datasetVersion: metadata.datasetVersion,
      generatedAtMs: metadata.generatedAtMs,
      expiresAtMs: metadata.expiresAtMs,
      declaredRecordCount: records.length,
    }),
    records: Object.freeze(records),
  });
}

export function applyCategoryDelta(baseDataset, delta) {
  const base = normalizeCategoryDataset(baseDataset);
  if (!delta || typeof delta !== 'object' || Array.isArray(delta)) throw new TypeError('invalid category delta');
  integer(delta.baseVersion, 1, Number.MAX_SAFE_INTEGER, 'category delta baseVersion');
  integer(delta.datasetVersion, 1, Number.MAX_SAFE_INTEGER, 'category delta datasetVersion');
  if (delta.baseVersion !== base.metadata.datasetVersion) throw new Error('category delta base version mismatch');
  if (delta.datasetVersion <= delta.baseVersion) throw new Error('category delta version must advance');
  integer(delta.generatedAtMs, 0, Number.MAX_SAFE_INTEGER, 'category delta generatedAtMs');
  integer(delta.expiresAtMs, 1, Number.MAX_SAFE_INTEGER, 'category delta expiresAtMs');
  if (delta.expiresAtMs <= delta.generatedAtMs) throw new TypeError('invalid category delta expiry');
  const upserts = Array.isArray(delta.upserts) ? delta.upserts : [];
  const removes = Array.isArray(delta.removes) ? delta.removes : [];
  if (upserts.length + removes.length > MAX_CATEGORY_RECORDS) throw new RangeError('category delta operation cap exceeded');

  const map = new Map(base.records.map((record) => [`${record.host}\0${record.scope}`, record]));
  for (const removal of removes) {
    const host = normalizeHost(removal?.host);
    if (!SCOPES.has(removal?.scope)) throw new TypeError('invalid category removal scope');
    map.delete(`${host}\0${removal.scope}`);
  }
  for (const raw of upserts) {
    const candidate = normalizeCategoryDataset({
      metadata: { schemaVersion: CATEGORY_SCHEMA_VERSION, datasetVersion: delta.datasetVersion, generatedAtMs: delta.generatedAtMs, expiresAtMs: delta.expiresAtMs, declaredRecordCount: 1 },
      records: [raw],
    }).records[0];
    map.set(`${candidate.host}\0${candidate.scope}`, candidate);
  }
  const records = [...map.values()];
  return normalizeCategoryDataset({
    metadata: { schemaVersion: CATEGORY_SCHEMA_VERSION, datasetVersion: delta.datasetVersion, generatedAtMs: delta.generatedAtMs, expiresAtMs: delta.expiresAtMs, declaredRecordCount: records.length },
    records,
  });
}

export class CategoryIndex {
  #dataset;
  #recordsByHost;
  #recordsByCategory;

  constructor(dataset) {
    this.#dataset = normalizeCategoryDataset(dataset);
    const map = new Map();
    const categoryMap = new Map();
    for (const record of this.#dataset.records) {
      const bucket = map.get(record.host) ?? [];
      bucket.push(record);
      map.set(record.host, bucket);
      for (const category of record.categories) {
        const categoryBucket = categoryMap.get(category) ?? [];
        categoryBucket.push(record);
        categoryMap.set(category, categoryBucket);
      }
    }
    this.#recordsByHost = map;
    this.#recordsByCategory = categoryMap;
  }

  dataset() { return this.#dataset; }
  status(nowMs) { integer(nowMs, 0, Number.MAX_SAFE_INTEGER, 'nowMs'); return nowMs > this.#dataset.metadata.expiresAtMs ? 'stale' : 'current'; }
  stats() { return Object.freeze({ datasetVersion: this.#dataset.metadata.datasetVersion, recordCount: this.#dataset.records.length }); }

  lookup(hostValue, nowMs, minConfidence = 1) {
    integer(nowMs, 0, Number.MAX_SAFE_INTEGER, 'nowMs');
    integer(minConfidence, 1, 100, 'minConfidence');
    const status = this.status(nowMs);
    if (status === 'stale') return Object.freeze({ datasetStatus: status, categories: Object.freeze([]), matches: Object.freeze([]) });
    const host = normalizeHost(hostValue);
    const matches = [];
    const consider = (candidateHost, relation) => {
      for (const record of this.#recordsByHost.get(candidateHost) ?? []) {
        if (record.confidence < minConfidence || record.expiresAtMs <= nowMs) continue;
        if (relation === 'parent-domain' && record.scope !== 'host-and-subdomains') continue;
        matches.push(Object.freeze({ host: candidateHost, relation, scope: record.scope, confidence: record.confidence, categories: record.categories }));
      }
    };
    consider(host, 'exact');
    for (let index = host.indexOf('.'); index >= 0; index = host.indexOf('.', index + 1)) consider(host.slice(index + 1), 'parent-domain');
    const categorySet = new Set();
    for (const match of matches) for (const category of match.categories) categorySet.add(category);
    return Object.freeze({ datasetStatus: status, categories: Object.freeze([...categorySet].sort()), matches: Object.freeze(matches) });
  }

  domainsForCategory(categoryValue, nowMs, minConfidence = 80, cap = MAX_CATEGORY_DOMAINS_PER_QUERY) {
    const category = normalizeCategory(categoryValue);
    integer(nowMs, 0, Number.MAX_SAFE_INTEGER, 'nowMs');
    integer(minConfidence, 1, 100, 'minConfidence');
    integer(cap, 1, MAX_CATEGORY_DOMAINS_PER_QUERY, 'category domain cap');
    if (this.status(nowMs) === 'stale') return Object.freeze([]);
    const out = [];
    // Phase 31: query the precomputed category bucket instead of rescanning the
    // complete (up to 100k-record) dataset for every Strict/Family category.
    for (const record of this.#recordsByCategory.get(category) ?? []) {
      if (record.confidence < minConfidence || record.expiresAtMs <= nowMs) continue;
      out.push(Object.freeze({ host: record.host, scope: record.scope, confidence: record.confidence }));
      if (out.length >= cap) break;
    }
    return Object.freeze(out);
  }
}
