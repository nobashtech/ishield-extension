// iShield clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
// This documentation-only header does not change runtime behavior.

'use strict';

export const REPUTATION_SCHEMA_VERSION = 1;
export const MAX_BROWSER_REPUTATION_RECORDS = 10000;
export const MAX_BROWSER_REPUTATION_SOURCES = 512;
export const MAX_INDICATORS_PER_HOST = 8;
export const MAX_SUFFIX_LABELS = 32;
const CATEGORY_RANK = Object.freeze({
  suspicious: 1,
  malvertising: 2,
  scam: 3,
  phishing: 4,
  malware: 5,
});
const CATEGORIES = new Set(Object.keys(CATEGORY_RANK));
const SCOPES = new Set(['exact', 'host-and-subdomains']);
const EVIDENCE = new Set(['verified-feed', 'analyst-review', 'first-party-report', 'verified-user-report', 'heuristic-correlation']);

function normalizeCompiledHost(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 253) throw new TypeError('invalid reputation host');
  const withoutRoot = value.endsWith('.') ? value.slice(0, -1) : value;
  if (!withoutRoot || withoutRoot.endsWith('.') || /[^a-zA-Z0-9.:-]/.test(withoutRoot)) throw new TypeError('reputation host must be precompiled ASCII/punycode');
  const normalized = withoutRoot.toLowerCase();
  if (normalized.split('.').some((label) => label.length === 0 || label.length > 63)) throw new TypeError('invalid reputation host labels');
  return normalized;
}

function validateInteger(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`invalid ${name}`);
}

function better(candidate, current) {
  if (!current) return true;
  if (candidate.confidence !== current.confidence) return candidate.confidence > current.confidence;
  if (CATEGORY_RANK[candidate.category] !== CATEGORY_RANK[current.category]) return CATEGORY_RANK[candidate.category] > CATEGORY_RANK[current.category];
  if (candidate.relation !== current.relation) return candidate.relation === 'exact';
  if (candidate.observedAtMs !== current.observedAtMs) return candidate.observedAtMs > current.observedAtMs;
  return candidate.sourceId < current.sourceId;
}

export class LocalReputationIndex {
  #metadata;
  #sources;
  #records;

  constructor(dataset) {
    if (!dataset || typeof dataset !== 'object') throw new TypeError('invalid reputation dataset');
    const { metadata, sources, records } = dataset;
    if (!metadata || typeof metadata !== 'object') throw new TypeError('missing reputation metadata');
    if (metadata.schemaVersion !== REPUTATION_SCHEMA_VERSION) throw new TypeError('unsupported reputation schema');
    validateInteger(metadata.datasetVersion, 1, Number.MAX_SAFE_INTEGER, 'datasetVersion');
    validateInteger(metadata.generatedAtMs, 0, Number.MAX_SAFE_INTEGER, 'generatedAtMs');
    validateInteger(metadata.expiresAtMs, 1, Number.MAX_SAFE_INTEGER, 'expiresAtMs');
    if (metadata.expiresAtMs <= metadata.generatedAtMs) throw new TypeError('invalid dataset expiry');
    if (!Array.isArray(sources) || sources.length > MAX_BROWSER_REPUTATION_SOURCES) throw new RangeError('source cap exceeded');
    if (!Array.isArray(records) || records.length > MAX_BROWSER_REPUTATION_RECORDS) throw new RangeError('record cap exceeded');
    if (metadata.declaredSourceCount !== sources.length || metadata.declaredRecordCount !== records.length) throw new TypeError('declared reputation counts mismatch');

    const sourceIds = new Set();
    for (const source of sources) {
      validateInteger(source?.id, 1, 0xffffffff, 'source id');
      if (sourceIds.has(source.id)) throw new TypeError('duplicate reputation source');
      if (typeof source.name !== 'string' || source.name.length < 1 || source.name.length > 64) throw new TypeError('invalid source name');
      if (typeof source.sourceTag !== 'string' || source.sourceTag.length < 1 || source.sourceTag.length > 96) throw new TypeError('invalid source tag');
      sourceIds.add(source.id);
    }

    const map = new Map();
    const identities = new Set();
    for (const record of records) {
      const host = normalizeCompiledHost(record?.host);
      if (!CATEGORIES.has(record.category)) throw new TypeError('invalid reputation category');
      if (!SCOPES.has(record.scope)) throw new TypeError('invalid reputation scope');
      if (!EVIDENCE.has(record.evidence)) throw new TypeError('invalid reputation evidence');
      validateInteger(record.confidence, 1, 100, 'confidence');
      validateInteger(record.sourceId, 1, 0xffffffff, 'sourceId');
      validateInteger(record.observedAtMs, 0, Number.MAX_SAFE_INTEGER, 'observedAtMs');
      validateInteger(record.expiresAtMs, 1, Number.MAX_SAFE_INTEGER, 'expiresAtMs');
      if (record.expiresAtMs <= record.observedAtMs) throw new TypeError('invalid indicator expiry');
      if (!sourceIds.has(record.sourceId)) throw new TypeError('unknown reputation source');
      const identity = `${host}\u0000${record.category}\u0000${record.sourceId}\u0000${record.scope}`;
      if (identities.has(identity)) throw new TypeError('duplicate reputation indicator');
      identities.add(identity);
      const bucket = map.get(host) ?? [];
      if (bucket.length >= MAX_INDICATORS_PER_HOST) throw new RangeError('per-host reputation cap exceeded');
      bucket.push(Object.freeze({ ...record, host: undefined }));
      map.set(host, bucket);
    }

    this.#metadata = Object.freeze({ ...metadata });
    this.#sources = new Map(sources.map((source) => [source.id, Object.freeze({ ...source })]));
    this.#records = map;
  }

  status(nowMs) {
    validateInteger(nowMs, 0, Number.MAX_SAFE_INTEGER, 'nowMs');
    return nowMs > this.#metadata.expiresAtMs ? 'stale' : 'current';
  }

  source(sourceId) {
    return this.#sources.get(sourceId) ?? null;
  }

  stats() {
    let recordCount = 0;
    for (const bucket of this.#records.values()) recordCount += bucket.length;
    return Object.freeze({ hostCount: this.#records.size, recordCount, sourceCount: this.#sources.size });
  }

  lookup(compiledHost, nowMs, minConfidence = 1) {
    validateInteger(nowMs, 0, Number.MAX_SAFE_INTEGER, 'nowMs');
    validateInteger(minConfidence, 1, 100, 'minConfidence');
    const datasetStatus = this.status(nowMs);
    if (datasetStatus === 'stale') return Object.freeze({ datasetStatus, matched: null });
    const host = normalizeCompiledHost(compiledHost);
    const labels = host.includes(':') ? 0 : host.split('.').length;
    if (labels > MAX_SUFFIX_LABELS) throw new RangeError('reputation host too deep');

    let best = null;
    const consider = (candidateHost, relation) => {
      const bucket = this.#records.get(candidateHost);
      if (!bucket) return;
      for (const record of bucket) {
        if (record.confidence < minConfidence || record.expiresAtMs <= nowMs) continue;
        if (relation === 'parent-domain' && record.scope !== 'host-and-subdomains') continue;
        const candidate = Object.freeze({
          category: record.category,
          confidence: record.confidence,
          sourceId: record.sourceId,
          evidence: record.evidence,
          scope: record.scope,
          relation,
          observedAtMs: record.observedAtMs,
          expiresAtMs: record.expiresAtMs,
        });
        if (better(candidate, best)) best = candidate;
      }
    };

    consider(host, 'exact');
    if (!host.includes(':')) {
      let walked = 1;
      for (let index = host.indexOf('.'); index >= 0; index = host.indexOf('.', index + 1)) {
        walked += 1;
        if (walked > MAX_SUFFIX_LABELS) throw new RangeError('reputation host too deep');
        consider(host.slice(index + 1), 'parent-domain');
      }
    }
    return Object.freeze({ datasetStatus, matched: best });
  }
}
