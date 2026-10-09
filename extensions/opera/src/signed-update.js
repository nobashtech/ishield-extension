'use strict';

export const UPDATE_SCHEMA_VERSION = 1;
export const UPDATE_STATE_KEY = 'ishield.update.state.v1';
export const UPDATE_SLOT_A_KEY = 'ishield.update.slot.a.v1';
export const UPDATE_SLOT_B_KEY = 'ishield.update.slot.b.v1';
export const UPDATE_MAX_BUNDLE_BYTES = 4 * 1024 * 1024;
export const UPDATE_MAX_RESOURCES = 1;
export const UPDATE_MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;
export const UPDATE_MAX_VALIDITY_MS = 14 * 24 * 60 * 60 * 1000;
export const UPDATE_RESOURCE_KINDS = Object.freeze(['network-rules']);
const UPDATE_KIND_SET = new Set(UPDATE_RESOURCE_KINDS);
const ENCODER = new TextEncoder();
const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function assertPlainObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`invalid ${name}`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new TypeError(`invalid ${name} prototype`);
}

function assertExactKeys(value, allowed, name) {
  assertPlainObject(value, name);
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (DANGEROUS_KEYS.has(key) || !allowedSet.has(key)) throw new TypeError(`unexpected ${name} field: ${key}`);
  }
}

function integer(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`invalid ${name}`);
}

function bytesToBase64Url(bytes) {
  let raw = '';
  for (const byte of bytes) raw += String.fromCharCode(byte);
  if (typeof btoa === 'function') return btoa(raw).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
  return Buffer.from(bytes).toString('base64url');
}

function base64ToBytes(value, expectedLength = null) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096) throw new TypeError('invalid base64 value');
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/u.test(value) || /[-_]/u.test(value) && /[+/]/u.test(value)) throw new TypeError('invalid base64 alphabet');
  const firstPadding = value.indexOf('=');
  if (firstPadding >= 0 && (firstPadding < value.length - 2 || value.length % 4 !== 0)) throw new TypeError('invalid base64 padding');
  const unpadded = value.replace(/=+$/u, '');
  if (unpadded.length % 4 === 1) throw new TypeError('invalid base64 length');
  const normalized = unpadded.replace(/-/gu, '+').replace(/_/gu, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  let out;
  try {
    if (typeof atob === 'function') {
      const raw = atob(padded); out = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
    } else {
      out = Uint8Array.from(Buffer.from(padded, 'base64'));
    }
  } catch { throw new TypeError('invalid base64 value'); }
  const canonicalInput = unpadded.replace(/\+/gu, '-').replace(/\//gu, '_');
  if (bytesToBase64Url(out) !== canonicalInput) throw new TypeError('non-canonical base64 value');
  if (expectedLength !== null && out.length !== expectedLength) throw new TypeError('invalid base64 decoded length');
  return out;
}

function bytesToHex(bytes) { return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join(''); }

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) throw new TypeError('canonical JSON accepts safe integers only');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    assertPlainObject(value, 'canonical JSON object');
    const keys = Object.keys(value).sort();
    for (const key of keys) if (DANGEROUS_KEYS.has(key)) throw new TypeError('dangerous canonical JSON key rejected');
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('unsupported canonical JSON value');
}

export async function sha256Hex(value, subtle = globalThis.crypto?.subtle) {
  if (!subtle) throw new Error('WebCrypto unavailable');
  const bytes = typeof value === 'string' ? ENCODER.encode(value) : value;
  if (!(bytes instanceof Uint8Array)) throw new TypeError('sha256 input must be string or Uint8Array');
  return bytesToHex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
}

function unsignedEnvelope(bundle) {
  const { signature: _signature, ...unsigned } = bundle;
  return unsigned;
}

export function normalizeUpdateEnvelope(bundle) {
  assertExactKeys(bundle, ['schemaVersion', 'sequence', 'issuedAtMs', 'expiresAtMs', 'keyId', 'resources', 'signature'], 'update envelope');
  if (bundle.schemaVersion !== UPDATE_SCHEMA_VERSION) throw new TypeError('unsupported update schema');
  integer(bundle.sequence, 1, Number.MAX_SAFE_INTEGER, 'update sequence');
  integer(bundle.issuedAtMs, 0, Number.MAX_SAFE_INTEGER, 'update issuedAtMs');
  integer(bundle.expiresAtMs, 1, Number.MAX_SAFE_INTEGER, 'update expiresAtMs');
  if (bundle.expiresAtMs <= bundle.issuedAtMs || bundle.expiresAtMs - bundle.issuedAtMs > UPDATE_MAX_VALIDITY_MS) throw new TypeError('invalid update validity window');
  if (typeof bundle.keyId !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/u.test(bundle.keyId)) throw new TypeError('invalid update keyId');
  if (!Array.isArray(bundle.resources) || bundle.resources.length !== 1) throw new TypeError('filter update must contain exactly one resource');
  const seen = new Set();
  const resources = bundle.resources.map((raw) => {
    assertPlainObject(raw, 'update resource');
    if (!UPDATE_KIND_SET.has(raw.kind) || seen.has(raw.kind)) throw new TypeError('invalid or duplicate update resource kind');
    seen.add(raw.kind);
    integer(raw.version, 1, Number.MAX_SAFE_INTEGER, 'update resource version');
    if (raw.mode !== 'full') throw new TypeError('filter update resource must use full mode');
    assertExactKeys(raw, ['kind', 'version', 'mode', 'sha256', 'payload'], 'update resource');
    if (typeof raw.sha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(raw.sha256)) throw new TypeError('invalid update resource digest');
    if (raw.payload === undefined) throw new TypeError('missing update resource payload');
    return Object.freeze({ kind: raw.kind, version: raw.version, mode: 'full', sha256: raw.sha256, payload: raw.payload });
  });
  const signature = bundle.signature;
  assertExactKeys(signature, ['algorithm', 'value'], 'update signature');
  if (signature.algorithm !== 'Ed25519' || typeof signature.value !== 'string') throw new TypeError('invalid update signature');
  base64ToBytes(signature.value, 64);
  const normalized = { schemaVersion: UPDATE_SCHEMA_VERSION, sequence: bundle.sequence, issuedAtMs: bundle.issuedAtMs, expiresAtMs: bundle.expiresAtMs, keyId: bundle.keyId, resources, signature: { algorithm: 'Ed25519', value: signature.value } };
  const byteLength = ENCODER.encode(canonicalJson(normalized)).length;
  if (byteLength > UPDATE_MAX_BUNDLE_BYTES) throw new RangeError('update bundle byte cap exceeded');
  return Object.freeze(normalized);
}

export async function verifySignedUpdate(bundleInput, trustStore, { nowMs = Date.now(), minSequence = 0, subtle = globalThis.crypto?.subtle } = {}) {
  if (!subtle) throw new Error('WebCrypto unavailable');
  integer(nowMs, 0, Number.MAX_SAFE_INTEGER, 'nowMs');
  integer(minSequence, 0, Number.MAX_SAFE_INTEGER, 'minSequence');
  const bundle = normalizeUpdateEnvelope(bundleInput);
  if (bundle.sequence <= minSequence) throw new Error('update replay or downgrade rejected');
  if (bundle.issuedAtMs > nowMs + UPDATE_MAX_CLOCK_SKEW_MS) throw new Error('update issued in the future');
  if (bundle.expiresAtMs <= nowMs) throw new Error('update expired');
  const publicKeyRaw = trustStore?.[bundle.keyId];
  if (typeof publicKeyRaw !== 'string') throw new Error('untrusted update signing key');
  const key = await subtle.importKey('raw', base64ToBytes(publicKeyRaw, 32), { name: 'Ed25519' }, false, ['verify']);
  const signatureBytes = base64ToBytes(bundle.signature.value, 64);
  const signedBytes = ENCODER.encode(canonicalJson(unsignedEnvelope(bundle)));
  if (!await subtle.verify({ name: 'Ed25519' }, key, signatureBytes, signedBytes)) throw new Error('update signature verification failed');
  for (const resource of bundle.resources) {
    const actual = await sha256Hex(canonicalJson(resource.payload), subtle);
    if (actual !== resource.sha256) throw new Error(`update resource digest mismatch: ${resource.kind}`);
  }
  return bundle;
}

export function defaultUpdateState() { return Object.freeze({ schemaVersion: 1, activeSlot: 'a', previousSlot: null, sequence: 0, appliedAtMs: 0 }); }

function normalizeUpdateState(value) {
  if (!value || typeof value !== 'object') return defaultUpdateState();
  if (!['a', 'b'].includes(value.activeSlot)) return defaultUpdateState();
  const previousSlot = value.previousSlot === null || ['a', 'b'].includes(value.previousSlot) ? value.previousSlot : null;
  const sequence = Number.isSafeInteger(value.sequence) && value.sequence >= 0 ? value.sequence : 0;
  const appliedAtMs = Number.isSafeInteger(value.appliedAtMs) && value.appliedAtMs >= 0 ? value.appliedAtMs : 0;
  return Object.freeze({ schemaVersion: 1, activeSlot: value.activeSlot, previousSlot, sequence, appliedAtMs });
}


async function validateStoredSnapshot(snapshot, state, subtle = globalThis.crypto?.subtle) {
  if (!subtle) throw new Error('WebCrypto unavailable');
  assertExactKeys(snapshot, ['schemaVersion','sequence','keyId','issuedAtMs','expiresAtMs','resources'], 'stored update snapshot');
  if (snapshot.schemaVersion !== 1) throw new TypeError('invalid stored update snapshot schema');
  integer(snapshot.sequence, 1, state.sequence, 'stored update snapshot sequence');
  integer(snapshot.issuedAtMs, 0, Number.MAX_SAFE_INTEGER, 'stored update snapshot issuedAtMs');
  integer(snapshot.expiresAtMs, 1, Number.MAX_SAFE_INTEGER, 'stored update snapshot expiresAtMs');
  if (typeof snapshot.keyId !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/u.test(snapshot.keyId)) throw new TypeError('invalid stored update keyId');
  if (!Array.isArray(snapshot.resources) || snapshot.resources.length !== 1) throw new TypeError('stored filter snapshot must contain exactly one resource');
  const seen = new Set();
  for (const resource of snapshot.resources) {
    assertExactKeys(resource, ['kind','version','mode','sha256','payload'], 'stored update resource');
    if (!UPDATE_KIND_SET.has(resource.kind) || seen.has(resource.kind)) throw new TypeError('invalid stored update resource kind');
    seen.add(resource.kind);
    integer(resource.version, 1, Number.MAX_SAFE_INTEGER, 'stored update resource version');
    if (resource.mode !== 'full') throw new TypeError('stored update resource must be materialized');
    if (typeof resource.sha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(resource.sha256)) throw new TypeError('invalid stored update resource digest');
    const actual = await sha256Hex(canonicalJson(resource.payload), subtle);
    if (actual !== resource.sha256) throw new Error(`stored update resource digest mismatch: ${resource.kind}`);
  }
  return snapshot;
}

export class SignedUpdateStore {
  constructor(storageArea) {
    if (!storageArea?.get || !storageArea?.set) throw new TypeError('storage API unavailable');
    this.storageArea = storageArea;
    this.queue = Promise.resolve();
  }
  exclusive(operation) { const run = this.queue.then(operation, operation); this.queue = run.catch(() => undefined); return run; }
  async loadState() { const stored = await this.storageArea.get(UPDATE_STATE_KEY); return normalizeUpdateState(stored?.[UPDATE_STATE_KEY]); }
  async #loadSlot(slot, state) {
    const key = slot === 'a' ? UPDATE_SLOT_A_KEY : UPDATE_SLOT_B_KEY;
    const stored = await this.storageArea.get(key);
    const snapshot = stored?.[key] ?? null;
    if (!snapshot) return null;
    try { return await validateStoredSnapshot(snapshot, state); } catch { return null; }
  }
  loadActive() {
    return this.exclusive(async () => {
      const state = await this.loadState();
      const active = await this.#loadSlot(state.activeSlot, state);
      if (active) return Object.freeze({ state, snapshot: active, recovered: false });
      if (state.previousSlot && state.previousSlot !== state.activeSlot) {
        const previous = await this.#loadSlot(state.previousSlot, state);
        if (previous) {
          // Preserve the replay-protection high-water mark while recovering the last known-good slot.
          const recoveredState = Object.freeze({ schemaVersion:1, activeSlot:state.previousSlot, previousSlot:state.activeSlot, sequence:state.sequence, appliedAtMs:Date.now() });
          await this.storageArea.set({ [UPDATE_STATE_KEY]: recoveredState });
          return Object.freeze({ state: recoveredState, snapshot: previous, recovered: true });
        }
      }
      return Object.freeze({ state, snapshot: null, recovered: false });
    });
  }
  applyVerified(bundle, materializedResources = bundle.resources) {
    return this.exclusive(async () => {
      if (!Array.isArray(materializedResources) || materializedResources.length !== 1) throw new TypeError('materialized filter snapshot must contain exactly one resource');
      const state = await this.loadState();
      if (bundle.sequence <= state.sequence) throw new Error('update replay or downgrade rejected');
      const inactiveSlot = state.activeSlot === 'a' ? 'b' : 'a';
      const inactiveKey = inactiveSlot === 'a' ? UPDATE_SLOT_A_KEY : UPDATE_SLOT_B_KEY;
      const snapshot = Object.freeze({ schemaVersion: 1, sequence: bundle.sequence, keyId: bundle.keyId, issuedAtMs: bundle.issuedAtMs, expiresAtMs: bundle.expiresAtMs, resources: materializedResources });
      await this.storageArea.set({ [inactiveKey]: snapshot });
      const verifyWrite = await this.storageArea.get(inactiveKey);
      if (canonicalJson(verifyWrite?.[inactiveKey]) !== canonicalJson(snapshot)) throw new Error('update staging verification failed');
      await validateStoredSnapshot(snapshot, Object.freeze({ ...state, sequence: bundle.sequence }));
      const nextState = Object.freeze({ schemaVersion: 1, activeSlot: inactiveSlot, previousSlot: state.activeSlot, sequence: bundle.sequence, appliedAtMs: Date.now() });
      await this.storageArea.set({ [UPDATE_STATE_KEY]: nextState });
      return nextState;
    });
  }
  rollback() {
    return this.exclusive(async () => {
      const state = await this.loadState();
      if (!state.previousSlot) throw new Error('no update rollback slot available');
      const previousKey = state.previousSlot === 'a' ? UPDATE_SLOT_A_KEY : UPDATE_SLOT_B_KEY;
      const stored = await this.storageArea.get(previousKey);
      const snapshot = stored?.[previousKey];
      if (!snapshot || !Number.isSafeInteger(snapshot.sequence)) throw new Error('rollback snapshot unavailable');
      await validateStoredSnapshot(snapshot, state);
      // sequence is a monotonic high-water mark. Rollback changes the active slot but never
      // lowers replay protection, so a previously accepted bad bundle cannot be replayed.
      const next = Object.freeze({ schemaVersion: 1, activeSlot: state.previousSlot, previousSlot: state.activeSlot, sequence: state.sequence, appliedAtMs: Date.now() });
      await this.storageArea.set({ [UPDATE_STATE_KEY]: next });
      return next;
    });
  }
}
