'use strict';

import { SignedUpdateStore, verifySignedUpdate } from './signed-update.js';
import { materializeUpdateResources } from './update-runtime.js';
import { decodeUtf8Strict, isJsonContentType, strictJsonParse } from './strict-json.js';

const FILTER_UPDATE_ORIGIN = 'https://update.broxme.com';
const FILTER_UPDATE_PATH = '/ishield/manifest.json';
const MAX_FILTER_UPDATE_BYTES = 4 * 1024 * 1024;

function exactFilterUpdateUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) throw new TypeError('invalid filter update URL');
  let url; try { url = new URL(value); } catch { throw new TypeError('invalid filter update URL'); }
  if (url.origin !== FILTER_UPDATE_ORIGIN || url.pathname !== FILTER_UPDATE_PATH || url.search || url.hash || url.username || url.password) throw new TypeError('unapproved filter update URL');
  return url.href;
}

export class SignedUpdateClient {
  constructor({ storageArea, trustStore, fetchImpl = globalThis.fetch, now = () => Date.now() }) {
    if (typeof fetchImpl !== 'function') throw new TypeError('fetch implementation unavailable');
    this.store = new SignedUpdateStore(storageArea);
    this.trustStore = Object.freeze({ ...(trustStore ?? {}) });
    this.fetchImpl = fetchImpl;
    this.now = now;
  }

  async fetchAndApply(manifestUrl, { signal } = {}) {
    const url = exactFilterUpdateUrl(manifestUrl);
    const { state, snapshot } = await this.store.loadActive();
    const response = await this.fetchImpl(url, {
      method: 'GET',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal,
      headers: { Accept: 'application/json' },
    });
    if (!response?.ok) throw new Error(`filter update download failed: HTTP ${response?.status ?? 0}`);
    const contentLength = Number(response.headers?.get?.('content-length') ?? 0);
    if (Number.isFinite(contentLength) && contentLength > MAX_FILTER_UPDATE_BYTES) throw new RangeError('filter update response too large');
    const responseType = response.headers?.get?.('content-type');
    if (responseType && !isJsonContentType(responseType)) throw new TypeError('filter update response must be application/json');
    let text;
    if (typeof response.arrayBuffer === 'function') {
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.length > MAX_FILTER_UPDATE_BYTES) throw new RangeError('filter update response too large');
      text = decodeUtf8Strict(bytes);
    } else {
      text = await response.text();
      if (new TextEncoder().encode(text).length > MAX_FILTER_UPDATE_BYTES) throw new RangeError('filter update response too large');
    }
    const candidate = strictJsonParse(text, { maxDepth: 32, maxKeys: 50_000, maxNodes: 150_000 });
    const verified = await verifySignedUpdate(candidate, this.trustStore, { nowMs: this.now(), minSequence: state.sequence });
    const resources = await materializeUpdateResources(snapshot, verified);
    return this.store.applyVerified(verified, resources);
  }
}
