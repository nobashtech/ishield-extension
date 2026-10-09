'use strict';

export const RECOVERY_SCHEMA_VERSION = 1;
export const RECOVERY_STATE_KEY = 'ishield.breakage-recovery.v1';
export const RECOVERY_MAX_SITES = 256;
export const RECOVERY_MAX_SIGNAL_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const RECOVERY_DETECTION_WINDOW_MS = 10 * 60 * 1000;
export const AUTO_RECOVERY_TTL_MS = 30 * 60 * 1000;
export const MANUAL_RECOVERY_TTL_MS = 2 * 60 * 60 * 1000;
export const RECOVERY_LAYERS = Object.freeze(['cosmetic', 'scriptlets']);
const LAYER_SET = new Set(RECOVERY_LAYERS);
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

function int(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`invalid ${name}`);
  return value;
}

export function normalizeRecoveryHost(value) {
  if (typeof value !== 'string') throw new TypeError('invalid recovery host');
  const host = value.trim().toLowerCase().replace(/\.+$/u, '');
  if (!HOST_RE.test(host) || /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host)) throw new TypeError('recovery requires DNS host');
  return host;
}

function defaultState() { return Object.freeze({ schemaVersion: RECOVERY_SCHEMA_VERSION, sites: Object.freeze([]) }); }

function normalizeStoredSite(raw, nowMs) {
  try {
    const host = normalizeRecoveryHost(raw?.host);
    const lastProbeAtMs = int(raw?.lastProbeAtMs ?? 0, 0, Number.MAX_SAFE_INTEGER, 'lastProbeAtMs');
    if (lastProbeAtMs && nowMs - lastProbeAtMs > RECOVERY_MAX_SIGNAL_AGE_MS) return null;
    const badProbeCount = int(raw?.badProbeCount ?? 0, 0, 16, 'badProbeCount');
    const activatedAtMs = raw?.activatedAtMs == null ? null : int(raw.activatedAtMs, 0, Number.MAX_SAFE_INTEGER, 'activatedAtMs');
    const expiresAtMs = raw?.expiresAtMs == null ? null : int(raw.expiresAtMs, 1, Number.MAX_SAFE_INTEGER, 'expiresAtMs');
    const source = ['automatic', 'manual'].includes(raw?.source) ? raw.source : null;
    const active = expiresAtMs != null && expiresAtMs > nowMs && source != null;
    return Object.freeze({ host, badProbeCount, lastProbeAtMs, lastScore: int(raw?.lastScore ?? 0, 0, 20, 'lastScore'), activatedAtMs: active ? activatedAtMs : null, expiresAtMs: active ? expiresAtMs : null, source: active ? source : null, disabledLayers: active ? Object.freeze(['cosmetic', 'scriptlets']) : Object.freeze([]) });
  } catch { return null; }
}

export function normalizeRecoveryState(value, nowMs = Date.now()) {
  int(nowMs, 0, Number.MAX_SAFE_INTEGER, 'nowMs');
  if (!value || typeof value !== 'object' || value.schemaVersion !== RECOVERY_SCHEMA_VERSION || !Array.isArray(value.sites)) return defaultState();
  const sites = []; const seen = new Set();
  for (const raw of value.sites) {
    const site = normalizeStoredSite(raw, nowMs); if (!site || seen.has(site.host)) continue;
    seen.add(site.host); sites.push(site); if (sites.length >= RECOVERY_MAX_SITES) break;
  }
  return Object.freeze({ schemaVersion: RECOVERY_SCHEMA_VERSION, sites: Object.freeze(sites) });
}

export function scoreBreakageProbe(probe) {
  if (!probe || typeof probe !== 'object' || Array.isArray(probe)) throw new TypeError('invalid breakage probe');
  const scriptErrors = int(probe.scriptErrors ?? 0, 0, 64, 'scriptErrors');
  const resourceErrors = int(probe.resourceErrors ?? 0, 0, 128, 'resourceErrors');
  const visibleTextChars = int(probe.visibleTextChars ?? 0, 0, 20000, 'visibleTextChars');
  const bodyChildCount = int(probe.bodyChildCount ?? 0, 0, 10000, 'bodyChildCount');
  const interactiveCount = int(probe.interactiveCount ?? 0, 0, 5000, 'interactiveCount');
  const readyState = ['loading', 'interactive', 'complete'].includes(probe.readyState) ? probe.readyState : 'loading';
  let score = 0;
  if (scriptErrors >= 6) score += 4;
  if (scriptErrors >= 12) score += 2;
  if (resourceErrors >= 12) score += 2;
  if (readyState === 'complete' && bodyChildCount === 0) score += 7;
  else if (readyState === 'complete' && bodyChildCount > 0 && visibleTextChars < 40 && interactiveCount === 0) score += 5;
  return Math.min(20, score);
}

function siteView(site) { return Object.freeze({ ...site, disabledLayers: Object.freeze([...site.disabledLayers]) }); }

export class BreakageRecoveryStore {
  constructor(storageArea, now = () => Date.now()) {
    if (!storageArea?.get || !storageArea?.set) throw new TypeError('storage API unavailable');
    this.storageArea = storageArea; this.now = now; this.queue = Promise.resolve();
  }
  exclusive(operation) { const run = this.queue.then(operation, operation); this.queue = run.catch(() => undefined); return run; }
  async load() { const nowMs = this.now(); const raw = (await this.storageArea.get(RECOVERY_STATE_KEY))?.[RECOVERY_STATE_KEY]; return normalizeRecoveryState(raw, nowMs); }
  async write(state) { const normalized = normalizeRecoveryState(state, this.now()); await this.storageArea.set({ [RECOVERY_STATE_KEY]: normalized }); return normalized; }
  async status(hostInput) { const host = normalizeRecoveryHost(hostInput); const state = await this.load(); return state.sites.find((site) => site.host === host) ?? null; }
  recordProbe(hostInput, probe) {
    return this.exclusive(async () => {
      const host = normalizeRecoveryHost(hostInput); const nowMs = this.now(); const score = scoreBreakageProbe(probe); const state = await this.load();
      const sites = state.sites.filter((site) => site.host !== host).map((site) => ({ ...site, disabledLayers: [...site.disabledLayers] }));
      const previous = state.sites.find((site) => site.host === host) ?? null;
      const consecutive = score >= 6 && previous && nowMs - previous.lastProbeAtMs <= RECOVERY_DETECTION_WINDOW_MS ? Math.min(16, previous.badProbeCount + 1) : (score >= 6 ? 1 : 0);
      const wasActive = !!(previous?.expiresAtMs && previous.expiresAtMs > nowMs);
      const shouldActivate = !wasActive && score >= 6 && consecutive >= 2;
      const next = {
        host, badProbeCount: consecutive, lastProbeAtMs: nowMs, lastScore: score,
        activatedAtMs: shouldActivate ? nowMs : (wasActive ? previous.activatedAtMs : null),
        expiresAtMs: shouldActivate ? nowMs + AUTO_RECOVERY_TTL_MS : (wasActive ? previous.expiresAtMs : null),
        source: shouldActivate ? 'automatic' : (wasActive ? previous.source : null),
        disabledLayers: shouldActivate || wasActive ? ['cosmetic', 'scriptlets'] : [],
      };
      sites.unshift(next); const written = await this.write({ schemaVersion: RECOVERY_SCHEMA_VERSION, sites: sites.slice(0, RECOVERY_MAX_SITES) });
      const current = written.sites.find((site) => site.host === host);
      return Object.freeze({ activated: shouldActivate, score, site: current ? siteView(current) : null });
    });
  }
  activateManual(hostInput) {
    return this.exclusive(async () => {
      const host = normalizeRecoveryHost(hostInput); const nowMs = this.now(); const state = await this.load();
      const sites = state.sites.filter((site) => site.host !== host).map((site) => ({ ...site, disabledLayers: [...site.disabledLayers] }));
      sites.unshift({ host, badProbeCount: 0, lastProbeAtMs: nowMs, lastScore: 0, activatedAtMs: nowMs, expiresAtMs: nowMs + MANUAL_RECOVERY_TTL_MS, source: 'manual', disabledLayers: ['cosmetic', 'scriptlets'] });
      const written = await this.write({ schemaVersion: RECOVERY_SCHEMA_VERSION, sites: sites.slice(0, RECOVERY_MAX_SITES) });
      return siteView(written.sites[0]);
    });
  }
  clear(hostInput) {
    return this.exclusive(async () => {
      const host = normalizeRecoveryHost(hostInput); const state = await this.load();
      const written = await this.write({ schemaVersion: RECOVERY_SCHEMA_VERSION, sites: state.sites.filter((site) => site.host !== host) });
      return Object.freeze({ cleared: true, activeSiteCount: written.sites.filter((site) => site.expiresAtMs != null && site.expiresAtMs > this.now()).length });
    });
  }
  async activeScriptletExcludeMatches() {
    const nowMs = this.now(); const state = await this.load(); const out = [];
    for (const site of state.sites) {
      if (!(site.expiresAtMs != null && site.expiresAtMs > nowMs && site.disabledLayers.includes('scriptlets'))) continue;
      out.push(`*://${site.host}/*`); if (out.length >= RECOVERY_MAX_SITES) break;
    }
    return Object.freeze(out);
  }
}

export function resolveEffectiveCompatibility(hostInput, localSite, nowMs = Date.now()) {
  const host = normalizeRecoveryHost(hostInput);
  const localActive = !!(localSite?.host === host && localSite?.expiresAtMs != null && localSite.expiresAtMs > nowMs);
  const layers = localActive
    ? [...new Set((localSite.disabledLayers ?? []).filter((layer) => LAYER_SET.has(layer)))].sort()
    : [];
  return Object.freeze({
    active: layers.length > 0,
    disabledLayers: Object.freeze(layers),
    localRecovery: localActive,
    localSource: localActive ? localSite.source : null,
    localExpiresAtMs: localActive ? localSite.expiresAtMs : null,
  });
}
