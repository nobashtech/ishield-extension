'use strict';

import { canonicalJson, sha256Hex } from './signed-update.js';

export const UPDATE_RULE_ID_START = 1_400_000;
export const UPDATE_SOURCE_RULE_CAP = 10_000;
// Firefox permits 5,000 dynamic DNR rules. iShield reserves up to 3,560 for
// allowlist and Strict rules, so signed filter updates are capped at 1,400 compiled rules.
export const UPDATE_DYNAMIC_RULE_CAP = 1_400;
export const UPDATE_RULE_PRIORITY = 9_000;
const RESOURCE_TYPES = new Set(['main_frame','sub_frame','script','stylesheet','image','font','object','xmlhttprequest','ping','media','websocket','other']);

function resource(snapshot) {
  return snapshot?.resources?.find((item) => item.kind === 'network-rules') ?? null;
}

function normalizeNetworkRulesPayload(payload) {
  if (!payload || typeof payload !== 'object' || !Array.isArray(payload.rules)) throw new TypeError('invalid signed network-rules payload');
  if (Object.keys(payload).some((key) => key !== 'rules')) throw new TypeError('unexpected signed network-rules field');
  if (payload.rules.length > UPDATE_SOURCE_RULE_CAP) throw new RangeError('signed network source rule cap exceeded');
  return Object.freeze({ rules: Object.freeze(payload.rules.map((rule) => Object.freeze({ ...rule }))) });
}

export async function materializeUpdateResources(_previousSnapshot, verifiedBundle, subtle = globalThis.crypto?.subtle) {
  if (!Array.isArray(verifiedBundle?.resources) || verifiedBundle.resources.length !== 1) throw new TypeError('filter update must contain exactly one resource');
  const item = verifiedBundle.resources[0];
  if (item.kind !== 'network-rules' || item.mode !== 'full') throw new TypeError('only full network-rules filter updates are accepted');
  const payload = normalizeNetworkRulesPayload(item.payload);
  const digest = await sha256Hex(canonicalJson(payload), subtle);
  if (digest !== item.sha256) throw new Error('filter update digest mismatch');
  return Object.freeze([Object.freeze({ kind: 'network-rules', version: item.version, mode: 'full', sha256: digest, payload })]);
}

function normalizeRuleHost(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 253) throw new TypeError('invalid update rule host');
  let parsed; try { parsed = new URL(`https://${value}/`); } catch { throw new TypeError('invalid update rule host'); }
  const host = parsed.hostname.toLowerCase().replace(/\.$/u, '');
  const labels = host.split('.');
  if (!host || host.includes(':') || labels.length < 2 || /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host) || labels.some((label) => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) throw new TypeError('update rule requires DNS host');
  return host;
}

function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'); }
const MAX_DOMAINS_PER_RULE = 1000;

export function compileSignedNetworkRules(snapshot) {
  const item = resource(snapshot);
  if (!item) return [];
  if (item.mode !== 'full') throw new TypeError('signed network-rules snapshot must be materialized');
  const payload = normalizeNetworkRulesPayload(item.payload);
  const slots = [];
  const openGroups = new Map();
  for (const raw of payload.rules) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('invalid signed network rule');
    if (Object.keys(raw).some((key) => !['host','scope','resourceTypes'].includes(key))) throw new TypeError('unexpected signed network rule field');
    const host = normalizeRuleHost(raw.host);
    const scope = raw.scope === 'exact' ? 'exact' : (raw.scope === 'host-and-subdomains' || raw.scope == null ? 'host-and-subdomains' : (()=>{throw new TypeError('invalid signed network rule scope')})());
    const resourceTypes = [...new Set(Array.isArray(raw.resourceTypes) ? raw.resourceTypes : ['main_frame'])];
    if (resourceTypes.length < 1 || resourceTypes.some((value) => !RESOURCE_TYPES.has(value))) throw new TypeError('invalid signed network rule resourceTypes');
    if (scope === 'exact') {
      slots.push({ resourceTypes, regexFilter: `^https?://${escapeRegex(host)}(?::[0-9]{1,5})?(?:/|$)` });
      continue;
    }
    const key = [...resourceTypes].sort().join(',');
    let group = openGroups.get(key);
    if (!group || group.requestDomains.length >= MAX_DOMAINS_PER_RULE) {
      group = { resourceTypes, requestDomains: [] };
      openGroups.set(key, group);
      slots.push(group);
    }
    if (!group.requestDomains.includes(host)) group.requestDomains.push(host);
  }
  if (slots.length > UPDATE_DYNAMIC_RULE_CAP) throw new RangeError('compiled signed network rule cap exceeded');
  return slots.map((slot, offset) => {
    const condition = { resourceTypes: slot.resourceTypes };
    if (slot.regexFilter !== undefined) {
      condition.regexFilter = slot.regexFilter;
      condition.isUrlFilterCaseSensitive = true;
    } else {
      condition.requestDomains = slot.requestDomains;
    }
    return Object.freeze({ id: UPDATE_RULE_ID_START + offset, priority: UPDATE_RULE_PRIORITY, action: { type: 'block' }, condition });
  });
}

export function isSignedUpdateRuleId(id) { return Number.isInteger(id) && id >= UPDATE_RULE_ID_START && id < UPDATE_RULE_ID_START + UPDATE_DYNAMIC_RULE_CAP; }
