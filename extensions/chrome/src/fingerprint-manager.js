'use strict';

export const FINGERPRINT_REGISTRATION_ID = 'ishield_fingerprint_v1';
export const FINGERPRINT_MATCHES = Object.freeze(['http://*/*', 'https://*/*']);
export const FINGERPRINT_ALLOWLIST_CAP = 1000;
export const FINGERPRINT_COMPATIBILITY_CAP = 512;
const MODES = new Set(['balanced', 'strong', 'maximum']);

export function hostToFingerprintExcludeMatch(host) {
  if (typeof host !== 'string' || !host || host.length > 253 || /[\s/]/u.test(host)) throw new TypeError('invalid fingerprint exclude host');
  if (host.includes(':')) return `*://[${host}]/*`;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(host) || !host.includes('.')) return `*://${host}/*`;
  return `*://*.${host}/*`;
}

function normalizeCompatibility(values) {
  if (!Array.isArray(values)) return [];
  const out=[]; const seen=new Set();
  const re=/^\*:\/\/(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\/\*$/u;
  for (const value of values.slice(0,FINGERPRINT_COMPATIBILITY_CAP)) {
    if (typeof value !== 'string' || !re.test(value) || seen.has(value)) continue;
    seen.add(value); out.push(value);
  }
  return out;
}

export function desiredFingerprintRegistration(state, compatibilityExcludeMatches = []) {
  if (!state || state.protectionEnabled === false || state.features?.privacy === false) return null;
  const mode = MODES.has(state.mode) ? state.mode : 'strong';
  const excludes=[]; const seen=new Set();
  for (const host of Array.isArray(state.allowlist) ? state.allowlist.slice(0,FINGERPRINT_ALLOWLIST_CAP) : []) {
    const pattern=hostToFingerprintExcludeMatch(host); if(!seen.has(pattern)){seen.add(pattern);excludes.push(pattern);}
  }
  for (const pattern of normalizeCompatibility(compatibilityExcludeMatches)) if(!seen.has(pattern)){seen.add(pattern);excludes.push(pattern);}
  const registration = {
    id: FINGERPRINT_REGISTRATION_ID,
    matches: [...FINGERPRINT_MATCHES],
    js: [`content/fingerprint-mode-${mode}.js`],
    runAt: 'document_start',
    world: 'MAIN',
    allFrames: false,
    persistAcrossSessions: true,
  };
  if (excludes.length) registration.excludeMatches=excludes;
  return registration;
}

export async function reconcileFingerprintProtection(scriptingApi, state, compatibilityExcludeMatches = []) {
  if (!scriptingApi?.getRegisteredContentScripts || !scriptingApi?.registerContentScripts || !scriptingApi?.updateContentScripts || !scriptingApi?.unregisterContentScripts) throw new TypeError('scripting API unavailable');
  const existing=await scriptingApi.getRegisteredContentScripts({ids:[FINGERPRINT_REGISTRATION_ID]});
  const present=Array.isArray(existing)&&existing.some((item)=>item?.id===FINGERPRINT_REGISTRATION_ID);
  const desired=desiredFingerprintRegistration(state,compatibilityExcludeMatches);
  if(!desired){if(present)await scriptingApi.unregisterContentScripts({ids:[FINGERPRINT_REGISTRATION_ID]});return {active:false,mode:null,excludeMatchCount:0,operation:present?'unregistered':'none'};}
  if(present){await scriptingApi.updateContentScripts([{...desired, excludeMatches: desired.excludeMatches ?? []}]);return {active:true,mode:state.mode,excludeMatchCount:desired.excludeMatches?.length??0,operation:'updated'};}
  await scriptingApi.registerContentScripts([desired]);
  return {active:true,mode:state.mode,excludeMatchCount:desired.excludeMatches?.length??0,operation:'registered'};
}
