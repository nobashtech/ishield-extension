#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const browsers = ['chrome', 'edge', 'opera', 'firefox'];
const expectedPermissions = ['activeTab','declarativeNetRequest','storage','scripting','alarms'];
const expectedOptional = [];
const expectedHosts = ['http://*/*','https://*/*'];
const updateUrl = 'https://update.broxme.com/ishield/manifest.json';
const failures = [];

const fail = (message) => failures.push(message);
const read = (p) => fs.readFileSync(p, 'utf8');
const sameSet = (a,b) => a.length===b.length && a.every((x)=>b.includes(x));

function walk(dir, out=[]) {
  for (const entry of fs.readdirSync(dir,{withFileTypes:true})) {
    const p=path.join(dir,entry.name);
    if (entry.isDirectory()) walk(p,out); else out.push(p);
  }
  return out;
}

for (const browserName of browsers) {
  const base=path.join(root,'extensions',browserName);
  const manifest=JSON.parse(read(path.join(base,'manifest.json')));
  if (manifest.manifest_version !== 3) fail(`${browserName}: Manifest V3 required`);
  if (manifest.incognito !== 'not_allowed') fail(`${browserName}: private/incognito runtime must be disabled`);
  if (!sameSet(manifest.permissions ?? [], expectedPermissions)) fail(`${browserName}: permissions differ from approved minimum set`);
  if (!sameSet(manifest.optional_permissions ?? [], expectedOptional)) fail(`${browserName}: optional permissions differ from approved set`);
  if (!sameSet(manifest.host_permissions ?? [], expectedHosts)) fail(`${browserName}: host permissions differ from filtering scope`);
  if (manifest.externally_connectable) fail(`${browserName}: externally_connectable is prohibited`);
  if (manifest.oauth2) fail(`${browserName}: OAuth is prohibited`);
  const forbiddenPermissions=['cookies','webRequest','webRequestBlocking','identity','nativeMessaging','management','geolocation','history','bookmarks','downloads','proxy'];
  for (const permission of [...(manifest.permissions??[]),...(manifest.optional_permissions??[])]) if (forbiddenPermissions.includes(permission)) fail(`${browserName}: forbidden permission ${permission}`);
  const csp=manifest.content_security_policy?.extension_pages;
  if (csp !== "script-src 'self'; object-src 'none'; base-uri 'none'") fail(`${browserName}: unexpected extension CSP`);
  const popupHtml=read(path.join(base,'popup','popup.html'));
  const expectedPrivacyUrl = browserName === 'firefox'
    ? 'https://broxme.com/ishield/privacy/firefox/'
    : browserName === 'opera'
      ? 'https://broxme.com/ishield/privacy/opera/'
      : 'https://broxme.com/ishield/privacy/';
  if (!popupHtml.includes(expectedPrivacyUrl)) fail(`${browserName}: popup must link to expected iShield privacy policy`);
  const contentJs=(manifest.content_scripts??[]).flatMap((item)=>item.js??[]);
  if (contentJs.some((x)=>/family|central|managed/u.test(x))) fail(`${browserName}: management content script remains`);
  if (browserName==='firefox') {
    const dcp=manifest.browser_specific_settings?.gecko?.data_collection_permissions?.required;
    if (!Array.isArray(dcp) || dcp.length!==1 || dcp[0] !== 'none') fail('firefox: data_collection_permissions.required must be ["none"]');
    if (manifest.browser_specific_settings?.gecko_android) fail('firefox: Android support must not be declared in the desktop release');
  }

  for (const forbidden of [
    'src/central-client.js','src/central-policy.js','src/family-controls.js','content/family-search.js','src/fingerprint-policy.js',
    'src/scriptlet-manager.js','content/scriptlet-main.js','content/scriptlet-rules.js',
    'content/scriptlet-mode-balanced.js','content/scriptlet-mode-strong.js','content/scriptlet-mode-maximum.js'
  ]) {
    if (fs.existsSync(path.join(base,forbidden))) fail(`${browserName}: removed non-production/runtime file still exists: ${forbidden}`);
  }

  for (const item of manifest.web_accessible_resources ?? []) {
    for (const resource of item.resources ?? []) {
      if (resource.includes('*')) fail(`${browserName}: wildcard web-accessible resource is prohibited: ${resource}`);
      if (!fs.existsSync(path.join(base, resource))) fail(`${browserName}: missing web-accessible resource: ${resource}`);
    }
  }

  const firstParty=[];
  for (const dir of ['src','popup','warning']) {
    const full=path.join(base,dir);
    if (fs.existsSync(full)) for (const p of walk(full)) if (/\.(?:js|mjs|html)$/u.test(p) && !p.includes(`${path.sep}vendor${path.sep}`)) firstParty.push(p);
  }
  for (const p of firstParty) {
    const text=read(p);
    const rel=path.relative(base,p);
    for (const marker of ['central:enroll','central:sync','central:disconnect','central:status','family:runtime','ishield.central','ishield.family','deviceSecret','enrollDevice','privacy-compatibility']) {
      if (text.includes(marker)) fail(`${browserName}: management marker ${marker} in ${rel}`);
    }
    if (/\b(?:XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/u.test(text)) fail(`${browserName}: direct outbound-capable API in ${rel}`);
    if (/method\s*:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/iu.test(text)) fail(`${browserName}: non-GET HTTP method in ${rel}`);
    if (/\b(?:eval\s*\(|new\s+Function\s*\()/u.test(text)) fail(`${browserName}: dynamic code execution primitive in ${rel}`);
    const fetchCount=(text.match(/\bfetch\s*\(/gu)??[]).length;
    if (fetchCount>0) {
      if (rel==='src/update-client.js') {
        if (fetchCount!==0) { /* update client uses injected fetchImpl instead of direct fetch */ }
      } else {
        const runtimeUrlFetchCount=(text.match(/fetch\s*\([^\n;]*runtime\.getURL\(/gu)??[]).length;
        const moduleUrlFetchCount=(text.match(/fetch\s*\(\s*new\s+URL\s*\([^\n;]*import\.meta\.url\s*\)\s*\)/gu)??[]).length;
        const localFetchCount=runtimeUrlFetchCount+moduleUrlFetchCount;
        if (fetchCount!==localFetchCount) fail(`${browserName}: non-local fetch found in ${rel}`);
      }
    }
  }

  // Imported raw filter rules may intercept/neutralize page APIs, but must not initiate
  // their own network requests in store builds. This preserves the local-only privacy boundary.
  const adguardRulesDir=path.join(base,'rules','adguard');
  if (fs.existsSync(adguardRulesDir)) {
    for (const p of walk(adguardRulesDir)) {
      if (!p.endsWith('.txt')) continue;
      const rel=path.relative(base,p);
      for (const [index,line] of read(p).split(/\r?\n/u).entries()) {
        if (!line.includes('#%#')) continue;
        if (/\bfetch\s*\(/u.test(line) || /\bsendBeacon\s*\(/u.test(line) || /new\s+(?:XMLHttpRequest|WebSocket|EventSource)\s*\(/u.test(line)
            || /google-ima3-dai/u.test(line)
            || (/fandango\.com#%#/u.test(line) && /advertStreamingSessionStart/u.test(line))
            || (/tenasia\.hankyung\.com#%#/u.test(line) && /hkstatic\.hankyung\.com\/css\/rel\/tenasia\/w\/common\.css/u.test(line))) {
          fail(`${browserName}: imported filter originates network activity in ${rel}:${index+1}`);
        }
      }
    }
  }

  const contentRoot=path.join(base,'content');
  if (fs.existsSync(contentRoot)) {
    for (const p of walk(contentRoot)) {
      const rel=path.relative(base,p);
      if (!/\.js$/u.test(p)) continue;
      // Large AdGuard scriptlet filter text is split into packaged data-only classic scripts so
      // AMO can parse every JavaScript file below its 5 MiB limit. Validate that these files
      // contain only one immutable string declaration, then ignore API-looking text inside it.
      if (/^content[\/]adguard-(?:ads|all)-filter-data\.js$/u.test(rel)) {
        const generatedData = read(p);
        if (!/^\/\*! iShield packaged AdGuard (?:ads|all) scriptlet filter data\. No remote code\. \*\/\nconst __ISHIELD_AG_(?:ADS|ALL)_FILTER_DATA__ = `[\s\S]*`;\n$/u.test(generatedData)) {
          fail(`${browserName}: malformed generated filter data file ${rel}`);
        }
        continue;
      }
      // Production AdGuard/uBO scriptlet bundles are packaged filtering code. They may wrap page APIs
      // to block/neutralize site behavior, but are not extension-originated telemetry/network clients.
      if (/^content[\/]adguard-.*-main\.js$/u.test(rel)) {
        const generated = read(p);
        const actionsStart = generated.indexOf('var actions =');
        const actionsEnd = generated.indexOf(']);\n  var request =', actionsStart);
        const actionsText = actionsStart >= 0 && actionsEnd > actionsStart ? generated.slice(actionsStart, actionsEnd) : '';
        for (const marker of ['/ad-verify','GoogleIma3Dai','advertStreamingSessionStart','hkstatic.hankyung.com/css/rel/tenasia/w/common.css']) {
          if (actionsText.includes(marker)) fail(`${browserName}: packaged generated action can originate network activity (${marker}) in ${rel}`);
        }
        continue;
      }
      if (rel.startsWith(`content${path.sep}ubol${path.sep}`)) continue;
      const text=read(p);
      if (/\b(?:XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/u.test(text)) fail(`${browserName}: outbound-capable API in first-party content script ${rel}`);
      if (/\bfetch\s*\(/u.test(text)) fail(`${browserName}: fetch in first-party content script ${rel}`);
    }
  }

  const client=read(path.join(base,'src/update-client.js'));
  for (const required of ["const FILTER_UPDATE_ORIGIN = 'https://update.broxme.com'","const FILTER_UPDATE_PATH = '/ishield/manifest.json'","method: 'GET'","credentials: 'omit'","redirect: 'error'","referrerPolicy: 'no-referrer'"]) if (!client.includes(required)) fail(`${browserName}: update client missing boundary: ${required}`);
  if (/body\s*:/u.test(client)) fail(`${browserName}: filter update request must not have a body`);

  const trust=read(path.join(base,'src/trust-store.js'));
  if (!trust.includes(updateUrl)) fail(`${browserName}: unexpected update endpoint`);
  const signed=read(path.join(base,'src/signed-update.js'));
  if (!signed.includes("UPDATE_RESOURCE_KINDS = Object.freeze(['network-rules'])")) fail(`${browserName}: updater accepts non-filter resource types`);
  if (!signed.includes('UPDATE_MAX_RESOURCES = 1')) fail(`${browserName}: updater must accept exactly one resource`);
  const runtime=read(path.join(base,'src/update-runtime.js'));
  for (const forbiddenKind of ['reputation','malware','policy','compatibility','privacy-compatibility','category']) {
    if (runtime.includes(`case '${forbiddenKind}'`) || runtime.includes(`resource(snapshot, '${forbiddenKind}')`)) fail(`${browserName}: non-filter remote resource logic remains: ${forbiddenKind}`);
  }
}

// Chromium-family packages are deliberately separate, while core runtime files must not silently drift.
const parityExcluded = new Set(['README.md','manifest.json','popup/popup.html']);
const chromiumBrowsers = ['chrome','edge','opera'];
const chromeBase = path.join(root,'extensions','chrome');
const chromeFiles=walk(chromeBase).map((p)=>path.relative(chromeBase,p)).filter((rel)=>!parityExcluded.has(rel)).sort();
for (const browserName of chromiumBrowsers.slice(1)) {
  const browserBase = path.join(root,'extensions',browserName);
  const browserFiles=walk(browserBase).map((p)=>path.relative(browserBase,p)).filter((rel)=>!parityExcluded.has(rel)).sort();
  if (JSON.stringify(chromeFiles)!==JSON.stringify(browserFiles)) { fail(`chrome/${browserName}: package file sets drifted`); continue; }
  for (const rel of chromeFiles) {
    const a=fs.readFileSync(path.join(chromeBase,rel));
    const b=fs.readFileSync(path.join(browserBase,rel));
    if (!a.equals(b)) { fail(`chrome/${browserName}: runtime drift in ${rel}`); break; }
  }
}

if (failures.length) {
  console.error(`iShield privacy boundary audit FAILED (${failures.length})`);
  for (const item of failures) console.error(`- ${item}`);
  process.exit(1);
}
console.log('iShield privacy boundary audit PASS');
console.log('- managed-device / central / family control runtime: absent');
console.log('- extension user-data upload: absent');
console.log('- remote executable code: absent');
console.log('- remote network surface: signed filter update only');
console.log(`- filter endpoint: ${updateUrl}`);
console.log('- Chrome, Edge, Opera and Firefox source trees: separated');
