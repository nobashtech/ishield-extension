#!/usr/bin/env node
// iShield clean source module.
// Turns update/filters.txt into the signed manifest the extension downloads from
// https://update.broxme.com/ishield/manifest.json, and refuses to write anything the extension's
// own verifier would reject.
//
//   node scripts/publish_filters.mjs [--input update/filters.txt] [--out dist/update/ishield]
//        [--key ~/.ishield/update-signing-key.pem] [--key-id broxme-update-1] [--validity-days 13]
//
// A signed manifest is valid for at most 14 days, so re-run this (a weekly job is fine) and
// re-upload manifest.json; every run gets a new, strictly increasing sequence number.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { canonicalJson, sha256Hex, UPDATE_MAX_VALIDITY_MS, verifySignedUpdate } from '../extensions/chrome/src/signed-update.js';
import { compileSignedNetworkRules } from '../extensions/chrome/src/update-runtime.js';
import { UPDATE_TRUST_STORE } from '../extensions/chrome/src/trust-store.js';
import { parseFiltersText } from './lib/filters-text.mjs';
import { publicKeyOf } from './ishield_update_keys.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DAY_MS = 24 * 60 * 60 * 1000;

export async function buildSignedManifest({ filtersText, privateKey, keyId, nowMs = Date.now(), validityDays = 13, sequence = Math.floor(nowMs / 1000) }) {
  const { rules, errors } = parseFiltersText(filtersText);
  if (errors.length > 0) throw new Error(`filters.txt has ${errors.length} problem(s):\n  ${errors.join('\n  ')}`);
  if (rules.length === 0) throw new Error('filters.txt contains no rules');
  const validityMs = validityDays * DAY_MS;
  if (!(validityMs > 0 && validityMs <= UPDATE_MAX_VALIDITY_MS)) throw new Error('validity must be between 0 and 14 days');
  const payload = { rules };
  const unsigned = {
    schemaVersion: 1,
    sequence,
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + validityMs,
    keyId,
    resources: [{ kind: 'network-rules', version: sequence, mode: 'full', sha256: await sha256Hex(canonicalJson(payload)), payload }],
  };
  const signature = crypto.sign(null, Buffer.from(canonicalJson(unsigned)), privateKey).toString('base64url');
  const manifest = { ...unsigned, signature: { algorithm: 'Ed25519', value: signature } };
  // Dry run through the extension's real verifier and rule compiler.
  const trust = { [keyId]: publicKeyOf(privateKey) };
  const verified = await verifySignedUpdate(manifest, trust, { nowMs, minSequence: 0 });
  const compiled = compileSignedNetworkRules({ resources: [{ ...verified.resources[0], mode: 'full' }] });
  return { manifest, ruleCount: rules.length, compiledRuleCount: compiled.length, publicKey: trust[keyId] };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const option = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
  const input = path.resolve(root, option('--input', 'update/filters.txt'));
  const out = path.resolve(root, option('--out', 'dist/update/ishield'));
  const keyPath = path.resolve(option('--key', path.join(os.homedir(), '.ishield', 'update-signing-key.pem')));
  const keyId = option('--key-id', Object.keys(UPDATE_TRUST_STORE)[0] ?? 'broxme-update-1');
  const validityDays = Number(option('--validity-days', '13'));
  if (!fs.existsSync(keyPath)) { console.error(`No signing key at ${keyPath}. Run: node scripts/ishield_update_keys.mjs`); process.exit(1); }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(keyPath));
  const built = await buildSignedManifest({ filtersText: fs.readFileSync(input, 'utf8'), privateKey, keyId, validityDays });
  if (UPDATE_TRUST_STORE[keyId] !== undefined && UPDATE_TRUST_STORE[keyId] !== built.publicKey) {
    console.error(`The key at ${keyPath} does not match the public key trusted for "${keyId}" in trust-store.js. Extensions would reject this update.`);
    process.exit(1);
  }
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(built.manifest));
  fs.copyFileSync(input, path.join(out, 'filters.txt'));
  console.log(`Signed ${built.ruleCount} rule(s) as sequence ${built.manifest.sequence}; valid until ${new Date(built.manifest.expiresAtMs).toISOString()}.`);
  console.log(`Upload ${path.relative(root, out)}/manifest.json (Content-Type: application/json) to https://update.broxme.com/ishield/manifest.json`);
  console.log('filters.txt is copied alongside as the human-readable source; the extension only reads manifest.json.');
}
