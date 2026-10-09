#!/usr/bin/env node
// iShield clean source module.
// Generates the Ed25519 key pair that signs your filter updates. The PRIVATE key is written
// outside the repository (default ~/.ishield/update-signing-key.pem, mode 600) and must never be
// committed or uploaded; the PUBLIC key is printed for extensions/*/src/trust-store.js.
//
//   node scripts/ishield_update_keys.mjs [--key ~/.ishield/update-signing-key.pem]

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
const keyPath = path.resolve(args.includes('--key') ? args[args.indexOf('--key') + 1] : path.join(os.homedir(), '.ishield', 'update-signing-key.pem'));

export function publicKeyOf(privateKeyObject) {
  return crypto.createPublicKey(privateKeyObject).export({ format: 'jwk' }).x;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (fs.existsSync(keyPath)) {
    const existing = crypto.createPrivateKey(fs.readFileSync(keyPath));
    console.log(`A signing key already exists at ${keyPath} (not overwritten).`);
    console.log(`Public key: ${publicKeyOf(existing)}`);
    process.exit(0);
  }
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  console.log(`Private signing key written to ${keyPath} (mode 600). Back it up somewhere safe; never commit or upload it.`);
  console.log(`Public key: ${publicKeyOf(privateKey)}`);
}
