import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { canonicalJson, sha256Hex, verifySignedUpdate } from '../extensions/chrome/src/signed-update.js';
import { materializeUpdateResources, compileSignedNetworkRules } from '../extensions/chrome/src/update-runtime.js';

function signEnvelope(resources) {
  const {privateKey,publicKey}=crypto.generateKeyPairSync('ed25519');
  const now=Date.now();
  const unsigned={schemaVersion:1,sequence:1,issuedAtMs:now,expiresAtMs:now+86400000,keyId:'test',resources};
  const signature=crypto.sign(null,Buffer.from(canonicalJson(unsigned)),privateKey).toString('base64url');
  return {bundle:{...unsigned,signature:{algorithm:'Ed25519',value:signature}},trust:{test:publicKey.export({format:'jwk'}).x}};
}

test('signed network-rules filters verify and compile', async()=>{
  const payload={rules:[{host:'ads.example',scope:'host-and-subdomains',resourceTypes:['script','image']}]};
  const resource={kind:'network-rules',version:1,mode:'full',sha256:await sha256Hex(canonicalJson(payload)),payload};
  const {bundle,trust}=signEnvelope([resource]);
  const verified=await verifySignedUpdate(bundle,trust,{nowMs:bundle.issuedAtMs,minSequence:0});
  const materialized=await materializeUpdateResources(null,verified);
  const rules=compileSignedNetworkRules({resources:materialized});
  assert.equal(rules.length,1);
  assert.deepEqual(rules[0].condition.requestDomains,['ads.example']);
});

test('non-filter remote resource is rejected', async()=>{
  const payload={records:[]};
  const resource={kind:'reputation',version:1,mode:'full',sha256:await sha256Hex(canonicalJson(payload)),payload};
  const {bundle,trust}=signEnvelope([resource]);
  await assert.rejects(()=>verifySignedUpdate(bundle,trust,{nowMs:bundle.issuedAtMs,minSequence:0}),/invalid or duplicate update resource kind/u);
});

test('multiple remote resources are rejected', async()=>{
  const p1={rules:[{host:'one.example'}]}, p2={rules:[{host:'two.example'}]};
  const resources=[
    {kind:'network-rules',version:1,mode:'full',sha256:await sha256Hex(canonicalJson(p1)),payload:p1},
    {kind:'network-rules',version:2,mode:'full',sha256:await sha256Hex(canonicalJson(p2)),payload:p2}
  ];
  const {bundle,trust}=signEnvelope(resources);
  await assert.rejects(()=>verifySignedUpdate(bundle,trust,{nowMs:bundle.issuedAtMs,minSequence:0}),/exactly one resource/u);
});

test('compiled signed filters stay within Firefox dynamic-rule budget', () => {
  const payload = { rules: Array.from({ length: 1401 }, (_, index) => ({ host: `quota-${index}.example`, scope: 'exact', resourceTypes: ['main_frame'] })) };
  const snapshot = { resources: [{ kind: 'network-rules', version: 1, mode: 'full', sha256: '0'.repeat(64), payload }] };
  assert.throws(() => compileSignedNetworkRules(snapshot), /compiled signed network rule cap exceeded/);
});
