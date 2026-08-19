#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const path = process.argv[2] ?? 'build/real-kms-keys.json';
const manifest = JSON.parse(readFileSync(path, 'utf8'));
const retainedSmokeSpecs = [
  'RSA_2048',
  'ECC_NIST_P256',
  'ECC_NIST_EDWARDS25519',
  'ML_DSA_44',
];

for (const spec of retainedSmokeSpecs) {
  assert(!manifest.unavailable?.includes(spec), `${spec} is unavailable in ${manifest.region}`);
  for (const role of ['test', 'other']) {
    const key = manifest.keys?.[`${role}-${spec}`];
    assert(key, `${role}-${spec} was not provisioned`);
    assert.equal(key.spec, spec);
  }
}

console.log(`ok: real-KMS manifest covers ${retainedSmokeSpecs.join(', ')}`);
