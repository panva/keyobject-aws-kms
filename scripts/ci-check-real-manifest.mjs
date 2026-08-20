#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const path = process.argv[2] ?? 'build/real-kms-keys.json';
const manifest = JSON.parse(readFileSync(path, 'utf8'));
assert.deepEqual(
  manifest.roles,
  ['test'],
  'the focused real-KMS manifest must provision only the test role',
);
assert(
  Object.values(manifest.keys ?? {}).every((key) => key.role === 'test'),
  'the focused real-KMS manifest contains a key outside the test role',
);
const retainedSmokeSpecs = [
  'RSA_2048',
  'ECC_NIST_P256',
  'ECC_NIST_EDWARDS25519',
  'ML_DSA_44',
];

for (const spec of retainedSmokeSpecs) {
  assert(!manifest.unavailable?.includes(spec), `${spec} is unavailable in ${manifest.region}`);
  const key = manifest.keys?.[`test-${spec}`];
  assert(key, `test-${spec} was not provisioned`);
  assert.equal(key.spec, spec);
}

console.log(`ok: real-KMS manifest covers ${retainedSmokeSpecs.join(', ')}`);
