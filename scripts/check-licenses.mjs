#!/usr/bin/env node
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const manifestPath = join(root, 'third_party', 'components.json');
const licenses = join(root, 'third_party', 'licenses');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

assert.equal(manifest.schemaVersion, 1);
assert.equal(manifest.awsSdkTag, '1.11.855');

const required = new Set([
  'ada',
  'aws-cpp-sdk-core',
  'aws-cpp-sdk-kms',
  'aws-sdk-cpp-third-party',
  'aws-crt-cpp',
  'aws-c-auth',
  'aws-c-cal',
  'aws-c-common',
  'aws-c-compression',
  'aws-c-event-stream',
  'aws-c-http',
  'aws-c-io',
  'aws-c-mqtt',
  'aws-c-s3',
  'aws-c-sdkutils',
  'aws-checksums',
  's2n-tls',
  'libstdc++',
  'libgcc',
]);
const names = new Set(manifest.components.map(({ name }) => name));
assert.deepEqual([...names].sort(), [...required].sort(), 'component inventory drift');

const referenced = new Set();
for (const component of manifest.components) {
  for (const field of ['license', 'exception', 'notice']) {
    const file = component[field];
    if (file == null) continue;
    assert.equal(basename(file), file, `${component.name} ${field} must be a filename`);
    const path = join(licenses, file);
    assert.ok(existsSync(path), `${component.name} is missing ${field} ${file}`);
    assert.ok(readFileSync(path).length > 0, `${path} is empty`);
    referenced.add(file);
  }
}

const actual = readdirSync(licenses).sort();
assert.deepEqual(actual, [...referenced].sort(), 'unreferenced or missing license file');
console.log(`license inventory: ${manifest.components.length} components, ${actual.length} files`);
