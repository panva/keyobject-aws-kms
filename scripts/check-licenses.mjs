#!/usr/bin/env node
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const manifestPath = join(root, 'third_party', 'components.json');
const licenses = join(root, 'third_party', 'licenses');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const fetchCmake = readFileSync(join(root, 'cmake', 'FetchAwsSdkKms.cmake'), 'utf8');
const sdkTag = fetchCmake.match(
  /^set\(AWSKMS_AWS_SDK_TAG "([^"]+)" CACHE STRING$/m,
)?.[1];

assert.equal(manifest.schemaVersion, 1);
assert.ok(sdkTag, 'could not read AWSKMS_AWS_SDK_TAG');
assert.equal(manifest.awsSdkTag, sdkTag, 'AWS SDK component inventory drift');

const expectedComponents = new Map([
  ['ada', { licenseExpression: 'MIT', targets: 'all' }],
  ['aws-cpp-sdk-core', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-cpp-sdk-kms', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-crt-cpp', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-auth', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-cal', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-common', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-compression', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-event-stream', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-http', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-io', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-mqtt', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-s3', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-c-sdkutils', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['aws-checksums', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  ['s2n-tls', { licenseExpression: 'Apache-2.0', targets: 'all' }],
  [
    'cjson',
    {
      version: '1.7.19',
      license: 'cJSON-MIT.txt',
      notice: null,
      licenseExpression: 'MIT',
      targets: 'all',
    },
  ],
  [
    'libcbor',
    {
      version: '0.13.0',
      license: 'libcbor-MIT.txt',
      notice: null,
      licenseExpression: 'MIT',
      targets: 'all',
    },
  ],
  [
    'tinyxml2',
    {
      version: '11.0.0',
      license: 'tinyxml2-zlib.txt',
      notice: null,
      licenseExpression: 'Zlib',
      targets: 'all',
    },
  ],
  [
    'xxhash',
    {
      version: '0.8.3',
      license: 'xxHash-BSD-2-Clause.txt',
      notice: null,
      licenseExpression: 'BSD-2-Clause',
      targets: 'all',
    },
  ],
  [
    'apple-commoncrypto-spi',
    {
      license: 'APSL-2.0.txt',
      notice: 'Apple-CommonCrypto-SPI-NOTICE.txt',
      licenseExpression: 'APSL-2.0',
      targets: 'darwin',
    },
  ],
  [
    'libstdc++',
    {
      license: 'GPL-3.0.txt',
      exception: 'GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt',
      notice: null,
      licenseExpression: 'GPL-3.0-or-later WITH GCC-exception-3.1',
      targets: 'linux',
    },
  ],
  [
    'libgcc',
    {
      license: 'GPL-3.0.txt',
      exception: 'GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt',
      notice: null,
      licenseExpression: 'GPL-3.0-or-later WITH GCC-exception-3.1',
      targets: 'linux',
    },
  ],
]);
const required = new Set(expectedComponents.keys());
const names = new Set(manifest.components.map(({ name }) => name));
assert.equal(names.size, manifest.components.length, 'duplicate component name');
assert.deepEqual([...names].sort(), [...required].sort(), 'component inventory drift');

const allowedTargets = new Set(['all', 'darwin', 'linux']);
for (const component of manifest.components) {
  assert.ok(
    allowedTargets.has(component.targets),
    `${component.name} has unsupported targets ${component.targets}`,
  );
  const expected = expectedComponents.get(component.name);
  for (const [field, value] of Object.entries(expected)) {
    assert.equal(component[field], value, `${component.name} ${field} drift`);
  }
}

for (const name of [
  'aws-cpp-sdk-core',
  'aws-cpp-sdk-kms',
]) {
  const component = manifest.components.find((entry) => entry.name === name);
  assert.equal(component.version, sdkTag, `${name} version drift`);
}
for (const component of manifest.components.filter(({ commit }) => commit != null)) {
  assert.match(component.commit, /^[0-9a-f]{40}$/, `${component.name} commit`);
}
assert.equal(
  manifest.components.find(({ name }) => name === 'apple-commoncrypto-spi').commit,
  manifest.components.find(({ name }) => name === 'aws-c-cal').commit,
  'apple-commoncrypto-spi commit must match aws-c-cal',
);

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
