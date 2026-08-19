#!/usr/bin/env node
import assert from 'node:assert/strict';
import { getFips, setFips } from 'node:crypto';
import { resolve } from 'node:path';

const modulePath = process.argv[2];
if (!modulePath) {
  console.error('usage: ci-check-register-node.mjs <module>');
  process.exit(2);
}

assert.match(process.versions.openssl, /^3\.[0-4](?:\.|$)/u);
setFips(1);
assert.equal(getFips(), 1);
assert.throws(
  () => process.dlopen({ exports: {} }, resolve(modulePath)),
  (error) => {
    assert.equal(error.code, 'ERR_AWSKMS_OPENSSL_VERSION');
    assert.match(error.message, /requires OpenSSL 3\.5 or newer/u);
    assert.match(error.message, /EVP_get1_default_properties/u);
    return true;
  },
);
assert.equal(getFips(), 1);

console.log(
  `ok: Node ${process.version} / OpenSSL ${process.versions.openssl} reports the supported registration error`,
);
