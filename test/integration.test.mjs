/*
 * The remaining ways Node reaches a store-backed key, beyond a preloaded
 * KeyObject: a URL used inline as the key, the permission model, and the
 * passphrase option that KMS has no use for.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  createPrivateKey,
  createPublicKey,
  createSign,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

const DATA = randomBytes(128);
const URI = 'awskms:key-id=alias/test-RSA_2048';

describe('a URL used inline as the signing key', () => {
  // A distinct path through Node: the sign job loads the key itself rather than
  // being handed an already-loaded KeyObject.
  test('crypto.sign accepts a URL directly', () => {
    const signature = cryptoSign('sha256', DATA, { key: new URL(URI) });
    assert.ok(signature.byteLength > 0);

    const publicKey = createPublicKey(createPrivateKey({ key: new URL(URI) }));
    assert.equal(cryptoVerify('sha256', DATA, publicKey, signature), true);
  });

  test('with an explicit property query', () => {
    const signature = cryptoSign('sha256', DATA, {
      key: new URL(URI),
      properties: 'provider=awskms',
    });
    const publicKey = createPublicKey(createPrivateKey({ key: new URL(URI) }));
    assert.equal(cryptoVerify('sha256', DATA, publicKey, signature), true);
  });

  test('createSign().sign() accepts a URL directly', () => {
    const signature = createSign('sha256').update(DATA).sign({ key: new URL(URI) });
    const publicKey = createPublicKey(createPrivateKey({ key: new URL(URI) }));
    assert.equal(cryptoVerify('sha256', DATA, publicKey, signature), true);
  });

  test('a bad URI fails at the call, with our error code', () => {
    assert.throws(() => cryptoSign('sha256', DATA, { key: new URL('awskms:nope=1') }), {
      code: 'ERR_OSSL_AWSKMS_INVALID_URI',
    });
  });
});

describe('the passphrase option', () => {
  // KMS has no PIN. The passphrase callback is deliberately never invoked, because
  // Node's implementation cannot distinguish "no passphrase supplied" from "asked
  // and got nothing" -- calling it would make every ordinary load fail with
  // ERR_MISSING_PASSPHRASE.
  test('is harmless when supplied', () => {
    const key = createPrivateKey({ key: new URL(URI), passphrase: 'ignored' });
    assert.equal(key.asymmetricKeyType, 'rsa');
    assert.equal(
      cryptoVerify('sha256', DATA, createPublicKey(key), cryptoSign('sha256', DATA, key)),
      true,
    );
  });

  test('is harmless as a Buffer, too', () => {
    const key = createPrivateKey({ key: new URL(URI), passphrase: Buffer.from('ignored') });
    assert.equal(key.asymmetricKeyType, 'rsa');
  });

  test('omitting it does not trigger a passphrase prompt or error', () => {
    // The failure mode this guards against is ERR_MISSING_PASSPHRASE, which is
    // what happens if a loader asks for a passphrase it was not given.
    const key = createPrivateKey({ key: new URL(URI) });
    assert.equal(key.asymmetricKeyType, 'rsa');
  });
});

/*
 * The permission model. Node gates STORE loaders behind --allow-openssl-store,
 * separately from fs and net, precisely because a loader can reach files,
 * devices, tokens or the network without those scopes noticing -- which is
 * exactly what this provider does.
 *
 * These re-exec node, so they need the config path the driver generated.
 */
const cnf = process.env.AWSKMS_CNF;

function child(extraArgs, code) {
  return spawnSync(
    process.execPath,
    [`--openssl-config=${cnf}`, ...extraArgs, '-e', code],
    { encoding: 'utf8', env: process.env },
  );
}

describe('the permission model', { skip: !cnf ? 'no AWSKMS_CNF' : false }, () => {
  const loadAndSign = `
    const { createPrivateKey, createPublicKey, sign, verify } = require('crypto');
    const key = createPrivateKey({ key: new URL('${URI}') });
    const sig = sign('sha256', Buffer.from('hello'), key);
    if (verify('sha256', Buffer.from('hello'), createPublicKey(key), sig) !== true)
      throw new Error('verify failed');
    console.log('OK');
  `;

  test('works with --allow-openssl-store', () => {
    const r = child(['--permission', '--allow-openssl-store'], loadAndSign);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /OK/);
  });

  test('is denied without it', () => {
    const r = child(['--permission'], loadAndSign);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /ERR_ACCESS_DENIED/);
  });

  test('the denial names the OpenSSLStore permission and leaks no URI', () => {
    // Node redacts the URI from the permission error on purpose, since a URI can
    // carry credentials. Ours cannot today, but the guarantee is worth pinning.
    const r = child(
      ['--permission'],
      `
      const { createPrivateKey } = require('crypto');
      try {
        createPrivateKey({ key: new URL('${URI}') });
        console.log('UNEXPECTED SUCCESS');
      } catch (err) {
        console.log(JSON.stringify({
          code: err.code,
          permission: err.permission,
          resource: err.resource,
          mentionsUri: /alias\\/test-RSA_2048/.test(err.stack ?? ''),
        }));
      }
      `,
    );
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.code, 'ERR_ACCESS_DENIED');
    assert.equal(out.permission, 'OpenSSLStore');
    assert.equal(out.resource, '');
    assert.equal(out.mentionsUri, false);
  });

  test('works without fs read permission, since the loader bypasses that scope', () => {
    // This is the documented consequence of --allow-openssl-store granting broad
    // authority: it is not constrained by fs.read.
    const r = child(['--permission', '--allow-openssl-store'], loadAndSign);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /OK/);
  });

  test('the permission can be dropped at runtime', () => {
    const r = child(
      ['--permission', '--allow-openssl-store'],
      `
      const { createPrivateKey } = require('crypto');
      createPrivateKey({ key: new URL('${URI}') });   // fine
      process.permission.drop('openssl.store');
      if (process.permission.has('openssl.store') !== false) throw new Error('still granted');
      try {
        createPrivateKey({ key: new URL('${URI}') });
        console.log('UNEXPECTED SUCCESS');
      } catch (err) {
        console.log(err.code);
      }
      `,
    );
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /ERR_ACCESS_DENIED/);
  });
});
