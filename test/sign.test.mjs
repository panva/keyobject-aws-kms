/*
 * Signing and verifying with KMS-backed keys.
 *
 * Signing goes to KMS; verification is local against the cached public key. Both
 * of Node's code paths are exercised deliberately, because they reach the provider
 * completely differently:
 *
 *   crypto.sign(md, data, key)               -> EVP_DigestSignInit + digest_sign_*
 *   createSign(md).update(data).sign(key)    -> EVP_PKEY_sign on a digest
 *
 * and the callback form runs on the libuv threadpool rather than the main thread,
 * which is worth covering separately for something that holds a network client.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  constants,
  createPrivateKey,
  createPublicKey,
  createSign,
  createVerify,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { uri } from './inventory.mjs';
import { hasMlDsa, mlDsaSkipReason } from './capabilities.mjs';
import { skipFor, skipForAny } from './real-keys.mjs';

const DATA = randomBytes(1024);

const CASES = [
  { label: 'RSA_2048', keyType: 'rsa', digests: ['sha256', 'sha384', 'sha512'] },
  { label: 'RSA_3072', keyType: 'rsa', digests: ['sha256'] },
  { label: 'RSA_4096', keyType: 'rsa', digests: ['sha512'] },
  { label: 'ECC_NIST_P256', keyType: 'ec', digests: ['sha256'] },
  { label: 'ECC_NIST_P384', keyType: 'ec', digests: ['sha384'] },
  { label: 'ECC_NIST_P521', keyType: 'ec', digests: ['sha512'] },
  { label: 'ECC_SECG_P256K1', keyType: 'ec', digests: ['sha256'] },
];

const load = (label) => createPrivateKey({ key: new URL(uri('test', label)) });

for (const c of CASES) {
  describe(`${c.label} signing`, { skip: skipFor(c.label) }, () => {
    for (const digest of c.digests) {
      test(`one-shot sign and verify (${digest})`, () => {
        const key = load(c.label);
        const pub = createPublicKey(key);
        const sig = cryptoSign(digest, DATA, key);
        assert.ok(sig.byteLength > 0);
        assert.equal(cryptoVerify(digest, DATA, pub, sig), true);
        // Node also allows verifying with the private KeyObject, which reaches
        // our provider rather than the default one.
        assert.equal(cryptoVerify(digest, DATA, key, sig), true);
        // A tampered message must be false, not an exception.
        const other = Buffer.from(DATA);
        other[0] ^= 0xff;
        assert.equal(cryptoVerify(digest, other, pub, sig), false);
      });

      test(`streaming sign and verify (${digest})`, () => {
        const key = load(c.label);
        const pub = createPublicKey(key);
        // Chunked on purpose: this is the digest_sign_update path.
        const signer = createSign(digest);
        signer.update(DATA.subarray(0, 100));
        signer.update(DATA.subarray(100));
        const sig = signer.sign(key);
        assert.ok(sig.byteLength > 0);

        assert.equal(createVerify(digest).update(DATA).verify(pub, sig), true);
        assert.equal(createVerify(digest).update(DATA).verify(key, sig), true);
      });

      test(`the two paths produce mutually verifiable signatures (${digest})`, () => {
        const key = load(c.label);
        const pub = createPublicKey(key);
        const oneShot = cryptoSign(digest, DATA, key);
        const streamed = createSign(digest).update(DATA).sign(key);
        // Not byte equality: PSS and ECDSA are randomised. What matters is that
        // both paths made the same request shape and both verify.
        assert.equal(cryptoVerify(digest, DATA, pub, streamed), true);
        assert.equal(createVerify(digest).update(DATA).verify(pub, oneShot), true);
      });

      test(`async sign and verify on the threadpool (${digest})`, async () => {
        const key = load(c.label);
        const pub = createPublicKey(key);
        const sig = await new Promise((resolve, reject) =>
          cryptoSign(digest, DATA, key, (err, s) => (err ? reject(err) : resolve(s))),
        );
        assert.ok(sig.byteLength > 0);
        for (const k of [pub, key]) {
          assert.equal(
            await new Promise((resolve, reject) =>
              cryptoVerify(digest, DATA, k, sig, (err, ok) =>
                err ? reject(err) : resolve(ok),
              ),
            ),
            true,
          );
        }
      });
    }

    test('a signature verifies against an independently imported public key', () => {
      // Proves the signature is valid on its own terms, not merely
      // self-consistent with our provider: this public key is a plain
      // default-provider key parsed from SPKI.
      const key = load(c.label);
      const spki = createPublicKey(key).export({ type: 'spki', format: 'der' });
      const imported = createPublicKey({ key: spki, format: 'der', type: 'spki' });
      const digest = c.digests[0];
      const sig = cryptoSign(digest, DATA, key);
      assert.equal(cryptoVerify(digest, DATA, imported, sig), true);
    });

    test('a signature from a different key does not verify', () => {
      const digest = c.digests[0];
      const sig = cryptoSign(digest, DATA, load(c.label));
      const otherPub = createPublicKey(
        createPrivateKey({ key: new URL(uri('other', c.label)) }),
      );
      assert.equal(cryptoVerify(digest, DATA, otherPub, sig), false);
    });
  });
}

describe('RSA padding and salt length', { skip: skipFor('RSA_2048') }, () => {
  const key = () => load('RSA_2048');

  test('PKCS#1 v1.5 is the default', () => {
    const k = key();
    const sig = cryptoSign('sha256', DATA, k);
    assert.equal(
      cryptoVerify(
        'sha256',
        DATA,
        { key: createPublicKey(k), padding: constants.RSA_PKCS1_PADDING },
        sig,
      ),
      true,
    );
  });

  test('PSS with an explicit digest-length salt', () => {
    const k = key();
    const options = {
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32, // == SHA-256 output, which is what KMS uses
    };
    const sig = cryptoSign('sha256', DATA, { key: k, ...options });
    assert.equal(
      cryptoVerify('sha256', DATA, { key: createPublicKey(k), ...options }, sig),
      true,
    );
  });

  test('PSS with saltLength omitted still works', () => {
    // Node defaults to RSA_PSS_SALTLEN_MAX_SIGN here, which is the same value as
    // AUTO. KMS cannot vary its salt length, but AUTO expresses no requirement,
    // so this is accepted and signed with a digest-length salt -- rejecting it
    // would break the most idiomatic PSS call in Node.
    const k = key();
    const sig = createSign('sha256')
      .update(DATA)
      .sign({ key: k, padding: constants.RSA_PKCS1_PSS_PADDING });
    assert.ok(sig.byteLength > 0);
    assert.equal(
      createVerify('sha256').update(DATA).verify(
        {
          key: createPublicKey(k),
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_AUTO,
        },
        sig,
      ),
      true,
    );
  });

  test('an explicitly different salt length is refused, not silently changed', () => {
    // The caller demanded something KMS cannot do. Signing with a different salt
    // length than was asked for would be worse than failing.
    assert.throws(
      () =>
        cryptoSign('sha256', DATA, {
          key: key(),
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 64,
        }),
      { code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_SALT_LENGTH' },
    );
  });

  test('a maximal salt length is refused', () => {
    // -3 is OpenSSL's RSA_PSS_SALTLEN_MAX. Node does not export a constant for
    // it (only _DIGEST = -1 and _MAX_SIGN = _AUTO = -2), so it has to be written
    // literally -- but a caller can still ask for it, and it means "use the
    // largest salt that fits", which KMS cannot do.
    assert.throws(
      () =>
        cryptoSign('sha256', DATA, {
          key: key(),
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: -3,
        }),
      { code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_SALT_LENGTH' },
    );
  });

  test('AUTO and DIGEST both mean "no requirement" and are accepted', () => {
    const k = key();
    const pub = createPublicKey(k);
    for (const saltLength of [
      constants.RSA_PSS_SALTLEN_DIGEST,
      constants.RSA_PSS_SALTLEN_AUTO,
    ]) {
      const sig = cryptoSign('sha256', DATA, {
        key: k,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength,
      });
      assert.equal(
        cryptoVerify(
          'sha256',
          DATA,
          {
            key: pub,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: constants.RSA_PSS_SALTLEN_AUTO,
          },
          sig,
        ),
        true,
        `saltLength ${saltLength} should verify`,
      );
    }
  });
});

describe('ECDSA encoding', { skip: skipForAny(['ECC_NIST_P256', 'ECC_SECG_P256K1']) }, () => {
  test('dsaEncoding ieee-p1363 round-trips', () => {
    // KMS returns DER; Node converts to and from P1363 itself using the curve
    // order, which it gets from the group name our keymgmt reports.
    const key = load('ECC_NIST_P256');
    const pub = createPublicKey(key);
    const options = { dsaEncoding: 'ieee-p1363' };
    const sig = cryptoSign('sha256', DATA, { key, ...options });
    assert.equal(sig.byteLength, 64, 'P1363 for P-256 is exactly 2*32 bytes');
    assert.equal(cryptoVerify('sha256', DATA, { key: pub, ...options }, sig), true);
  });

  test('the default encoding is DER', () => {
    const key = load('ECC_NIST_P256');
    const sig = cryptoSign('sha256', DATA, key);
    assert.equal(sig[0], 0x30, 'a DER SEQUENCE');
    assert.ok(sig.byteLength <= 72 && sig.byteLength >= 68);
  });

  test('secp256k1 signatures are not low-S normalised', () => {
    // Documented behaviour rather than a defect: KMS does not normalise S, and
    // OpenSSL accepts both. Consumers needing BIP-62/EIP-2 canonical form must
    // normalise themselves. This test just pins that we pass KMS's bytes through
    // untouched, by checking a signature verifies as-is.
    const key = load('ECC_SECG_P256K1');
    const sig = cryptoSign('sha256', DATA, key);
    assert.equal(cryptoVerify('sha256', DATA, createPublicKey(key), sig), true);
  });
});

describe('digest constraints', { skip: skipForAny(['ECC_NIST_P256', 'RSA_2048']) }, () => {
  test('an EC key refuses a digest its curve does not use', () => {
    // KMS binds exactly one digest per curve, so signing P-256 with SHA-384 has
    // no KMS equivalent and must fail rather than silently use SHA-256.
    assert.throws(() => cryptoSign('sha384', DATA, load('ECC_NIST_P256')), {
      code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_DIGEST',
    });
  });

  // These are all real, available digests -- the refusal is about KMS not
  // offering them, not about the digest being unavailable. The reason code is
  // asserted exactly because it is the ONLY diagnosis that reaches a caller:
  // Node renders lib + reason and drops the detail text, so misreporting one of
  // these as a length mismatch (which an earlier ordering of the checks did,
  // since an unsupported digest has no expected length) leaves no way at all to
  // work out that the digest was the problem.
  for (const digest of ['sha1', 'sha3-256', 'sha3-512', 'sha512-256', 'shake256']) {
    test(`RSA refuses ${digest}, which KMS does not offer`, () => {
      assert.throws(() => cryptoSign(digest, DATA, load('RSA_2048')), {
        code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_DIGEST',
      });
    });
  }
});

describe('request accounting', { skip: skipForAny(['RSA_2048', 'ECC_NIST_P256']) }, () => {
  test('signing does not disturb ordinary keys in the same process', () => {
    const ours = load('RSA_2048');
    const theirs = generateKeyPairSync('rsa', { modulusLength: 2048 });

    const a = cryptoSign('sha256', DATA, ours);
    const b = cryptoSign('sha256', DATA, theirs.privateKey);

    assert.equal(cryptoVerify('sha256', DATA, createPublicKey(ours), a), true);
    assert.equal(cryptoVerify('sha256', DATA, theirs.publicKey, b), true);
    // And the two must not be interchangeable.
    assert.equal(cryptoVerify('sha256', DATA, theirs.publicKey, a), false);
  });
});

/*
 * These read the stub's own record of what the provider asked for. Skipped when
 * driving real KMS, and when the in-provider stub backend is used (there is no
 * HTTP endpoint to ask).
 */
const endpoint = process.env.AWSKMS_ENDPOINT;

/* The stub's record of what the provider actually asked for. Module scope so both
 * the accounting suite and the ML-DSA mu check can use it. */
const log = async () => (await (await fetch(`${endpoint}/__requests`)).json()).requests;
const clear = () => fetch(`${endpoint}/__requests`, { method: 'DELETE' });

/* Reading what the provider asked for needs the HTTP stub, which only exists for
 * the aws backend. The behaviour these tests check is exercised either way; it is
 * only the request-count assertions that need the log. */
const needsLog = !endpoint ? 'needs the stub request log (aws backend)' : false;

describe('KMS request accounting', { skip: !endpoint || process.env.AWSKMS_TEST_REAL === '1' }, () => {
  test('one signature costs exactly one kms:Sign', async () => {
    const key = load('RSA_2048');
    await clear();
    cryptoSign('sha256', DATA, key);
    const signs = (await log()).filter((r) => r.target === 'TrentService.Sign');
    // The size probe (sig == NULL) happens on this path and must not become a
    // billable request; more than one Sign here would mean it did.
    assert.equal(signs.length, 1, `expected 1 Sign, saw ${signs.length}`);
    assert.equal(signs[0].messageType, 'DIGEST');
    assert.equal(signs[0].messageLength, 32, 'a SHA-256 digest, not the message');
    assert.equal(signs[0].signingAlgorithm, 'RSASSA_PKCS1_V1_5_SHA_256');
  });

  test('the streaming path also costs exactly one, and sends a digest', async () => {
    const key = load('ECC_NIST_P384');
    await clear();
    createSign('sha384').update(DATA).sign(key);
    const signs = (await log()).filter((r) => r.target === 'TrentService.Sign');
    assert.equal(signs.length, 1);
    assert.equal(signs[0].messageType, 'DIGEST');
    assert.equal(signs[0].messageLength, 48);
    assert.equal(signs[0].signingAlgorithm, 'ECDSA_SHA_384');
  });

  test('verification never calls KMS', async () => {
    const key = load('RSA_2048');
    const pub = createPublicKey(key);
    const sig = cryptoSign('sha256', DATA, key);
    await clear();
    assert.equal(cryptoVerify('sha256', DATA, pub, sig), true);
    assert.equal(cryptoVerify('sha256', DATA, key, sig), true);
    assert.equal(createVerify('sha256').update(DATA).verify(pub, sig), true);
    assert.deepEqual(await log(), [], 'verification must be entirely local');
  });

  test('PSS asks KMS for the PSS algorithm', async () => {
    const key = load('RSA_2048');
    await clear();
    cryptoSign('sha256', DATA, {
      key,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    });
    const signs = (await log()).filter((r) => r.target === 'TrentService.Sign');
    assert.equal(signs.length, 1);
    assert.equal(signs[0].signingAlgorithm, 'RSASSA_PSS_SHA_256');
  });

  test('a refused salt length costs nothing', async () => {
    await clear();
    assert.throws(() =>
      cryptoSign('sha256', DATA, {
        key: load('RSA_2048'),
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 64,
      }),
    );
    const signs = (await log()).filter((r) => r.target === 'TrentService.Sign');
    assert.equal(signs.length, 0, 'must be rejected before any request is made');
  });
});

describe('Ed25519', { skip: skipFor('ECC_NIST_EDWARDS25519') }, () => {
  const load25519 = () => load('ECC_NIST_EDWARDS25519');

  test('signs and verifies with no digest', () => {
    const key = load25519();
    const pub = createPublicKey(key);
    const msg = randomBytes(100);
    // A null algorithm is how Node expresses PureEdDSA.
    const sig = cryptoSign(null, msg, key);
    assert.equal(sig.byteLength, 64);
    assert.equal(cryptoVerify(null, msg, pub, sig), true);
    assert.equal(cryptoVerify(null, msg, key, sig), true);

    const tampered = Buffer.from(msg);
    tampered[0] ^= 0xff;
    assert.equal(cryptoVerify(null, tampered, pub, sig), false);
  });

  test('the signature verifies against an independently imported public key', () => {
    const key = load25519();
    const msg = randomBytes(64);
    const spki = createPublicKey(key).export({ type: 'spki', format: 'der' });
    const imported = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    assert.equal(cryptoVerify(null, msg, imported, cryptoSign(null, msg, key)), true);
  });

  test('async signing works on the threadpool', async () => {
    const key = load25519();
    const msg = randomBytes(32);
    const sig = await new Promise((resolve, reject) =>
      cryptoSign(null, msg, key, (err, s) => (err ? reject(err) : resolve(s))),
    );
    assert.equal(sig.byteLength, 64);
    assert.equal(cryptoVerify(null, msg, createPublicKey(key), sig), true);
  });

  test('a supplied digest is refused rather than ignored', () => {
    // Otherwise this would silently produce a pure-EdDSA signature over the
    // message, which verifies but is not what was asked for.
    assert.throws(() => cryptoSign('sha512', randomBytes(32), load25519()), {
      code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_DIGEST',
    });
  });

  test('exactly 4096 bytes is the largest message that signs', () => {
    const key = load25519();
    const msg = randomBytes(4096);
    const sig = cryptoSign(null, msg, key);
    assert.equal(cryptoVerify(null, msg, createPublicKey(key), sig), true);
  });

  test('4097 bytes fails with a typed, explanatory error', () => {
    // Inherent to KMS, not an implementation limit: PureEdDSA needs the whole
    // message and KMS caps Message at 4096 bytes.
    assert.throws(() => cryptoSign(null, randomBytes(4097), load25519()), (err) => {
      assert.equal(err.code, 'ERR_OSSL_AWSKMS_MESSAGE_TOO_LARGE');
      return true;
    });
  });

  test('an empty message fails, because KMS requires at least one byte', () => {
    assert.throws(() => cryptoSign(null, Buffer.alloc(0), load25519()), {
      code: 'ERR_OSSL_AWSKMS_EMPTY_MESSAGE',
    });
  });
});

/*
 * ML-DSA. Unlike Ed25519 there is no message size limit, because the provider
 * computes the 64-byte FIPS 204 mu locally and sends that instead of the message.
 *
 * Needs the aws backend: EXTERNAL_MU signing requires OpenSSL 3.5's
 * EVP_PKEY_sign_message_init, which the in-provider stub deliberately avoids
 * referencing (it is a linker symbol, and depending on it would break the
 * one-build-any-host property). test/kms-stub.mjs shells out to pkeyutl instead.
 */

for (const [label, sigLen, pubLen] of [
  ['ML_DSA_44', 2420, 1312],
  ['ML_DSA_65', 3309, 1952],
  ['ML_DSA_87', 4627, 2592],
]) {
  describe(`${label}`, { skip: skipFor(label, !hasMlDsa ? mlDsaSkipReason : false) }, () => {
    test('signs and verifies with no digest', () => {
      const key = load(label);
      const pub = createPublicKey(key);
      const msg = randomBytes(200);
      const sig = cryptoSign(null, msg, key);
      assert.equal(sig.byteLength, sigLen);
      assert.equal(cryptoVerify(null, msg, pub, sig), true);
      assert.equal(cryptoVerify(null, msg, key, sig), true);

      const tampered = Buffer.from(msg);
      tampered[0] ^= 0xff;
      assert.equal(cryptoVerify(null, tampered, pub, sig), false);
    });

    test('the signature verifies as ordinary pure ML-DSA', async () => {
      // The real proof that EXTERNAL_MU was used correctly: an independently
      // imported default-provider public key must accept the signature as a
      // plain pure-ML-DSA signature over the original message.
      const key = load(label);
      const msg = randomBytes(500);
      const spki = createPublicKey(key).export({ type: 'spki', format: 'der' });
      const imported = createPublicKey({ key: spki, format: 'der', type: 'spki' });
      assert.equal(cryptoVerify(null, msg, imported, cryptoSign(null, msg, key)), true);
    });

    test('no message size limit, unlike Ed25519', () => {
      // 100 KB: far past the 4096-byte Message cap, which mu removes entirely.
      const key = load(label);
      const msg = randomBytes(100 * 1024);
      const sig = cryptoSign(null, msg, key);
      assert.equal(cryptoVerify(null, msg, createPublicKey(key), sig), true);
    });

    test('the mu sent to KMS matches an independently computed one', { skip: needsLog }, async () => {
      // mu = SHAKE256( SHAKE256(pk,64) || 0x00 || |ctx| || ctx || M , 64 )
      // with an empty context string. Computed here from scratch, so this checks
      // the provider's arithmetic rather than trusting round-trip success --
      // including the classic off-by-one of including the BIT STRING's leading
      // unused-bits octet in tr.
      const { createHash } = await import('node:crypto');
      const key = load(label);
      const msg = randomBytes(321);
      const spki = createPublicKey(key).export({ type: 'spki', format: 'der' });
      const pk = spki.subarray(spki.length - pubLen);
      assert.equal(pk.length, pubLen);

      const tr = createHash('shake256', { outputLength: 64 }).update(pk).digest();
      const expected = createHash('shake256', { outputLength: 64 })
        .update(tr)
        .update(Buffer.from([0x00, 0x00]))
        .update(msg)
        .digest();

      await clear();
      cryptoSign(null, msg, key);
      const signs = (await log()).filter((r) => r.target === 'TrentService.Sign');
      assert.equal(signs.length, 1);
      assert.equal(signs[0].messageType, 'EXTERNAL_MU');
      assert.equal(signs[0].messageLength, 64);
      assert.equal(signs[0].signingAlgorithm, 'ML_DSA_SHAKE_256');
      assert.deepEqual(Buffer.from(signs[0].message, 'base64'), expected);
    });

    test('a supplied digest is refused', () => {
      assert.throws(() => cryptoSign('sha256', randomBytes(32), load(label)), {
        code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_DIGEST',
      });
    });

    test('the ML-DSA seed is not exportable', () => {
      // Node reads OSSL_PKEY_PARAM_ML_DSA_SEED for raw-seed export; a KMS key has
      // no seed to give, and it must fail rather than yield something empty.
      assert.throws(() => load(label).export({ format: 'raw-seed' }));
    });
  });
}

/*
 * Context strings.
 *
 * The 255-byte cap comes from FIPS 204, and OpenSSL and Node both enforce it
 * (Node rejects longer ones with ERR_OUT_OF_RANGE before the provider is
 * reached). AWS KMS has no context parameter at all and so contributes no limit:
 * the context only ever affects the mu computed locally, and mu is 64 bytes
 * however long the context is -- so KMS's 4096-byte Message cap is never in play.
 *
 * Only ML-DSA can honour one, because it is the only family where we compute what
 * gets signed. Everywhere else KMS signs the message or digest directly with no
 * context, so a non-empty context must be refused rather than silently dropped.
 */
describe('ML-DSA context strings', { skip: skipFor('ML_DSA_44', !hasMlDsa ? mlDsaSkipReason : false) }, () => {
  const label = 'ML_DSA_44';
  const PUB_LEN = 1312;

  const referenceMu = async (spki, context, msg) => {
    const { createHash } = await import('node:crypto');
    const pk = spki.subarray(spki.length - PUB_LEN);
    const tr = createHash('shake256', { outputLength: 64 }).update(pk).digest();
    return createHash('shake256', { outputLength: 64 })
      .update(tr)
      .update(Buffer.from([0x00, context.length]))
      .update(context)
      .update(msg)
      .digest();
  };

  test('a context string is folded into mu, not dropped', { skip: needsLog }, async () => {
    const key = load(label);
    const spki = createPublicKey(key).export({ type: 'spki', format: 'der' });
    const msg = randomBytes(64);
    const context = Buffer.from('my-context');

    await clear();
    const sig = cryptoSign(null, msg, { key, context });
    const signs = (await log()).filter((r) => r.target === 'TrentService.Sign');
    assert.equal(signs.length, 1);
    assert.deepEqual(
      Buffer.from(signs[0].message, 'base64'),
      await referenceMu(spki, context, msg),
      'the mu sent must include the context',
    );

    // And it must round-trip: same context verifies, different context does not.
    assert.equal(cryptoVerify(null, msg, { key: createPublicKey(key), context }, sig), true);
    assert.equal(
      cryptoVerify(null, msg, { key: createPublicKey(key), context: Buffer.from('other') }, sig),
      false,
    );
    // ...and neither does no context at all.
    assert.equal(cryptoVerify(null, msg, createPublicKey(key), sig), false);
  });

  test('an absent context and an empty one produce the same mu', { skip: needsLog }, async () => {
    // FIPS 204 encodes the length either way, so |ctx| = 0 in both cases.
    const key = load(label);
    const msg = randomBytes(48);

    await clear();
    cryptoSign(null, msg, key);
    cryptoSign(null, msg, { key, context: Buffer.alloc(0) });
    const signs = (await log()).filter((r) => r.target === 'TrentService.Sign');
    assert.equal(signs.length, 2);
    assert.deepEqual(
      Buffer.from(signs[0].message, 'base64'),
      Buffer.from(signs[1].message, 'base64'),
    );
  });

  test('a signature made with an empty context verifies without one', () => {
    const key = load(label);
    const msg = randomBytes(48);
    const sig = cryptoSign(null, msg, { key, context: Buffer.alloc(0) });
    assert.equal(cryptoVerify(null, msg, createPublicKey(key), sig), true);
  });

  test('a 1-byte context works', () => {
    const key = load(label);
    const msg = randomBytes(32);
    const context = Buffer.from([0x41]);
    const sig = cryptoSign(null, msg, { key, context });
    assert.equal(cryptoVerify(null, msg, { key: createPublicKey(key), context }, sig), true);
  });

  test('a 255-byte context works -- the FIPS 204 maximum', () => {
    const key = load(label);
    const msg = randomBytes(32);
    const context = randomBytes(255);
    const sig = cryptoSign(null, msg, { key, context });
    assert.equal(cryptoVerify(null, msg, { key: createPublicKey(key), context }, sig), true);
  });

  test('a 256-byte context is rejected by Node before reaching the provider', () => {
    assert.throws(
      () => cryptoSign(null, randomBytes(32), { key: load(label), context: randomBytes(256) }),
      { code: 'ERR_OUT_OF_RANGE' },
    );
  });

  test('an empty message signs fine, because mu is sent rather than the message', { skip: needsLog }, async () => {
    // Unlike Ed25519, ML-DSA never hits KMS's 1-byte Message minimum: what goes
    // on the wire is always a 64-byte mu.
    const key = load(label);
    const empty = Buffer.alloc(0);
    await clear();
    const sig = cryptoSign(null, empty, key);
    const signs = (await log()).filter((r) => r.target === 'TrentService.Sign');
    assert.equal(signs[0].messageLength, 64);
    assert.equal(cryptoVerify(null, empty, createPublicKey(key), sig), true);
  });
});

describe('context strings are refused where KMS cannot honour them', { skip: skipForAny(['ECC_NIST_EDWARDS25519', 'ECC_NIST_P256', 'RSA_2048']) }, () => {
  const context = Buffer.from('ctx');

  /*
   * Ed25519 is the interesting one. A context does not merely get ignored by
   * OpenSSL -- it selects a different algorithm. Node knows this and sets
   * OSSL_SIGNATURE_PARAM_INSTANCE to "Ed25519ctx" alongside the context string
   * (ncrypto's signInitWithContext), because "OpenSSL silently ignores the
   * context string" without it.
   *
   * Ed25519ctx is not what AWS KMS does: ED25519_SHA_512 with MessageType=RAW is
   * PureEdDSA, and Sign has no context parameter. So the provider refuses the
   * instance directly -- not merely as a side effect of also seeing a context --
   * and it refuses at init rather than at sign, so nothing is sent.
   */
  test('Ed25519 refuses one when signing', () => {
    assert.throws(
      () => cryptoSign(null, randomBytes(32), { key: load('ECC_NIST_EDWARDS25519'), context }),
      { code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_PARAMETER' },
    );
  });

  test('Ed25519 refuses one when verifying, too', () => {
    // Otherwise a caller could be told a pure signature is a valid Ed25519ctx one.
    const key = load('ECC_NIST_EDWARDS25519');
    const msg = randomBytes(32);
    const signature = cryptoSign(null, msg, key);
    assert.throws(
      () => cryptoVerify(null, msg, { key: createPublicKey(key), context }, signature),
      { code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_PARAMETER' },
    );
  });

  test('Ed25519 with an empty context is still pure Ed25519, and works', () => {
    // Node only sets the INSTANCE param when the context is non-empty, so an
    // empty one leaves the pure algorithm selected.
    const key = load('ECC_NIST_EDWARDS25519');
    const msg = randomBytes(32);
    const signature = cryptoSign(null, msg, { key, context: Buffer.alloc(0) });
    assert.equal(cryptoVerify(null, msg, createPublicKey(key), signature), true);
  });

  // For RSA and ECDSA the rejection comes from Node, not from here: its
  // SupportsContextString() allows a context only for EdDSA and PQC keys
  // (crypto_sig.cc), so the call fails before the provider is reached. The
  // provider refuses them anyway -- a guard that fails closed on something it
  // cannot honour is worth keeping even when the current caller never reaches it.
  test('RSA refuses one, via Node', () => {
    assert.throws(
      () => cryptoSign('sha256', DATA, { key: load('RSA_2048'), context }),
      { code: 'ERR_CRYPTO_OPERATION_FAILED' },
    );
  });

  test('ECDSA refuses one, via Node', () => {
    assert.throws(
      () => cryptoSign('sha256', DATA, { key: load('ECC_NIST_P256'), context }),
      { code: 'ERR_CRYPTO_OPERATION_FAILED' },
    );
  });

  test('but an empty context is accepted everywhere, being the same as none', () => {
    const empty = Buffer.alloc(0);
    for (const [label, digest] of [
      ['RSA_2048', 'sha256'],
      ['ECC_NIST_P256', 'sha256'],
      ['ECC_NIST_EDWARDS25519', null],
    ]) {
      const key = load(label);
      const msg = randomBytes(32);
      const sig = cryptoSign(digest, msg, { key, context: empty });
      assert.equal(cryptoVerify(digest, msg, createPublicKey(key), sig), true, label);
    }
  });
});

describe('empty messages', { skip: skipForAny(['RSA_2048', 'ECC_NIST_P384', 'ECC_NIST_EDWARDS25519']) }, () => {
  test('RSA and ECDSA sign an empty message, since a digest is what goes over', () => {
    for (const [label, digest] of [
      ['RSA_2048', 'sha256'],
      ['ECC_NIST_P384', 'sha384'],
    ]) {
      const key = load(label);
      const empty = Buffer.alloc(0);
      const sig = cryptoSign(digest, empty, key);
      assert.equal(cryptoVerify(digest, empty, createPublicKey(key), sig), true, label);
    }
  });

  test('Ed25519 cannot, because KMS requires at least one byte of Message', () => {
    assert.throws(() => cryptoSign(null, Buffer.alloc(0), load('ECC_NIST_EDWARDS25519')), {
      code: 'ERR_OSSL_AWSKMS_EMPTY_MESSAGE',
    });
  });
});

/*
 * Verifying against a public key that made a round trip through PEM.
 *
 * The DER checks elsewhere hand bytes straight to the SPKI decoder; PEM goes
 * through OpenSSL's PEM reader first, which is a different path, and PEM is the
 * form people actually move around -- config files, environment variables,
 * anything copy-pasted. Worth exercising as its own thing rather than assuming the
 * DER case covers it.
 *
 * The re-ingested key is an ordinary default-provider key (the config's
 * default_properties keeps a bare-name fetch away from this provider), so this is
 * also an interop claim: the signature stands on its own, away from the code that
 * produced it.
 */
describe('public key round-tripped through PEM', () => {
  const FAMILIES = [
    { label: 'RSA_2048', digest: 'sha256', keyType: 'rsa' },
    { label: 'RSA_4096', digest: 'sha512', keyType: 'rsa' },
    { label: 'ECC_NIST_P256', digest: 'sha256', keyType: 'ec' },
    { label: 'ECC_NIST_P384', digest: 'sha384', keyType: 'ec' },
    { label: 'ECC_NIST_P521', digest: 'sha512', keyType: 'ec' },
    { label: 'ECC_SECG_P256K1', digest: 'sha256', keyType: 'ec' },
    { label: 'ECC_NIST_EDWARDS25519', digest: null, keyType: 'ed25519' },
    { label: 'ML_DSA_44', digest: null, keyType: 'ml-dsa-44', needsMlDsa: true },
    { label: 'ML_DSA_65', digest: null, keyType: 'ml-dsa-65', needsMlDsa: true },
    { label: 'ML_DSA_87', digest: null, keyType: 'ml-dsa-87', needsMlDsa: true },
  ];

  for (const f of FAMILIES) {
    describe(f.label, { skip: skipFor(f.label, f.needsMlDsa && !hasMlDsa ? mlDsaSkipReason : false) }, () => {
      const exportPem = (key) =>
        createPublicKey(key).export({ type: 'spki', format: 'pem' });

      test('a PEM string re-ingests into an equivalent KeyObject', () => {
        const key = load(f.label);
        // A bare PEM string, which is how Node users normally pass one around.
        const reingested = createPublicKey(exportPem(key));
        assert.equal(reingested.type, 'public');
        assert.equal(reingested.asymmetricKeyType, f.keyType);
        assert.deepEqual(
          reingested.asymmetricKeyDetails,
          createPublicKey(key).asymmetricKeyDetails,
        );
      });

      test('a signature verifies against the PEM-re-ingested key', () => {
        const key = load(f.label);
        const reingested = createPublicKey(exportPem(key));
        const signature = cryptoSign(f.digest, DATA, key);
        assert.equal(cryptoVerify(f.digest, DATA, reingested, signature), true);

        // A different message must not verify...
        const tampered = Buffer.from(DATA);
        tampered[0] ^= 0xff;
        assert.equal(cryptoVerify(f.digest, tampered, reingested, signature), false);

        // ...and neither must a corrupted signature, as false rather than a throw.
        const corrupted = Buffer.from(signature);
        corrupted[corrupted.length - 1] ^= 0xff;
        assert.equal(cryptoVerify(f.digest, DATA, reingested, corrupted), false);
      });

      test('the streaming verifier also accepts it', () => {
        if (f.digest === null) return; // no streaming form for the one-shot families
        const key = load(f.label);
        const reingested = createPublicKey(exportPem(key));
        const signature = createSign(f.digest).update(DATA).sign(key);
        assert.equal(
          createVerify(f.digest).update(DATA).verify(reingested, signature),
          true,
        );
      });

      test('PEM -> KeyObject -> DER reproduces the original DER exactly', () => {
        // Closes the loop on the PEM body == DER check: not only does the PEM
        // carry the same bytes, decoding it yields the same SubjectPublicKeyInfo.
        const key = load(f.label);
        const der = createPublicKey(key).export({ type: 'spki', format: 'der' });
        const viaPem = createPublicKey(exportPem(key)).export({
          type: 'spki',
          format: 'der',
        });
        assert.deepEqual(viaPem, der);
      });

      test('PEM -> KeyObject -> PEM is stable', () => {
        const key = load(f.label);
        const pem = exportPem(key);
        assert.equal(
          createPublicKey(pem).export({ type: 'spki', format: 'pem' }),
          pem,
        );
      });

      test('a PEM from a different key does not verify', () => {
        const key = load(f.label);
        const otherPem = exportPem(
          createPrivateKey({ key: new URL(uri('other', f.label)) }),
        );
        const signature = cryptoSign(f.digest, DATA, key);
        assert.equal(
          cryptoVerify(f.digest, DATA, createPublicKey(otherPem), signature),
          false,
        );
      });
    });
  }
});
