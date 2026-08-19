/*
 * Every export format, for both node:crypto and WebCrypto.
 *
 * Public JWK export matters more here than it might look: publishing a JWK is how
 * a verifier normally gets a signing key (a JWKS endpoint for JWT verification),
 * and it is the one export path that does NOT go through an encoder -- Node reads
 * the key's components directly, so it depends on our keymgmt actually exposing
 * them rather than on SPKI encoding working. The tests re-import each JWK and
 * verify a real signature with it, which is the workflow rather than just the call.
 *
 * The mirror image matters as much: no private-material format may ever succeed,
 * whatever route is taken to it.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { uri } from './inventory.mjs';
import { hasMlDsa, mlDsaSkipReason } from './capabilities.mjs';
import { skipFor } from './real-keys.mjs';

const { subtle } = globalThis.crypto;
const DATA = randomBytes(128);
const load = (label) => createPrivateKey({ key: new URL(uri('test', label)) });


const CASES = [
  {
    label: 'RSA_2048',
    digest: 'sha256',
    jwk: { kty: 'RSA', members: ['n', 'e'] },
    // RSA has no raw form at all, so raw-public is a category error, not a refusal.
    rawPublic: null,
    webcrypto: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    webcryptoJwk: { kty: 'RSA', alg: 'RS256' },
    webcryptoRaw: null,
    webcryptoRawPublic: null,
  },
  {
    label: 'ECC_NIST_P256',
    digest: 'sha256',
    jwk: { kty: 'EC', crv: 'P-256', members: ['x', 'y'] },
    rawPublic: 65, // uncompressed point: 0x04 || X || Y
    webcrypto: { name: 'ECDSA', namedCurve: 'P-256' },
    webcryptoJwk: { kty: 'EC', crv: 'P-256' },
    webcryptoRaw: 65,
    webcryptoRawPublic: 65,
  },
  {
    label: 'ECC_NIST_P384',
    digest: 'sha384',
    jwk: { kty: 'EC', crv: 'P-384', members: ['x', 'y'] },
    rawPublic: 97,
    webcrypto: { name: 'ECDSA', namedCurve: 'P-384' },
    webcryptoJwk: { kty: 'EC', crv: 'P-384' },
    webcryptoRaw: 97,
    webcryptoRawPublic: 97,
  },
  {
    label: 'ECC_NIST_EDWARDS25519',
    digest: null,
    jwk: { kty: 'OKP', crv: 'Ed25519', members: ['x'] },
    rawPublic: 32,
    webcrypto: { name: 'Ed25519' },
    webcryptoJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519' },
    webcryptoRaw: 32,
    webcryptoRawPublic: 32,
  },
  {
    label: 'ML_DSA_44',
    digest: null,
    // AKP ("Algorithm Key Pair"), the JOSE key type for PQC signatures.
    jwk: { kty: 'AKP', alg: 'ML-DSA-44', members: ['pub'] },
    rawPublic: 1312,
    webcrypto: { name: 'ML-DSA-44' },
    webcryptoJwk: { kty: 'AKP', alg: 'ML-DSA-44' },
    webcryptoRaw: null, // ML-DSA uses raw-public, not raw
    webcryptoRawPublic: 1312,
    needsMlDsa: true,
  },
  {
    label: 'ML_DSA_87',
    digest: null,
    jwk: { kty: 'AKP', alg: 'ML-DSA-87', members: ['pub'] },
    rawPublic: 2592,
    webcrypto: { name: 'ML-DSA-87' },
    webcryptoJwk: { kty: 'AKP', alg: 'ML-DSA-87' },
    webcryptoRaw: null,
    webcryptoRawPublic: 2592,
    needsMlDsa: true,
  },
];

/* Anything that would betray private key material, in any spelling. */
const PRIVATE_JWK_MEMBERS = ['d', 'k', 'p', 'q', 'dp', 'dq', 'qi', 'priv', 'seed'];

for (const c of CASES) {
  describe(`${c.label} exports`, { skip: skipFor(c.label, c.needsMlDsa && !hasMlDsa ? mlDsaSkipReason : false) }, () => {
    const pub = () => createPublicKey(load(c.label));

    /* ---------------------------------------------------- node:crypto, public */

    test('exports a public JWK with the right shape and no private members', () => {
      const jwk = pub().export({ format: 'jwk' });
      assert.equal(jwk.kty, c.jwk.kty);
      if (c.jwk.crv !== undefined) assert.equal(jwk.crv, c.jwk.crv);
      if (c.jwk.alg !== undefined) assert.equal(jwk.alg, c.jwk.alg);
      for (const m of c.jwk.members) {
        assert.equal(typeof jwk[m], 'string', `expected member ${m}`);
        assert.ok(jwk[m].length > 0, `member ${m} is empty`);
      }
      for (const m of PRIVATE_JWK_MEMBERS) {
        assert.equal(jwk[m], undefined, `public JWK must not contain "${m}"`);
      }
    });

    test('the public JWK re-imports and verifies a real signature', () => {
      // The JWKS workflow: publish the JWK, verify elsewhere with it.
      const key = load(c.label);
      const jwk = createPublicKey(key).export({ format: 'jwk' });
      const reimported = createPublicKey({ key: jwk, format: 'jwk' });
      assert.equal(reimported.type, 'public');

      const signature = cryptoSign(c.digest, DATA, key);
      assert.equal(cryptoVerify(c.digest, DATA, reimported, signature), true);

      const tampered = Buffer.from(DATA);
      tampered[0] ^= 0xff;
      assert.equal(cryptoVerify(c.digest, tampered, reimported, signature), false);
    });

    test('the public JWK round-trips to the same SPKI', () => {
      const key = load(c.label);
      const der = createPublicKey(key).export({ type: 'spki', format: 'der' });
      const jwk = createPublicKey(key).export({ format: 'jwk' });
      const viaJwk = createPublicKey({ key: jwk, format: 'jwk' }).export({
        type: 'spki',
        format: 'der',
      });
      assert.deepEqual(viaJwk, der);
    });

    test(`raw-public ${c.rawPublic === null ? 'is not applicable' : 'is exactly ' + c.rawPublic + ' bytes'}`, () => {
      if (c.rawPublic === null) {
        // Not a refusal by us -- the format simply does not exist for this key type.
        assert.throws(() => pub().export({ format: 'raw-public' }), {
          code: 'ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS',
        });
        return;
      }
      const raw = pub().export({ format: 'raw-public' });
      assert.ok(Buffer.isBuffer(raw));
      assert.equal(raw.byteLength, c.rawPublic);
      if (c.jwk.kty === 'EC') {
        assert.equal(raw[0], 0x04, 'an uncompressed EC point');
      }
    });

    /* --------------------------------------------------- node:crypto, private */

    // PKCS#8 is the format that reaches the keymgmt export, so it is the one
    // carrying this provider's reason code. The exact assertion is what
    // distinguishes "the provider declined to hand over private material" from
    // "Node happened to fail first for an unrelated reason". A regex also
    // accepting ERR_CRYPTO_OPERATION_FAILED cannot tell those apart, and would
    // keep passing if the export rule (keymgmt.export returning 0 for
    // SELECT_PRIVATE_KEY) were removed entirely.
    for (const options of [
      { type: 'pkcs8', format: 'pem' },
      { type: 'pkcs8', format: 'der' },
    ]) {
      test(`export(${options.type}/${options.format}) is refused by the provider`, () => {
        assert.throws(() => load(c.label).export(options), {
          code: 'ERR_OSSL_AWSKMS_PRIVATE_KEY_NOT_EXPORTABLE',
          library: 'aws-kms',
          reason: 'awskms private key not exportable',
        });
      });
    }

    test('no other private format succeeds either, in any spelling', () => {
      const key = load(c.label);
      for (const options of [
        { format: 'jwk' },
        { format: 'raw-private' },
        { format: 'raw-seed' },
      ]) {
        assert.throws(
          () => key.export(options),
          (err) => {
            // These go through Node's own guards, which fire before OpenSSL is
            // consulted, so the code is Node's rather than the provider's. Either
            // is correct; silently succeeding would not be.
            assert.match(
              err.code ?? '',
              /ERR_CRYPTO_OPERATION_FAILED|ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS|ERR_OSSL/,
              `export(${JSON.stringify(options)}) gave ${err.code}: ${err.message}`,
            );
            return true;
          },
        );
      }
    });

    /* ------------------------------------------------------------- WebCrypto */

    if (c.webcrypto) {
      const alg = c.webcrypto;
      const signAlg =
        alg.name === 'ECDSA' ? { name: 'ECDSA', hash: c.digest === 'sha384' ? 'SHA-384' : 'SHA-256' } : alg.name;

      test('WebCrypto exports a public JWK with an alg and key_ops', async () => {
        const jwk = await subtle.exportKey('jwk', pub().toCryptoKey(alg, true, ['verify']));
        assert.equal(jwk.kty, c.webcryptoJwk.kty);
        if (c.webcryptoJwk.crv !== undefined) assert.equal(jwk.crv, c.webcryptoJwk.crv);
        if (c.webcryptoJwk.alg !== undefined) assert.equal(jwk.alg, c.webcryptoJwk.alg);
        assert.deepEqual(jwk.key_ops, ['verify']);
        assert.equal(jwk.ext, true);
        for (const m of PRIVATE_JWK_MEMBERS) {
          assert.equal(jwk[m], undefined, `public JWK must not contain "${m}"`);
        }
      });

      test('the WebCrypto JWK re-imports and verifies', async () => {
        const key = load(c.label);
        const jwk = await subtle.exportKey('jwk', createPublicKey(key).toCryptoKey(alg, true, ['verify']));
        const reimported = await subtle.importKey('jwk', jwk, alg, true, ['verify']);
        const signature = await subtle.sign(signAlg, key.toCryptoKey(alg, false, ['sign']), DATA);
        assert.equal(await subtle.verify(signAlg, reimported, signature, DATA), true);
      });

      test(`WebCrypto raw export ${c.webcryptoRaw === null ? 'is unsupported for this type' : 'is ' + c.webcryptoRaw + ' bytes'}`, async () => {
        const publicCryptoKey = pub().toCryptoKey(alg, true, ['verify']);
        if (c.webcryptoRaw === null) {
          await assert.rejects(subtle.exportKey('raw', publicCryptoKey));
          return;
        }
        const raw = await subtle.exportKey('raw', publicCryptoKey);
        assert.equal(raw.byteLength, c.webcryptoRaw);
      });

      if (c.webcryptoRawPublic !== null && c.webcryptoRawPublic !== undefined) {
        test(`WebCrypto raw-public export is ${c.webcryptoRawPublic} bytes`, async () => {
          const raw = await subtle.exportKey('raw-public', pub().toCryptoKey(alg, true, ['verify']));
          assert.equal(raw.byteLength, c.webcryptoRawPublic);
          // And it must agree with what node:crypto produces.
          if (c.rawPublic !== null) {
            assert.deepEqual(Buffer.from(raw), pub().export({ format: 'raw-public' }));
          }
        });
      }

      test('WebCrypto refuses every private export, extractable or not', async () => {
        const key = load(c.label);
        for (const extractable of [false, true]) {
          const privateCryptoKey = key.toCryptoKey(alg, extractable, ['sign']);
          for (const format of ['pkcs8', 'jwk', 'raw-seed', 'raw-secret']) {
            await assert.rejects(
              subtle.exportKey(format, privateCryptoKey),
              (err) => {
                assert.ok(
                  err instanceof Error,
                  `exportKey(${format}, extractable=${extractable}) should reject`,
                );
                return true;
              },
            );
          }
        }
      });
    }
  });
}
