/*
 * WebCrypto.
 *
 * This is a genuinely separate route into the provider from crypto.sign(): Node
 * normalises the algorithm itself, tracks `extractable` and key usages, and for
 * ECDSA converts between DER and IEEE-P1363. It is also how most modern code
 * signs -- JWS and JWT libraries go through subtle, not crypto.sign -- so it is
 * worth covering on its own terms rather than assuming the lower-level tests
 * imply it.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { uri } from './inventory.mjs';
import { hasMlDsa, mlDsaSkipReason } from './capabilities.mjs';
import { skipFor } from './real-keys.mjs';

const { subtle } = globalThis.crypto;
const DATA = randomBytes(256);

const load = (label) => createPrivateKey({ key: new URL(uri('test', label)) });


/* `importAlgorithm` is what toCryptoKey() takes; `signAlgorithm` is what
 * subtle.sign() takes. They differ where the operation carries a parameter the
 * key does not -- RSA-PSS's saltLength, ECDSA's hash. */
const CASES = [
  {
    label: 'RSA_2048',
    importAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  },
  {
    label: 'RSA_3072',
    importAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  },
  {
    label: 'RSA_4096',
    importAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  },
  {
    label: 'RSA_2048',
    name: 'RSA-PSS (PS256)',
    importAlgorithm: { name: 'RSA-PSS', hash: 'SHA-256' },
    // 32 == SHA-256 output, which is the only salt length KMS produces. This is
    // also exactly what JWS PS256 specifies, so the common case matches.
    signAlgorithm: { name: 'RSA-PSS', saltLength: 32 },
  },
  {
    label: 'ECC_NIST_P256',
    importAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' },
    signAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    signatureLength: 64, // P1363, not DER: Node converts what KMS returns
  },
  {
    label: 'ECC_NIST_P384',
    importAlgorithm: { name: 'ECDSA', namedCurve: 'P-384' },
    signAlgorithm: { name: 'ECDSA', hash: 'SHA-384' },
    signatureLength: 96,
  },
  {
    label: 'ECC_NIST_P521',
    importAlgorithm: { name: 'ECDSA', namedCurve: 'P-521' },
    signAlgorithm: { name: 'ECDSA', hash: 'SHA-512' },
    signatureLength: 132,
  },
  { label: 'ECC_NIST_EDWARDS25519', importAlgorithm: { name: 'Ed25519' }, signatureLength: 64 },
  { label: 'ML_DSA_44', importAlgorithm: { name: 'ML-DSA-44' }, signatureLength: 2420, needsMlDsa: true },
  { label: 'ML_DSA_65', importAlgorithm: { name: 'ML-DSA-65' }, signatureLength: 3309, needsMlDsa: true },
  { label: 'ML_DSA_87', importAlgorithm: { name: 'ML-DSA-87' }, signatureLength: 4627, needsMlDsa: true },
];

for (const c of CASES) {
  const title = c.name ?? `${c.label} (${c.importAlgorithm.name})`;
  const signAlgorithm = c.signAlgorithm ?? c.importAlgorithm.name;

  describe(`WebCrypto ${title}`, { skip: skipFor(c.label, c.needsMlDsa && !hasMlDsa ? mlDsaSkipReason : false) }, () => {
    const keys = () => {
      const privateKey = load(c.label);
      return {
        privateCryptoKey: privateKey.toCryptoKey(c.importAlgorithm, false, ['sign']),
        publicCryptoKey: createPublicKey(privateKey).toCryptoKey(c.importAlgorithm, true, ['verify']),
      };
    };

    test('toCryptoKey produces keys with the expected shape', () => {
      const { privateCryptoKey, publicCryptoKey } = keys();
      assert.equal(privateCryptoKey.type, 'private');
      assert.equal(privateCryptoKey.extractable, false);
      assert.deepEqual(privateCryptoKey.usages, ['sign']);
      assert.equal(publicCryptoKey.type, 'public');
      assert.equal(publicCryptoKey.extractable, true);
      assert.deepEqual(publicCryptoKey.usages, ['verify']);
    });

    test('subtle.sign and subtle.verify round-trip', async () => {
      const { privateCryptoKey, publicCryptoKey } = keys();
      const signature = await subtle.sign(signAlgorithm, privateCryptoKey, DATA);
      assert.ok(signature instanceof ArrayBuffer);
      assert.ok(signature.byteLength > 0);
      if (c.signatureLength !== undefined) {
        assert.equal(signature.byteLength, c.signatureLength);
      }
      assert.equal(await subtle.verify(signAlgorithm, publicCryptoKey, signature, DATA), true);

      const tampered = Buffer.from(DATA);
      tampered[0] ^= 0xff;
      assert.equal(await subtle.verify(signAlgorithm, publicCryptoKey, signature, tampered), false);
    });

    test('the signature verifies against a plain imported public key', async () => {
      // Proves interoperability rather than self-consistency: this public key is
      // an ordinary default-provider key, imported from SPKI.
      const privateKey = load(c.label);
      const spki = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
      const imported = await subtle.importKey('spki', spki, c.importAlgorithm, true, ['verify']);
      const signature = await subtle.sign(
        signAlgorithm,
        privateKey.toCryptoKey(c.importAlgorithm, false, ['sign']),
        DATA,
      );
      assert.equal(await subtle.verify(signAlgorithm, imported, signature, DATA), true);
    });

    test('a non-extractable private key refuses export, per WebCrypto', async () => {
      const { privateCryptoKey } = keys();
      await assert.rejects(subtle.exportKey('pkcs8', privateCryptoKey), {
        name: 'InvalidAccessError',
      });
    });

    test('even an extractable private key cannot be exported, because KMS holds it', async () => {
      // toCryptoKey does not force extractable to false, so a caller can build an
      // extractable CryptoKey from a key that physically cannot be exported. The
      // refusal then has to come from the provider, later.
      const privateCryptoKey = load(c.label).toCryptoKey(c.importAlgorithm, true, ['sign']);
      assert.equal(privateCryptoKey.extractable, true);

      for (const format of ['pkcs8', 'jwk']) {
        await assert.rejects(subtle.exportKey(format, privateCryptoKey), (err) => {
          assert.ok(
            err.name === 'OperationError' || err.code === 'ERR_CRYPTO_OPERATION_FAILED',
            `unexpected error for ${format}: ${err.name} ${err.code}`,
          );
          return true;
        });
      }
    });

    test('the public key exports as SPKI', async () => {
      const { publicCryptoKey } = keys();
      const spki = await subtle.exportKey('spki', publicCryptoKey);
      assert.ok(spki instanceof ArrayBuffer);
      assert.ok(spki.byteLength > 0);
      // And it must match what the KeyObject produces.
      const viaKeyObject = createPublicKey(load(c.label)).export({ type: 'spki', format: 'der' });
      assert.deepEqual(Buffer.from(spki), viaKeyObject);
    });
  });
}

describe('WebCrypto RSA-PSS salt lengths', () => {
  const importAlgorithm = { name: 'RSA-PSS', hash: 'SHA-256' };

  test('a digest-length salt is accepted, which is what JWS PS256 uses', async () => {
    const privateKey = load('RSA_2048');
    const signature = await subtle.sign(
      { name: 'RSA-PSS', saltLength: 32 },
      privateKey.toCryptoKey(importAlgorithm, false, ['sign']),
      DATA,
    );
    assert.equal(
      await subtle.verify(
        { name: 'RSA-PSS', saltLength: 32 },
        createPublicKey(privateKey).toCryptoKey(importAlgorithm, true, ['verify']),
        signature,
        DATA,
      ),
      true,
    );
  });

  test('any other salt length is refused rather than silently changed', async () => {
    // WebCrypto always passes an explicit saltLength, so unlike crypto.sign there
    // is no "no requirement" case to be lenient about here.
    const privateCryptoKey = load('RSA_2048').toCryptoKey(importAlgorithm, false, ['sign']);
    await assert.rejects(
      subtle.sign({ name: 'RSA-PSS', saltLength: 64 }, privateCryptoKey, DATA),
      (err) => {
        assert.match(
          `${err.name} ${err.code ?? ''} ${err.cause?.message ?? err.message}`,
          /UNSUPPORTED_SALT_LENGTH|OperationError/,
        );
        return true;
      },
    );
  });
});

describe('WebCrypto key usage enforcement', () => {
  test('a sign-only key cannot verify, and vice versa', async () => {
    const privateKey = load('RSA_2048');
    const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    const signKey = privateKey.toCryptoKey(algorithm, false, ['sign']);
    const verifyKey = createPublicKey(privateKey).toCryptoKey(algorithm, true, ['verify']);
    const signature = await subtle.sign(algorithm.name, signKey, DATA);

    await assert.rejects(subtle.verify(algorithm.name, signKey, signature, DATA), {
      name: 'InvalidAccessError',
    });
    await assert.rejects(subtle.sign(algorithm.name, verifyKey, DATA), {
      name: 'InvalidAccessError',
    });
  });
});
