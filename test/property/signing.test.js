import assert from 'node:assert/strict';
import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import test from 'node:test';

import fc from 'fast-check';

import { uri } from '../inventory.mjs';
import { isReal } from '../real-keys.mjs';

const arbitraryMessage = fc.uint8Array({ minLength: 0, maxLength: 4096 });
const arbitraryMutation = fc.nat();
const localOnly = isReal ? 'property tests never send generated cases to AWS' : false;

function mutate(bytes, offset) {
  if (bytes.byteLength === 0) return Buffer.from([1]);
  const copy = Buffer.from(bytes);
  copy[offset % copy.byteLength] ^= 1;
  return copy;
}

test('RSA signatures authenticate arbitrary messages', { skip: localOnly }, () => {
  const privateKey = createPrivateKey({
    key: new URL(uri('test', 'RSA_2048')),
  });
  const publicKey = createPublicKey(privateKey);
  const otherPublicKey = createPublicKey(
    createPrivateKey({ key: new URL(uri('other', 'RSA_2048')) }),
  );

  fc.assert(
    fc.property(
      arbitraryMessage,
      arbitraryMutation,
      arbitraryMutation,
      (message, messageOffset, signatureOffset) => {
        const signature = sign('sha256', message, privateKey);

        assert.equal(verify('sha256', message, publicKey, signature), true);
        assert.equal(
          verify('sha256', mutate(message, messageOffset), publicKey, signature),
          false,
        );
        assert.equal(
          verify(
            'sha256',
            message,
            publicKey,
            mutate(signature, signatureOffset),
          ),
          false,
        );
        assert.equal(verify('sha256', message, otherPublicKey, signature), false);
      },
    ),
    { numRuns: 64 },
  );
});

test('WebCrypto ECDSA authenticates arbitrary messages', { skip: localOnly }, async () => {
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
  const operation = { name: 'ECDSA', hash: 'SHA-256' };
  const privateKey = createPrivateKey({
    key: new URL(uri('test', 'ECC_NIST_P256')),
  });
  const signingKey = privateKey.toCryptoKey(algorithm, false, ['sign']);
  const verificationKey = createPublicKey(privateKey).toCryptoKey(
    algorithm,
    true,
    ['verify'],
  );

  await fc.assert(
    fc.asyncProperty(
      arbitraryMessage,
      arbitraryMutation,
      arbitraryMutation,
      async (message, messageOffset, signatureOffset) => {
        const signature = await crypto.subtle.sign(
          operation,
          signingKey,
          message,
        );

        assert.equal(
          await crypto.subtle.verify(
            operation,
            verificationKey,
            signature,
            message,
          ),
          true,
        );
        assert.equal(
          await crypto.subtle.verify(
            operation,
            verificationKey,
            signature,
            mutate(message, messageOffset),
          ),
          false,
        );
        assert.equal(
          await crypto.subtle.verify(
            operation,
            verificationKey,
            mutate(new Uint8Array(signature), signatureOffset),
            message,
          ),
          false,
        );
      },
    ),
    { numRuns: 32 },
  );
});
