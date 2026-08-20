/*
 * The deliberately small real-service pass.
 *
 * The ordinary suite already drives the AWS SDK against a faithful HTTP KMS
 * stub and can inspect every request.  Re-running export, registration, URI,
 * temp-path, cleanup, permission, and fault-injection coverage against AWS adds
 * latency but no extra observation.  This file keeps only what a real service
 * can prove: every retained family and KMS signing mode works through a genuine
 * FIPS endpoint, and a genuine KMS error reaches the documented public code.
 * It can also be selected explicitly with the HTTP stub to validate this focused
 * inventory itself; that never substitutes for the real FIPS run.
 */
import assert from 'node:assert/strict';
import {
  constants,
  createPrivateKey,
  createPublicKey,
  getFips,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { KEY_SPECS, REAL_KMS_COVERAGE, specsFor, uri } from './inventory.mjs';
import { isReal } from './real-keys.mjs';

const sign = promisify(cryptoSign);
const manifestPath = process.env.AWSKMS_TEST_MANIFEST ?? 'build/real-kms-keys.json';
const manifest = isReal
  ? JSON.parse(readFileSync(manifestPath, 'utf8'))
  : { smoke: true, unavailable: [], keys: {} };

const sorted = (values) => [...values].sort();
const byFamily = (specs, family) => specs.filter((entry) => entry.family === family);

const rsaDigests = [
  ['sha256', 32],
  ['sha384', 48],
  ['sha512', 64],
];
const ecDigests = new Map([
  ['ECC_NIST_P256', 'sha256'],
  ['ECC_NIST_P384', 'sha384'],
  ['ECC_NIST_P521', 'sha512'],
]);
const ecWebCrypto = new Map([
  ['ECC_NIST_P256', ['P-256', 'SHA-256']],
  ['ECC_NIST_P384', ['P-384', 'SHA-384']],
  ['ECC_NIST_P521', ['P-521', 'SHA-512']],
]);

function expectedKeyType(entry) {
  switch (entry.family) {
    case 'rsa':
      return 'rsa';
    case 'ec':
      return 'ec';
    case 'ed25519':
      return 'ed25519';
    case 'ml-dsa':
      return entry.spec.toLowerCase().replaceAll('_', '-');
    default:
      throw new Error(`no KeyObject type for ${entry.family}`);
  }
}

test('real AWS KMS FIPS coverage', async (t) => {
  if (isReal) {
    assert.equal(process.env.AWSKMS_TEST_FIPS, '1');
    assert.equal(getFips(), 1, 'the real-service process must have FIPS defaults active');
    assert.equal(manifest.region, process.env.AWS_REGION);
    assert.deepEqual(manifest.roles, ['test']);
  } else {
    assert.equal(
      process.env.AWSKMS_STUB,
      '1',
      'offline validation requires the AWS backend and HTTP KMS stub',
    );
    assert(process.env.AWSKMS_ENDPOINT, 'the HTTP KMS stub endpoint is missing');
  }
  assert.equal(typeof manifest.smoke, 'boolean');

  const selected = specsFor({ smokeOnly: manifest.smoke });
  const unavailable = new Set(manifest.unavailable ?? []);
  assert.equal(
    unavailable.size,
    manifest.unavailable?.length ?? 0,
    'the unavailable KeySpec list must not contain duplicates',
  );

  for (const name of unavailable) {
    const entry = KEY_SPECS.find(({ spec }) => spec === name);
    assert(entry, `manifest reports an unknown unavailable KeySpec: ${name}`);
    assert.equal(entry.pqc, true, `a retained non-PQC KeySpec is unavailable: ${name}`);
  }

  const available = selected.filter(({ spec }) => !unavailable.has(spec));
  if (isReal) {
    for (const entry of available) {
      const key = manifest.keys?.[`test-${entry.spec}`];
      assert(key, `test-${entry.spec} was not provisioned`);
      assert.equal(key.spec, entry.spec);
      assert.equal(key.role, 'test');
    }
  }

  /* These sets are populated only after a real operation succeeds.  The final
   * assertions make a missing family or mode a failure, never a test skip. */
  const coveredFamilies = new Set();
  const coveredInterfaces = new Set();
  const coveredModes = new Set();
  const coveredErrors = new Set();
  const nodeKeySpecs = new Set();
  const realArnKeySpecs = new Set();
  const webCryptoKeySpecs = new Set();
  const keys = new Map();
  const load = (entry) => {
    let key = keys.get(entry.spec);
    if (!key) {
      let keyUri = uri('test', entry.spec);
      if (isReal && entry.spec === 'RSA_2048') {
        const arn = manifest.keys?.['test-RSA_2048']?.arn;
        assert.equal(typeof arn, 'string', 'test-RSA_2048 has no ARN in the manifest');
        assert(arn.length > 0, 'test-RSA_2048 has an empty ARN in the manifest');
        keyUri = `aws-kms:key-id=${arn}`;
      }
      key = createPrivateKey({ key: new URL(keyUri) });
      assert.equal(key.type, 'private');
      assert.equal(key.asymmetricKeyType, expectedKeyType(entry));
      if (isReal && entry.spec === 'RSA_2048') realArnKeySpecs.add(entry.spec);
      keys.set(entry.spec, key);
    }
    return key;
  };
  const importedPublic = (key) => createPublicKey({
    key: createPublicKey(key).export({ type: 'spki', format: 'der' }),
    type: 'spki',
    format: 'der',
  });

  await t.test('RSA PKCS#1 v1.5 and RSA-PSS', async () => {
    const entries = byFamily(available, 'rsa');
    assert(entries.length > 0, 'no RSA KeySpec was selected');
    for (const entry of entries) {
      const key = load(entry);
      const publicKey = importedPublic(key);
      for (const [digest, saltLength] of rsaDigests) {
        const message = Buffer.from(`real KMS ${entry.spec} ${digest}`);
        const pkcs1 = await sign(digest, message, key);
        assert.equal(cryptoVerify(digest, message, publicKey, pkcs1), true);

        const options = {
          key,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength,
        };
        const pss = await sign(digest, message, options);
        assert.equal(
          cryptoVerify(
            digest,
            message,
            {
              key: publicKey,
              padding: constants.RSA_PKCS1_PSS_PADDING,
              saltLength,
            },
            pss,
          ),
          true,
        );
      }
      nodeKeySpecs.add(entry.spec);
    }
    coveredFamilies.add('rsa');
    coveredModes.add('rsa-pkcs1-v1_5');
    coveredModes.add('rsa-pss');
    coveredInterfaces.add('node-crypto');
  });

  await t.test('NIST ECDSA', async () => {
    const entries = byFamily(available, 'ec');
    assert(entries.length > 0, 'no NIST ECDSA KeySpec was selected');
    for (const entry of entries) {
      const digest = ecDigests.get(entry.spec);
      assert(digest, `no ECDSA digest for ${entry.spec}`);
      const key = load(entry);
      const publicKey = importedPublic(key);
      const message = Buffer.from(`real KMS ${entry.spec}`);
      const signature = await sign(digest, message, key);
      assert.equal(cryptoVerify(digest, message, publicKey, signature), true);
      nodeKeySpecs.add(entry.spec);
    }
    coveredFamilies.add('ec');
    coveredModes.add('ecdsa');
    coveredInterfaces.add('node-crypto');
  });

  await t.test('Ed25519', async () => {
    const entries = byFamily(available, 'ed25519');
    assert(entries.length > 0, 'no Ed25519 KeySpec was selected');
    for (const entry of entries) {
      const key = load(entry);
      const publicKey = importedPublic(key);
      const message = Buffer.from(`real KMS ${entry.spec}`);
      const signature = await sign(null, message, key);
      assert.equal(cryptoVerify(null, message, publicKey, signature), true);
      nodeKeySpecs.add(entry.spec);
    }
    coveredFamilies.add('ed25519');
    coveredModes.add('ed25519');
    coveredInterfaces.add('node-crypto');
  });

  await t.test('ML-DSA with externally computed mu', async () => {
    const entries = byFamily(available, 'ml-dsa');
    assert(entries.length > 0, 'no ML-DSA KeySpec was selected');
    for (const entry of entries) {
      const key = load(entry);
      const publicKey = importedPublic(key);
      /* Far beyond KMS's RAW-message limit: success proves that the provider
       * computed the fixed-size FIPS 204 mu and selected EXTERNAL_MU. */
      const message = Buffer.alloc(8 * 1024, 0xa5);
      const signature = await sign(null, message, key);
      assert.equal(cryptoVerify(null, message, publicKey, signature), true);
      nodeKeySpecs.add(entry.spec);
    }
    coveredFamilies.add('ml-dsa');
    coveredModes.add('ml-dsa');
    coveredInterfaces.add('node-crypto');
  });

  await t.test('WebCrypto signs with every selected KeySpec', async () => {
    for (const entry of available) {
      let algorithms;
      switch (entry.family) {
        case 'rsa':
          algorithms = [
            {
              key: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
              sign: 'RSASSA-PKCS1-v1_5',
            },
            {
              key: { name: 'RSA-PSS', hash: 'SHA-256' },
              sign: { name: 'RSA-PSS', saltLength: 32 },
            },
          ];
          break;
        case 'ec': {
          const [namedCurve, hash] = ecWebCrypto.get(entry.spec) ?? [];
          assert(namedCurve && hash, `no WebCrypto ECDSA parameters for ${entry.spec}`);
          algorithms = [
            {
              key: { name: 'ECDSA', namedCurve },
              sign: { name: 'ECDSA', hash },
            },
          ];
          break;
        }
        case 'ed25519':
          algorithms = [{ key: { name: 'Ed25519' }, sign: 'Ed25519' }];
          break;
        case 'ml-dsa':
          algorithms = [
            {
              key: { name: entry.spec.replaceAll('_', '-') },
              sign: entry.spec.replaceAll('_', '-'),
            },
          ];
          break;
        default:
          assert.fail(`no WebCrypto algorithm for ${entry.family}`);
      }

      const key = load(entry);
      for (const algorithm of algorithms) {
        const privateKey = key.toCryptoKey(algorithm.key, false, ['sign']);
        const publicKey = createPublicKey(key).toCryptoKey(algorithm.key, true, ['verify']);
        const message = Buffer.from(
          `real KMS WebCrypto ${entry.spec} ${algorithm.key.name}`,
        );
        const signature = await globalThis.crypto.subtle.sign(
          algorithm.sign, privateKey, message,
        );
        assert.equal(
          await globalThis.crypto.subtle.verify(
            algorithm.sign, publicKey, signature, message,
          ),
          true,
        );
      }
      webCryptoKeySpecs.add(entry.spec);
    }
    coveredInterfaces.add('webcrypto');
  });

  await t.test('a real KMS not-found response keeps its public error code', () => {
    const missing = isReal
      ? `alias/awskms-${manifest.runId}-focused-missing`
        .toLowerCase()
        .replaceAll('_', '-')
      : 'alias/focused-missing';
    assert.throws(
      () => createPrivateKey({ key: new URL(`aws-kms:key-id=${missing}`) }),
      { code: 'ERR_OSSL_AWSKMS_KEY_NOT_FOUND' },
    );
    coveredErrors.add('key-not-found');
  });

  assert.deepEqual(sorted(coveredFamilies), sorted(REAL_KMS_COVERAGE.families));
  assert.deepEqual(sorted(coveredInterfaces), sorted(REAL_KMS_COVERAGE.interfaces));
  assert.deepEqual(sorted(coveredModes), sorted(REAL_KMS_COVERAGE.signatureModes));
  assert.deepEqual(sorted(coveredErrors), sorted(REAL_KMS_COVERAGE.serviceErrors));
  assert.deepEqual(sorted(nodeKeySpecs), sorted(available.map(({ spec }) => spec)));
  assert.deepEqual(sorted(webCryptoKeySpecs), sorted(available.map(({ spec }) => spec)));
  if (isReal) {
    assert.deepEqual(
      sorted(realArnKeySpecs),
      ['RSA_2048'],
      'the real lane must load and use RSA_2048 by genuine key ARN',
    );
  }
});
