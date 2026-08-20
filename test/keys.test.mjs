/*
 * Loading KMS-backed keys through the STORE loader, and everything that follows
 * from having one: key introspection, deriving the public key, SPKI export,
 * refusal to export the private half, and equality.
 *
 * Assertions here deliberately mirror Node's own provider conformance fixture
 * (test/parallel/test-crypto-key-store-pkcs11.js), because that is the de-facto
 * specification for what a provider-backed KeyObject must support.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  getCurves,
} from 'node:crypto';
import { uri } from './inventory.mjs';
import { hasMlDsa, mlDsaSkipReason } from './capabilities.mjs';
import { realArn, regionAttr, skipFor } from './real-keys.mjs';

/* The stub backend picks a key spec from any KeySpec name in the key id, so
 * these exercise realistic URI shapes at the same time. */
const CASES = [
  {
    label: 'RSA_2048',
    uri: uri('test', 'RSA_2048'),
    keyType: 'rsa',
    details: { modulusLength: 2048, publicExponent: 65537n },
    privateExports: [
      { type: 'pkcs8', format: 'pem' },
      { type: 'pkcs8', format: 'der' },
      { type: 'pkcs1', format: 'pem' },
      { type: 'pkcs1', format: 'der' },
      { format: 'jwk' },
    ],
  },
  {
    label: 'RSA_4096',
    /* A key id given as a full key ARN. The stub resolves the placeholder below by
     * finding a KeySpec name inside it; real KMS needs a genuine ARN, taken from
     * the manifest, which makes this the case that covers ARN-to-region resolution
     * against a real ARN. A real ARN cannot be hardcoded here: keys are recreated
     * every run, so it changes legitimately. */
    uri: `aws-kms:key-id=${realArn('test', 'RSA_4096') ?? 'arn:aws:kms:eu-central-1:111122223333:key/RSA_4096'}`,
    aliasUri: uri('test', 'RSA_4096'),
    keyType: 'rsa',
    details: { modulusLength: 4096, publicExponent: 65537n },
  },
  {
    label: 'ECC_NIST_P256',
    /* Carries an explicit region. In real mode it has to be the region the keys
     * live in, or the load goes elsewhere and fails in a way resembling a
     * provisioning bug. It also covers the redundant-but-consistent case: a
     * `;region=` equal to the ambient region is accepted, not treated as a
     * conflict. */
    uri: uri('test', 'ECC_NIST_P256', regionAttr()),
    keyType: 'ec',
    details: { namedCurve: 'prime256v1' },
    privateExports: [
      { type: 'pkcs8', format: 'pem' },
      { type: 'sec1', format: 'pem' },
      { format: 'jwk' },
    ],
  },
  {
    label: 'ECC_NIST_P384',
    uri: uri('test', 'ECC_NIST_P384'),
    keyType: 'ec',
    details: { namedCurve: 'secp384r1' },
  },
  {
    label: 'ECC_NIST_P521',
    uri: uri('test', 'ECC_NIST_P521'),
    keyType: 'ec',
    details: { namedCurve: 'secp521r1' },
  },
  {
    label: 'ECC_NIST_EDWARDS25519',
    uri: uri('test', 'ECC_NIST_EDWARDS25519'),
    keyType: 'ed25519',
    details: {},
  },
  {
    label: 'ML_DSA_44',
    uri: uri('test', 'ML_DSA_44'),
    keyType: 'ml-dsa-44',
    details: {},
    needs: 'ml-dsa',
  },
  {
    label: 'ML_DSA_87',
    uri: uri('test', 'ML_DSA_87'),
    keyType: 'ml-dsa-87',
    details: {},
    needs: 'ml-dsa',
  },
];


for (const c of CASES) {
  describe(c.label, { skip: skipFor(c.label, c.needs === 'ml-dsa' && !hasMlDsa ? mlDsaSkipReason : false) }, () => {
    const load = () => createPrivateKey({ key: new URL(c.uri) });

    test('loads as a private key with the right identity', () => {
      const key = load();
      assert.equal(key.type, 'private');
      assert.equal(key.asymmetricKeyType, c.keyType);
      assert.deepEqual(key.asymmetricKeyDetails, c.details);
    });

    test('createPublicKey derives a usable public key', () => {
      const pub = createPublicKey(load());
      assert.equal(pub.type, 'public');
      assert.equal(pub.asymmetricKeyType, c.keyType);
      assert.deepEqual(pub.asymmetricKeyDetails, c.details);
    });

    test('exports SPKI, with the PEM body matching the DER exactly', () => {
      const pub = createPublicKey(load());
      const pem = pub.export({ type: 'spki', format: 'pem' });
      const der = pub.export({ type: 'spki', format: 'der' });

      assert.equal(pem.split('\n')[0], '-----BEGIN PUBLIC KEY-----');
      assert.ok(Buffer.isBuffer(der) && der.byteLength > 0);
      // Not redundant with the label check: encoding a provider-backed RSA key
      // through PEM_write_bio_PUBKEY() yields a PKCS#1 body under a SPKI label,
      // which only a byte comparison catches.
      const body = Buffer.from(
        pem.split('\n').filter((l) => !l.startsWith('---')).join(''),
        'base64',
      );
      assert.deepEqual(body, der);
    });

    test('refuses to export the private key', () => {
      const key = load();
      for (const options of c.privateExports ?? [{ type: 'pkcs8', format: 'pem' }]) {
        assert.throws(() => key.export(options), (err) => {
          // The message has to say something useful; a bare
          // ERR_CRYPTO_OPERATION_FAILED with no code would be a regression.
          assert.match(
            err.message,
            /not exportable|Failed to encode private key|Failed to export/i,
            `export(${JSON.stringify(options)}) message: ${err.message}`,
          );
          return true;
        });
      }
    });

    test('equals() identifies the same key across loads', () => {
      const key = load();
      assert.equal(key.equals(load()), true);
      if (c.aliasUri) {
        assert.equal(
          key.equals(createPrivateKey({ key: new URL(c.aliasUri) })),
          true,
          'the ARN and alias must identify the same key',
        );
      }
      // The other inventory role is a different key even when the spec matches,
      // so this must be false for every case -- equality compares the public
      // halves, not the URI.
      const other = createPrivateKey({
        key: new URL(uri('other', c.label)),
      });
      assert.equal(key.equals(other), false);
      assert.equal(other.asymmetricKeyType, c.keyType);
    });

    test('loads with and without an explicit property query', () => {
      // All three must work. Without `properties`, a bare-name keymgmt fetch
      // resolves to the default provider, and it is this store loader's lack of
      // export_object that makes libcrypto fall back to our keymgmt instead.
      //
      // The empty string is the third case because ncrypto treats it as "no
      // query" rather than passing an empty C string through to
      // OSSL_STORE_open_ex, and that distinction sits directly on this loader's
      // path.
      for (const properties of ['provider=aws-kms', '']) {
        const loaded = createPrivateKey({ key: new URL(c.uri), properties });
        assert.equal(loaded.asymmetricKeyType, c.keyType);
        assert.equal(loaded.equals(load()), true);
      }
    });

    if (c.keyType === 'ec') {
      test('reports a group name, which the SM2 check needs', () => {
        // ncrypto's MayBeSM2Key() reads OSSL_PKEY_PARAM_GROUP_NAME to decide
        // whether the prehashed sign fallback is safe, and it fails CLOSED: a
        // curve it cannot determine is assumed to be SM2 and loses the fallback.
        // Node surfaces the same parameter as namedCurve, so asserting it here
        // covers that dependency as well as key introspection.
        const named = load().asymmetricKeyDetails.namedCurve;
        assert.equal(named, c.details.namedCurve);
        assert.notEqual(named, 'SM2');
      });
    }
  });
}

describe('URI handling', () => {
  test('rejects a URI with no key-id', () => {
    assert.throws(() => createPrivateKey({ key: new URL('aws-kms:region=eu-central-1') }), {
      code: 'ERR_OSSL_AWSKMS_INVALID_URI',
    });
  });

  test('rejects an unknown attribute rather than ignoring it', () => {
    assert.throws(
      () => createPrivateKey({ key: new URL('aws-kms:key-id=alias/test-RSA_2048;object=x') }),
      { code: 'ERR_OSSL_AWSKMS_INVALID_URI' },
    );
  });

  /*
   * The impossible account id `1` is load-bearing, in both stub and real mode.
   *
   * The conflict is detected while parsing, before any client is built or request
   * sent, and an unreachable ARN is what demonstrates that. A regression into
   * contacting KMS first would fail with ERR_OSSL_AWSKMS_KEY_NOT_FOUND or
   * _ACCESS_DENIED instead of _REGION_CONFLICT. Substituting a genuine ARN removes
   * that distinction and leaves an assertion that merely happens to pass.
   */
  test('rejects a region that contradicts the key ARN, without a network call', () => {
    assert.throws(
      () =>
        createPrivateKey({
          key: new URL(
            'aws-kms:key-id=arn:aws:kms:eu-central-1:1:key/RSA_2048;region=us-east-1',
          ),
        }),
      { code: 'ERR_OSSL_AWSKMS_REGION_CONFLICT' },
    );
  });

  test('reports an unknown key with a readable code', () => {
    assert.throws(() => createPrivateKey({ key: new URL('aws-kms:key-id=alias/nothing') }), {
      code: 'ERR_OSSL_AWSKMS_KEY_NOT_FOUND',
    });
  });

  test('a URL is only accepted for private keys', () => {
    // createPublicKey() must not take a URL; the documented route is to load the
    // private key and derive from it.
    assert.throws(() => createPublicKey(new URL('aws-kms:key-id=alias/test-RSA_2048')), {
      code: 'ERR_INVALID_ARG_TYPE',
    });
  });

  test('a plain object that merely looks like a URL is not one', () => {
    // Otherwise an attacker-supplied JWK could redirect the load to a URI of
    // their choosing.
    const spoofed = { href: 'aws-kms:key-id=alias/test-RSA_2048', protocol: 'aws-kms:' };
    assert.throws(() => createPrivateKey(spoofed), { code: 'ERR_INVALID_ARG_TYPE' });
  });
});

describe('coexistence with the default provider', () => {
  // This provider registers keymgmt under the same names as the default one
  // ("RSA", "EC"), so ordinary key operations in the same process must be
  // unaffected. `default_properties = ?provider!=aws-kms` in the config is what
  // guarantees it regardless of the order providers are listed in.
  test('generateKeyPairSync still works for rsa, ec and ed25519', () => {
    assert.equal(generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.asymmetricKeyType, 'rsa');
    assert.equal(
      generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.asymmetricKeyDetails.namedCurve,
      'prime256v1',
    );
    assert.equal(generateKeyPairSync('ed25519').privateKey.asymmetricKeyType, 'ed25519');
  });

  test('ordinary PEM keys still import, and still export', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const reimported = createPrivateKey(pem);
    assert.equal(reimported.asymmetricKeyType, 'rsa');
    // An ordinary key must remain exportable: our refusal applies only to ours.
    assert.ok(reimported.export({ type: 'pkcs8', format: 'pem' }).length > 0);
  });

  test('the curve list is unaffected', () => {
    assert.ok(getCurves().includes('prime256v1'));
  });
});
