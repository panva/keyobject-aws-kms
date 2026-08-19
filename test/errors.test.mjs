/*
 * The refusals: every code path where the provider declines rather than guesses.
 *
 * Node renders only the library and reason of an OpenSSL error --
 * ERR_error_string_n() drops the file, line, function and the detail text this
 * provider attaches to every error. `err.code` is therefore the entire diagnosis a
 * caller receives, which makes a wrong reason code a wrong message rather than a
 * cosmetic flaw. The assertions here are on exact codes for that reason, rather
 * than regexes that would also accept a generic failure.
 *
 * Several of these paths are reachable only with help from the stubs, which honour
 * markers in the key id that make GetPublicKey return something malformed (see the
 * fault injection blocks in src/kms_stub.c and test/kms-stub.mjs). A bad KeySpec,
 * or a SubjectPublicKeyInfo disagreeing with it, are things only the real service
 * can produce.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  constants,
  createPrivateKey,
  randomBytes,
  sign as cryptoSign,
} from 'node:crypto';
import { uri } from './inventory.mjs';
import { isReal } from './real-keys.mjs';

const load = (label) => createPrivateKey({ key: new URL(uri('test', label)) });
const faulty = (marker, spec) =>
  createPrivateKey({ key: new URL(`aws-kms:key-id=alias/${marker}-${spec}`) });

/* Fault injection is a property of the stubs. Against real KMS there is nothing
 * to inject into, and a real account will never return these. */
const stubOnly = isReal ? 'fault injection is stub-only' : false;

describe('a key spec this provider does not implement', { skip: stubOnly }, () => {
  test('is refused at load, not at first use', () => {
    // SM2 is a real KMS key spec this provider deliberately does not implement.
    // Failing at createPrivateKey() rather than at the first sign locates the
    // mistake where it was made.
    assert.throws(() => faulty('fault-badspec', 'RSA_2048'), {
      code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_KEY_SPEC',
      library: 'aws-kms',
    });
  });
});

describe('a malformed public key from the service', { skip: stubOnly }, () => {
  // Every one of these is a distinct branch in spki.c, and every one of them
  // would otherwise produce a key object that half-works: loads fine, then
  // produces signatures that verify nowhere.
  for (const [marker, spec, why] of [
    ['fault-emptyspki', 'RSA_2048', 'an empty PublicKey blob'],
    ['fault-truncspki', 'RSA_2048', 'a truncated SubjectPublicKeyInfo'],
    ['fault-badspki', 'RSA_2048', 'a corrupt SubjectPublicKeyInfo body'],
    ['fault-wrongtype', 'ECC_NIST_P256', 'an EC key delivered as RSA_2048'],
    ['fault-wronggroup', 'ECC_NIST_P256', 'a P-256 key delivered as ECC_NIST_P384'],
  ]) {
    test(`${why} is refused`, () => {
      assert.throws(() => faulty(marker, spec), {
        code: 'ERR_OSSL_AWSKMS_MALFORMED_PUBLIC_KEY',
        library: 'aws-kms',
      });
    });
  }

  test('the wrong-curve case is caught even though the key type matches', () => {
    // EVP_PKEY_is_a() reports "EC" for both, so only a group-name comparison
    // catches this. Undetected, signing would ask KMS for ECDSA_SHA_384 against a
    // P-256 key.
    assert.throws(() => faulty('fault-wronggroup', 'ECC_NIST_P256'), {
      code: 'ERR_OSSL_AWSKMS_MALFORMED_PUBLIC_KEY',
    });
  });
});

/*
 * The KMS-exception-to-err.code mapping.
 *
 * This is reason_for() in src/kms_aws.cc, and it is the reason `err.code` is worth
 * anything in production: it is what turns a KMS failure into something a caller
 * can branch on rather than a generic operation failure.
 *
 * It runs through the real AWS SDK, so these also pin down the SDK's own
 * classification -- whether aws-sdk-cpp maps the wire string "DisabledException"
 * onto KMSErrors::DISABLED is a fact about the SDK, not about this provider, and
 * this is the only place it is checked. Needs the HTTP stub, so it is aws-backend
 * only; the offline backend has its own much smaller mapping.
 */
const httpStub = process.env.AWSKMS_ENDPOINT;
const needsHttpStub = httpStub && !isReal ? false : 'needs the HTTP stub backend';

describe('KMS exceptions map to distinct error codes', { skip: needsHttpStub }, () => {
  const MAPPINGS = [
    ['NotFoundException', 'ERR_OSSL_AWSKMS_KEY_NOT_FOUND'],
    ['DisabledException', 'ERR_OSSL_AWSKMS_KEY_DISABLED'],
    ['KMSInvalidStateException', 'ERR_OSSL_AWSKMS_INVALID_KEY_STATE'],
    ['InvalidKeyUsageException', 'ERR_OSSL_AWSKMS_INVALID_KEY_USAGE'],
    ['AccessDeniedException', 'ERR_OSSL_AWSKMS_ACCESS_DENIED'],
  ];

  for (const [exception, code] of MAPPINGS) {
    test(`${exception} at load -> ${code}`, () => {
      assert.throws(
        () => createPrivateKey({ key: new URL(`aws-kms:key-id=alias/fault-err-${exception}-RSA_2048`) }),
        { code, library: 'aws-kms' },
      );
    });
  }

  // The fallback branch: anything reason_for() does not recognise must still get
  // an operation-specific code, never an empty error queue -- an empty queue
  // degrades to a bare ERR_CRYPTO_OPERATION_FAILED with no code at all.
  for (const exception of ['KeyUnavailableException', 'DependencyTimeoutException']) {
    test(`an unmapped ${exception} still yields GET_PUBLIC_KEY_FAILED`, () => {
      assert.throws(
        () => createPrivateKey({ key: new URL(`aws-kms:key-id=alias/fault-err-${exception}-RSA_2048`) }),
        { code: 'ERR_OSSL_AWSKMS_GET_PUBLIC_KEY_FAILED' },
      );
    });
  }

  // The sign path separately: this is what a long-running process hits when a key
  // that worked at startup is disabled or scheduled for deletion underneath it.
  for (const [exception, code] of [
    ['DisabledException', 'ERR_OSSL_AWSKMS_KEY_DISABLED'],
    ['KMSInvalidStateException', 'ERR_OSSL_AWSKMS_INVALID_KEY_STATE'],
    ['AccessDeniedException', 'ERR_OSSL_AWSKMS_ACCESS_DENIED'],
  ]) {
    test(`${exception} at sign time -> ${code}`, () => {
      const key = createPrivateKey({
        key: new URL(`aws-kms:key-id=alias/fault-signerr-${exception}-RSA_2048`),
      });
      assert.throws(() => cryptoSign('sha256', randomBytes(32), key), { code });
    });
  }

  test('an unmapped exception at sign time yields SIGN_FAILED, not the load code', () => {
    const key = createPrivateKey({
      key: new URL('aws-kms:key-id=alias/fault-signerr-KeyUnavailableException-RSA_2048'),
    });
    assert.throws(() => cryptoSign('sha256', randomBytes(32), key), {
      code: 'ERR_OSSL_AWSKMS_SIGN_FAILED',
    });
  });
});

describe('a key that is not for signing', { skip: needsHttpStub }, () => {
  test('an ENCRYPT_DECRYPT key is refused at load, before any signing is attempted', () => {
    // GetPublicKey succeeds and the SPKI parses; only KeyUsage is wrong. Failing
    // at createPrivateKey() rather than at the first sign is what makes the
    // mistake locatable.
    //
    // Reachable only here: the check lives in kms_aws.cc, and the admin role in
    // docs/real-kms-setup.md deliberately cannot create an ENCRYPT_DECRYPT key
    // (its policy pins kms:KeyUsage to SIGN_VERIFY), so testing this against real
    // KMS would mean weakening the very scoping that makes the harness safe.
    assert.throws(
      () => createPrivateKey({ key: new URL('aws-kms:key-id=alias/fault-keyusage-RSA_2048') }),
      { code: 'ERR_OSSL_AWSKMS_INVALID_KEY_USAGE', library: 'aws-kms' },
    );
  });
});

describe('throttling is retried before it is reported', { skip: needsHttpStub }, () => {
  // The slowest test here, and the slowness is the assertion: the SDK retries
  // ThrottlingException with backoff, so ERR_OSSL_AWSKMS_THROTTLED surfaces only
  // once retries are exhausted. The operational consequence is that
  // crypto.sign()'s synchronous form blocks the event loop for the whole retry
  // sequence rather than one round trip. This becoming fast would mean retries
  // were lost and the README's timing note had gone stale.
  test('a throttled sign retries, then reports THROTTLED', () => {
    const key = createPrivateKey({
      key: new URL('aws-kms:key-id=alias/fault-signerr-ThrottlingException-RSA_2048'),
    });
    const started = Date.now();
    assert.throws(() => cryptoSign('sha256', randomBytes(32), key), {
      code: 'ERR_OSSL_AWSKMS_THROTTLED',
    });
    const elapsed = Date.now() - started;
    assert.ok(elapsed > 500, `expected retries with backoff, but it failed in ${elapsed}ms`);
  });
});

describe('RSA padding modes KMS cannot honour', () => {
  // KMS offers PKCS#1 v1.5 and PSS. Anything else must fail rather than be
  // quietly signed with one of the two -- a signature produced under a different
  // padding than the caller asked for is worse than no signature.
  for (const [name, padding] of [
    ['RSA_NO_PADDING', constants.RSA_NO_PADDING],
    ['RSA_PKCS1_OAEP_PADDING', constants.RSA_PKCS1_OAEP_PADDING],
    ['RSA_X931_PADDING', constants.RSA_X931_PADDING],
  ]) {
    test(`${name} is refused`, () => {
      assert.throws(
        () => cryptoSign('sha256', randomBytes(32), { key: load('RSA_2048'), padding }),
        { code: 'ERR_OSSL_AWSKMS_UNSUPPORTED_PADDING', library: 'aws-kms' },
      );
    });
  }
});

/*
 * The prehashed path with a wrong-length input.
 *
 * Node cannot reach this: every Node signing path computes the digest with the
 * same EVP_MD it declared, so the length always agrees. It is reachable from a
 * non-Node caller, which is the defence-in-depth case this provider retains
 * deliberately, and is therefore exercised through the openssl CLI as the ML-DSA
 * oracle is.
 *
 * Skipped where the CLI cannot load the provider, which is host-dependent.
 */
const cliOpenssl = process.env.AWSKMS_OPENSSL ?? 'openssl';
const cnf = process.env.AWSKMS_CNF;

function pkeyutlSign(inputBytes) {
  const dir = mkdtempSync(join(tmpdir(), 'awskms-prehash-'));
  try {
    const inPath = join(dir, 'in.bin');
    writeFileSync(inPath, inputBytes);
    return spawnSync(
      cliOpenssl,
      [
        'pkeyutl', '-sign',
        '-inkey', uri('test', 'RSA_2048'),
        '-pkeyopt', 'digest:sha256',
        '-in', inPath,
        '-out', join(dir, 'out.bin'),
      ],
      { encoding: 'utf8', env: { ...process.env, OPENSSL_CONF: cnf } },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const cliWorks = cnf && !isReal && pkeyutlSign(randomBytes(32)).status === 0;

describe('the prehashed path rejects a wrong-length digest', {
  skip: cliWorks ? false : 'needs an openssl CLI that can load the provider',
}, () => {
  test('a 48-byte input under SHA-256 is refused, and never reaches KMS', () => {
    // A message supplied where a digest was expected. KMS would sign it and
    // return something that verifies nowhere, so it fails locally instead.
    const r = pkeyutlSign(randomBytes(48));
    assert.notEqual(r.status, 0, 'signing a wrong-length digest must fail');
    assert.match(r.stderr, /awskms digest length mismatch/);
    // The CLI, unlike Node, surfaces the detail text.
    assert.match(r.stderr, /expected a 32-byte digest, got 48 bytes/);
  });

  test('a correct 32-byte digest still signs, so the check is not just refusing everything', () => {
    assert.equal(pkeyutlSign(randomBytes(32)).status, 0);
  });
});
