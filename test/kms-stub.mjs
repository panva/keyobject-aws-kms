/*
 * A local stand-in for the KMS API, spoken over the real wire protocol so the real
 * AWS SDK talks to it unmodified. That covers the actual client, signing, endpoint
 * resolution and error unmarshalling rather than a shortcut around them.
 *
 * The contract below was verified against a real Aws::KMS::KMSClient:
 *   POST /  Content-Type: application/x-amz-json-1.1
 *   X-Amz-Target: TrentService.GetPublicKey | TrentService.Sign
 *   blobs base64, errors as {"__type": "...", "message": "..."}
 * Plain http:// is fine -- no TLS anywhere -- and the SDK never verifies a
 * response signature. It does refuse to send with no credentials at all, so the
 * caller must set dummy ones.
 *
 * Signing goes through the `openssl` CLI rather than node:crypto because KMS's
 * MessageType semantics map exactly onto pkeyutl and not onto anything node
 * exposes: there is no node API for "sign this already-computed digest", and none
 * at all for ML-DSA external-mu.
 */
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const OPENSSL = process.env.AWSKMS_OPENSSL ?? 'openssl';

/* Which KeySpecs this stub can serve depends on the openssl CLI it has. */
function opensslSupports(algorithm) {
  const r = spawnSync(OPENSSL, ['genpkey', '-algorithm', algorithm, '-out', '/dev/null'], {
    stdio: 'ignore',
  });
  return r.status === 0;
}

const SPECS = {
  RSA_2048: { algorithm: 'rsa', options: { modulusLength: 2048 } },
  RSA_3072: { algorithm: 'rsa', options: { modulusLength: 3072 } },
  RSA_4096: { algorithm: 'rsa', options: { modulusLength: 4096 } },
  ECC_NIST_P256: { algorithm: 'ec', options: { namedCurve: 'prime256v1' } },
  ECC_NIST_P384: { algorithm: 'ec', options: { namedCurve: 'secp384r1' } },
  ECC_NIST_P521: { algorithm: 'ec', options: { namedCurve: 'secp521r1' } },
  ECC_SECG_P256K1: { algorithm: 'ec', options: { namedCurve: 'secp256k1' } },
  ECC_NIST_EDWARDS25519: { algorithm: 'ed25519', options: {} },
  ML_DSA_44: { algorithm: 'ml-dsa-44', options: {}, cliName: 'ML-DSA-44' },
  ML_DSA_65: { algorithm: 'ml-dsa-65', options: {}, cliName: 'ML-DSA-65' },
  ML_DSA_87: { algorithm: 'ml-dsa-87', options: {}, cliName: 'ML-DSA-87' },
};

const SIGNING_ALGORITHMS = {
  RSA: [
    'RSASSA_PSS_SHA_256',
    'RSASSA_PSS_SHA_384',
    'RSASSA_PSS_SHA_512',
    'RSASSA_PKCS1_V1_5_SHA_256',
    'RSASSA_PKCS1_V1_5_SHA_384',
    'RSASSA_PKCS1_V1_5_SHA_512',
  ],
  ECC_NIST_P256: ['ECDSA_SHA_256'],
  ECC_NIST_P384: ['ECDSA_SHA_384'],
  ECC_NIST_P521: ['ECDSA_SHA_512'],
  ECC_SECG_P256K1: ['ECDSA_SHA_256'],
  ECC_NIST_EDWARDS25519: ['ED25519_SHA_512', 'ED25519_PH_SHA_512'],
  ML_DSA: ['ML_DSA_SHAKE_256'],
};

const signingAlgorithmsFor = (spec) =>
  SIGNING_ALGORITHMS[spec] ??
  (spec.startsWith('RSA_') ? SIGNING_ALGORITHMS.RSA : SIGNING_ALGORITHMS.ML_DSA);

const DIGEST_OF = { SHA_256: 'sha256', SHA_384: 'sha384', SHA_512: 'sha512' };

/* HTTP status only affects the SDK's retry classification; the exception name is
 * what it maps to an error type. Values from the KMS API reference. */
const STATUS = {
  NotFoundException: 400,
  DisabledException: 400,
  InvalidKeyUsageException: 400,
  KMSInvalidStateException: 400,
  UnsupportedOperationException: 400,
  ValidationException: 400,
  SerializationException: 400,
  AccessDeniedException: 400,
  KMSInternalException: 500,
  KeyUnavailableException: 500,
  DependencyTimeoutException: 500,
  ThrottlingException: 400,
};

export function createKmsStub({ verbose = !!process.env.AWSKMS_STUB_VERBOSE } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'awskms-stub-'));
  const keys = new Map(); // key id -> { spec, pemPath, spkiDer }
  let requests = [];

  /* Any KeySpec name appearing in the key id selects that spec, so tests can use
   * realistic aliases and ARNs. Generated on first use and kept for the life of
   * the stub, so load/sign/verify all agree. */
  function resolve(keyId) {
    if (keys.has(keyId)) return keys.get(keyId);
    const spec = Object.keys(SPECS).find((s) =>
      keyId.toLowerCase().includes(s.toLowerCase()),
    );
    if (!spec) return null;
    const { algorithm, options } = SPECS[spec];
    let pair;
    try {
      pair = generateKeyPairSync(algorithm, options);
    } catch {
      return null; // host openssl too old for this spec
    }
    const pemPath = join(dir, `${spec}-${keys.size}.pem`);
    writeFileSync(pemPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    const record = {
      spec,
      pemPath,
      spkiDer: pair.publicKey.export({ type: 'spki', format: 'der' }),
    };
    keys.set(keyId, record);
    return record;
  }

  const send = (res, status, body) => {
    const buf = Buffer.from(JSON.stringify(body));
    res.writeHead(status, {
      'content-type': 'application/x-amz-json-1.1',
      'content-length': buf.length,
      'x-amzn-RequestId': 'stub-00000000-0000-0000-0000-000000000000',
    });
    res.end(buf);
  };
  const fail = (res, type, message) =>
    send(res, STATUS[type] ?? 400, { __type: type, message });

  /*
   * A key id containing one of these markers makes GetPublicKey return something
   * malformed, which is what exercises the provider's own validation. Those paths
   * are otherwise unreachable offline: they guard against a KeySpec this provider
   * does not implement, and against a SubjectPublicKeyInfo disagreeing with the
   * KeySpec reported beside it, both producible only by the real service.
   *
   * The markers match those in src/kms_stub.c, so the same tests run against both
   * backends.
   */
  function injectFault(keyId, rec) {
    let { spec, spkiDer } = rec;
    /* A key that exists and parses fine but is not for signing. Only the real
     * backend checks this -- the offline one has no KeyUsage concept -- so it is
     * the HTTP stub that can reach kms_aws.cc's guard, through the real SDK. */
    let keyUsage = keyId.includes('fault-keyusage') ? 'ENCRYPT_DECRYPT' : 'SIGN_VERIFY';

    if (keyId.includes('fault-badspec')) spec = 'SM2';
    else if (keyId.includes('fault-wrongtype')) spec = 'RSA_2048';
    else if (keyId.includes('fault-wronggroup')) {
      spec = spec === 'ECC_NIST_P256' ? 'ECC_NIST_P384' : 'ECC_NIST_P256';
    }

    if (keyId.includes('fault-emptyspki')) spkiDer = Buffer.alloc(0);
    else if (keyId.includes('fault-truncspki')) {
      spkiDer = spkiDer.subarray(0, Math.floor(spkiDer.length / 2));
    } else if (keyId.includes('fault-badspki')) {
      // Corrupt the body but keep the leading SEQUENCE tag, so this fails in the
      // parser rather than being rejected as obviously-not-DER.
      spkiDer = Buffer.from(spkiDer);
      for (let i = spkiDer.length >> 1; i < spkiDer.length; i++) spkiDer[i] ^= 0xff;
    }

    return { spec, spkiDer, keyUsage };
  }

  /*
   * `fault-err-<ExceptionName>` in a key id makes GetPublicKey return that KMS
   * exception; `fault-signerr-<ExceptionName>` lets the key load and fails the
   * Sign instead.
   *
   * These exercise reason_for() in src/kms_aws.cc, the table turning a KMS
   * exception into the err.code a caller sees. The request goes through the real
   * AWS SDK, so they also pin down the SDK's own classification: whether
   * aws-sdk-cpp maps the wire string "DisabledException" onto KMSErrors::DISABLED
   * is a fact about the SDK, and this is the only place it is checked.
   */
  function requestedError(keyId, prefix) {
    const m = new RegExp(`${prefix}-([A-Za-z]+Exception)`).exec(keyId);
    return m?.[1] ?? null;
  }

  function getPublicKey(res, body) {
    const keyId = body.KeyId ?? '';
    const requested = requestedError(keyId, 'fault-err');
    if (requested) return fail(res, requested, `stub: injected ${requested}`);
    const rec = resolve(keyId);
    if (!rec) return fail(res, 'NotFoundException', `Key '${keyId}' does not exist`);
    const { spec, spkiDer, keyUsage } = injectFault(keyId, rec);
    return send(res, 200, {
      KeyId: `arn:aws:kms:us-east-1:000000000000:key/${keyId}`,
      KeySpec: spec,
      KeyUsage: keyUsage,
      SigningAlgorithms: signingAlgorithmsFor(rec.spec),
      PublicKey: spkiDer.toString('base64'),
    });
  }

  /* Mirrors KMS's MessageType semantics exactly, via pkeyutl. */
  function pkeyutlArgs(rec, algorithm, messageType) {
    const args = ['pkeyutl', '-sign', '-inkey', rec.pemPath];

    if (algorithm === 'ML_DSA_SHAKE_256') {
      if (messageType !== 'EXTERNAL_MU') return { error: 'only EXTERNAL_MU is implemented for ML-DSA' };
      // The input already IS mu, which is what mu:1 means.
      return { args: [...args, '-rawin', '-pkeyopt', 'mu:1'] };
    }
    if (algorithm.startsWith('ED25519')) {
      if (messageType !== 'RAW') return { error: 'ED25519_SHA_512 requires MessageType RAW' };
      return { args: [...args, '-rawin'] };
    }
    if (messageType !== 'DIGEST') {
      return { error: `the stub only implements MessageType DIGEST for ${algorithm}` };
    }
    if (algorithm.startsWith('ECDSA_')) {
      const md = DIGEST_OF[algorithm.slice('ECDSA_'.length)];
      return { args: [...args, '-pkeyopt', `digest:${md}`] };
    }
    if (algorithm.startsWith('RSASSA_PSS_')) {
      const md = DIGEST_OF[algorithm.slice('RSASSA_PSS_'.length)];
      // KMS always uses salt length == digest length, and MGF1 == the digest.
      return {
        args: [
          ...args,
          '-pkeyopt', 'rsa_padding_mode:pss',
          '-pkeyopt', 'rsa_pss_saltlen:digest',
          '-pkeyopt', `digest:${md}`,
        ],
      };
    }
    if (algorithm.startsWith('RSASSA_PKCS1_V1_5_')) {
      const md = DIGEST_OF[algorithm.slice('RSASSA_PKCS1_V1_5_'.length)];
      return {
        args: [...args, '-pkeyopt', 'rsa_padding_mode:pkcs1', '-pkeyopt', `digest:${md}`],
      };
    }
    return { error: `unknown SigningAlgorithm ${algorithm}` };
  }

  function sign(res, body) {
    const keyId = body.KeyId ?? '';
    /* The key loaded fine; the Sign is what fails. This is the path that matters
     * most, because it is the one a long-running process hits after a key that
     * worked at startup is disabled or scheduled for deletion underneath it. */
    const requested = requestedError(keyId, 'fault-signerr');
    if (requested) return fail(res, requested, `stub: injected ${requested}`);

    const rec = resolve(keyId);
    if (!rec) return fail(res, 'NotFoundException', `Key '${body.KeyId}' does not exist`);

    const algorithm = body.SigningAlgorithm;
    const messageType = body.MessageType ?? 'RAW';
    if (!signingAlgorithmsFor(rec.spec).includes(algorithm)) {
      return fail(
        res,
        'InvalidKeyUsageException',
        `Algorithm ${algorithm} is incompatible with key spec ${rec.spec}`,
      );
    }

    const message = Buffer.from(body.Message ?? '', 'base64');
    // KMS's documented Message constraint. Ed25519 is the only spec that feels
    // it, and the provider is expected to reject oversize input before it gets
    // here -- so if this fires from a test, the provider has a bug.
    if (message.length < 1 || message.length > 4096) {
      return fail(res, 'ValidationException', 'Message must be 1-4096 bytes');
    }
    if (messageType === 'EXTERNAL_MU' && message.length !== 64) {
      return fail(res, 'ValidationException', 'EXTERNAL_MU Message must be 64 bytes');
    }

    const plan = pkeyutlArgs(rec, algorithm, messageType);
    if (plan.error) return fail(res, 'UnsupportedOperationException', plan.error);

    const inPath = join(dir, 'in.bin');
    const outPath = join(dir, 'out.bin');
    writeFileSync(inPath, message);
    const r = spawnSync(OPENSSL, [...plan.args, '-in', inPath, '-out', outPath]);
    if (r.status !== 0) {
      return fail(
        res,
        'KMSInternalException',
        `stub signing failed: ${(r.stderr ?? '').toString().split('\n')[0]}`,
      );
    }

    return send(res, 200, {
      KeyId: `arn:aws:kms:us-east-1:000000000000:key/${body.KeyId}`,
      Signature: readFileSync(outPath).toString('base64'),
      SigningAlgorithm: algorithm,
    });
  }

  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const target = req.headers['x-amz-target'] ?? '';
      let body;
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        return fail(res, 'SerializationException', 'malformed JSON body');
      }
      // The introspection endpoints are not part of the KMS API and must not be
      // recorded, or reading the log would change it. They let a test running in
      // a child process see what the provider actually asked for, which is how
      // "a size probe costs nothing" is asserted.
      if (req.url === '/__requests') {
        if (req.method === 'GET') return send(res, 200, { requests });
        if (req.method === 'DELETE') {
          requests = [];
          return send(res, 200, { ok: true });
        }
      }

      requests.push({ target, keyId: body.KeyId, messageType: body.MessageType,
                      signingAlgorithm: body.SigningAlgorithm,
                      messageLength: body.Message ? Buffer.from(body.Message, 'base64').length : 0,
                      message: body.Message });
      if (verbose) console.error('[kms-stub]', target, JSON.stringify(body).slice(0, 160));
      if (req.method !== 'POST' || req.url !== '/') {
        return fail(res, 'SerializationException', `unexpected ${req.method} ${req.url}`);
      }
      switch (target) {
        case 'TrentService.GetPublicKey':
          return getPublicKey(res, body);
        case 'TrentService.Sign':
          return sign(res, body);
        default:
          return fail(res, 'UnsupportedOperationException', `unsupported target '${target}'`);
      }
    });
  });

  return {
    server,
    get requests() {
      return requests;
    },
    reset() {
      requests = [];
    },
    /* Which specs this stub can actually serve, so tests can skip the rest. */
    supported() {
      const out = {};
      for (const [spec, { algorithm, cliName }] of Object.entries(SPECS)) {
        out[spec] = cliName ? opensslSupports(cliName) : true;
        if (out[spec]) {
          try {
            generateKeyPairSync(algorithm, SPECS[spec].options);
          } catch {
            out[spec] = false;
          }
        }
      }
      return out;
    },
    async listen() {
      await new Promise((r) => server.listen(0, '127.0.0.1', r));
      const { port } = server.address();
      return { port, endpoint: `http://127.0.0.1:${port}` };
    },
    async close() {
      await new Promise((r) => server.close(r));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*\//, ''))) {
  const stub = createKmsStub({ verbose: true });
  const { port, endpoint } = await stub.listen();
  console.log(`STUB_PORT=${port}`);
  console.log(`AWS_ENDPOINT_URL_KMS=${endpoint}`);
}
