/*
 * The N-API registration route runs before any KMS operation. Keep these tests
 * in fresh child processes so their process-wide OpenSSL property policies do
 * not leak into the rest of the suite.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey } from 'node:crypto';

const modulePath = process.env.AWSKMS_MODULE;
const cnf = process.env.AWSKMS_CNF;
const [opensslMajor, opensslMinor] = process.versions.openssl.split('.').map(Number);
const hasDefaultPropertyGetter =
  opensslMajor > 3 || (opensslMajor === 3 && opensslMinor >= 5);
let hasStoreLoader = false;
try {
  createPrivateKey({ key: new URL('aws-kms:not-a-valid-attribute=1') });
  hasStoreLoader = true;
} catch (error) {
  hasStoreLoader = error.code !== 'ERR_INVALID_ARG_TYPE';
}

function cleanEnv() {
  const env = { ...process.env };

  delete env.NODE_OPTIONS;
  delete env.OPENSSL_CONF;
  return env;
}

function child(args, source, options = {}) {
  return spawnSync(process.execPath, [...args, '-e', source], {
    encoding: 'utf8',
    env: cleanEnv(),
    ...options,
  });
}

const dlopen = `process.dlopen({ exports: {} }, ${JSON.stringify(modulePath)});`;

const registerWorker = String.raw`
  const { parentPort, workerData } = require('node:worker_threads');
  const { generateKeyPairSync, randomBytes } = require('node:crypto');
  const gate = new Int32Array(workerData.gate);

  Atomics.add(gate, 0, 1);
  Atomics.notify(gate, 0);
  if (Atomics.wait(gate, 1, 0, 30_000) === 'timed-out') {
    parentPort.postMessage({ ok: false, error: 'timed out at the start gate' });
  } else {
    try {
      process.dlopen({ exports: {} }, workerData.modulePath);
      if (randomBytes(16).byteLength !== 16) throw new Error('randomBytes failed');
      if (generateKeyPairSync('ed25519').publicKey.asymmetricKeyType !== 'ed25519') {
        throw new Error('ordinary Ed25519 generation was redirected');
      }
      parentPort.postMessage({ ok: true });
    } catch (error) {
      parentPort.postMessage({
        ok: false,
        error: error && (error.stack || error.message) || String(error),
      });
    }
  }
`;

test(
  'register preserves fips=yes and is idempotent',
  { skip: !hasDefaultPropertyGetter ? 'EVP_get1_default_properties needs OpenSSL 3.5' : false },
  () => {
    const result = child(
      [],
      `
        const assert = require('node:assert/strict');
        const { getFips, setFips } = require('node:crypto');

        setFips(1);
        assert.equal(getFips(), 1);
        ${dlopen}
        ${dlopen}
        assert.equal(getFips(), 1);
      `,
    );

    assert.equal(result.status, 0, result.stderr);
  },
);

test(
  'register is process-wide and deterministic across Workers',
  {
    skip: !hasDefaultPropertyGetter
      ? 'EVP_get1_default_properties needs OpenSSL 3.5'
      : false,
    timeout: 60_000,
  },
  () => {
    const result = child(
      [],
      `
        const assert = require('node:assert/strict');
        const { generateKeyPairSync, randomBytes } = require('node:crypto');
        const { Worker } = require('node:worker_threads');

        const count = 16;
        const modulePath = ${JSON.stringify(modulePath)};
        const workerSource = ${JSON.stringify(registerWorker)};
        const gate = new Int32Array(
          new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2),
        );

        function completion(worker) {
          return new Promise((resolve, reject) => {
            let message;
            worker.once('message', (value) => { message = value; });
            worker.once('error', reject);
            worker.once('exit', (code) => {
              if (code !== 0) {
                reject(new Error('register worker exited with status ' + code));
              } else if (message === undefined) {
                reject(new Error('register worker exited without a result'));
              } else {
                resolve(message);
              }
            });
          });
        }

        async function waitForWorkers() {
          const deadline = Date.now() + 30_000;
          while (Atomics.load(gate, 0) !== count) {
            if (Date.now() >= deadline) {
              throw new Error(
                'only ' + Atomics.load(gate, 0) + ' of ' + count +
                ' register workers reached the start gate'
              );
            }
            await new Promise((resolve) => setImmediate(resolve));
          }
        }

        async function main() {
          const workers = Array.from(
            { length: count },
            () => new Worker(workerSource, {
              eval: true,
              workerData: { gate: gate.buffer, modulePath },
            }),
          );
          const completions = workers.map(completion);

          try {
            await waitForWorkers();
            Atomics.store(gate, 1, 1);
            Atomics.notify(gate, 1, count);

            const results = await Promise.all(completions);
            assert.deepEqual(
              results,
              Array.from({ length: count }, () => ({ ok: true })),
            );
          } finally {
            Atomics.store(gate, 1, 1);
            Atomics.notify(gate, 1, count);
          }

          // A later call from the main isolate must see the same completed
          // registration and leave ordinary crypto routed to the default
          // provider.
          process.dlopen({ exports: {} }, modulePath);
          assert.equal(randomBytes(16).byteLength, 16);
          assert.equal(
            generateKeyPairSync('ed25519').publicKey.asymmetricKeyType,
            'ed25519',
          );
        }

        main().catch((error) => {
          console.error(error && (error.stack || error.message) || error);
          process.exitCode = 1;
        });
      `,
      { timeout: 55_000 },
    );

    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr);
  },
);

test(
  'KMS algorithms remain eligible under a preserved fips=yes policy',
  {
    skip: !hasDefaultPropertyGetter
      ? 'EVP_get1_default_properties needs OpenSSL 3.5'
      : !hasStoreLoader
        ? 'Node cannot pass a URL to createPrivateKey()'
        : false,
  },
  () => {
    const result = child(
      [],
      `
        const assert = require('node:assert/strict');
        const { createPrivateKey, setFips } = require('node:crypto');

        setFips(1);
        ${dlopen}
        assert.throws(
          () => createPrivateKey({
            key: new URL('aws-kms:not-a-valid-attribute=1'),
            properties: 'provider=aws-kms',
          }),
          { code: 'ERR_OSSL_AWSKMS_INVALID_URI' },
        );
      `,
    );

    assert.equal(result.status, 0, result.stderr);
  },
);

test(
  'register retains fallback providers for unrelated crypto',
  { skip: !hasDefaultPropertyGetter ? 'EVP_get1_default_properties needs OpenSSL 3.5' : false },
  () => {
    const result = child(
      [],
      `
        const assert = require('node:assert/strict');
        const { generateKeyPairSync, randomBytes } = require('node:crypto');

        ${dlopen}
        assert.equal(randomBytes(16).byteLength, 16);
        assert.equal(generateKeyPairSync('ed25519').publicKey.asymmetricKeyType, 'ed25519');
      `,
    );

    assert.equal(result.status, 0, result.stderr);
  },
);

test(
  'register is harmless after the same provider was activated by config',
  {
    skip: !hasDefaultPropertyGetter
      ? 'EVP_get1_default_properties needs OpenSSL 3.5'
      : !cnf
        ? 'no AWSKMS_CNF'
        : false,
  },
  () => {
    const result = child(
      [`--openssl-config=${cnf}`],
      `
        const assert = require('node:assert/strict');
        const { generateKeyPairSync, randomBytes } = require('node:crypto');

        ${dlopen}
        ${dlopen}
        assert.equal(randomBytes(16).byteLength, 16);
        assert.equal(generateKeyPairSync('ed25519').publicKey.asymmetricKeyType, 'ed25519');
      `,
    );

    assert.equal(result.status, 0, result.stderr);
  },
);

test(
  'register refuses a conflicting use of its reserved property marker',
  { skip: !hasDefaultPropertyGetter ? 'EVP_get1_default_properties needs OpenSSL 3.5' : false },
  () => {
    const dir = mkdtempSync(join(tmpdir(), 'awskms-register-conflict-'));
    const config = join(dir, 'openssl.cnf');

    try {
      writeFileSync(
        config,
        `openssl_conf = node_init
nodejs_conf  = node_init

[node_init]
alg_section = algs

[algs]
default_properties = ?keyobject.aws_kms=yes
`,
      );

      const result = child(
        [`--openssl-config=${config}`],
        `
          const assert = require('node:assert/strict');
          require('node:crypto').randomBytes(1);

          assert.throws(
            () => { ${dlopen} },
            (error) => {
              assert.equal(error.code, 'ERR_AWSKMS_PROVIDER_REGISTRATION');
              assert.match(error.message, /reserved property keyobject\\.aws_kms/);
              return true;
            },
          );
        `,
      );

      assert.equal(result.status, 0, result.stderr);
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  },
);

test(
  'register fails clearly on OpenSSL before 3.5 without changing global policy',
  { skip: hasDefaultPropertyGetter ? 'runtime has EVP_get1_default_properties' : false },
  () => {
    const result = child(
      [],
      `
        const assert = require('node:assert/strict');
        const { getFips, setFips } = require('node:crypto');

        setFips(1);
        assert.throws(
          () => { ${dlopen} },
          (error) => {
            assert.equal(error.code, 'ERR_AWSKMS_OPENSSL_VERSION');
            assert.match(error.message, /requires OpenSSL 3\\.5 or newer/);
            return true;
          },
        );
        assert.equal(getFips(), 1);
      `,
    );

    assert.equal(result.status, 0, result.stderr);
  },
);
