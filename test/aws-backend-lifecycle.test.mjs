/*
 * AWS SDK client lifecycle and routing tests.
 *
 * These need the aws backend, but never contact AWS: test/run.mjs points the
 * real SDK at the local HTTP KMS stub and exposes its request log.  Keeping the
 * tests on the wire path is important here because client construction, cache
 * lookup, eviction, and teardown all sit below the provider's STORE/signature
 * operations and above the SDK transport.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { test } from 'node:test';
import { Worker } from 'node:worker_threads';
import { dirname, join } from 'node:path';

const endpoint = process.env.AWSKMS_ENDPOINT;
const cnf = process.env.AWSKMS_CNF;
const modulePath = process.env.AWSKMS_MODULE;
const unloadHarness = process.env.AWSKMS_UNLOAD_HARNESS ??
  (modulePath && join(dirname(modulePath), 'awskms_provider_unload'));
let backend;
try {
  backend = readFileSync(join(dirname(modulePath), 'awskms-backend'), 'utf8').trim();
} catch {
  backend = process.env.AWSKMS_STUB === '1' ? 'aws' : undefined;
}
const needsHttpStub =
  endpoint && process.env.AWSKMS_STUB === '1' && process.env.AWSKMS_TEST_REAL !== '1'
    ? false
    : 'needs the aws backend with the local HTTP KMS stub';

async function requestLog() {
  const response = await fetch(`${endpoint}/__requests`);
  assert.equal(response.status, 200);
  return (await response.json()).requests;
}

async function clearRequestLog() {
  const response = await fetch(`${endpoint}/__requests`, { method: 'DELETE' });
  assert.equal(response.status, 200);
}

const CLIENT_WORKER = String.raw`
  const { parentPort, workerData } = require('node:worker_threads');
  const {
    createPrivateKey,
    createPublicKey,
    sign,
    verify,
  } = require('node:crypto');

  const gate = new Int32Array(workerData.gate);
  Atomics.add(gate, 0, 1);
  Atomics.notify(gate, 0);

  if (Atomics.wait(gate, 1, 0, 30_000) === 'timed-out') {
    parentPort.postMessage({ ok: false, error: 'timed out at the start gate' });
  } else {
    try {
      const key = createPrivateKey({ key: new URL(workerData.uri) });
      const message = Buffer.from('concurrent aws client creation');
      const signature = sign('sha256', message, key);
      if (!verify('sha256', message, createPublicKey(key), signature)) {
        throw new Error('signature did not verify');
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

function workerCompletion(worker) {
  return new Promise((resolve, reject) => {
    let message;

    worker.once('message', (value) => {
      message = value;
    });
    worker.once('error', reject);
    worker.once('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`client worker exited with status ${code}`));
      } else if (message === undefined) {
        reject(new Error('client worker exited without a result'));
      } else {
        resolve(message);
      }
    });
  });
}

async function waitForWorkers(gate, expected) {
  const deadline = Date.now() + 30_000;
  while (Atomics.load(gate, 0) !== expected) {
    if (Date.now() >= deadline) {
      throw new Error(
        `only ${Atomics.load(gate, 0)} of ${expected} client workers reached the start gate`,
      );
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
}

test(
  'concurrent first use safely publishes one shared client configuration',
  { skip: needsHttpStub, timeout: 60_000 },
  async () => {
    await clearRequestLog();

    const count = 16;
    const gate = new Int32Array(
      new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2),
    );
    const uri =
      'aws-kms:key-id=alias/concurrent-client-RSA_2048;region=us-east-1';
    const workers = Array.from(
      { length: count },
      () =>
        new Worker(CLIENT_WORKER, {
          eval: true,
          workerData: { gate: gate.buffer, uri },
        }),
    );
    const completions = workers.map(workerCompletion);
    let completed = false;

    try {
      await waitForWorkers(gate, count);
      Atomics.store(gate, 1, 1);
      Atomics.notify(gate, 1, count);

      const results = await Promise.all(completions);
      assert.deepEqual(
        results,
        Array.from({ length: count }, () => ({ ok: true })),
      );
      completed = true;
    } finally {
      Atomics.store(gate, 1, 1);
      Atomics.notify(gate, 1, count);
      if (!completed) {
        await Promise.allSettled(workers.map((worker) => worker.terminate()));
      }
    }

    const requests = await requestLog();
    const forKey = requests.filter(
      ({ keyId }) => keyId === 'alias/concurrent-client-RSA_2048',
    );
    assert.equal(
      forKey.filter(({ target }) => target === 'TrentService.GetPublicKey').length,
      count,
    );
    assert.equal(
      forKey.filter(({ target }) => target === 'TrentService.Sign').length,
      count,
    );
  },
);

test(
  'more than 64 routing configurations remain usable across LRU eviction',
  { skip: needsHttpStub, timeout: 60_000 },
  async () => {
    await clearRequestLog();

    const count = 70;
    const keyId = 'alias/client-lru-RSA_2048';
    let oldest;
    let newest;

    for (let i = 0; i < count; i++) {
      const region = `awskms-test-${String(i).padStart(2, '0')}`;
      const key = createPrivateKey({
        key: new URL(`aws-kms:key-id=${keyId};region=${region}`),
      });
      if (i === 0) oldest = key;
      if (i === count - 1) newest = key;
    }

    let requests = await requestLog();
    const publicKeyRequests = requests.filter(
      ({ target, keyId: requestedKey }) =>
        target === 'TrentService.GetPublicKey' && requestedKey === keyId,
    );
    assert.equal(publicKeyRequests.length, count);

    // The oldest route has fallen out of a 64-entry cache, while the newest is
    // still hot. Both paths must remain usable, including destruction of the
    // evicted SDK client outside the cache lock.
    for (const key of [oldest, newest]) {
      const message = Buffer.from('lru route remains usable');
      const signature = sign('sha256', message, key);
      assert.equal(verify('sha256', message, createPublicKey(key), signature), true);
    }

    requests = await requestLog();
    assert.equal(
      requests.filter(
        ({ target, keyId: requestedKey }) =>
          target === 'TrentService.Sign' && requestedKey === keyId,
      ).length,
      2,
    );
  },
);

test(
  'FIPS mode rejects an endpoint override before an SDK request',
  { skip: needsHttpStub },
  async () => {
    await clearRequestLog();

    const encodedEndpoint = encodeURIComponent(endpoint);
    assert.throws(
      () =>
        createPrivateKey({
          key: new URL(
            `aws-kms:key-id=alias/fips-endpoint-RSA_2048?endpoint=${encodedEndpoint}`,
          ),
          properties: 'fips=yes',
        }),
      { code: 'ERR_OSSL_AWSKMS_FIPS_ROUTING' },
    );
    assert.deepEqual(await requestLog(), []);
  },
);

test(
  'FIPS mode rejects a case-insensitive China region before an SDK request',
  { skip: needsHttpStub || (!cnf && 'no AWSKMS_CNF'), timeout: 30_000 },
  async () => {
    await clearRequestLog();

    const env = {
      ...process.env,
      AWS_CONFIG_FILE: '/dev/null',
      AWS_SHARED_CREDENTIALS_FILE: '/dev/null',
      AWS_MAX_ATTEMPTS: '1',
    };
    for (const name of [
      'AWSKMS_ENDPOINT',
      'AWS_ENDPOINT_URL',
      'AWS_ENDPOINT_URL_KMS',
      'AWS_PROFILE',
      'AWS_DEFAULT_PROFILE',
    ]) {
      delete env[name];
    }

    const child = spawnSync(
      process.execPath,
      [
        `--openssl-config=${cnf}`,
        '-e',
        `
          const assert = require('node:assert/strict');
          const { createPrivateKey } = require('node:crypto');
          assert.throws(
            () => createPrivateKey({
              key: new URL(
                'aws-kms:key-id=alias/fips-china-RSA_2048;region=CN-north-1'
              ),
              properties: 'fips=yes',
            }),
            { code: 'ERR_OSSL_AWSKMS_FIPS_ROUTING' },
          );
          console.log('FIPS_ROUTING_REJECTED');
        `,
      ],
      { encoding: 'utf8', env, timeout: 20_000 },
    );

    assert.equal(child.error, undefined, child.error?.message);
    assert.equal(child.status, 0, child.stderr);
    assert.match(child.stdout, /FIPS_ROUTING_REJECTED/);
    assert.deepEqual(await requestLog(), []);
  },
);

test(
  'a child with an active AWS client unloads the provider and exits cleanly',
  { skip: needsHttpStub || (!cnf && 'no AWSKMS_CNF'), timeout: 30_000 },
  () => {
    const child = spawnSync(
      process.execPath,
      [
        `--openssl-config=${cnf}`,
        '-e',
        `
          const {
            createPrivateKey,
            createPublicKey,
            sign,
            verify,
          } = require('node:crypto');
          const key = createPrivateKey({
            key: new URL(
              'aws-kms:key-id=alias/clean-exit-RSA_2048;region=us-east-1'
            ),
          });
          const message = Buffer.from('clean provider exit');
          const signature = sign('sha256', message, key);
          if (!verify('sha256', message, createPublicKey(key), signature)) {
            throw new Error('signature did not verify');
          }
          console.log('CLEAN_EXIT');
        `,
      ],
      { encoding: 'utf8', env: process.env, timeout: 20_000 },
    );

    assert.equal(child.error, undefined, child.error?.message);
    assert.equal(child.signal, null);
    assert.equal(child.status, 0, child.stderr);
    assert.match(child.stdout, /CLEAN_EXIT/);
  },
);

test(
  'explicit provider unload leaves the host process usable',
  {
    skip: process.env.AWSKMS_TEST_REAL === '1'
      ? 'explicit unload uses only an offline backend'
      : !unloadHarness || !existsSync(unloadHarness)
        ? 'provider-unload harness was not built'
        : backend === 'aws' && needsHttpStub
          ? needsHttpStub
          : false,
    timeout: 30_000,
  },
  async () => {
    if (backend === 'aws') await clearRequestLog();

    const keyId = 'alias/explicit-provider-unload-RSA_2048';
    const child = spawnSync(
      unloadHarness,
      [
        dirname(modulePath),
        `aws-kms:key-id=${keyId};region=us-east-1`,
      ],
      { encoding: 'utf8', env: process.env, timeout: 20_000 },
    );

    assert.equal(child.error, undefined, child.error?.message);
    assert.equal(child.signal, null);
    assert.equal(child.status, 0, child.stderr);
    assert.match(child.stdout, /AWS_CLIENT_CREATED/);
    assert.match(child.stdout, /PROVIDER_UNLOADED/);
    assert.match(child.stdout, /ORDINARY_CRYPTO_OK/);

    if (backend === 'aws') {
      const requests = (await requestLog()).filter(
        ({ keyId: requestedKey }) => requestedKey === keyId,
      );
      assert.equal(
        requests.filter(({ target }) => target === 'TrentService.GetPublicKey').length,
        1,
      );
      assert.equal(
        requests.filter(({ target }) => target === 'TrentService.Sign').length,
        1,
      );
    }
  },
);
