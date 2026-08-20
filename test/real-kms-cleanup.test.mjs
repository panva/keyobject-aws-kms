import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { after, before, describe, test } from 'node:test';

const root = resolve(import.meta.dirname, '..');
const script = join(root, 'scripts', 'real-kms-keys.mjs');
const account = '111122223333';
const region = 'eu-central-1';
const runId = 'local-0123456789abcdef01234567';
const keyId = '12345678-1234-1234-1234-123456789012';
const arn = `arn:aws:kms:${region}:${account}:key/${keyId}`;
const alias = `alias/awskms-${runId}-test-rsa-2048`;

let directory;
let fakeAws;
let logPath;

function manifest(overrides = {}) {
  const tags = {
    'awskms-provider-test': '1',
    'awskms-run': runId,
    'awskms-role': 'test',
    'awskms-spec': 'RSA_2048',
  };
  return {
    version: 1,
    account,
    region,
    runId,
    smoke: true,
    createdAt: '2026-08-19T00:00:00.000Z',
    unavailable: [],
    keys: {
      'test-RSA_2048': {
        alias,
        keyId,
        arn,
        keySpec: 'RSA_2048',
        spec: 'RSA_2048',
        role: 'test',
        expectedTags: tags,
      },
    },
    ...overrides,
  };
}

function run(args, {
  scenario = 'tagged',
  value = manifest(),
  manifestPresent = true,
  manifestExplicit = true,
} = {}) {
  const manifestPath = manifestExplicit
    ? join(directory, 'manifest.json')
    : join(directory, 'build', 'real-kms-keys.json');
  mkdirSync(join(directory, 'build'), { recursive: true });
  if (manifestPresent) writeFileSync(manifestPath, `${JSON.stringify(value)}\n`);
  else rmSync(manifestPath, { force: true });
  writeFileSync(logPath, '');
  return spawnSync(
    process.execPath,
    [
      script,
      ...args,
      ...(manifestExplicit ? ['--manifest', manifestPath] : []),
      '--region', region,
      '--profile', 'fake',
    ],
    {
      cwd: directory,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${directory}${delimiter}${process.env.PATH}`,
        FAKE_AWS_LOG: logPath,
        FAKE_AWS_SCENARIO: scenario,
        FAKE_AWS_ACCOUNT: account,
        FAKE_AWS_REGION: region,
        FAKE_AWS_RUN: runId,
        FAKE_AWS_KEY_ID: keyId,
        FAKE_AWS_ARN: arn,
        FAKE_AWS_ALIAS: alias,
      },
    },
  );
}

function calls() {
  return readFileSync(logPath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function destructiveCalls() {
  return calls().filter((args) =>
    args.includes('delete-alias') || args.includes('schedule-key-deletion'));
}

before(() => {
  directory = mkdtempSync(join(tmpdir(), 'awskms-real-cleanup-'));
  logPath = join(directory, 'calls.log');
  fakeAws = join(directory, 'aws');
  writeFileSync(fakeAws, `#!/usr/bin/env node
const { appendFileSync, readFileSync } = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === '--version') process.exit(0);
appendFileSync(process.env.FAKE_AWS_LOG, JSON.stringify(args) + '\\n');
const has = (value) => args.includes(value);
const valueAfter = (value) => args[args.indexOf(value) + 1];
const output = (value) => process.stdout.write(JSON.stringify(value));
if (has('get-caller-identity')) {
  output({ Account: process.env.FAKE_AWS_ACCOUNT, Arn: 'arn:aws:iam::111122223333:role/test' });
} else if (has('describe-key')) {
  const requested = valueAfter('--key-id');
  const foreign = process.env.FAKE_AWS_SCENARIO === 'foreign-alias' && requested === process.env.FAKE_AWS_ALIAS;
  const targetArn = foreign
    ? 'arn:aws:kms:eu-central-1:111122223333:key/ffffffff-ffff-ffff-ffff-ffffffffffff'
    : process.env.FAKE_AWS_ARN;
  output({ KeyMetadata: {
    Arn: targetArn,
    KeyId: targetArn.slice(targetArn.lastIndexOf('/') + 1),
    KeySpec: 'RSA_2048',
    KeyState: 'Enabled',
  } });
} else if (has('list-resource-tags')) {
  const tagReads = readFileSync(process.env.FAKE_AWS_LOG, 'utf8')
    .split('\\n')
    .filter((line) => line.includes('list-resource-tags')).length;
  const untagged = process.env.FAKE_AWS_SCENARIO === 'untagged' ||
    (process.env.FAKE_AWS_SCENARIO === 'tag-removed-after-preflight' && tagReads > 1);
  const tags = untagged ? [] : [
    { TagKey: 'awskms-provider-test', TagValue: '1' },
    { TagKey: 'awskms-run', TagValue: process.env.FAKE_AWS_RUN },
    { TagKey: 'awskms-role', TagValue: 'test' },
    { TagKey: 'awskms-spec', TagValue: 'RSA_2048' },
  ];
  output({ Tags: tags });
} else if (has('get-resources')) {
  output({ ResourceTagMappingList: [
    { ResourceARN: process.env.FAKE_AWS_ARN },
  ] });
} else if (has('delete-alias') && process.env.FAKE_AWS_SCENARIO === 'delete-alias-denied') {
  process.stderr.write(
    'An error occurred (AccessDeniedException) when calling the DeleteAlias operation: denied\\n',
  );
  process.exit(254);
} else {
  output({});
}
`);
  chmodSync(fakeAws, 0o700);
});

after(() => rmSync(directory, { recursive: true, force: true }));

describe('real KMS cleanup safety', () => {
  for (const value of ['0', '-1', '1.5', 'NaN']) {
    test(`rejects --concurrency ${value} before invoking AWS`, () => {
      const result = run(['teardown', '--concurrency', value]);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /positive integer/);
      assert.deepEqual(calls(), []);
    });
  }

  test('a missing teardown manifest is an error before invoking AWS', () => {
    const result = run(['teardown'], { manifestPresent: false });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /manifest not found/);
    assert.deepEqual(calls(), []);
  });

  test('reap ignores an unusable implicit default manifest and sweeps tags', () => {
    const result = run(['reap'], {
      value: { version: 0 },
      manifestExplicit: false,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stderr, /ignoring unusable default manifest/);
    const mutations = destructiveCalls();
    assert.equal(mutations.length, 1);
    assert.ok(mutations[0].includes('schedule-key-deletion'));
  });

  test('reap uses a valid implicit default manifest for alias cleanup', () => {
    const result = run(['reap'], { manifestExplicit: false });
    assert.equal(result.status, 0, result.stderr);
    const mutations = destructiveCalls();
    assert.equal(mutations.length, 2);
    assert.ok(mutations[0].includes('delete-alias'));
    assert.ok(mutations[1].includes('schedule-key-deletion'));
  });

  test('teardown --sweep works without an implicit default manifest', () => {
    const result = run(['teardown', '--sweep'], {
      manifestPresent: false,
      manifestExplicit: false,
    });
    assert.equal(result.status, 0, result.stderr);
    const mutations = destructiveCalls();
    assert.equal(mutations.length, 1);
    assert.ok(mutations[0].includes('schedule-key-deletion'));
  });

  test('reap rejects an unusable explicit manifest without destructive calls', () => {
    const result = run(['reap'], { value: { version: 0 } });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /manifest version must be 1/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('reap rejects a missing explicit manifest without destructive calls', () => {
    const result = run(['reap'], { manifestPresent: false });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /manifest not found/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('reap rejects a foreign explicit manifest without destructive calls', () => {
    const result = run(['reap'], {
      value: manifest({ account: '999900001111' }),
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /does not match caller account/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('rejects a manifest with a foreign run id without destructive calls', () => {
    const result = run(['teardown'], {
      value: manifest({ runId: 'somebody-elses-run' }),
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /invalid runId/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('rejects a foreign manifest account without destructive calls', () => {
    const result = run(['teardown'], {
      value: manifest({ account: '999900001111' }),
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /does not match caller account/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('rejects a foreign manifest region without destructive calls', () => {
    const result = run(['teardown'], {
      value: manifest({ region: 'us-west-2' }),
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /manifest region .* does not match/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('rejects a key ARN outside the manifest account without destructive calls', () => {
    const value = manifest();
    value.keys['test-RSA_2048'].arn =
      `arn:aws:kms:${region}:999900001111:key/${keyId}`;
    const result = run(['teardown'], { value });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ARN outside the selected account\/region/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('rejects an untagged manifest key without destructive calls', () => {
    const result = run(['teardown'], { scenario: 'untagged' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ownership tag/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('rejects an alias that points at a foreign key without destructive calls', () => {
    const result = run(['teardown'], { scenario: 'foreign-alias' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /refusing to delete/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('rechecks ownership tags immediately before alias deletion', () => {
    const result = run(['teardown'], { scenario: 'tag-removed-after-preflight' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ownership tag/);
    assert.deepEqual(destructiveCalls(), []);
  });

  test('deletes the verified alias before scheduling the verified key', () => {
    const result = run(['teardown']);
    assert.equal(result.status, 0, result.stderr);
    const mutations = destructiveCalls();
    assert.equal(mutations.length, 2);
    assert.ok(mutations[0].includes('delete-alias'));
    assert.ok(mutations[1].includes('schedule-key-deletion'));
  });

  test('schedules a verified owned key even when alias deletion is denied', () => {
    const result = run(['teardown'], { scenario: 'delete-alias-denied' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /alias deletion failure\(s\)/);
    const mutations = destructiveCalls();
    assert.equal(mutations.length, 2);
    assert.ok(mutations[0].includes('delete-alias'));
    assert.ok(mutations[1].includes('schedule-key-deletion'));
  });
});
