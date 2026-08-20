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
let timingPath;

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

function parallelManifest(count = 4) {
  const value = manifest({ keys: {} });
  const expectedTags = manifest().keys['test-RSA_2048'].expectedTags;
  for (let index = 0; index < count; index++) {
    const suffix = String(index + 1).padStart(12, '0');
    const parallelKeyId = `00000000-0000-0000-0000-${suffix}`;
    const parallelArn = `arn:aws:kms:${region}:${account}:key/${parallelKeyId}`;
    const parallelAlias = `alias/awskms-${runId}-parallel-${index + 1}`;
    value.keys[`parallel-${index + 1}`] = {
      alias: parallelAlias,
      keyId: parallelKeyId,
      arn: parallelArn,
      keySpec: 'RSA_2048',
      spec: 'RSA_2048',
      role: 'test',
      expectedTags,
    };
  }
  return value;
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
  writeFileSync(timingPath, '');
  const targets = Object.values(value?.keys ?? {}).map((key) => ({
    alias: key.alias,
    keyId: key.keyId,
    arn: key.arn,
    keySpec: key.keySpec,
  }));
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
        FAKE_AWS_TIMING_LOG: timingPath,
        FAKE_AWS_SCENARIO: scenario,
        FAKE_AWS_TARGETS: JSON.stringify(targets),
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

function timingEvents() {
  return readFileSync(timingPath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function maximumConcurrency(events) {
  const active = new Set();
  let maximum = 0;
  for (const event of events) {
    if (event.type === 'start') {
      active.add(event.pid);
      maximum = Math.max(maximum, active.size);
    } else {
      active.delete(event.pid);
    }
  }
  assert.equal(active.size, 0);
  return maximum;
}

before(() => {
  directory = mkdtempSync(join(tmpdir(), 'awskms-real-cleanup-'));
  logPath = join(directory, 'calls.log');
  timingPath = join(directory, 'timing.log');
  fakeAws = join(directory, 'aws');
  writeFileSync(fakeAws, `#!/usr/bin/env node
const { appendFileSync, readFileSync } = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === '--version') process.exit(0);
appendFileSync(process.env.FAKE_AWS_LOG, JSON.stringify(args) + '\\n');
const has = (value) => args.includes(value);
const valueAfter = (value) => args[args.indexOf(value) + 1];
const targets = JSON.parse(process.env.FAKE_AWS_TARGETS);
const timing = (type) => appendFileSync(
  process.env.FAKE_AWS_TIMING_LOG,
  JSON.stringify({ type, pid: process.pid, args }) + '\\n',
);
if (process.env.FAKE_AWS_SCENARIO === 'delayed' && has('kms')) {
  timing('start');
  process.on('exit', () => timing('end'));
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
}
const output = (value) => process.stdout.write(JSON.stringify(value));
if (has('get-caller-identity')) {
  output({ Account: process.env.FAKE_AWS_ACCOUNT, Arn: 'arn:aws:iam::111122223333:role/test' });
} else if (has('describe-key')) {
  const requested = valueAfter('--key-id');
  const selected = targets.find((target) =>
    target.alias === requested || target.keyId === requested || target.arn === requested
  );
  if (process.env.FAKE_AWS_SCENARIO === 'target-not-found' &&
      requested === targets[0]?.arn) {
    process.stderr.write(
      'An error occurred (NotFoundException) when calling the DescribeKey operation: missing\\n',
    );
    process.exit(254);
  }
  const aliasReads = readFileSync(process.env.FAKE_AWS_LOG, 'utf8')
    .split('\\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .filter((call) => call.includes('describe-key') && call.includes(requested)).length;
  const foreign =
    (process.env.FAKE_AWS_SCENARIO === 'foreign-alias' && requested === process.env.FAKE_AWS_ALIAS) ||
    (process.env.FAKE_AWS_SCENARIO === 'foreign-alias-last' && requested === targets.at(-1)?.alias) ||
    (process.env.FAKE_AWS_SCENARIO === 'alias-retargeted-after-preflight' &&
     requested === targets[0]?.alias && aliasReads > 1);
  const targetArn = foreign
    ? 'arn:aws:kms:eu-central-1:111122223333:key/ffffffff-ffff-ffff-ffff-ffffffffffff'
    : selected?.arn ?? process.env.FAKE_AWS_ARN;
  output({ KeyMetadata: {
    Arn: targetArn,
    KeyId: targetArn.slice(targetArn.lastIndexOf('/') + 1),
    KeySpec: selected?.keySpec ?? 'RSA_2048',
    KeyState: 'Enabled',
  } });
} else if (has('list-resource-tags')) {
  const requested = valueAfter('--key-id');
  const tagReads = readFileSync(process.env.FAKE_AWS_LOG, 'utf8')
    .split('\\n')
    .filter((line) => line.includes('list-resource-tags')).length;
  const untagged = process.env.FAKE_AWS_SCENARIO === 'untagged' ||
    (process.env.FAKE_AWS_SCENARIO === 'tag-removed-after-preflight' && tagReads > 1) ||
    (process.env.FAKE_AWS_SCENARIO === 'untagged-last' && requested === targets.at(-1)?.keyId);
  const tags = untagged ? [] : [
    { TagKey: 'awskms-provider-test', TagValue: '1' },
    { TagKey: 'awskms-run', TagValue: process.env.FAKE_AWS_RUN },
    { TagKey: 'awskms-role', TagValue: 'test' },
    { TagKey: 'awskms-spec', TagValue: 'RSA_2048' },
  ];
  output({ Tags: tags });
} else if (has('get-resources')) {
  const resources = targets.length === 0
    ? [process.env.FAKE_AWS_ARN]
    : targets.map((target) => target.arn);
  output({ ResourceTagMappingList: resources.map((ResourceARN) => ({ ResourceARN })) });
} else if (has('delete-alias') && process.env.FAKE_AWS_SCENARIO === 'delete-alias-denied') {
  process.stderr.write(
    'An error occurred (AccessDeniedException) when calling the DeleteAlias operation: denied\\n',
  );
  process.exit(254);
} else if (has('delete-alias') &&
           process.env.FAKE_AWS_SCENARIO === 'delete-one-alias-denied' &&
           valueAfter('--alias-name') === targets[0]?.alias) {
  process.stderr.write(
    'An error occurred (AccessDeniedException) when calling the DeleteAlias operation: denied\\n',
  );
  process.exit(254);
} else if (has('schedule-key-deletion') &&
           process.env.FAKE_AWS_SCENARIO === 'schedule-one-key-denied' &&
           valueAfter('--key-id') === targets[0]?.arn) {
  process.stderr.write(
    'An error occurred (AccessDeniedException) when calling the ScheduleKeyDeletion operation: denied\\n',
  );
  process.exit(254);
} else if (has('schedule-key-deletion') &&
           process.env.FAKE_AWS_SCENARIO === 'already-pending-deletion') {
  process.stderr.write(
    'An error occurred (KMSInvalidStateException) when calling the ScheduleKeyDeletion operation: key is pending deletion\\n',
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

  test('treats an asynchronously reported missing target as already cleaned', () => {
    const result = run(['teardown', '--json'], { scenario: 'target-not-found' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /"scheduled":0/);
    assert.deepEqual(destructiveCalls(), []);
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

  test('preflights every target before mutating when one target is untagged', () => {
    const result = run(['teardown', '--concurrency', '2'], {
      scenario: 'untagged-last',
      value: parallelManifest(),
    });
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

  test('preflights every alias before mutating when one alias is foreign', () => {
    const result = run(['teardown', '--concurrency', '2'], {
      scenario: 'foreign-alias-last',
      value: parallelManifest(),
    });
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

  test('refuses an alias retargeted after preflight but still schedules its owned key', () => {
    const result = run(['teardown'], {
      scenario: 'alias-retargeted-after-preflight',
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /it now targets/);
    const mutations = destructiveCalls();
    assert.equal(mutations.length, 1);
    assert.ok(mutations[0].includes('schedule-key-deletion'));
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

  test('accepts a key that is already pending deletion', () => {
    const result = run(['teardown'], { scenario: 'already-pending-deletion' });
    assert.equal(result.status, 0, result.stderr);
    const mutations = destructiveCalls();
    assert.equal(mutations.length, 2);
    assert.ok(mutations[0].includes('delete-alias'));
    assert.ok(mutations[1].includes('schedule-key-deletion'));
  });

  test('cleanup dry-run verifies live state and prints only mutations', () => {
    const result = run(['teardown', '--dry-run']);
    assert.equal(result.status, 0, result.stderr);
    const recorded = calls();
    assert.ok(recorded.some((args) => args.includes('get-caller-identity')));
    assert.ok(recorded.some((args) => args.includes('list-resource-tags')));
    assert.deepEqual(destructiveCalls(), []);
    assert.match(result.stdout, /\[dry-run\] aws kms delete-alias/);
    assert.match(result.stdout, /\[dry-run\] aws kms schedule-key-deletion/);
    assert.doesNotMatch(result.stdout, /\[dry-run\] aws kms describe-key/);
  });

  test('reap dry-run discovers and verifies live tagged keys', () => {
    const result = run(['reap', '--dry-run'], {
      manifestPresent: false,
      manifestExplicit: false,
    });
    assert.equal(result.status, 0, result.stderr);
    const recorded = calls();
    assert.ok(recorded.some((args) => args.includes('get-resources')));
    assert.ok(recorded.some((args) => args.includes('list-resource-tags')));
    assert.deepEqual(destructiveCalls(), []);
    assert.match(result.stdout, /\[dry-run\] aws kms schedule-key-deletion/);
    assert.doesNotMatch(result.stdout, /\[dry-run\] aws kms delete-alias/);
  });

  test('cleanup dry-run fails closed before printing mutations', () => {
    const result = run(['teardown', '--dry-run'], { scenario: 'untagged' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ownership tag/);
    assert.deepEqual(destructiveCalls(), []);
    assert.doesNotMatch(result.stdout, /\[dry-run\] aws kms (?:delete-alias|schedule-key-deletion)/);
  });

  test('cleanup dry-run rejects a foreign alias before printing mutations', () => {
    const result = run(['teardown', '--dry-run'], { scenario: 'foreign-alias' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /refusing to delete/);
    assert.deepEqual(destructiveCalls(), []);
    assert.doesNotMatch(result.stdout, /\[dry-run\] aws kms (?:delete-alias|schedule-key-deletion)/);
  });

  test('bounds concurrent cleanup and preserves the read-only preflight barrier', () => {
    const value = parallelManifest();
    const result = run(['teardown', '--concurrency', '2'], {
      scenario: 'delayed',
      value,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(maximumConcurrency(timingEvents()), 2);

    const recorded = calls();
    const firstMutation = recorded.findIndex((args) =>
      args.includes('delete-alias') || args.includes('schedule-key-deletion'));
    assert.notEqual(firstMutation, -1);
    const preflightCalls = recorded.slice(0, firstMutation);
    for (const key of Object.values(value.keys)) {
      assert.ok(preflightCalls.some((args) =>
        args.includes('describe-key') && args.includes(key.arn)));
      assert.ok(preflightCalls.some((args) =>
        args.includes('list-resource-tags') && args.includes(key.keyId)));
      assert.ok(preflightCalls.some((args) =>
        args.includes('describe-key') && args.includes(key.alias)));
    }
  });

  test('aggregates an alias failure without withholding other key schedules', () => {
    const value = parallelManifest(3);
    const result = run(['teardown', '--concurrency', '2'], {
      scenario: 'delete-one-alias-denied',
      value,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /1 alias deletion failure\(s\)/);
    const schedules = destructiveCalls().filter((args) =>
      args.includes('schedule-key-deletion'));
    assert.equal(schedules.length, 3);
  });

  test('aggregates a key failure after attempting every owned key schedule', () => {
    const value = parallelManifest(3);
    const result = run(['teardown', '--concurrency', '2'], {
      scenario: 'schedule-one-key-denied',
      value,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /1 owned key scheduling failure\(s\)/);
    const schedules = destructiveCalls().filter((args) =>
      args.includes('schedule-key-deletion'));
    assert.equal(schedules.length, 3);
  });
});
