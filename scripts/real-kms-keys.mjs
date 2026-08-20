#!/usr/bin/env node
/*
 * Provision and remove the AWS KMS keys used by the real-service test suite.
 *
 * Every run gets collision-resistant aliases and create-time ownership tags.
 * Cleanup is deliberately two-phase: all manifest, account, region, alias and
 * tag checks complete before the first DeleteAlias or ScheduleKeyDeletion call.
 * A corrupt manifest or a foreign alias therefore cannot turn into a destructive
 * request.
 *
 * USAGE
 *   node scripts/real-kms-keys.mjs setup    [options]
 *   node scripts/real-kms-keys.mjs teardown [options]
 *   node scripts/real-kms-keys.mjs status   [options]
 *   node scripts/real-kms-keys.mjs reap     [options]
 *
 * OPTIONS
 *   --region <r>       required, or AWS_REGION/AWS_DEFAULT_REGION/profile
 *   --profile <p>      AWS profile; required locally unless ambient credentials
 *                      are explicitly allowed
 *   --smoke            provision the smoke subset
 *   --roles <scope>    provision test only, or all roles (default all)
 *   --manifest <path>  default build/real-kms-keys.json
 *   --window <days>    integer 7..30 (default 7)
 *   --concurrency <n>  positive integer (default 4)
 *   --sweep            include every owned tagged key in cleanup
 *   --dry-run          print mutations without making them; cleanup still
 *                      performs live read-only discovery and verification
 *   --json             print a machine-readable result
 */
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import {
  aws,
  awsTry,
  awsTryAsync,
  configuredRegion,
  hasAwsCli,
  pollUntil,
  sleep,
} from './aws-cli.mjs';
import { required, ROLES } from '../test/inventory.mjs';

const MANIFEST_VERSION = 1;
const TAGS = Object.freeze({
  owner: 'awskms-provider-test',
  run: 'awskms-run',
  role: 'awskms-role',
  spec: 'awskms-spec',
});
const OWNER_VALUE = '1';
const ALIAS_PREFIX = 'alias/awskms-';

const log = (...args) => console.log(...args);
const readOnlyOptions = (opts) => opts.dryRun
  ? { ...opts, dryRun: false }
  : opts;

function parseArgs(argv) {
  const cmd = argv[0];
  const opts = {
    region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION,
    profile: process.env.AWS_PROFILE,
    smoke: false,
    roles: [...ROLES],
    rolesExplicit: false,
    manifest: 'build/real-kms-keys.json',
    manifestExplicit: false,
    window: 7,
    concurrency: 4,
    sweep: false,
    dryRun: false,
    json: false,
  };

  for (let i = 1; i < argv.length; i++) {
    const argument = argv[i];
    const next = () => {
      const value = argv[++i];
      if (value === undefined) throw new Error(`${argument} needs a value`);
      return value;
    };
    switch (argument) {
      case '--region': opts.region = next(); break;
      case '--profile': opts.profile = next(); break;
      case '--manifest':
        opts.manifest = next();
        opts.manifestExplicit = true;
        break;
      case '--window': opts.window = Number(next()); break;
      case '--concurrency': opts.concurrency = Number(next()); break;
      case '--smoke': opts.smoke = true; break;
      case '--roles': {
        const roles = next();
        if (roles === 'test') opts.roles = ['test'];
        else if (roles === 'all') opts.roles = [...ROLES];
        else throw new Error('--roles must be test or all');
        opts.rolesExplicit = true;
        break;
      }
      case '--sweep': opts.sweep = true; break;
      case '--dry-run': opts.dryRun = true; break;
      case '--json': opts.json = true; break;
      default: throw new Error(`unknown option ${argument}`);
    }
  }

  if (!Number.isInteger(opts.concurrency) || opts.concurrency <= 0) {
    throw new Error('--concurrency must be a positive integer');
  }
  if (!Number.isInteger(opts.window) || opts.window < 7 || opts.window > 30) {
    throw new Error('--window must be an integer from 7 through 30');
  }
  if (cmd !== 'setup' && opts.rolesExplicit) {
    throw new Error('--roles is only valid with setup');
  }
  return { cmd, opts };
}

async function mapLimit(items, limit, fn) {
  const output = new Array(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      for (;;) {
        const index = next++;
        if (index >= items.length) return;
        output[index] = await fn(items[index], index);
      }
    },
  );
  await Promise.all(workers);
  return output;
}

async function withRetry(fn, { attempts = 6, what = 'call' } = {}) {
  let delay = 500;
  for (let attempt = 1; ; attempt++) {
    const result = fn();
    if (result.ok) return result.value;
    const retryable = [
      'ThrottlingException',
      'LimitExceededException',
      'KMSInternalException',
    ].includes(result.error.errorCode);
    if (!retryable || attempt >= attempts) throw result.error;
    log(`  ${what}: ${result.error.errorCode}, retrying in ${delay}ms`);
    await sleep(delay);
    delay *= 2;
  }
}

function isUnsupportedSpec(error) {
  return error.errorCode === 'UnsupportedOperationException' ||
    (error.errorCode === 'ValidationException' &&
      /KeySpec|key spec|not support/i.test(error.stderr));
}

function makeRunId() {
  const ci = process.env.GITHUB_RUN_ID
    ? `gh-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT ?? '1'}-`
    : 'local-';
  return `${ci}${randomBytes(12).toString('hex')}`.toLowerCase();
}

function aliasFor(runId, key) {
  const suffix = `${key.role}-${key.spec}`
    .toLowerCase()
    .replaceAll('_', '-');
  return `${ALIAS_PREFIX}${runId}-${suffix}`;
}

function expectedTags(runId, role, spec) {
  return {
    [TAGS.owner]: OWNER_VALUE,
    [TAGS.run]: runId,
    [TAGS.role]: role,
    [TAGS.spec]: spec,
  };
}

function tagArguments(tags) {
  return Object.entries(tags).map(
    ([key, value]) => `TagKey=${key},TagValue=${value}`,
  );
}

function describeAlias(alias, opts) {
  const result = awsTry(['kms', 'describe-key', '--key-id', alias], opts);
  if (result.ok) return result.value?.KeyMetadata ?? null;
  if (result.error.errorCode === 'NotFoundException') return null;
  throw result.error;
}

async function describeAliasAsync(alias, opts) {
  const result = await awsTryAsync(
    ['kms', 'describe-key', '--key-id', alias],
    readOnlyOptions(opts),
  );
  if (result.ok) return result.value?.KeyMetadata ?? null;
  if (result.error.errorCode === 'NotFoundException') return null;
  throw result.error;
}

function parseKeyArn(arn) {
  const match = /^arn:[^:]+:kms:([^:]+):(\d{12}):key\/(.+)$/.exec(arn ?? '');
  return match ? { region: match[1], account: match[2], keyId: match[3] } : null;
}

function validateManifest(manifest, opts) {
  if (!manifest || manifest.version !== MANIFEST_VERSION) {
    throw new Error(`manifest version must be ${MANIFEST_VERSION}`);
  }
  if (manifest.account !== opts.account) {
    throw new Error(
      `manifest account ${manifest.account ?? '(missing)'} does not match caller account ${opts.account}`,
    );
  }
  if (manifest.region !== opts.region) {
    throw new Error(
      `manifest region ${manifest.region ?? '(missing)'} does not match ${opts.region}`,
    );
  }
  if (!/^(?:gh-[0-9]+-[0-9]+-|local-)[a-f0-9]{24}$/.test(manifest.runId ?? '')) {
    throw new Error('manifest has an invalid runId');
  }
  if (!manifest.keys || typeof manifest.keys !== 'object' || Array.isArray(manifest.keys)) {
    throw new Error('manifest keys must be an object');
  }
  const roles = manifest.roles ?? ROLES;
  if (!Array.isArray(roles) || roles.length === 0 ||
      new Set(roles).size !== roles.length ||
      roles.some((role) => !ROLES.includes(role))) {
    throw new Error(`manifest roles must contain unique values from ${ROLES.join(', ')}`);
  }

  for (const [name, key] of Object.entries(manifest.keys)) {
    const arn = parseKeyArn(key.arn);
    if (!arn || arn.account !== opts.account || arn.region !== opts.region) {
      throw new Error(`manifest key ${name} has an ARN outside the selected account/region`);
    }
    if (key.keyId !== arn.keyId || key.role == null || key.spec == null) {
      throw new Error(`manifest key ${name} has inconsistent identity fields`);
    }
    if (!roles.includes(key.role)) {
      throw new Error(`manifest key ${name} has role ${key.role} outside manifest roles`);
    }
    if (!key.alias?.startsWith(`${ALIAS_PREFIX}${manifest.runId}-`)) {
      throw new Error(`manifest key ${name} has an alias outside this run's namespace`);
    }
    const expected = expectedTags(manifest.runId, key.role, key.spec);
    if (JSON.stringify(key.expectedTags) !== JSON.stringify(expected)) {
      throw new Error(`manifest key ${name} has unexpected ownership tags`);
    }
  }
}

function readManifest(opts, { optional = true } = {}) {
  const path = resolve(opts.manifest);
  if (!existsSync(path)) {
    if (optional) return null;
    throw new Error(`manifest not found: ${path}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`cannot parse manifest ${path}: ${error.message}`);
  }
  validateManifest(manifest, opts);
  return manifest;
}

async function setup(opts) {
  const runId = makeRunId();
  const wanted = required({ smokeOnly: opts.smoke, roles: opts.roles });
  log(`provisioning ${wanted.length} keys in ${opts.region} for ${runId}`);

  const results = await mapLimit(wanted, opts.concurrency, async (key) => {
    const label = `${key.role}-${key.spec}`;
    const alias = aliasFor(runId, key);
    const tags = expectedTags(runId, key.role, key.spec);

    if (describeAlias(alias, opts) != null) {
      throw new Error(`refusing to replace the already-existing run alias ${alias}`);
    }

    let created;
    try {
      created = await withRetry(
        () => awsTry([
          'kms', 'create-key',
          '--key-spec', key.spec,
          '--key-usage', 'SIGN_VERIFY',
          '--description', `keyobject-aws-kms test key (${runId} ${label})`,
          '--tags', ...tagArguments(tags),
        ], opts),
        { what: `${label} create-key` },
      );
    } catch (error) {
      if (isUnsupportedSpec(error)) {
        log(`  ${label}: skipped; ${key.spec} is unavailable in ${opts.region}`);
        return { ...key, unavailable: true };
      }
      throw error;
    }

    if (opts.dryRun) {
      return {
        ...key,
        alias,
        keyId: '(dry-run)',
        arn: '(dry-run)',
        expectedTags: tags,
      };
    }

    const metadata = created.KeyMetadata;
    await pollUntil(
      () => {
        const result = awsTry(
          ['kms', 'describe-key', '--key-id', metadata.KeyId],
          opts,
        );
        return result.ok && result.value?.KeyMetadata?.KeyState === 'Enabled';
      },
      { what: `${label} to become Enabled` },
    );

    await withRetry(
      () => awsTry([
        'kms', 'create-alias',
        '--alias-name', alias,
        '--target-key-id', metadata.KeyId,
      ], opts),
      { what: `${label} create-alias` },
    );

    log(`  ${label}: ${metadata.KeyId}`);
    return {
      ...key,
      alias,
      keyId: metadata.KeyId,
      arn: metadata.Arn,
      keySpec: metadata.KeySpec,
      expectedTags: tags,
    };
  });

  const unavailable = results.filter((result) => result.unavailable)
    .map((result) => result.spec);
  const keys = {};
  for (const result of results) {
    if (result.unavailable) continue;
    keys[`${result.role}-${result.spec}`] = {
      alias: result.alias,
      keyId: result.keyId,
      arn: result.arn,
      keySpec: result.keySpec,
      spec: result.spec,
      role: result.role,
      expectedTags: result.expectedTags,
    };
  }

  const manifest = {
    version: MANIFEST_VERSION,
    account: opts.account,
    region: opts.region,
    runId,
    smoke: opts.smoke,
    roles: opts.roles,
    createdAt: new Date().toISOString(),
    unavailable: [...new Set(unavailable)],
    keys,
  };

  if (!opts.dryRun) {
    const path = resolve(opts.manifest);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    log(`manifest: ${path}`);
  }
  return manifest;
}

function sweepTagged(opts) {
  const readOpts = readOnlyOptions(opts);
  const result = awsTry([
    'resourcegroupstaggingapi', 'get-resources',
    '--tag-filters', `Key=${TAGS.owner},Values=${OWNER_VALUE}`,
    '--resource-type-filters', 'kms:key',
  ], readOpts);
  if (result.ok) {
    return (result.value?.ResourceTagMappingList ?? [])
      .map((mapping) => mapping.ResourceARN);
  }

  const listed = awsTry(['kms', 'list-keys'], readOpts);
  if (!listed.ok) throw listed.error;
  const found = [];
  for (const { KeyId, KeyArn } of listed.value?.Keys ?? []) {
    const tags = awsTry(
      ['kms', 'list-resource-tags', '--key-id', KeyId],
      readOpts,
    );
    if (!tags.ok) continue;
    if ((tags.value?.Tags ?? []).some(
      (tag) => tag.TagKey === TAGS.owner && tag.TagValue === OWNER_VALUE,
    )) found.push(KeyArn ?? KeyId);
  }
  return found;
}

async function verifyOwnedTarget(target, opts) {
  const described = await awsTryAsync(
    ['kms', 'describe-key', '--key-id', target.id],
    readOnlyOptions(opts),
  );
  if (!described.ok && described.error.errorCode === 'NotFoundException') {
    return { exists: false, metadata: null };
  }
  if (!described.ok) throw described.error;
  const metadata = described.value?.KeyMetadata;
  const arn = parseKeyArn(metadata?.Arn);
  if (!arn || arn.account !== opts.account || arn.region !== opts.region) {
    throw new Error(`${target.why} resolves outside the selected account/region`);
  }

  const listed = await awsTryAsync(
    ['kms', 'list-resource-tags', '--key-id', metadata.KeyId],
    readOnlyOptions(opts),
  );
  if (!listed.ok) throw listed.error;
  const actual = Object.fromEntries(
    (listed.value?.Tags ?? []).map((tag) => [tag.TagKey, tag.TagValue]),
  );
  for (const [key, value] of Object.entries(target.expectedTags)) {
    if (actual[key] !== value) {
      throw new Error(
        `refusing to modify ${metadata.Arn}: ownership tag ${key} must be ${value}`,
      );
    }
  }
  if (target.keySpec && metadata.KeySpec !== target.keySpec) {
    throw new Error(
      `refusing to modify ${metadata.Arn}: expected ${target.keySpec}, got ${metadata.KeySpec}`,
    );
  }
  return { exists: true, metadata };
}

async function scheduleDeletion(keyId, opts, what) {
  const result = await awsTryAsync([
    'kms', 'schedule-key-deletion',
    '--key-id', keyId,
    '--pending-window-in-days', String(opts.window),
  ], opts);
  if (result.ok || result.error.errorCode === 'NotFoundException') return;
  if (result.error.errorCode === 'KMSInvalidStateException' &&
      /is (?!not )pending (deletion|replica deletion)/.test(result.error.stderr)) {
    return;
  }
  throw new Error(`${what}: ${result.error.message}`);
}

function collectTargets(manifest, opts) {
  const targets = new Map();
  const add = (target) => {
    if (target.id && !targets.has(target.id)) targets.set(target.id, target);
  };

  for (const [name, key] of Object.entries(manifest?.keys ?? {})) {
    add({
      id: key.arn,
      why: `manifest:${name}`,
      alias: key.alias,
      keySpec: key.keySpec ?? key.spec,
      expectedTags: key.expectedTags,
    });
  }
  if (opts.sweep) {
    for (const arn of sweepTagged(opts)) {
      add({
        id: arn,
        why: 'tag-sweep',
        alias: null,
        keySpec: null,
        expectedTags: { [TAGS.owner]: OWNER_VALUE },
      });
    }
  }
  return [...targets.values()];
}

async function teardown(opts) {
  /* A normal teardown without its manifest is a billing leak, not a successful
   * no-op. Only an explicit tag sweep is allowed to proceed without one. */
  let manifest;
  try {
    manifest = readManifest(opts, {
      optional: opts.sweep && !opts.manifestExplicit,
    });
  } catch (error) {
    /* An ownership-tag sweep is recovery, so a stale implicit manifest must not
     * prevent it from finding owned keys. An explicitly selected manifest
     * remains a fail-closed assertion about the cleanup scope. */
    if (!opts.sweep || opts.manifestExplicit) throw error;
    console.error(
      `ignoring unusable default manifest ${resolve(opts.manifest)} during tag sweep: ${error.message}`,
    );
    manifest = null;
  }
  const targets = collectTargets(manifest, opts);
  if (targets.length === 0) {
    log('nothing to tear down');
    return { scheduled: 0 };
  }

  /* Preflight every target and alias before the first destructive request. */
  const preflight = await mapLimit(targets, opts.concurrency, async (target) => {
    const verified = await verifyOwnedTarget(target, opts);
    if (!verified.exists) return null;

    let alias = null;
    if (target.alias) {
      const aliasTarget = await describeAliasAsync(target.alias, opts);
      if (aliasTarget == null) return { target, alias };
      if (aliasTarget.Arn !== verified.metadata.Arn) {
        throw new Error(
          `refusing to delete ${target.alias}: it targets ${aliasTarget.Arn}, not ${verified.metadata.Arn}`,
        );
      }
      alias = target.alias;
    }
    return { target, alias };
  });

  const activeEntries = preflight.filter(Boolean);
  const active = activeEntries.map(({ target }) => target);
  const aliases = activeEntries.filter(({ alias }) => alias != null);

  const aliasResults = await mapLimit(aliases, opts.concurrency, async ({ alias, target }) => {
    /* Recheck immediately before the destructive call.  The all-target
     * preflight above guarantees a bad manifest causes zero mutations; this
     * second check also closes the ordinary tag/alias TOCTOU window. */
    try {
      const verified = await verifyOwnedTarget(target, opts);
      const aliasTarget = await describeAliasAsync(alias, opts);
      if (!verified.exists || aliasTarget == null) return 0;
      if (aliasTarget.Arn !== verified.metadata.Arn) {
        throw new Error(
          `refusing to delete ${alias}: it now targets ${aliasTarget.Arn}, not ${verified.metadata.Arn}`,
        );
      }
      const result = await awsTryAsync(
        ['kms', 'delete-alias', '--alias-name', alias],
        opts,
      );
      if (!result.ok && result.error.errorCode !== 'NotFoundException') {
        throw result.error;
      }
      return 0;
    } catch (error) {
      /* The preflight passed before this phase began. A per-alias operational or
       * TOCTOU failure must remain visible, but must not keep other verified keys
       * enabled and billable. Every key is independently rechecked below. */
      console.error(`  alias:${alias}: ${error.message}`);
      return 1;
    }
  });
  const aliasFailures = aliasResults.reduce((total, failed) => total + failed, 0);

  const keyResults = await mapLimit(active, opts.concurrency, async (target) => {
    try {
      const verified = await verifyOwnedTarget(target, opts);
      if (!verified.exists) return 0;
      await scheduleDeletion(target.id, opts, target.why);
      return 0;
    } catch (error) {
      console.error(`  ${target.why}: ${error.message}`);
      return 1;
    }
  });
  const keyFailures = keyResults.reduce((total, failed) => total + failed, 0);
  if (aliasFailures !== 0 || keyFailures !== 0) {
    throw new Error(
      `cleanup completed with ${aliasFailures} alias deletion failure(s) and ` +
      `${keyFailures} owned key scheduling failure(s)`,
    );
  }
  return { scheduled: active.length };
}

function status(opts) {
  const manifest = readManifest(opts, { optional: true });
  if (!manifest) {
    log('no manifest');
    return [];
  }
  const rows = Object.values(manifest.keys).map((key) => {
    const metadata = describeAlias(key.alias, readOnlyOptions(opts));
    return {
      alias: key.alias,
      state: metadata?.KeyState ?? 'absent',
      keyId: metadata?.KeyId ?? '',
      keySpec: metadata?.KeySpec ?? '',
      mismatch: metadata && metadata.Arn !== key.arn ? 'FOREIGN TARGET' : '',
    };
  });
  for (const row of rows) {
    log(`${row.alias} ${row.state} ${row.keySpec} ${row.keyId} ${row.mismatch}`);
  }
  return rows;
}

async function main() {
  const { cmd, opts } = parseArgs(process.argv.slice(2));
  if (!['setup', 'teardown', 'status', 'reap'].includes(cmd)) {
    throw new Error('usage: real-kms-keys.mjs <setup|teardown|status|reap> [options]');
  }
  if (cmd === 'teardown' && !opts.sweep && !existsSync(resolve(opts.manifest))) {
    throw new Error(`manifest not found: ${resolve(opts.manifest)}`);
  }
  if (!hasAwsCli()) throw new Error('the `aws` CLI is required and was not found on PATH');

  let regionSource = opts.region ? 'command line or environment' : null;
  if (!opts.region && opts.profile) {
    opts.region = configuredRegion(opts.profile);
    if (opts.region) regionSource = `profile ${opts.profile}`;
  }
  if (!opts.region) {
    throw new Error('no region; pass --region, set AWS_REGION, or configure the profile');
  }
  if (!opts.profile && !process.env.CI &&
      !process.env.AWSKMS_ALLOW_AMBIENT_CREDENTIALS) {
    throw new Error('--profile is required outside CI; ambient credentials need AWSKMS_ALLOW_AMBIENT_CREDENTIALS=1');
  }

  if (opts.dryRun && cmd === 'setup') {
    opts.account = '000000000000';
  } else {
    const identity = aws(
      ['sts', 'get-caller-identity'],
      readOnlyOptions(opts),
    );
    opts.account = identity.Account;
    log(`account ${identity.Account} as ${identity.Arn}`);
  }
  log(`region ${opts.region} (from ${regionSource})`);

  let result;
  switch (cmd) {
    case 'setup':
      result = await setup(opts);
      break;
    case 'teardown':
      result = await teardown(opts);
      break;
    case 'status':
      result = status(opts);
      break;
    case 'reap':
      result = await teardown({ ...opts, sweep: true });
      break;
  }
  if (opts.json) console.log(JSON.stringify(result));
}

main().catch((error) => {
  console.error(`\n${error.message}`);
  process.exitCode = 1;
});
