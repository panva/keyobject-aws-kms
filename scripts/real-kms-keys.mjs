#!/usr/bin/env node
/*
 * Provisions and tears down the real AWS KMS keys the test suite needs.
 *
 * LIFECYCLE
 * ---------
 * Keys are created fresh at the start of every run and scheduled for deletion at
 * the end. Deletion is never cancelled, so key ARNs differ between runs and the
 * aliases are the only stable handle.
 *
 * That follows from three properties of KMS pricing:
 *
 *   - a key scheduled for deletion is not charged;
 *   - a disabled key is charged at the full rate, making "park them between runs"
 *     the expensive option rather than the cheap one;
 *   - cancelling a deletion re-bills the entire waiting period "as though it was
 *     never scheduled", so reviving keys costs the same as never scheduling
 *     deletion at all -- about $22/month for this inventory, against about $0.73
 *     for a create-and-schedule pass, since the $1/key/month is prorated hourly.
 *
 * ALIAS INVARIANT: THE NAME IS FREED BEFORE THE KEY IS SCHEDULED
 * -------------------------------------------------------------
 * An alias is a region-unique name and stays attached to its key for the whole
 * pending-deletion window; aliases are removed only when the key is actually
 * deleted, at least seven days later and possibly up to 24 hours after the
 * scheduled date.
 *
 * A teardown that only scheduled deletion would therefore leave
 * alias/test-RSA_2048 occupied by a dying key, and the next run's CreateAlias
 * would fail with AlreadyExistsException -- making the suite unrunnable for a week
 * for a reason that resembles nothing about its cause.
 *
 * DeleteAlias consequently runs first, while the key is still enabled, and
 * ScheduleKeyDeletion second. That order also sidesteps any question of which
 * alias operations are permitted against a key already pending deletion. Every
 * code path below preserves it.
 *
 * A consequence of that ordering is that no aliases exist between runs, so running
 * the suite without provisioning fails with NotFoundException ->
 * ERR_OSSL_AWSKMS_KEY_NOT_FOUND rather than something requiring interpretation.
 *
 * IDEMPOTENCE
 * -----------
 * Both subcommands tolerate being run twice, being run after the other half
 * crashed, and being run when the tests never started.
 *
 * An existing alias at setup time means a previous run did not tear down, so setup
 * deletes that alias and schedules its key before creating the replacement. Setup
 * is therefore also the reaper for the most common leak, a CI runner dying mid-job.
 *
 * Teardown takes the union of three sources, since any one can be incomplete: the
 * manifest setup wrote, the aliases the inventory declares, and (with --sweep)
 * every key carrying the test tag. A key found in more than one is scheduled once.
 *
 * USAGE
 *   node scripts/real-kms-keys.mjs setup    [options]
 *   node scripts/real-kms-keys.mjs teardown [options]
 *   node scripts/real-kms-keys.mjs status   [options]
 *   node scripts/real-kms-keys.mjs reap     [options]   # tag sweep, orphans only
 *
 * OPTIONS
 *   --region <r>       required (or AWS_REGION); passed explicitly to every call
 *   --profile <p>      an existing profile from ~/.aws/config -- normally
 *                      awskms-admin, created by real-kms-bootstrap.mjs.
 *                      Required locally; omitted in CI, where the role
 *                      arrives through OIDC instead
 *   --smoke            the 4-spec / 8-key subset instead of all 11 / 22
 *   --manifest <path>  where the key ARNs are written / read
 *                      (default build/real-kms-keys.json)
 *   --window <days>    ScheduleKeyDeletion waiting period (default 7, the minimum)
 *   --concurrency <n>  parallel API calls (default 4, to stay under CreateKey quota)
 *   --sweep            teardown/reap also scans by tag for orphans
 *   --dry-run          print every call, make none
 *   --json             machine-readable summary on stdout
 */
import { writeFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { aws, awsTry, configuredRegion, hasAwsCli, pollUntil, sleep } from './aws-cli.mjs';
import { required } from '../test/inventory.mjs';

/* Applied at CreateKey time, so a sweep can find orphans whose alias is already
 * gone -- the one leak setup cannot self-heal. TagResource fails once a key is
 * pending deletion, so tagging later is not an option. */
const TAG_KEY = 'awskms-provider-test';
const TAG_VALUE = '1';

/* ------------------------------------------------------------------ arguments */

function parseArgs(argv) {
  const cmd = argv[0];
  const opts = {
    region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION,
    profile: process.env.AWS_PROFILE,
    smoke: false,
    manifest: 'build/real-kms-keys.json',
    window: 7,
    concurrency: 4,
    sweep: false,
    dryRun: false,
    json: false,
  };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case '--region': opts.region = next(); break;
      case '--profile': opts.profile = next(); break;
      case '--manifest': opts.manifest = next(); break;
      case '--window': opts.window = Number(next()); break;
      case '--concurrency': opts.concurrency = Number(next()); break;
      case '--smoke': opts.smoke = true; break;
      case '--sweep': opts.sweep = true; break;
      case '--dry-run': opts.dryRun = true; break;
      case '--json': opts.json = true; break;
      default: throw new Error(`unknown option ${a}`);
    }
  }
  return { cmd, opts };
}

/* --------------------------------------------------------------------- helpers */

const log = (...a) => console.log(...a);

/* Bounded parallelism. CreateKey has a low per-second quota and 22 at once would
 * spend the run retrying throttles instead of provisioning. */
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

/*
 * Retries the throttling errors, and nothing else. A retry loop that swallows
 * everything would turn a permissions problem into a slow timeout.
 */
async function withRetry(fn, { attempts = 6, what = 'call' } = {}) {
  let delay = 500;
  for (let i = 1; ; i++) {
    const r = fn();
    if (r.ok) return r.value;
    const code = r.error.errorCode;
    const retryable =
      code === 'ThrottlingException' ||
      code === 'LimitExceededException' ||
      code === 'KMSInternalException';
    if (!retryable || i >= attempts) throw r.error;
    log(`  ${what}: ${code}, retrying in ${delay}ms (${i}/${attempts})`);
    await sleep(delay);
    delay *= 2;
  }
}

/* A KeySpec unsupported in this region, distinguished from every other failure so
 * the suites skip those specs instead of failing on them. */
function isUnsupportedSpec(err) {
  if (err.errorCode === 'UnsupportedOperationException') return true;
  /* ValidationException covers "unrecognised KeySpec", which is what an older
   * region returns for ML-DSA. Match on the message to avoid swallowing genuine
   * validation mistakes in this script. */
  return (
    err.errorCode === 'ValidationException' &&
    /KeySpec|key spec|not support/i.test(err.stderr)
  );
}

/* ---------------------------------------------------------------- alias lookup */

/*
 * Resolves an alias to its key metadata, or null when the alias does not exist.
 *
 * DescribeKey accepts an alias name directly, and it works for a key that is
 * pending deletion -- which is essential here, since that is the state every key
 * from a previous run is in.
 */
function describeAlias(aliasName, opts) {
  const r = awsTry(['kms', 'describe-key', '--key-id', aliasName], opts);
  if (r.ok) return r.value?.KeyMetadata ?? null;
  if (r.error.errorCode === 'NotFoundException') return null;
  throw r.error;
}

/* ----------------------------------------------------------------------- setup */

async function setup(opts) {
  const wanted = required({ smokeOnly: opts.smoke });
  log(`provisioning ${wanted.length} keys in ${opts.region}${opts.smoke ? ' (smoke subset)' : ''}`);

  const results = await mapLimit(wanted, opts.concurrency, async (k) => {
    const tag = `${k.role}-${k.spec}`;

    /* A pre-existing alias means a previous run leaked, normally a CI runner that
     * died before teardown. The name is freed first (see the alias invariant at
     * the top of this file), then the key is scheduled so it stops billing. */
    const existing = describeAlias(k.alias, opts);
    if (existing) {
      log(`  ${tag}: found a leaked key ${existing.KeyId} (${existing.KeyState}), reaping`);
      await withRetry(() => awsTry(['kms', 'delete-alias', '--alias-name', k.alias], opts), {
        what: `${tag} delete-alias`,
      });
      /* Already-pending keys cost nothing, so leave them to expire. */
      if (existing.KeyState !== 'PendingDeletion') {
        await scheduleDeletion(existing.KeyId, opts, tag);
      }
    }

    /* Create the key. */
    let created;
    try {
      created = await withRetry(
        () =>
          awsTry(
            [
              'kms', 'create-key',
              '--key-spec', k.spec,
              '--key-usage', 'SIGN_VERIFY',
              '--description', `tiny-aws-kms-openssl-provider test key (${tag})`,
              '--tags',
              `TagKey=${TAG_KEY},TagValue=${TAG_VALUE}`,
              `TagKey=awskms-role,TagValue=${k.role}`,
              `TagKey=awskms-spec,TagValue=${k.spec}`,
            ],
            opts,
          ),
        { what: `${tag} create-key` },
      );
    } catch (err) {
      if (isUnsupportedSpec(err)) {
        log(`  ${tag}: SKIPPED -- ${k.spec} is not available in ${opts.region}`);
        return { ...k, unavailable: true };
      }
      throw err;
    }

    if (opts.dryRun) return { ...k, keyId: '(dry-run)', arn: '(dry-run)' };

    const meta = created.KeyMetadata;

    /* KMS is not read-your-writes consistent, so a CreateAlias immediately after
     * CreateKey can fail with NotFoundException on a key that certainly exists.
     * Confirm the key is visible and Enabled before naming it. */
    await pollUntil(
      () => {
        const r = awsTry(['kms', 'describe-key', '--key-id', meta.KeyId], opts);
        return r.ok && r.value?.KeyMetadata?.KeyState === 'Enabled';
      },
      { what: `${tag} to become Enabled` },
    );

    /* CreateAlias, falling back to UpdateAlias if the name reappeared between the
     * reap above and here -- the two-runs-overlapping race. The workflow's
     * concurrency group prevents it; recovery costs one call, whereas losing the
     * race otherwise fails the whole run. UpdateAlias re-points the name at this
     * run's key irrespective of what it pointed at before. */
    await withRetry(
      () => {
        const r = awsTry(
          ['kms', 'create-alias', '--alias-name', k.alias, '--target-key-id', meta.KeyId],
          opts,
        );
        if (r.ok || r.error.errorCode !== 'AlreadyExistsException') return r;
        log(`  ${tag}: alias reappeared (concurrent run?), re-pointing it`);
        return awsTry(
          ['kms', 'update-alias', '--alias-name', k.alias, '--target-key-id', meta.KeyId],
          opts,
        );
      },
      { what: `${tag} create-alias` },
    );

    log(`  ${tag}: ${meta.KeyId}`);
    return { ...k, keyId: meta.KeyId, arn: meta.Arn, keySpec: meta.KeySpec };
  });

  const unavailable = results.filter((r) => r.unavailable).map((r) => r.spec);
  const keys = {};
  for (const r of results) {
    if (r.unavailable) continue;
    keys[`${r.role}-${r.spec}`] = {
      alias: r.alias, keyId: r.keyId, arn: r.arn, keySpec: r.keySpec, spec: r.spec, role: r.role,
    };
  }

  const manifest = {
    region: opts.region,
    smoke: opts.smoke,
    createdAt: new Date().toISOString(),
    runId: process.env.GITHUB_RUN_ID ?? null,
    /* Specs unavailable in this region. The suites read this and skip, rather
     * than reporting a provisioning gap as a provider bug. */
    unavailable: [...new Set(unavailable)],
    keys,
  };

  if (!opts.dryRun) {
    const path = resolve(opts.manifest);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
    log(`manifest: ${path}`);
  }
  if (unavailable.length) {
    log(`unavailable in ${opts.region}: ${[...new Set(unavailable)].join(', ')}`);
  }
  return manifest;
}

/* -------------------------------------------------------------------- teardown */

async function scheduleDeletion(keyId, opts, what) {
  const r = awsTry(
    [
      'kms', 'schedule-key-deletion',
      '--key-id', keyId,
      '--pending-window-in-days', String(opts.window),
    ],
    opts,
  );
  if (r.ok) {
    log(`  ${what}: scheduled ${keyId}`);
    return true;
  }
  /* Already gone is the desired end state. */
  if (r.error.errorCode === 'NotFoundException') {
    log(`  ${what}: ${keyId} already gone`);
    return true;
  }
  /*
   * ScheduleKeyDeletion is NOT idempotent -- a second call fails with
   * KMSInvalidStateException rather than succeeding, and does not reset the
   * window. Treating that as success is what makes teardown safe to run twice.
   *
   * But KMSInvalidStateException is NOT specific to "already pending": the same
   * exception covers a key in Creating, Updating or PendingImport. Accepting the
   * exception CODE alone would silently report success for a key that is still
   * Enabled and still billing -- the exact failure teardown exists to prevent. So
   * match the message.
   *
   * Prefix-match on "is pending deletion": the full sentence differs between
   * callers (some carry an "(or pending replica deletion)" suffix, some do not).
   * The word "not" is the discriminator against the opposite error, hence the
   * negative lookahead.
   */
  if (
    r.error.errorCode === 'KMSInvalidStateException' &&
    /is (?!not )pending (deletion|replica deletion)/.test(r.error.stderr)
  ) {
    log(`  ${what}: ${keyId} already pending deletion`);
    return true;
  }
  throw r.error;
}

function readManifest(opts) {
  const path = resolve(opts.manifest);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

/*
 * Every key carrying our tag. This finds orphans whose alias is already gone,
 * which is the one leak setup cannot detect on its own.
 *
 * Two routes, because the first is faster but its support for KMS could not be
 * confirmed in AWS's own documentation: the Resource Groups Tagging API's own
 * reference says it returns "All tagged resources, whether the tagging used the
 * Resource Groups Tagging API or not", but KMS's tagging page never mentions it,
 * and the supported-services tables are JavaScript-rendered so they cannot be
 * read. Rather than trust it, fall back to enumerating KMS directly -- slower and
 * chattier, but it cannot silently return nothing and leave keys billing.
 *
 * The CLI auto-paginates both, so there is no page loop here.
 */
function sweepTagged(opts) {
  const r = awsTry(
    [
      'resourcegroupstaggingapi', 'get-resources',
      '--tag-filters', `Key=${TAG_KEY},Values=${TAG_VALUE}`,
      '--resource-type-filters', 'kms:key',
    ],
    opts,
  );
  if (r.ok) {
    const arns = (r.value?.ResourceTagMappingList ?? []).map((m) => m.ResourceARN);
    log(`  sweep (tagging API): ${arns.length} tagged key(s)`);
    return arns;
  }

  log(`  tagging API unavailable (${r.error.errorCode ?? 'error'}); enumerating KMS directly`);
  return sweepByEnumeration(opts);
}

/* The fallback: list every key in the region and check its tags. Needs only
 * kms:ListKeys + kms:ListResourceTags, no tag:GetResources. */
function sweepByEnumeration(opts) {
  const listed = awsTry(['kms', 'list-keys'], opts);
  if (!listed.ok) {
    log(`  cannot enumerate keys (${listed.error.errorCode ?? 'error'}); sweep found nothing`);
    return [];
  }
  const found = [];
  for (const { KeyId, KeyArn } of listed.value?.Keys ?? []) {
    const tags = awsTry(['kms', 'list-resource-tags', '--key-id', KeyId], opts);
    /* AccessDenied on someone else's key is expected in a shared account, and is
     * not our business -- skip quietly rather than failing the sweep. */
    if (!tags.ok) continue;
    const ours = (tags.value?.Tags ?? []).some(
      (t) => t.TagKey === TAG_KEY && t.TagValue === TAG_VALUE,
    );
    if (ours) found.push(KeyArn ?? KeyId);
  }
  log(`  sweep (enumeration): ${found.length} tagged key(s)`);
  return found;
}

async function teardown(opts) {
  /* The union of three sources, because each can be incomplete on its own: the
   * manifest is missing if setup died before writing it, alias resolution misses
   * keys whose alias was never created, and the tag sweep needs an extra
   * permission that may not be granted. */
  const targets = new Map();
  const add = (id, why) => {
    if (id && !targets.has(id)) targets.set(id, why);
  };

  const manifest = readManifest(opts);
  if (manifest) {
    for (const [name, k] of Object.entries(manifest.keys ?? {})) add(k.arn ?? k.keyId, `manifest:${name}`);
    log(`manifest lists ${Object.keys(manifest.keys ?? {}).length} keys`);
  } else {
    log('no manifest; falling back to alias resolution');
  }

  /* Every alias name is freed before anything is scheduled -- the invariant at
   * the top of this file. The alias is deleted regardless of which run created the
   * key, because an alias left behind blocks the next run from provisioning, and a
   * dropped name is cheaper than an AlreadyExistsException a week later. */
  for (const k of required({ smokeOnly: opts.smoke })) {
    const meta = describeAlias(k.alias, opts);
    if (!meta) continue;
    add(meta.KeyId, `alias:${k.role}-${k.spec}`);
    const r = awsTry(['kms', 'delete-alias', '--alias-name', k.alias], opts);
    if (!r.ok && r.error.errorCode !== 'NotFoundException') throw r.error;
  }

  if (opts.sweep) for (const arn of sweepTagged(opts)) add(arn, 'tag-sweep');

  if (targets.size === 0) {
    log('nothing to tear down');
    return { scheduled: 0 };
  }

  log(`scheduling ${targets.size} keys for deletion (window ${opts.window}d)`);
  const entries = [...targets.entries()];
  let failures = 0;
  await mapLimit(entries, opts.concurrency, async ([id, why]) => {
    try {
      await scheduleDeletion(id, opts, why);
    } catch (err) {
      /* One failure does not abandon the rest, since every key left standing is
       * billable. Failures are collected and reported after the loop. */
      failures++;
      console.error(`  ${why}: FAILED to schedule ${id}: ${err.message}`);
    }
  });

  if (failures > 0) {
    throw new Error(
      `${failures} of ${targets.size} keys could not be scheduled for deletion; ` +
        'they are still billable -- check them manually',
    );
  }
  return { scheduled: targets.size };
}

/* ---------------------------------------------------------------------- status */

function status(opts) {
  const rows = required({ smokeOnly: opts.smoke }).map((k) => {
    const meta = describeAlias(k.alias, opts);
    return {
      alias: k.alias,
      state: meta?.KeyState ?? 'absent',
      keyId: meta?.KeyId ?? '',
      keySpec: meta?.KeySpec ?? '',
      /* An alias pointing at the wrong spec makes the tests fail deep inside
       * signature assertions rather than reporting a provisioning problem. */
      mismatch: meta && meta.KeySpec !== k.spec ? `EXPECTED ${k.spec}` : '',
    };
  });
  for (const r of rows) {
    log(
      `${r.alias.padEnd(34)} ${r.state.padEnd(16)} ${r.keySpec.padEnd(22)} ${r.keyId} ${r.mismatch}`,
    );
  }
  const billable = rows.filter((r) => r.state === 'Enabled' || r.state === 'Disabled').length;
  log(`\n${billable} key(s) currently billable`);
  return rows;
}

/* ------------------------------------------------------------------------ main */

async function main() {
  const { cmd, opts } = parseArgs(process.argv.slice(2));

  if (!cmd || !['setup', 'teardown', 'status', 'reap'].includes(cmd)) {
    console.error(readFileSync(new URL(import.meta.url), 'utf8').split('\n * USAGE')[1]?.split('*/')[0] ?? '');
    console.error('usage: real-kms-keys.mjs <setup|teardown|status|reap> [options]');
    process.exit(2);
  }
  if (!hasAwsCli()) {
    console.error('the `aws` CLI is required and was not found on PATH');
    process.exit(2);
  }
  /*
   * The guard exists to stop a SILENT default -- aws-sdk-cpp substitutes
   * us-east-1 when its own resolution comes up empty, which is how a key that
   * plainly exists turns into NotFoundException. A region the profile declares is
   * not a guess, so it counts; where it came from is printed either way.
   */
  let regionSource = opts.region ? 'the command line or environment' : null;
  if (!opts.region && opts.profile) {
    const fromProfile = configuredRegion(opts.profile);
    if (fromProfile) {
      opts.region = fromProfile;
      regionSource = `profile ${opts.profile}`;
    }
  }
  if (!opts.region) {
    console.error('No region. Pass --region, set AWS_REGION, or give the profile one.');
    console.error('This will not fall back to a default: the AWS SDK silently uses');
    console.error('us-east-1, which surfaces later as a key that plainly exists not');
    console.error('being found.');
    process.exit(2);
  }

  /* In CI the role arrives via OIDC and there is no profile. Locally, requiring
   * one explicitly is deliberate: the command creates and deletes keys, so it does
   * not fall back to whatever ambient credentials happen to be configured. */
  if (!opts.profile && !process.env.CI && !process.env.AWSKMS_ALLOW_AMBIENT_CREDENTIALS) {
    console.error('--profile (or AWS_PROFILE) is required outside CI.');
    console.error('This creates and deletes real KMS keys, so it will not use ambient credentials.');
    console.error('Set AWSKMS_ALLOW_AMBIENT_CREDENTIALS=1 only if you are certain.');
    process.exit(2);
  }

  log(`region ${opts.region} (from ${regionSource})`);
  const who = opts.dryRun ? null : aws(['sts', 'get-caller-identity'], opts);
  if (who) log(`account ${who.Account} as ${who.Arn}`);
  log('');

  switch (cmd) {
    case 'setup': {
      const m = await setup(opts);
      if (opts.json) console.log(JSON.stringify(m));
      break;
    }
    case 'teardown': {
      const r = await teardown(opts);
      if (opts.json) console.log(JSON.stringify(r));
      break;
    }
    case 'status':
      status(opts);
      break;
    case 'reap': {
      /* Orphans only: tagged keys not already pending deletion. Backs the
       * scheduled reaper, which bounds what a dead runner can leave billing. */
      const arns = sweepTagged({ ...opts, sweep: true });
      log(`${arns.length} tagged key(s) found`);
      let n = 0;
      for (const arn of arns) {
        const meta = awsTry(['kms', 'describe-key', '--key-id', arn], opts);
        if (!meta.ok) continue;
        const state = meta.value?.KeyMetadata?.KeyState;
        if (state === 'PendingDeletion') continue;
        await scheduleDeletion(arn, opts, 'reap');
        n++;
      }
      log(`${n} orphan(s) scheduled`);
      break;
    }
  }
}

main().catch((err) => {
  console.error(`\n${err.message}`);
  process.exit(1);
});
