/*
 * A thin wrapper over the `aws` CLI.
 *
 * The CLI rather than @aws-sdk/client-kms on purpose, twice over:
 *
 *  - this repo has no npm dependencies and no package.json, and a test-only
 *    provisioning script is a poor reason to acquire both;
 *  - credential resolution stays AWS's own. That is the same constraint the
 *    provider itself is held to, so the provisioner cannot accidentally work in a
 *    credential setup the provider would fail in, or vice versa.
 *
 * The CLI is preinstalled on GitHub Actions ubuntu and macos runners.
 */
import { spawnSync } from 'node:child_process';

export class AwsCliError extends Error {
  constructor({ argv, code, stderr, errorCode }) {
    super(`aws ${argv.join(' ')} failed (exit ${code}): ${stderr.trim() || '(no stderr)'}`);
    this.name = 'AwsCliError';
    this.argv = argv;
    this.exitCode = code;
    this.stderr = stderr;
    /* The AWS exception name, e.g. NotFoundException, parsed out of the CLI's
     * error line. This is what callers branch on. */
    this.errorCode = errorCode;
  }
}

/*
 * The CLI reports service exceptions as
 *   An error occurred (NotFoundException) when calling the DescribeKey operation: ...
 * There is no machine-readable form of this, so it is parsed. The parse failing
 * is not fatal -- errorCode is simply undefined and the caller treats it as
 * unrecognised, which is the safe direction.
 */
function errorCodeOf(stderr) {
  return /An error occurred \(([A-Za-z0-9_.]+)\)/.exec(stderr)?.[1];
}

export function hasAwsCli() {
  const r = spawnSync('aws', ['--version'], { encoding: 'utf8' });
  return r.status === 0;
}

/*
 * Runs an aws CLI subcommand and returns parsed JSON (or null for a command that
 * outputs nothing). `global` supplies --region/--profile, which are passed
 * explicitly rather than left to the environment so a run cannot silently land in
 * a different account than the caller intended.
 */
export function aws(args, { region, profile, dryRun = false, quiet = false } = {}) {
  const argv = [...args, '--output', 'json'];
  if (region) argv.push('--region', region);
  if (profile) argv.push('--profile', profile);

  if (dryRun) {
    console.log(`  [dry-run] aws ${argv.join(' ')}`);
    return null;
  }

  const r = spawnSync('aws', argv, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw r.error;
  if (r.status !== 0) {
    const err = new AwsCliError({
      argv,
      code: r.status,
      stderr: r.stderr ?? '',
      errorCode: errorCodeOf(r.stderr ?? ''),
    });
    if (!quiet) throw err;
    return { error: err };
  }
  const out = (r.stdout ?? '').trim();
  return out === '' ? null : JSON.parse(out);
}

/* Same, but a recognised service exception is returned rather than thrown, so
 * callers can treat "not found" as a state instead of a failure. */
export function awsTry(args, opts = {}) {
  const r = aws(args, { ...opts, quiet: true });
  if (r && r.error) return { ok: false, error: r.error };
  return { ok: true, value: r };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/*
 * The region a profile declares in ~/.aws/config, or null.
 *
 * `aws configure get` prints a bare value rather than JSON, so it cannot go
 * through aws() above, which appends --output json.
 */
export function configuredRegion(profile) {
  const argv = ['configure', 'get', 'region'];
  if (profile) argv.push('--profile', profile);
  const r = spawnSync('aws', argv, { encoding: 'utf8' });
  const out = (r.stdout ?? '').trim();
  return r.status === 0 && out !== '' ? out : null;
}

/*
 * KMS state changes are not read-your-writes consistent, so acting on a key
 * immediately after changing it requires polling rather than assuming.
 */
export async function pollUntil(fn, { attempts = 30, intervalMs = 1000, what = 'condition' } = {}) {
  let last;
  for (let i = 0; i < attempts; i++) {
    last = await fn();
    if (last) return last;
    await sleep(intervalMs);
  }
  throw new Error(`timed out waiting for ${what} after ${attempts} attempts`);
}
