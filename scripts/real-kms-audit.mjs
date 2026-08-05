#!/usr/bin/env node
/*
 * Verifies request accounting against the REAL service, via CloudTrail.
 *
 * The offline suites assert "one kms:Sign per signature" by reading the HTTP
 * stub's request log. Real KMS has no such log, so that assertion has always
 * been skipped in real mode -- leaving the single most expensive property of the
 * provider unverified where it actually costs money.
 *
 * What is being protected: OpenSSL asks "how big will this signature be?" by
 * calling sign with a NULL buffer, and Node does that on four separate code
 * paths, several of them twice per signature. A provider that forwarded those
 * probes would bill two or three times per signature and block the event loop for
 * each. It would also return a signature that does not match the probed length,
 * since KMS is hedged.
 *
 * CloudTrail's Event history covers this with no trail to create and no storage
 * cost: KMS API calls are management events, retained free for 90 days. The only
 * permission needed is cloudtrail:LookupEvents, held by the admin role -- not the
 * signer, which must keep holding nothing but kms:Sign and kms:GetPublicKey.
 *
 * The catch is latency: events are typically visible within about 15 minutes, so
 * this polls rather than asserting synchronously. That is why it is a separate
 * command instead of a test.
 *
 * USAGE
 *   node scripts/real-kms-audit.mjs --profile awskms-admin [options]
 *
 * OPTIONS
 *   --profile <p>         profile that can call cloudtrail:LookupEvents
 *                         (awskms-admin; re-run real-kms-bootstrap.mjs if this
 *                         fails with AccessDenied)
 *   --signer-profile <p>  profile the signing workload runs as
 *                         (default awskms-signer)
 *   --region <r>          defaults to the profile's region
 *   --module <path>       aws-backend module (default build-aws/awskms.{dylib,so})
 *   --node <path>         node with STORE loader support (default this one)
 *   --signatures <n>      signatures to make (default 5)
 *   --wait <seconds>      how long to poll CloudTrail (default 1200)
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { aws, configuredRegion, hasAwsCli, sleep } from './aws-cli.mjs';
import { writeCnf } from '../test/cnf.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

function parseArgs(argv) {
  const o = {
    signerProfile: 'awskms-signer',
    module: join(root, 'build-aws', process.platform === 'darwin' ? 'awskms.dylib' : 'awskms.so'),
    node: process.execPath,
    signatures: 5,
    wait: 1200,
    manifest: join(root, 'build', 'real-kms-keys.json'),
  };
  for (let i = 0; i < argv.length; i++) {
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${argv[i - 1]} needs a value`);
      return v;
    };
    switch (argv[i]) {
      case '--profile': o.profile = next(); break;
      case '--signer-profile': o.signerProfile = next(); break;
      case '--region': o.region = next(); break;
      case '--module': o.module = resolve(next()); break;
      case '--node': o.node = resolve(next()); break;
      case '--manifest': o.manifest = resolve(next()); break;
      case '--signatures': o.signatures = Number(next()); break;
      case '--wait': o.wait = Number(next()); break;
      default: throw new Error(`unknown option ${argv[i]}`);
    }
  }
  return o;
}

/*
 * The workload, run in a child because OpenSSL reads its config once at library
 * init, so the provider cannot be activated from an already-running process.
 *
 * Deliberately exercises the three things CloudTrail can distinguish:
 *   - ONE key load          -> expect exactly 1 GetPublicKey
 *   - N signatures          -> expect exactly N Sign, despite the size probes
 *   - N local verifications -> expect NO additional calls of any kind
 */
const WORKLOAD = `
import { createPrivateKey, createPublicKey, sign, verify, randomBytes } from 'node:crypto';
const [uri, n] = [process.env.AUDIT_URI, Number(process.env.AUDIT_N)];
const key = createPrivateKey({ key: new URL(uri) });   // 1 GetPublicKey
const pub = createPublicKey(key);                      // no network
const sigs = [];
for (let i = 0; i < n; i++) sigs.push(sign('sha256', randomBytes(64), key));
let verified = 0;
for (const s of sigs) if (verify('sha256', randomBytes(64), pub, s) === false) verified++;
console.log(JSON.stringify({ signatures: sigs.length, verifiesRun: verified }));
`;

function runWorkload(uri, opts, cnf) {
  const r = spawnSync(opts.node, [`--openssl-config=${cnf}`, '--input-type=module', '-e', WORKLOAD], {
    encoding: 'utf8',
    env: {
      ...process.env,
      AWSKMS_MODULE: opts.module,
      AUDIT_URI: uri,
      AUDIT_N: String(opts.signatures),
      AWS_PROFILE: opts.signerProfile,
      AWS_REGION: opts.region,
      /* The signer profile is the point: if the workload could only sign with
       * broader credentials, the count would prove less than it appears to. */
      AWS_DEFAULT_REGION: opts.region,
    },
  });
  if (r.status !== 0) {
    throw new Error(`workload failed (exit ${r.status}):\n${(r.stderr || '').trim()}`);
  }
  return JSON.parse(r.stdout.trim().split('\n').pop());
}

/* CloudTrail allows exactly one lookup attribute per call, so the event name is
 * the filter and the key is matched here. */
function lookup(eventName, sinceIso, opts) {
  const out = aws(
    ['cloudtrail', 'lookup-events',
      '--lookup-attributes', `AttributeKey=EventName,AttributeValue=${eventName}`,
      '--start-time', sinceIso],
    opts,
  );
  return (out?.Events ?? []).map((e) => {
    let detail = {};
    try { detail = JSON.parse(e.CloudTrailEvent); } catch { /* keep the envelope */ }
    return {
      time: e.EventTime,
      name: e.EventName,
      keyId: detail.requestParameters?.keyId ?? detail.resources?.[0]?.ARN ?? null,
      principal: detail.userIdentity?.arn ?? null,
      errorCode: detail.errorCode ?? null,
    };
  });
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!hasAwsCli()) { console.error('the `aws` CLI is required'); process.exit(2); }
  if (!opts.profile) {
    console.error('--profile is required: a profile that can call cloudtrail:LookupEvents');
    process.exit(2);
  }
  if (!opts.region) opts.region = configuredRegion(opts.profile);
  if (!opts.region) { console.error('no region; pass --region'); process.exit(2); }
  if (!existsSync(opts.module)) {
    console.error(`no module at ${opts.module}; build the aws backend first`);
    process.exit(2);
  }

  let manifest;
  try { manifest = JSON.parse(readFileSync(opts.manifest, 'utf8')); }
  catch { console.error(`no key manifest at ${opts.manifest}; run setup first`); process.exit(2); }

  const entry = manifest.keys?.['test-RSA_2048'];
  if (!entry) { console.error('manifest has no test-RSA_2048 key'); process.exit(2); }

  /* Start the window slightly in the past: CloudTrail timestamps come from the
   * service, and a clock a few seconds ahead here would exclude our own events. */
  const since = new Date(Date.now() - 120_000).toISOString();

  console.log(`region  ${opts.region}`);
  console.log(`key     ${entry.alias}  ${entry.arn}`);
  console.log(`making  ${opts.signatures} signatures + ${opts.signatures} local verifications as ${opts.signerProfile}\n`);

  const cnf = await writeCnf(opts.module);
  const did = runWorkload(`awskms:key-id=${entry.arn}`, opts, cnf);
  console.log(`workload done: ${did.signatures} signatures made\n`);

  const want = { Sign: opts.signatures, GetPublicKey: 1 };
  const deadline = Date.now() + opts.wait * 1000;
  let seen = null;

  console.log(`polling CloudTrail (events are typically visible within ~15 min)`);
  for (let attempt = 1; Date.now() < deadline; attempt++) {
    seen = {};
    for (const name of Object.keys(want)) {
      seen[name] = lookup(name, since, opts).filter(
        (e) => e.keyId === entry.arn || e.keyId === entry.keyId || e.keyId === entry.alias,
      );
    }
    const counts = Object.entries(seen).map(([k, v]) => `${k}=${v.length}/${want[k]}`).join(' ');
    console.log(`  attempt ${attempt}: ${counts}`);
    if (Object.entries(want).every(([k, n]) => seen[k].length >= n)) break;
    await sleep(30_000);
  }

  console.log('');
  let bad = 0;
  for (const [name, expected] of Object.entries(want)) {
    const got = seen[name].length;
    const ok = got === expected;
    if (!ok) bad++;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}: ${got}, expected exactly ${expected}`);
  }

  /* Every call must have come from the signer, not from some broader identity
   * that happened to be in the environment. */
  const principals = [...new Set(Object.values(seen).flat().map((e) => e.principal).filter(Boolean))];
  console.log(`\n  principals seen: ${principals.join(', ') || '(none recorded)'}`);
  if (principals.some((p) => !/AwskmsTestSigner/.test(p))) {
    console.log('  NOTE: a principal other than AwskmsTestSigner made these calls');
  }

  if (bad === 0) {
    console.log(`\nexactly ${opts.signatures} Sign for ${opts.signatures} signatures, and 1 GetPublicKey`);
    console.log('for the whole run -- size probes cost nothing and verification is local.');
  } else {
    console.log('\nCounts did not match. If a count is LOW, CloudTrail may still be catching');
    console.log('up -- re-run with a longer --wait before treating it as a finding.');
    process.exitCode = 1;
  }
}

main().catch((err) => { console.error(`\n${err.message}`); process.exit(1); });
