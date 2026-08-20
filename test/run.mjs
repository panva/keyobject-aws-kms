/*
 * Test driver.
 *
 * The re-exec is not optional: OpenSSL reads its configuration exactly once,
 * during library initialisation, so a provider cannot be activated from inside an
 * already-running process. Every test therefore runs in a child started with
 * --openssl-config.
 *
 *   node test/run.mjs [test-file ...]
 *
 * Environment:
 *   AWSKMS_MODULE   path to the built module   (default: build/awskms.{so,dylib})
 *   AWSKMS_NODE     node binary to test with   (default: this one)
 *   AWSKMS_CNF      an openssl.cnf to use      (default: generated here)
 */
import { spawn, spawnSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const modulePath = resolve(
  process.env.AWSKMS_MODULE ??
    join(root, 'build', process.platform === 'darwin' ? 'aws-kms.dylib' : 'aws-kms.so'),
);
if (!existsSync(modulePath)) {
  console.error(`awskms module not found at ${modulePath}`);
  console.error('build it first, or set AWSKMS_MODULE=');
  process.exit(2);
}

const nodeBin = process.env.AWSKMS_NODE ?? process.execPath;

let cnf = process.env.AWSKMS_CNF;
if (!cnf) {
  const { writeCnf } = await import('./cnf.mjs');
  cnf = await writeCnf(modulePath);
}

/*
 * With the aws backend the module talks to the real SDK, so tests need something
 * for it to talk to. The stub speaks the actual wire protocol, which is the whole
 * point: it exercises the real client rather than bypassing it.
 *
 * Set AWSKMS_TEST_REAL=1 to drive real KMS instead. That path deliberately
 * requires an explicit profile and will not fall back to ambient credentials.
 */
/* Which backend the module was built with, recorded by CMake beside it. */
let backend = 'aws';
try {
  backend = (await import('node:fs')).readFileSync(join(dirname(modulePath), 'awskms-backend'), 'utf8').trim();
} catch {
  /* not a cmake build dir; assume the real backend */
}

/* The in-provider stub backend never makes a network call, so there is nothing
 * for an HTTP stub to serve. */
const usesStub = backend === 'aws' && process.env.AWSKMS_TEST_REAL !== '1';
let stub;
/* Extra `node --test` flags added below. */
const extraArgs = [];
const serialise = (why) => {
  if (extraArgs.includes('--test-concurrency=1')) return;
  extraArgs.push('--test-concurrency=1');
  console.log(`# running test files serially: ${why}`);
};
// AWSKMS_CNF is passed on so tests can re-exec node themselves, which the
// permission-model checks need.
const childEnv = { ...process.env, AWSKMS_MODULE: modulePath, AWSKMS_CNF: cnf };

if (usesStub) {
  const { createKmsStub } = await import('./kms-stub.mjs');
  stub = createKmsStub();
  const { endpoint } = await stub.listen();
  Object.assign(childEnv, {
    AWSKMS_ENDPOINT: endpoint,
    AWS_ENDPOINT_URL_KMS: endpoint,
    // The SDK will not send a request with no credentials at all, but it never
    // verifies a response signature, so anything well-formed works.
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    AWS_REGION: 'us-east-1',
    AWS_DEFAULT_REGION: 'us-east-1',
    // Otherwise the credential chain stalls probing 169.254.169.254.
    AWS_EC2_METADATA_DISABLED: 'true',
    AWSKMS_STUB: '1',
    /*
     * Which specs this stub cannot serve, so the tests skip them rather than
     * failing. The stub signs by shelling out to the `openssl` CLI, and which
     * CLI that is decides what it can do: ubuntu ships 3.0.13, which has no
     * ML-DSA, while a homebrew or self-built 3.5+ does. AWSKMS_OPENSSL selects
     * it.
     *
     * The stub runs in this process and the tests run in a child, so its
     * supported-key list crosses the process boundary as an environment value.
     */
    AWSKMS_STUB_UNSUPPORTED: Object.entries(stub.supported())
      .filter(([, ok]) => !ok)
      .map(([spec]) => spec)
      .join(','),
  });
  console.log(`# kms stub listening on ${endpoint}`);
  /*
   * The HTTP stub keeps ONE request log for the whole run, and the tests that
   * assert on it clear it first. node --test runs files concurrently, so a
   * concurrent file's Sign can land between the clear and the read, or its clear
   * can wipe an entry mid-assertion. The result depends purely on scheduling.
   *
   * Serialising is the whole fix: it is the shared log that is unsafe, not the
   * assertions. The suite is a few seconds either way.
   */
  serialise('the HTTP stub keeps one shared request log');
} else if (backend !== 'aws') {
  /*
   * AWSKMS_TEST_REAL=1 against the offline backend would otherwise be silently
   * ignored: that module has no AWS client in it, so the run would pass without
   * ever reaching AWS while looking exactly like a real one. Refuse instead --
   * a green run that proves nothing is worse than a failed one.
   */
  if (process.env.AWSKMS_TEST_REAL === '1') {
    console.error(`AWSKMS_TEST_REAL=1 needs the aws backend, but ${modulePath}`);
    console.error(`was built with the ${backend} backend and contains no AWS client.`);
    console.error('Point AWSKMS_MODULE at an aws-backend build, e.g.:');
    console.error('  AWSKMS_MODULE=build-aws/aws-kms.dylib');
    process.exit(2);
  }
  console.log(`# module was built with the ${backend} backend; no HTTP stub needed`);
} else {
  /*
   * Real KMS. Credentials must be deliberate, never ambient -- but "deliberate"
   * looks different in the two places this runs: locally it is a named profile, and
   * in CI the role arrives via OIDC as session environment variables with no
   * profile at all. Requiring AWS_PROFILE unconditionally would make CI
   * unrunnable; accepting anything would let a stray shell spend money.
   */
  const viaProfile = Boolean(process.env.AWS_PROFILE);
  const viaOidc = Boolean(process.env.CI && process.env.AWS_SESSION_TOKEN);
  if (!viaProfile && !viaOidc) {
    console.error('AWSKMS_TEST_REAL=1 needs credentials chosen explicitly:');
    console.error('  locally: AWS_PROFILE=<profile>');
    console.error('  in CI:   an assumed role (CI and AWS_SESSION_TOKEN both set)');
    console.error('It will not fall back to ambient or default credentials.');
    process.exit(2);
  }
  if (!process.env.AWS_REGION) {
    console.error('AWSKMS_TEST_REAL=1 requires AWS_REGION.');
    console.error('The provider resolves its region through the AWS chain, so leaving');
    console.error('this unset lets the tests and the provider disagree silently.');
    process.exit(2);
  }

  /*
   * The manifest says which keys exist and where. A region mismatch against it is
   * worth catching here rather than as 300 NotFoundExceptions that read exactly
   * like a provisioning failure.
   */
  const manifestPath = process.env.AWSKMS_TEST_MANIFEST ?? join(root, 'build', 'real-kms-keys.json');
  childEnv.AWSKMS_TEST_MANIFEST = manifestPath;
  let manifest;
  try {
    manifest = JSON.parse((await import('node:fs')).readFileSync(manifestPath, 'utf8'));
  } catch {
    console.error(`No key manifest at ${manifestPath}.`);
    console.error('Run: node scripts/real-kms-keys.mjs setup --smoke');
    process.exit(2);
  }
  if (manifest.region !== process.env.AWS_REGION) {
    console.error(
      `Manifest region ${manifest.region} does not match AWS_REGION ${process.env.AWS_REGION}.`,
    );
    console.error('Re-run setup for this region, or correct AWS_REGION.');
    process.exit(2);
  }

  console.log(
    `# driving real AWS KMS in ${manifest.region}` +
      `${viaProfile ? ` with profile ${process.env.AWS_PROFILE}` : ' with an assumed role'}`,
  );
  console.log(`# ${Object.keys(manifest.keys ?? {}).length} keys provisioned${manifest.smoke ? ' (smoke subset)' : ''}`);
  if (manifest.unavailable?.length) {
    console.log(`# unavailable in ${manifest.region}: ${manifest.unavailable.join(', ')}`);
  }
  /*
   * node --test runs files concurrently by default, and a 22-spec matrix bursting
   * at once can trip the per-region cryptographic-operations request-rate quota,
   * which surfaces as ERR_OSSL_AWSKMS_THROTTLED and resembles a provider bug. The
   * suite is I/O-bound on KMS anyway.
   */
  serialise('the per-region cryptographic-operations request-rate quota');
}

/*
 * The end-to-end suites need a Node build that can pass a URL to
 * createPrivateKey() and dispatch it through OSSL_STORE. Detect the capability
 * directly rather than tying it to a release number or letting every test fail
 * with an opaque ERR_INVALID_ARG_TYPE.
 *
 * This is checked in a child, because the capability depends on the node binary
 * under test rather than the one running this script.
 */
const probe = spawn(nodeBin, ['-e', `
  const { createPrivateKey } = require('crypto');
  try {
    createPrivateKey({ key: new URL('aws-kms:key-id=probe') });
  } catch (err) {
    // Anything other than a type rejection means the URL was accepted as a key.
    process.exit(err.code === 'ERR_INVALID_ARG_TYPE' ? 1 : 0);
  }
  process.exit(0);
`], { stdio: 'ignore' });
const hasStoreLoader = (await new Promise((r) => probe.on('exit', r))) === 0;

if (!hasStoreLoader) {
  const version = spawnSync(nodeBin, ['-p', 'process.version'], { encoding: 'utf8' }).stdout?.trim();
  console.log(`# ${nodeBin} (${version}) cannot pass a URL to createPrivateKey().`);
  console.log('# Skipping the end-to-end suites: this build lacks URL-backed');
  console.log('# OSSL_STORE private-key loading.');
  console.log('#');
  console.log('# The provider itself is still verified without it:');
  console.log('#   scripts/check-load.sh <build-dir> <node>   loadability + symbol audit');
  console.log('#   <build-dir>/awskms_unit                    unit tests');
  console.log('#');
  console.log('# Point AWSKMS_NODE at a capable Node build to run these.');
  await stub?.close();
  process.exit(0);
}

let files = process.argv.slice(2);
if (files.length === 0) {
  files = (await readdir(here))
    .filter((f) => f.endsWith('.test.mjs'))
    .sort()
    .map((f) => join(here, f));
}

const child = spawn(
  nodeBin,
  [`--openssl-config=${cnf}`, '--test', '--test-reporter=spec', ...extraArgs, ...files],
  { stdio: 'inherit', env: childEnv },
);
const code = await new Promise((r) => child.on('exit', r));
await stub?.close();
process.exit(code ?? 1);
