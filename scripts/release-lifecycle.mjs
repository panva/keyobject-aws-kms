#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  appendFileSync,
  copyFileSync,
  constants,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const stableVersion = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const targets = [
  'darwin-arm64',
  'linux-arm64',
  'linux-x64',
  'linuxmusl-arm64',
  'linuxmusl-x64',
];
const packageNames = [
  '@keyobject/aws-kms',
  ...targets.map((target) => `@keyobject/aws-kms-${target}`),
];

function fail(message) {
  throw new Error(message);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function sourceManifest(directory = root) {
  return readJson(join(directory, 'npm', 'core', 'package.json'));
}

function releaseVersion(directory = root) {
  const { version } = sourceManifest(directory);
  if (!stableVersion.test(version) || version === '0.0.0') {
    fail(`refusing non-release version ${version}`);
  }
  return version;
}

export function extractReleaseNotes(changelog, version) {
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const heading = new RegExp(`^## \\[?${escaped}(?:\\]|\\s)`, 'm');
  const match = heading.exec(changelog);
  if (match === null) {
    fail(`could not find a "## ${version}" heading in CHANGELOG.md`);
  }
  const start = changelog.indexOf('\n', match.index) + 1;
  const remainder = changelog.slice(start);
  const next = /^## \[?\d+\.\d+\.\d+/m.exec(remainder);
  return (next === null ? remainder : remainder.slice(0, next.index)).trim();
}

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, {
    cwd: options.cwd ?? root,
    encoding: 'utf8',
    stdio: options.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !options.allowFailure) {
    const detail = options.capture ? `: ${result.stderr.trim()}` : '';
    fail(`${commandName} exited with status ${result.status}${detail}`);
  }
  return result;
}

export function requireDiscussionCategory(
  repository = process.env.GITHUB_REPOSITORY,
  run = command,
) {
  if (!repository?.includes('/')) fail('GITHUB_REPOSITORY is not set');
  const [owner, name] = repository.split('/');
  const query = `query($owner:String!,$name:String!){repository(owner:$owner,name:$name){discussionCategories(first:100){nodes{name slug}}}}`;
  const result = run(
    'gh',
    ['api', 'graphql', '-f', `query=${query}`, '-F', `owner=${owner}`, '-F', `name=${name}`],
    { capture: true },
  );
  const categories = JSON.parse(result.stdout).data?.repository
    ?.discussionCategories?.nodes;
  if (
    !Array.isArray(categories) ||
    !categories.some(({ name: categoryName, slug }) =>
      categoryName === 'Releases' && slug === 'releases')
  ) {
    fail('create a Releases discussion category in repository Settings before publishing');
  }
}

export function findPriorReleaseArtifact(
  repository = process.env.GITHUB_REPOSITORY,
  runId = process.env.GITHUB_RUN_ID,
  run = command,
) {
  if (!repository?.includes('/')) fail('GITHUB_REPOSITORY is not set');
  if (!/^[1-9]\d*$/.test(runId ?? '')) fail('GITHUB_RUN_ID is not set');
  const result = run(
    'gh',
    [
      'api', '--paginate', '--slurp',
      `repos/${repository}/actions/runs/${runId}/artifacts?per_page=100`,
    ],
    { capture: true },
  );
  const pages = JSON.parse(result.stdout);
  if (
    !Array.isArray(pages) ||
    !pages.every((page) => Array.isArray(page?.artifacts))
  ) {
    fail('GitHub artifact response is not paginated JSON');
  }
  const candidates = pages
    .flatMap((page) => page.artifacts)
    .filter(({ name }) => name === 'release-payload');
  if (candidates.some(({ expired }) => typeof expired !== 'boolean')) {
    fail('prior release-payload artifact has no expiration state');
  }
  const artifacts = candidates.filter(({ expired }) => !expired);
  const unique = new Map(artifacts.map((artifact) => [artifact.id, artifact]));
  if (unique.size > 1) {
    fail('multiple nonexpired release-payload artifacts exist for this run');
  }
  const [artifact] = unique.values();
  if (artifact === undefined) {
    console.log('no prior release-payload artifact exists for this run');
    return undefined;
  }
  if (!Number.isSafeInteger(artifact.id) || artifact.id <= 0) {
    fail('prior release-payload artifact has an invalid ID');
  }
  console.log(`found prior release-payload artifact ${artifact.id}`);
  return artifact;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function sha512Integrity(path) {
  return `sha512-${createHash('sha512')
    .update(readFileSync(path))
    .digest('base64')}`;
}

function tarballName(packageName, version) {
  return `${packageName.slice(1).replace('/', '-')}-${version}.tgz`;
}

const attestationBundleName = 'release-payload.sigstore.json';

function releaseSubjects(version) {
  return [
    ...targets.map((target) => `awskms-${version}-${target}.tar.gz`),
    ...packageNames.map((name) => tarballName(name, version)),
  ].sort();
}

export function expectedPayload(version, { attested = true } = {}) {
  return [
    ...releaseSubjects(version),
    'SHA256SUMS',
    ...(attested ? [attestationBundleName] : []),
  ].sort();
}

function tarManifest(path) {
  const result = command(
    'tar',
    ['-xOzf', path, 'package/package.json'],
    { capture: true },
  );
  return JSON.parse(result.stdout);
}

function inspectAttestationBundle(path, directory, subjects) {
  let bundle;
  let statement;
  try {
    bundle = JSON.parse(readFileSync(path, 'utf8'));
    const envelope = bundle.dsseEnvelope;
    if (
      !bundle.mediaType?.startsWith('application/vnd.dev.sigstore.bundle.') ||
      envelope?.payloadType !== 'application/vnd.in-toto+json' ||
      typeof envelope.payload !== 'string' ||
      !Array.isArray(envelope.signatures) ||
      envelope.signatures.length === 0 ||
      typeof bundle.verificationMaterial !== 'object'
    ) {
      fail('attestation bundle is not a Sigstore in-toto DSSE bundle');
    }
    statement = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
    if (statement?._type !== 'https://in-toto.io/Statement/v1') {
      fail('attestation bundle does not contain an in-toto v1 statement');
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('attestation bundle')) {
      throw error;
    }
    fail(`attestation bundle is unreadable: ${error?.message ?? error}`);
  }

  const expected = subjects.map((name) => ({
    name,
    digest: sha256(join(directory, name)),
  }));
  const actual = Array.isArray(statement.subject)
    ? statement.subject.map(({ name, digest }) => ({
        name,
        digest: digest?.sha256,
      }))
    : undefined;
  if (
    !Array.isArray(actual) ||
    actual.some(({ name, digest }) =>
      typeof name !== 'string' || typeof digest !== 'string') ||
    JSON.stringify(actual.sort((left, right) => left.name.localeCompare(right.name))) !==
      JSON.stringify(expected)
  ) {
    fail('attestation bundle subjects do not match the eleven release tarballs');
  }
}

export function inspectPayload(
  directory,
  version = releaseVersion(),
  { attested = true } = {},
) {
  const actual = readdirSync(directory).sort();
  const expected = expectedPayload(version, { attested });
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`release payload inventory mismatch: expected ${expected.join(', ')}`);
  }

  const packages = packageNames.map((name) => {
    const path = resolve(directory, tarballName(name, version));
    const manifest = tarManifest(path);
    if (manifest.name !== name || manifest.version !== version) {
      fail(`${basename(path)} does not contain ${name}@${version}`);
    }
    return { name, version, path, manifest, integrity: sha512Integrity(path) };
  });

  const core = packages.find(({ name }) => name === '@keyobject/aws-kms');
  const expectedDependencies = packageNames.slice(1).sort();
  const actualDependencies = Object.keys(core.manifest.optionalDependencies ?? {}).sort();
  if (
    JSON.stringify(actualDependencies) !== JSON.stringify(expectedDependencies) ||
    expectedDependencies.some(
      (name) => core.manifest.optionalDependencies[name] !== version,
    )
  ) {
    fail('the packed core optionalDependencies do not match all five satellites');
  }

  const subjects = releaseSubjects(version);
  const checksums = `${subjects
    .map((name) => `${sha256(join(directory, name))}  ${name}`)
    .join('\n')}\n`;
  if (readFileSync(join(directory, 'SHA256SUMS'), 'utf8') !== checksums) {
    fail('SHA256SUMS does not exactly cover the eleven sorted tarballs');
  }
  const bundle = attested ? join(directory, attestationBundleName) : undefined;
  if (bundle !== undefined) {
    inspectAttestationBundle(bundle, directory, subjects);
  }
  return { bundle, packages, subjects, version };
}

export function stageAttestationBundle(
  directory,
  source,
  version = releaseVersion(),
) {
  const { subjects } = inspectPayload(directory, version, { attested: false });
  inspectAttestationBundle(source, directory, subjects);
  const destination = join(directory, attestationBundleName);
  if (existsSync(destination)) {
    fail(`refusing to overwrite ${attestationBundleName}`);
  }
  copyFileSync(source, destination);
  inspectPayload(directory, version);
  return destination;
}

export function reuseAttestationBundle(
  previous,
  current,
  version = releaseVersion(),
) {
  inspectPayload(previous, version);
  inspectPayload(current, version, { attested: false });
  const expected = expectedPayload(version, { attested: false });
  const changed = expected.filter(
    (name) => !readFileSync(join(previous, name)).equals(
      readFileSync(join(current, name)),
    ),
  );
  if (changed.length !== 0) {
    fail(`release payload changed across run attempts: ${changed.join(', ')}`);
  }
  copyFileSync(
    join(previous, attestationBundleName),
    join(current, attestationBundleName),
    constants.COPYFILE_EXCL,
  );
  inspectPayload(current, version);
}

export function comparePayloads(previous, current, version = releaseVersion()) {
  inspectPayload(previous, version);
  inspectPayload(current, version);
  const expected = expectedPayload(version);
  const changed = expected.filter(
    (name) => !readFileSync(join(previous, name)).equals(
      readFileSync(join(current, name)),
    ),
  );
  if (changed.length !== 0) {
    fail(`release payload changed across run attempts: ${changed.join(', ')}`);
  }
  console.log('current release payload is byte-identical to the prior run attempt');
}

export async function waitForNpm({
  directory,
  version = releaseVersion(),
  registry = process.env.AWSKMS_RELEASE_REGISTRY ?? 'https://registry.npmjs.org',
  timeout = 60 * 60_000,
  interval = 60_000,
  fetchImpl = fetch,
  now = Date.now,
  sleep = (milliseconds) => new Promise((resolveSleep) =>
    setTimeout(resolveSleep, milliseconds)),
}) {
  const { packages } = inspectPayload(directory, version);
  const deadline = now() + timeout;
  for (;;) {
    const poll = new AbortController();
    const results = await Promise.all(packages.map(async (packageArtifact) => {
      const url = `${registry.replace(/\/$/, '')}/${encodeURIComponent(packageArtifact.name)}/${version}`;
      let response;
      try {
        const requestTimeout = Math.max(
          1,
          Math.min(15_000, deadline - now()),
        );
        response = await fetchImpl(url, {
          headers: { accept: 'application/json' },
          signal: AbortSignal.any([
            poll.signal,
            AbortSignal.timeout(requestTimeout),
          ]),
        });
      } catch (error) {
        return `${packageArtifact.name} (${error.message})`;
      }
      if (response.ok) {
        const published = await response.json();
        if (
          published.version !== version ||
          published.dist?.integrity !== packageArtifact.integrity
        ) {
          poll.abort();
          return {
            mismatch: `${packageArtifact.name}@${version} is published with different bytes`,
          };
        }
        return undefined;
      }
      if (response.status !== 404) {
        return `${packageArtifact.name} (registry ${response.status})`;
      }
      return packageArtifact.name;
    }));
    const mismatch = results.find(
      (entry) => typeof entry === 'object' && entry?.mismatch,
    );
    if (mismatch !== undefined) fail(mismatch.mismatch);
    const pending = results.filter((entry) => typeof entry === 'string');
    if (pending.length === 0) {
      console.log(`all six exact npm artifacts for ${version} are available`);
      return;
    }
    if (now() >= deadline) {
      fail(
        `npm approval timed out for ${pending.join(', ')}; approve or reject ` +
        'the pending stages, then rerun the failed jobs',
      );
    }
    console.log(`waiting for npm approval: ${pending.join(', ')}`);
    await sleep(Math.min(interval, deadline - now()));
    if (now() >= deadline) {
      fail(
        `npm approval timed out for ${pending.join(', ')}; approve or reject ` +
        'the pending stages, then rerun the failed jobs',
      );
    }
  }
}

export function selectPackage(directory, name, output, version = releaseVersion()) {
  const { packages } = inspectPayload(directory, version);
  const selected = packages.find((entry) => entry.name === name);
  if (selected === undefined) fail(`unexpected npm package ${name}`);
  if (existsSync(output)) fail(`refusing to overwrite package selection directory ${output}`);
  mkdirSync(output, { recursive: false, mode: 0o700 });
  writeFileSync(join(output, 'package.json'), `${JSON.stringify(selected.manifest, null, 2)}\n`, {
    mode: 0o600,
  });
  writeFileSync(join(output, 'tarball'), `${selected.path}\n`, { mode: 0o600 });
  return selected;
}

function releaseView(tag, run) {
  const result = run(
    'gh',
    ['release', 'view', tag, '--json', 'assets,isDraft'],
    { capture: true, allowFailure: true },
  );
  if (result.status === 0) return JSON.parse(result.stdout);
  if (/release not found|not found/i.test(result.stderr)) return undefined;
  fail(`could not inspect GitHub Release ${tag}: ${result.stderr.trim()}`);
}

function assertAssetNames(release, expected, allowMissing) {
  const actual = release.assets.map(({ name }) => name).sort();
  const unexpected = actual.filter((name) => !expected.includes(name));
  const missing = expected.filter((name) => !actual.includes(name));
  if (unexpected.length !== 0 || (!allowMissing && missing.length !== 0)) {
    fail(
      `GitHub Release asset mismatch; unexpected: ${unexpected.join(', ') || 'none'}; ` +
      `missing: ${missing.join(', ') || 'none'}`,
    );
  }
}

function verifyRemoteAssets(release, tag, expected, directory, temporary, run) {
  assertAssetNames(release, expected, false);
  const downloaded = join(temporary, 'assets');
  rmSync(downloaded, { recursive: true, force: true });
  mkdirSync(downloaded);
  run('gh', ['release', 'download', tag, '--dir', downloaded]);
  const actual = readdirSync(downloaded).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${tag} downloaded asset inventory differs from the release payload`);
  }
  for (const name of expected) {
    if (sha256(join(downloaded, name)) !== sha256(join(directory, name))) {
      fail(`${tag} is already published with a different ${name}`);
    }
  }
}

export function publishGithubRelease({
  directory,
  version = releaseVersion(),
  changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8'),
  tag = process.env.GITHUB_REF_NAME ?? `v${version}`,
  run = command,
}) {
  inspectPayload(directory, version);
  const expected = expectedPayload(version);
  const notes = extractReleaseNotes(changelog, version);
  const temporary = mkdtempSync(join(tmpdir(), 'awskms-release-'));
  const notesPath = join(temporary, 'notes.md');
  writeFileSync(notesPath, `${notes}\n`);
  try {
    const release = releaseView(tag, run);
    if (release !== undefined && !release.isDraft) {
      verifyRemoteAssets(release, tag, expected, directory, temporary, run);
      console.log(`${tag} is already published with the exact release assets`);
      return;
    }

    if (release !== undefined) assertAssetNames(release, expected, true);
    if (release === undefined) {
      run('gh', [
        'release', 'create', tag, '--draft', '--verify-tag',
        '--notes-file', notesPath, '--title', tag,
      ]);
    }
    run('gh', [
      'release', 'upload', tag,
      ...expected.map((name) => join(directory, name)),
      '--clobber',
    ]);
    const uploaded = releaseView(tag, run);
    if (uploaded === undefined) {
      fail(`${tag} disappeared after its assets were uploaded`);
    }
    verifyRemoteAssets(uploaded, tag, expected, directory, temporary, run);
    run('gh', [
      'release', 'edit', tag, '--draft=false', '--verify-tag',
      '--notes-file', notesPath, '--title', tag,
      '--discussion-category', 'Releases',
    ]);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function option(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  if (index === args.length - 1) fail(`${name} requires a value`);
  return args[index + 1];
}

async function main(args = process.argv.slice(2)) {
  const operation = args.shift();
  switch (operation) {
    case 'discussion-category':
      requireDiscussionCategory();
      break;
    case 'prior-artifact': {
      const artifact = findPriorReleaseArtifact();
      const output = option(args, '--output');
      appendFileSync(
        output,
        artifact === undefined
          ? 'found=false\n'
          : `found=true\nid=${artifact.id}\n`,
      );
      break;
    }
    case 'validate-payload': {
      const payload = resolve(option(args, '--payload', 'dist'));
      command('scripts/ci-verify-release.sh', [payload, releaseVersion()]);
      inspectPayload(payload, releaseVersion(), { attested: false });
      break;
    }
    case 'validate-attested-payload': {
      const payload = resolve(option(args, '--payload', 'dist'));
      command('scripts/ci-verify-release.sh', [payload, releaseVersion()]);
      inspectPayload(payload);
      break;
    }
    case 'stage-attestation':
      stageAttestationBundle(
        resolve(option(args, '--payload', 'dist')),
        resolve(option(args, '--bundle')),
      );
      break;
    case 'reuse-attestation':
      reuseAttestationBundle(
        resolve(option(args, '--previous')),
        resolve(option(args, '--current')),
      );
      break;
    case 'compare-payloads':
      comparePayloads(
        resolve(option(args, '--previous')),
        resolve(option(args, '--current')),
      );
      break;
    case 'select-package':
      selectPackage(
        resolve(option(args, '--payload')),
        option(args, '--name'),
        resolve(option(args, '--output')),
      );
      break;
    case 'wait-npm':
      await waitForNpm({ directory: resolve(option(args, '--payload')) });
      break;
    case 'github-release':
      publishGithubRelease({ directory: resolve(option(args, '--payload')) });
      break;
    default:
      fail(`unknown release lifecycle operation ${operation ?? '(missing)'}`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`error: ${error.message}`);
    process.exitCode = 1;
  });
}
