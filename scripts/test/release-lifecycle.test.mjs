import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import test from 'node:test';

import {
  comparePayloads,
  expectedPayload,
  findPriorReleaseArtifact,
  inspectPayload,
  publishGithubRelease,
  requireDiscussionCategory,
  waitForNpm,
} from '../release-lifecycle.mjs';

const version = '1.2.3';
const names = [
  '@keyobject/aws-kms',
  '@keyobject/aws-kms-darwin-arm64',
  '@keyobject/aws-kms-linux-arm64',
  '@keyobject/aws-kms-linux-x64',
  '@keyobject/aws-kms-linuxmusl-arm64',
  '@keyobject/aws-kms-linuxmusl-x64',
];

function digest(algorithm, path, encoding = 'hex') {
  return createHash(algorithm).update(readFileSync(path)).digest(encoding);
}

function packageFilename(name) {
  return `${name.slice(1).replace('/', '-')}-${version}.tgz`;
}

function makeTarball(directory, manifest) {
  const staging = mkdtempSync(join(tmpdir(), 'awskms-release-package-'));
  mkdirSync(join(staging, 'package'));
  writeFileSync(
    join(staging, 'package', 'package.json'),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  const output = join(directory, packageFilename(manifest.name));
  const result = spawnSync(
    'tar',
    ['czf', output, '-C', staging, 'package'],
    { encoding: 'utf8' },
  );
  rmSync(staging, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr);
}

function refreshChecksums(directory) {
  const files = expectedPayload(version).filter((name) => name !== 'SHA256SUMS');
  writeFileSync(
    join(directory, 'SHA256SUMS'),
    `${files.map((name) => `${digest('sha256', join(directory, name))}  ${name}`).join('\n')}\n`,
  );
}

function payload(t) {
  const directory = mkdtempSync(join(tmpdir(), 'awskms-release-payload-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const name of expectedPayload(version)) {
    if (name.endsWith('.tar.gz')) writeFileSync(join(directory, name), name);
  }
  const optionalDependencies = Object.fromEntries(
    names.slice(1).map((name) => [name, version]),
  );
  for (const name of names) {
    makeTarball(directory, {
      name,
      version,
      ...(name === '@keyobject/aws-kms' ? { optionalDependencies } : {}),
    });
  }
  refreshChecksums(directory);
  return directory;
}

function registryRecords(directory) {
  return new Map(inspectPayload(directory, version).packages.map((entry) => [
    entry.name,
    {
      version,
      dist: { integrity: entry.integrity },
    },
  ]));
}

function packageFromUrl(url) {
  return decodeURIComponent(new URL(url).pathname.split('/').at(-2));
}

test('requires an exact twelve-file payload and checksum inventory', (t) => {
  const directory = payload(t);
  assert.deepEqual(readdirSync(directory).sort(), expectedPayload(version));
  assert.equal(inspectPayload(directory, version).packages.length, 6);

  writeFileSync(join(directory, 'unexpected'), 'sentinel');
  assert.throws(
    () => inspectPayload(directory, version),
    /release payload inventory mismatch/,
  );
});

test('waits once, fetches each poll concurrently, and verifies all integrities', async (t) => {
  const directory = payload(t);
  const records = registryRecords(directory);
  let requests = 0;
  let sleeps = 0;
  await waitForNpm({
    directory,
    version,
    timeout: 100,
    interval: 1,
    now: () => sleeps,
    sleep: async () => { sleeps += 1; },
    fetchImpl: async (url) => {
      requests += 1;
      if (requests <= 6) return new Response('', { status: 404 });
      return Response.json(records.get(packageFromUrl(url)));
    },
  });
  assert.equal(sleeps, 1);
  assert.equal(requests, 12);
});

test('continues safely after only part of the npm release is live', async (t) => {
  const directory = payload(t);
  const records = registryRecords(directory);
  let requests = 0;
  let sleeps = 0;
  await waitForNpm({
    directory,
    version,
    timeout: 100,
    interval: 1,
    now: () => sleeps,
    sleep: async () => { sleeps += 1; },
    fetchImpl: async (url) => {
      const packageName = packageFromUrl(url);
      const firstPoll = requests < 6;
      requests += 1;
      if (firstPoll && names.indexOf(packageName) >= 3) {
        return new Response('', { status: 404 });
      }
      return Response.json(records.get(packageName));
    },
  });
  assert.equal(sleeps, 1);
  assert.equal(requests, 12);
});

test('fails immediately when an existing npm version has different bytes', async (t) => {
  const directory = payload(t);
  let requests = 0;
  await assert.rejects(
    waitForNpm({
      directory,
      version,
      timeout: 100,
      interval: 1,
      sleep: async () => assert.fail('integrity drift must not be retried'),
      fetchImpl: async () => {
        requests += 1;
        return Response.json({ version, dist: { integrity: 'sha512-wrong' } });
      },
    }),
    /published with different bytes/,
  );
  assert.equal(requests, 6);
});

test('npm approval timeout is actionable', async (t) => {
  const directory = payload(t);
  let clock = 0;
  await assert.rejects(
    waitForNpm({
      directory,
      version,
      timeout: 1,
      interval: 1,
      now: () => clock,
      sleep: async () => { clock += 1; },
      fetchImpl: async () => new Response('', { status: 404 }),
    }),
    /approve or reject the pending stages, then rerun the failed jobs/,
  );
});

test('requires the exact Releases discussion category', () => {
  const runner = (command, args) => {
    assert.equal(command, 'gh');
    assert.deepEqual(args.slice(0, 2), ['api', 'graphql']);
    return {
      status: 0,
      stdout: JSON.stringify({
        data: {
          repository: {
            discussionCategories: {
              nodes: [{ name: 'Releases', slug: 'releases' }],
            },
          },
        },
      }),
      stderr: '',
    };
  };
  assert.doesNotThrow(() => requireDiscussionCategory('panva/keyobject-aws-kms', runner));
  assert.throws(
    () => requireDiscussionCategory('panva/keyobject-aws-kms', () => ({
      status: 0,
      stdout: JSON.stringify({
        data: { repository: { discussionCategories: { nodes: [] } } },
      }),
      stderr: '',
    })),
    /create a Releases discussion category/,
  );
});

test('finds one nonexpired payload artifact from a prior run attempt', () => {
  const calls = [];
  const artifact = findPriorReleaseArtifact(
    'panva/keyobject-aws-kms',
    '12345',
    (command, args) => {
      calls.push([command, args]);
      return {
        status: 0,
        stdout: JSON.stringify([
          {
            artifacts: [
              { id: 10, name: 'release-payload', expired: true },
              { id: 11, name: 'unrelated', expired: false },
            ],
          },
          {
            artifacts: [
              { id: 12, name: 'release-payload', expired: false },
            ],
          },
        ]),
        stderr: '',
      };
    },
  );
  assert.equal(artifact.id, 12);
  assert.deepEqual(calls, [[
    'gh',
    [
      'api', '--paginate', '--slurp',
      'repos/panva/keyobject-aws-kms/actions/runs/12345/artifacts?per_page=100',
    ],
  ]]);
});

test('allows no prior payload but rejects ambiguous prior artifacts', () => {
  const response = (artifacts) => () => ({
    status: 0,
    stdout: JSON.stringify([{ artifacts }]),
    stderr: '',
  });
  assert.equal(
    findPriorReleaseArtifact(
      'panva/keyobject-aws-kms',
      '12345',
      response([{ id: 1, name: 'release-payload', expired: true }]),
    ),
    undefined,
  );
  assert.throws(
    () => findPriorReleaseArtifact(
      'panva/keyobject-aws-kms',
      '12345',
      response([
        { id: 1, name: 'release-payload', expired: false },
        { id: 2, name: 'release-payload', expired: false },
      ]),
    ),
    /multiple nonexpired release-payload artifacts/,
  );
});

test('locks all twelve payload files to the first successful attempt', (t) => {
  const previous = payload(t);
  const current = mkdtempSync(join(tmpdir(), 'awskms-release-current-'));
  t.after(() => rmSync(current, { recursive: true, force: true }));
  copyPayload(previous, current);
  assert.doesNotThrow(() => comparePayloads(previous, current, version));

  writeFileSync(
    join(current, 'awskms-1.2.3-linux-x64.tar.gz'),
    'different but independently checksummed bytes',
  );
  refreshChecksums(current);
  assert.throws(
    () => comparePayloads(previous, current, version),
    /release payload changed across run attempts: SHA256SUMS.*linux-x64/,
  );
});

function assetList(directory) {
  return expectedPayload(version).map((name) => ({ name }));
}

function copyPayload(directory, output, { corrupt } = {}) {
  for (const name of expectedPayload(version)) {
    copyFileSync(join(directory, name), join(output, name));
  }
  if (corrupt) writeFileSync(join(output, corrupt), 'different bytes');
}

test('uploads, re-downloads, verifies, then publishes a new GitHub Release', (t) => {
  const directory = payload(t);
  const calls = [];
  let viewed = 0;
  const run = (command, args) => {
    assert.equal(command, 'gh');
    calls.push(args);
    if (args[0] === 'release' && args[1] === 'view') {
      viewed += 1;
      if (viewed === 1) {
        return { status: 1, stdout: '', stderr: 'release not found' };
      }
      return {
        status: 0,
        stdout: JSON.stringify({ isDraft: true, assets: assetList(directory) }),
        stderr: '',
      };
    }
    if (args[0] === 'release' && args[1] === 'download') {
      copyPayload(directory, args[args.indexOf('--dir') + 1]);
    }
    return { status: 0, stdout: '', stderr: '' };
  };

  publishGithubRelease({
    directory,
    version,
    tag: `v${version}`,
    changelog: `# Changelog\n\n## ${version} (2026-08-20)\n\nRelease notes.\n`,
    run,
  });
  assert.ok(calls.some((args) => args[1] === 'create' && args.includes('--draft')));
  assert.ok(calls.some((args) => args[1] === 'download'));
  const edit = calls.find((args) => args[1] === 'edit');
  assert.ok(edit.includes('--draft=false'));
  assert.ok(edit.includes('Releases'));
  const upload = calls.find((args) => args[1] === 'upload');
  assert.equal(upload.filter((entry) => expectedPayload(version).includes(basename(entry))).length, 12);
});

test('does not publish a draft whose downloaded asset bytes differ', (t) => {
  const directory = payload(t);
  const calls = [];
  const run = (command, args) => {
    calls.push(args);
    if (args[1] === 'view') {
      return {
        status: 0,
        stdout: JSON.stringify({ isDraft: true, assets: assetList(directory) }),
        stderr: '',
      };
    }
    if (args[1] === 'download') {
      copyPayload(directory, args[args.indexOf('--dir') + 1], {
        corrupt: 'SHA256SUMS',
      });
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  assert.throws(
    () => publishGithubRelease({
      directory,
      version,
      tag: `v${version}`,
      changelog: `## ${version} (2026-08-20)\n\nNotes.\n`,
      run,
    }),
    /different SHA256SUMS/,
  );
  assert.equal(calls.some((args) => args[1] === 'edit'), false);
});

test('repairs a partial draft but rejects unexpected draft assets', (t) => {
  const directory = payload(t);
  let views = 0;
  const partialRun = (command, args) => {
    if (args[1] === 'view') {
      views += 1;
      return {
        status: 0,
        stdout: JSON.stringify({
          isDraft: true,
          assets: views === 1 ? assetList(directory).slice(0, 2) : assetList(directory),
        }),
        stderr: '',
      };
    }
    if (args[1] === 'download') {
      copyPayload(directory, args[args.indexOf('--dir') + 1]);
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  assert.doesNotThrow(() => publishGithubRelease({
    directory,
    version,
    tag: `v${version}`,
    changelog: `## ${version} (2026-08-20)\n\nNotes.\n`,
    run: partialRun,
  }));

  assert.throws(
    () => publishGithubRelease({
      directory,
      version,
      tag: `v${version}`,
      changelog: `## ${version} (2026-08-20)\n\nNotes.\n`,
      run: (command, args) => args[1] === 'view'
        ? {
            status: 0,
            stdout: JSON.stringify({
              isDraft: true,
              assets: [...assetList(directory), { name: 'foreign-file' }],
            }),
            stderr: '',
          }
        : { status: 0, stdout: '', stderr: '' },
    }),
    /unexpected: foreign-file/,
  );
});

test('rejects a published GitHub Release with a missing asset', (t) => {
  const directory = payload(t);
  assert.throws(
    () => publishGithubRelease({
      directory,
      version,
      tag: `v${version}`,
      changelog: `## ${version} (2026-08-20)\n\nNotes.\n`,
      run: (command, args) => args[1] === 'view'
        ? {
            status: 0,
            stdout: JSON.stringify({
              isDraft: false,
              assets: assetList(directory).filter(
                ({ name }) => name !== 'awskms-1.2.3-darwin-arm64.tar.gz',
              ),
            }),
            stderr: '',
          }
        : { status: 0, stdout: '', stderr: '' },
    }),
    /missing: awskms-1\.2\.3-darwin-arm64\.tar\.gz/,
  );
});

test('accepts an already-published release only when all twelve bytes match', (t) => {
  const directory = payload(t);
  const calls = [];
  const run = (command, args) => {
    calls.push(args);
    if (args[1] === 'view') {
      return {
        status: 0,
        stdout: JSON.stringify({ isDraft: false, assets: assetList(directory) }),
        stderr: '',
      };
    }
    if (args[1] === 'download') {
      copyPayload(directory, args[args.indexOf('--dir') + 1]);
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  publishGithubRelease({
    directory,
    version,
    tag: `v${version}`,
    changelog: `## ${version} (2026-08-20)\n\nNotes.\n`,
    run,
  });
  assert.deepEqual(calls.map((args) => args[1]), ['view', 'download']);
});

test('rejects different bytes on an already-published release without mutation', (t) => {
  const directory = payload(t);
  const calls = [];
  const run = (command, args) => {
    calls.push(args);
    if (args[1] === 'view') {
      return {
        status: 0,
        stdout: JSON.stringify({ isDraft: false, assets: assetList(directory) }),
        stderr: '',
      };
    }
    if (args[1] === 'download') {
      copyPayload(directory, args[args.indexOf('--dir') + 1], {
        corrupt: 'keyobject-aws-kms-1.2.3.tgz',
      });
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  assert.throws(
    () => publishGithubRelease({
      directory,
      version,
      tag: `v${version}`,
      changelog: `## ${version} (2026-08-20)\n\nNotes.\n`,
      run,
    }),
    /different keyobject-aws-kms-1\.2\.3\.tgz/,
  );
  assert.deepEqual(calls.map((args) => args[1]), ['view', 'download']);
});
