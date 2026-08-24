import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  checkRelease,
  nativePackages,
  normalizeChangelog,
  prepareRelease,
  syncReleaseVersion,
} from '../release-version.mjs';

function fixture({
  changelogVersion = '1.2.3',
  cmakeVersion = '1.2.2',
  dependencyVersion = '1.2.2',
  readme = '# Package\n',
  version = '1.2.3',
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'awskms-release-version-'));
  mkdirSync(join(root, 'npm/core'), { recursive: true });
  const optionalDependencies = Object.fromEntries(
    nativePackages.map((name) => [name, dependencyVersion]),
  );
  writeFileSync(
    join(root, 'npm/core/package.json'),
    `${JSON.stringify(
      { name: '@keyobject/aws-kms', version, optionalDependencies },
      null,
      2,
    )}\n`,
  );
  writeFileSync(
    join(root, 'CMakeLists.txt'),
    `project(awskms\n  VERSION ${cmakeVersion}\n  LANGUAGES C CXX)\n`,
  );
  writeFileSync(
    join(root, 'CHANGELOG.md'),
    `# Changelog\n\n## [${changelogVersion}](https://example.test/v${changelogVersion}) (2026-08-20)\n`,
  );
  writeFileSync(join(root, 'README.md'), readme);
  return root;
}

function useFixture(t, options) {
  const root = fixture(options);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  return root;
}

function initializeGit(root) {
  execFileSync('git', ['init', '--quiet'], { cwd: root });
  execFileSync('git', ['add', '.'], { cwd: root });
  execFileSync(
    'git',
    [
      '-c',
      'user.name=fixture',
      '-c',
      'user.email=fixture@example.test',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '--quiet',
      '-m',
      'fixture',
    ],
    { cwd: root },
  );
}

test('synchronizes exactly five native versions and CMake', (t) => {
  const root = useFixture(t);
  assert.deepEqual(syncReleaseVersion({ root }), {
    previousVersion: '1.2.2',
    version: '1.2.3',
  });

  const manifest = JSON.parse(readFileSync(join(root, 'npm/core/package.json')));
  assert.deepEqual(Object.keys(manifest.optionalDependencies).sort(), [...nativePackages].sort());
  assert.deepEqual(new Set(Object.values(manifest.optionalDependencies)), new Set(['1.2.3']));
  assert.match(readFileSync(join(root, 'CMakeLists.txt'), 'utf8'), /VERSION 1\.2\.3/);
});

test('stages only the two synchronized version files', (t) => {
  const root = useFixture(t);
  writeFileSync(join(root, 'unrelated.txt'), 'base\n');
  initializeGit(root);
  writeFileSync(join(root, 'unrelated.txt'), 'changed\n');

  syncReleaseVersion({ root, stage: true });

  assert.deepEqual(
    execFileSync('git', ['diff', '--cached', '--name-only'], {
      cwd: root,
      encoding: 'utf8',
    })
      .trim()
      .split('\n'),
    ['CMakeLists.txt', 'npm/core/package.json'],
  );
  assert.equal(
    execFileSync('git', ['diff', '--name-only'], {
      cwd: root,
      encoding: 'utf8',
    }).trim(),
    'unrelated.txt',
  );
});

test('requires a clean tracked worktree and index before bumping', (t) => {
  const root = useFixture(t, {
    cmakeVersion: '1.2.3',
    dependencyVersion: '1.2.3',
  });
  writeFileSync(join(root, 'tracked.txt'), 'base\n');
  initializeGit(root);
  assert.equal(prepareRelease({ root }), '1.2.3');

  writeFileSync(join(root, 'tracked.txt'), 'unstaged\n');
  assert.throws(
    () => prepareRelease({ root }),
    /requires a clean tracked worktree and index/,
  );

  execFileSync('git', ['add', 'tracked.txt'], { cwd: root });
  assert.throws(
    () => prepareRelease({ root }),
    /requires a clean tracked worktree and index/,
  );
});

test('rejects dependency drift before changing either version file', (t) => {
  const root = useFixture(t);
  const manifestPath = join(root, 'npm/core/package.json');
  const cmakePath = join(root, 'CMakeLists.txt');
  const manifest = JSON.parse(readFileSync(manifestPath));
  manifest.optionalDependencies[nativePackages[0]] = '1.2.1';
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const beforeManifest = readFileSync(manifestPath);
  const beforeCmake = readFileSync(cmakePath);

  assert.throws(
    () => syncReleaseVersion({ root }),
    /native optionalDependencies must agree before synchronization/,
  );
  assert.deepEqual(readFileSync(manifestPath), beforeManifest);
  assert.deepEqual(readFileSync(cmakePath), beforeCmake);
});

test('rejects an unexpected native optional dependency', (t) => {
  const root = useFixture(t);
  const manifestPath = join(root, 'npm/core/package.json');
  const manifest = JSON.parse(readFileSync(manifestPath));
  manifest.optionalDependencies['@keyobject/aws-kms-unexpected'] = '1.2.2';
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  assert.throws(
    () => syncReleaseVersion({ root }),
    /must have exactly these native optionalDependencies/,
  );
});

test('rejects a CMake version that disagrees before synchronization', (t) => {
  const root = useFixture(t, { cmakeVersion: '1.2.1' });
  assert.throws(
    () => syncReleaseVersion({ root }),
    /native optionalDependencies and CMake project VERSION must agree/,
  );
});

test('rejects missing or duplicate CMake project version declarations', (t) => {
  const missing = useFixture(t);
  writeFileSync(join(missing, 'CMakeLists.txt'), 'project(other VERSION 1.2.2)\n');
  assert.throws(
    () => syncReleaseVersion({ root: missing }),
    /must contain exactly one awskms project VERSION/,
  );

  const duplicate = useFixture(t);
  writeFileSync(
    join(duplicate, 'CMakeLists.txt'),
    'project(awskms VERSION 1.2.2)\nproject(awskms VERSION 1.2.2)\n',
  );
  assert.throws(
    () => syncReleaseVersion({ root: duplicate }),
    /must contain exactly one awskms project VERSION/,
  );
});

test('checks coherent release metadata and its exact tag', (t) => {
  const root = useFixture(t, {
    cmakeVersion: '1.2.3',
    dependencyVersion: '1.2.3',
  });
  assert.equal(checkRelease({ root, tag: 'v1.2.3' }), '1.2.3');
  assert.throws(
    () => checkRelease({ root, tag: 'v1.2.4' }),
    /release tag must be exactly v1\.2\.3/,
  );
});

test('rejects placeholder and non-stable release versions', (t) => {
  const placeholder = useFixture(t, {
    changelogVersion: '0.0.0',
    cmakeVersion: '0.0.0',
    dependencyVersion: '0.0.0',
    version: '0.0.0',
  });
  assert.throws(
    () => checkRelease({ root: placeholder, tag: 'v0.0.0' }),
    /must not be the 0\.0\.0 placeholder/,
  );

  const prerelease = useFixture(t, { version: '1.2.3-rc.0' });
  assert.throws(
    () => syncReleaseVersion({ root: prerelease }),
    /must be a stable numeric X\.Y\.Z version/,
  );
});

test('rejects a missing changelog section', (t) => {
  const root = useFixture(t, {
    changelogVersion: '1.2.2',
    cmakeVersion: '1.2.3',
    dependencyVersion: '1.2.3',
  });
  assert.throws(
    () => checkRelease({ root, tag: 'v1.2.3' }),
    /must contain exactly one release heading for 1\.2\.3/,
  );
});

test('rejects the unreleased README note', (t) => {
  const marker = ['Work', 'in', 'progress'].join(' ');
  const root = useFixture(t, {
    cmakeVersion: '1.2.3',
    dependencyVersion: '1.2.3',
    readme: `> **${marker}.**\n`,
  });
  assert.throws(
    () => prepareRelease({ root }),
    /README\.md still declares the package unreleased/,
  );
  assert.throws(
    () => checkRelease({ root, tag: 'v1.2.3' }),
    /README\.md still declares the package unreleased/,
  );
});

test('normalizes linked release headings without changing subsections', (t) => {
  const root = useFixture(t);
  const contents = [
    '# Changelog',
    '',
    '### [1.2.3](https://example.test/v1.2.3) (2026-08-20)',
    '',
    '### Features',
    '',
  ].join('\n');
  writeFileSync(join(root, 'CHANGELOG.md'), contents);

  normalizeChangelog({ root });

  assert.equal(
    readFileSync(join(root, 'CHANGELOG.md'), 'utf8'),
    contents.replace('### [1.2.3]', '## [1.2.3]'),
  );
});

test('separates adjacent linked and unlinked release headings', (t) => {
  const root = useFixture(t);
  const contents = [
    '# Changelog',
    '',
    '## [1.2.3](https://example.test/v1.2.3) (2026-08-20)',
    '',
    '### Fixes',
    '',
    '* newest fix',
    '## [1.2.2](https://example.test/v1.2.2) (2026-08-19)',
    '',
    '### Features',
    '',
    '* older feature',
    '## 1.0.0 (2026-08-18)',
    '',
  ].join('\n');
  const expected = contents
    .replace('* newest fix\n## [1.2.2]', '* newest fix\n\n## [1.2.2]')
    .replace('* older feature\n## 1.0.0', '* older feature\n\n## 1.0.0');
  writeFileSync(join(root, 'CHANGELOG.md'), contents);

  normalizeChangelog({ root });

  assert.equal(readFileSync(join(root, 'CHANGELOG.md'), 'utf8'), expected);
  normalizeChangelog({ root });
  assert.equal(readFileSync(join(root, 'CHANGELOG.md'), 'utf8'), expected);
});

test('removes only the duplicated initial header from the first release', (t) => {
  const root = useFixture(t);
  const header = [
    '# Changelog',
    '',
    'All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.',
    '',
  ].join('\n');
  const release = [
    '### [1.2.3](https://example.test/v1.2.3) (2026-08-20)',
    '',
    '### Features',
    '',
    '* first release',
    '',
  ].join('\n');
  writeFileSync(join(root, 'CHANGELOG.md'), `${header}\n${release}${header}`);

  normalizeChangelog({ root });

  assert.equal(
    readFileSync(join(root, 'CHANGELOG.md'), 'utf8'),
    `${header}\n${release.replace('### [1.2.3]', '## [1.2.3]').trimEnd()}\n`,
  );
});
