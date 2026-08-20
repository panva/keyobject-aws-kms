#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const coreManifest = 'npm/core/package.json';
const cmakeProject = 'CMakeLists.txt';
const changelog = 'CHANGELOG.md';
const readme = 'README.md';
const changelogHeader = [
  '# Changelog',
  '',
  'All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.',
  '',
].join('\n');
const stableVersion = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const incompleteReadme = new RegExp(
  ['work', 'in', 'progress'].join('[\\s-]+'),
  'i',
);

export const nativePackages = Object.freeze([
  '@keyobject/aws-kms-darwin-arm64',
  '@keyobject/aws-kms-linux-arm64',
  '@keyobject/aws-kms-linux-x64',
  '@keyobject/aws-kms-linuxmusl-arm64',
  '@keyobject/aws-kms-linuxmusl-x64',
]);

function fail(message) {
  throw new Error(message);
}

function read(root, path) {
  try {
    return readFileSync(join(root, path), 'utf8');
  } catch (cause) {
    throw new Error(`could not read ${path}`, { cause });
  }
}

function parseManifest(contents) {
  let manifest;
  try {
    manifest = JSON.parse(contents);
  } catch (cause) {
    throw new Error(`${coreManifest} is not valid JSON`, { cause });
  }

  if (manifest?.name !== '@keyobject/aws-kms') {
    fail(`${coreManifest} must describe @keyobject/aws-kms`);
  }
  assertStableVersion(manifest.version, `${coreManifest} version`, {
    allowPlaceholder: true,
  });

  const dependencies = manifest.optionalDependencies;
  if (
    dependencies == null ||
    typeof dependencies !== 'object' ||
    Array.isArray(dependencies)
  ) {
    fail(`${coreManifest} optionalDependencies must be an object`);
  }
  const actual = Object.keys(dependencies).sort();
  const expected = [...nativePackages].sort();
  if (
    actual.length !== expected.length ||
    actual.some((name, index) => name !== expected[index])
  ) {
    fail(
      `${coreManifest} must have exactly these native optionalDependencies: ${expected.join(', ')}`,
    );
  }
  for (const name of nativePackages) {
    assertStableVersion(
      dependencies[name],
      `${coreManifest} optionalDependencies.${name}`,
      { allowPlaceholder: true },
    );
  }
  return manifest;
}

function parseCmake(contents) {
  const matches = [
    ...contents.matchAll(/project\(awskms\s+VERSION\s+([^\s)]+)/g),
  ];
  if (matches.length !== 1) {
    fail(`${cmakeProject} must contain exactly one awskms project VERSION`);
  }
  const version = matches[0][1];
  assertStableVersion(version, `${cmakeProject} project VERSION`, {
    allowPlaceholder: true,
  });
  return {
    end: matches[0].index + matches[0][0].length,
    start: matches[0].index + matches[0][0].length - version.length,
    version,
  };
}

function assertStableVersion(version, subject, { allowPlaceholder = false } = {}) {
  if (typeof version !== 'string' || !stableVersion.test(version)) {
    fail(`${subject} must be a stable numeric X.Y.Z version`);
  }
  if (!allowPlaceholder && version === '0.0.0') {
    fail(`${subject} must not be the 0.0.0 placeholder`);
  }
}

function assertDependencyAndCmakeAgreement(state, expectedVersion) {
  for (const name of nativePackages) {
    if (state.manifest.optionalDependencies[name] !== expectedVersion) {
      fail(`${name} version must equal ${expectedVersion}`);
    }
  }
  if (state.cmake.version !== expectedVersion) {
    fail(`${cmakeProject} project VERSION must equal ${expectedVersion}`);
  }
}

function assertReadmeReady(contents) {
  if (incompleteReadme.test(contents)) {
    fail('README.md still declares the package unreleased');
  }
}

function assertCleanTrackedState(root) {
  let status;
  try {
    status = execFileSync(
      'git',
      ['status', '--porcelain=v1', '--untracked-files=no'],
      { cwd: root, encoding: 'utf8' },
    );
  } catch (cause) {
    throw new Error('could not inspect the tracked release state', { cause });
  }
  if (status !== '') {
    fail(
      `release preparation requires a clean tracked worktree and index; found: ${status.trim().split('\n').join(', ')}`,
    );
  }
}

function assertChangelogVersion(contents, version) {
  const escaped = version.replaceAll('.', '\\.');
  const heading = new RegExp(
    `^## (?:\\[${escaped}\\]\\([^\\r\\n]+\\)|${escaped}) \\(\\d{4}-\\d{2}-\\d{2}\\)$`,
    'gm',
  );
  const matches = [...contents.matchAll(heading)];
  if (matches.length !== 1) {
    fail(`${changelog} must contain exactly one release heading for ${version}`);
  }
}

export function readReleaseState({ root = defaultRoot } = {}) {
  const manifestContents = read(root, coreManifest);
  const cmakeContents = read(root, cmakeProject);
  return {
    cmake: parseCmake(cmakeContents),
    cmakeContents,
    manifest: parseManifest(manifestContents),
    manifestContents,
    root,
  };
}

export function prepareRelease({ root = defaultRoot } = {}) {
  const state = readReleaseState({ root });
  assertDependencyAndCmakeAgreement(state, state.manifest.version);
  assertReadmeReady(read(root, readme));
  assertCleanTrackedState(root);
  return state.manifest.version;
}

export function syncReleaseVersion({ root = defaultRoot, stage = false } = {}) {
  const state = readReleaseState({ root });
  const target = state.manifest.version;
  assertStableVersion(target, `${coreManifest} version`);

  const previous = new Set(
    nativePackages.map((name) => state.manifest.optionalDependencies[name]),
  );
  if (previous.size !== 1) {
    fail('native optionalDependencies must agree before synchronization');
  }
  const [previousVersion] = previous;
  if (state.cmake.version !== previousVersion) {
    fail('native optionalDependencies and CMake project VERSION must agree before synchronization');
  }

  for (const name of nativePackages) {
    state.manifest.optionalDependencies[name] = target;
  }
  const nextManifest = `${JSON.stringify(state.manifest, null, 2)}\n`;
  const nextCmake =
    state.cmakeContents.slice(0, state.cmake.start) +
    target +
    state.cmakeContents.slice(state.cmake.end);

  const nextState = {
    cmake: parseCmake(nextCmake),
    manifest: parseManifest(nextManifest),
  };
  assertDependencyAndCmakeAgreement(nextState, target);

  writeFileSync(join(root, coreManifest), nextManifest);
  writeFileSync(join(root, cmakeProject), nextCmake);
  if (stage) {
    execFileSync('git', ['add', '--', coreManifest, cmakeProject], {
      cwd: root,
      stdio: 'inherit',
    });
  }
  return { previousVersion, version: target };
}

export function normalizeChangelog({ root = defaultRoot } = {}) {
  const path = join(root, changelog);
  const contents = read(root, changelog);
  let normalized = contents.replace(/^### \[/gm, '## [');

  // On the first release commit-and-tag-version has no release heading from
  // which to slice the old changelog body, so it appends the initial header a
  // second time. Remove only that exact trailing seed; an unexpected second
  // header remains visible for review instead of being silently rewritten.
  const duplicate = `\n${changelogHeader}`;
  if (
    normalized.startsWith(changelogHeader) &&
    normalized.endsWith(duplicate) &&
    normalized.indexOf(duplicate, changelogHeader.length) ===
      normalized.length - duplicate.length
  ) {
    normalized = `${normalized.slice(0, -duplicate.length).trimEnd()}\n`;
  }
  if (normalized !== contents) writeFileSync(path, normalized);
}

export function checkRelease({ root = defaultRoot, tag } = {}) {
  const state = readReleaseState({ root });
  const version = state.manifest.version;
  assertStableVersion(version, `${coreManifest} version`);
  assertDependencyAndCmakeAgreement(state, version);
  if (tag !== `v${version}`) {
    fail(`release tag must be exactly v${version}`);
  }
  assertChangelogVersion(read(root, changelog), version);
  assertReadmeReady(read(root, readme));
  return version;
}

function parseTag(arguments_) {
  if (arguments_.length === 2 && arguments_[0] === '--tag') {
    return arguments_[1];
  }
  if (arguments_.length === 1 && arguments_[0].startsWith('--tag=')) {
    return arguments_[0].slice('--tag='.length);
  }
  fail('usage: release-version.mjs check --tag vX.Y.Z');
}

function main([command, ...arguments_]) {
  switch (command) {
    case 'prepare':
      if (arguments_.length !== 0) fail('usage: release-version.mjs prepare');
      prepareRelease();
      break;
    case 'sync': {
      if (arguments_.length !== 0) fail('usage: release-version.mjs sync');
      const { previousVersion, version } = syncReleaseVersion({ stage: true });
      console.log(`synchronized release version from ${previousVersion} to ${version}`);
      break;
    }
    case 'normalize-changelog':
      if (arguments_.length !== 0) {
        fail('usage: release-version.mjs normalize-changelog');
      }
      normalizeChangelog();
      break;
    case 'check': {
      const version = checkRelease({ tag: parseTag(arguments_) });
      console.log(`release metadata is coherent for v${version}`);
      break;
    }
    default:
      fail(
        'usage: release-version.mjs prepare | sync | normalize-changelog | check --tag vX.Y.Z',
      );
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`error: ${error.message}`);
    process.exitCode = 1;
  }
}
