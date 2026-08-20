#!/usr/bin/env node
// Refresh the exact SDK/CRT versions represented by the public legal manifest.
// An unknown gitlink fails closed until its license and notice are reviewed.
import { spawnSync } from 'node:child_process';
import {
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';

const version = process.argv[2];
if (process.argv.length !== 3 || !/^\d+\.\d+\.\d+$/.test(version ?? '')) {
  console.error(`usage: ${process.argv[1]} <aws-sdk-cpp-version>`);
  process.exit(2);
}

const root = resolve(import.meta.dirname, '..');
const manifestPath = join(root, 'third_party', 'components.json');

// These are review checkpoints, not merely upstream metadata. If one changes,
// refresh the bundled legal payload first and update its SHA in the same commit.
const sdkLegalFiles = new Map([
  ['LICENSE', '8dada3edaf50dbc082c9a125058f25def75e625a'],
  ['LICENSE.txt', '3adf3884dda91cc70aca0b8553406b159a530702'],
  ['NOTICE.txt', '66bbe1f2efa5f06838ef6d68a4644c858a8f92fa'],
]);
const sdkReviewedFiles = new Map([
  [
    'src/aws-cpp-sdk-core/source/external/cjson/cJSON.cpp',
    'f4a4169239cfc6f911de2c55b2d75767cbaf3dbe',
  ],
  [
    'src/aws-cpp-sdk-core/include/aws/core/external/cjson/cJSON.h',
    '293586ac8ae3fd5aed1d61f5295dbed9abe46579',
  ],
  [
    'src/aws-cpp-sdk-core/source/external/tinyxml2/tinyxml2.cpp',
    '48131817bfcd3259631bb47ced9ef6445c02f035',
  ],
  [
    'src/aws-cpp-sdk-core/include/aws/core/external/tinyxml2/tinyxml2.h',
    '3917ce68620a3858ed4938d8206663d1901ff3d7',
  ],
]);
const reviewedComponentDeclarations = new Map([
  ['cjson', {
    version: '1.7.19',
    license: 'cJSON-MIT.txt',
    licenseExpression: 'MIT',
    notice: null,
    targets: 'all',
  }],
  ['libcbor', {
    version: '0.13.0',
    license: 'libcbor-MIT.txt',
    licenseExpression: 'MIT',
    notice: null,
    targets: 'all',
  }],
  ['tinyxml2', {
    version: '11.0.0',
    license: 'tinyxml2-zlib.txt',
    licenseExpression: 'Zlib',
    notice: null,
    targets: 'all',
  }],
  ['xxhash', {
    version: '0.8.3',
    license: 'xxHash-BSD-2-Clause.txt',
    licenseExpression: 'BSD-2-Clause',
    notice: null,
    targets: 'all',
  }],
  ['apple-commoncrypto-spi', {
    license: 'APSL-2.0.txt',
    licenseExpression: 'APSL-2.0',
    notice: 'Apple-CommonCrypto-SPI-NOTICE.txt',
    targets: 'darwin',
  }],
]);
const crtLegalFiles = new Map([
  ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
  ['NOTICE', '8b820137a0aa14f48ecaa89c3602139eaa2f7f88'],
]);
const awsCCommonThirdPartyLicensesSha =
  '4fd9353d7d8fe1ea937b159e2202233db21ac8fb';
const gitlinkComponents = new Map([
  ['crt/aws-c-auth', {
    name: 'aws-c-auth',
    repository: 'awslabs/aws-c-auth',
    legalFiles: new Map([
      ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
      ['NOTICE', '7b3f69846bfdf9678ddf1c4a011c8eb61aab0e4e'],
    ]),
  }],
  ['crt/aws-c-cal', {
    name: 'aws-c-cal',
    repository: 'awslabs/aws-c-cal',
    legalFiles: new Map([
      ['LICENSE', '67db8588217f266eb561f75fae738656325deac9'],
      ['NOTICE', 'df81ba71af0026d3dab3ab7a9ad68bd15540b575'],
    ]),
    reviewedFiles: new Map([
      [
        'source/darwin/common_cryptor_spi.h',
        'efe620103b8e8cef662f924704bf58777e005597',
      ],
    ]),
  }],
  ['crt/aws-c-common', {
    name: 'aws-c-common',
    repository: 'awslabs/aws-c-common',
    legalFiles: new Map([
      ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
      ['NOTICE', 'dae662e8b4ddc581eab03e5198d56b1b416df26d'],
      [
        'THIRD-PARTY-LICENSES.txt',
        awsCCommonThirdPartyLicensesSha,
      ],
    ]),
    reviewedFiles: new Map([
      [
        'THIRD-PARTY-LICENSES.txt',
        awsCCommonThirdPartyLicensesSha,
      ],
    ]),
  }],
  ['crt/aws-c-compression', {
    name: 'aws-c-compression',
    repository: 'awslabs/aws-c-compression',
    legalFiles: new Map([
      ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
      ['NOTICE', '7c0e91fdb76e83319e08723682868f529f8ee65b'],
    ]),
  }],
  ['crt/aws-c-event-stream', {
    name: 'aws-c-event-stream',
    repository: 'awslabs/aws-c-event-stream',
    legalFiles: new Map([
      ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
      ['NOTICE', '3eaf9af6564f7bd0313c25116d67bd30d0d02828'],
    ]),
  }],
  ['crt/aws-c-http', {
    name: 'aws-c-http',
    repository: 'awslabs/aws-c-http',
    legalFiles: new Map([
      ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
      ['NOTICE', '6ac9e1e1186961079a288d7861a89dd42db4ccf4'],
    ]),
  }],
  ['crt/aws-c-io', {
    name: 'aws-c-io',
    repository: 'awslabs/aws-c-io',
    legalFiles: new Map([
      ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
      ['NOTICE', '7939cd2397dc0b7a4b1aa55f23ad6d97f5ad1211'],
    ]),
  }],
  ['crt/aws-c-mqtt', {
    name: 'aws-c-mqtt',
    repository: 'awslabs/aws-c-mqtt',
    legalFiles: new Map([
      ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
      ['NOTICE', '5f56b8d0d823073804e4029ef0a19fa837cfd965'],
    ]),
  }],
  ['crt/aws-c-s3', {
    name: 'aws-c-s3',
    repository: 'awslabs/aws-c-s3',
    legalFiles: new Map([
      ['LICENSE', '67db8588217f266eb561f75fae738656325deac9'],
      ['NOTICE', '616fc5889451895dbf9768e6787c8308c33bef22'],
    ]),
  }],
  ['crt/aws-c-sdkutils', {
    name: 'aws-c-sdkutils',
    repository: 'awslabs/aws-c-sdkutils',
    legalFiles: new Map([
      ['LICENSE', '67db8588217f266eb561f75fae738656325deac9'],
      ['NOTICE', '616fc5889451895dbf9768e6787c8308c33bef22'],
    ]),
  }],
  ['crt/aws-checksums', {
    name: 'aws-checksums',
    repository: 'awslabs/aws-checksums',
    legalFiles: new Map([
      ['LICENSE', '8dada3edaf50dbc082c9a125058f25def75e625a'],
    ]),
    reviewedFiles: new Map([
      [
        'source/external/xxhash.h',
        '2ee0db661812f096abe8db478313722579849543',
      ],
    ]),
  }],
  ['crt/s2n', {
    name: 's2n-tls',
    repository: 'awslabs/s2n',
    legalFiles: new Map([
      ['LICENSE', 'd645695673349e3947e8e5ae42332d0ac3164cd7'],
      ['NOTICE', 'f8bbcc301b59800d2f6ac5c1f82cb2d8bcff31b2'],
    ]),
  }],
]);
const excludedGitlinks = new Map([
  ['crt/aws-lc', 'https://github.com/awslabs/aws-lc.git'],
]);

function fail(message) {
  throw new Error(message);
}

function ghApi(endpoint) {
  const result = spawnSync('gh', ['api', endpoint], {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(`could not run gh api for ${endpoint}`, {
      cause: result.error,
    });
  }
  if (result.status !== 0) {
    fail(
      `gh api failed for ${endpoint}: ${result.stderr.trim() || `exit ${result.status}`}`,
    );
  }
  try {
    return JSON.parse(result.stdout);
  } catch (cause) {
    throw new Error(`gh api returned invalid JSON for ${endpoint}`, { cause });
  }
}

function requireSha(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) {
    fail(`${label} is not a full Git commit SHA`);
  }
  return value;
}

function sameMembers(actual, expected) {
  return (
    actual.length === expected.length &&
    actual.every((value, index) => value === expected[index])
  );
}

function assertSameKeys(actual, expected, label) {
  const actualKeys = [...actual.keys()].sort();
  const expectedKeys = [...expected.keys()].sort();
  if (!sameMembers(actualKeys, expectedKeys)) {
    const missing = expectedKeys.filter((key) => !actual.has(key));
    const unexpected = actualKeys.filter((key) => !expected.has(key));
    fail(
      `${label} needs review (missing: ${missing.join(', ') || 'none'}; unexpected: ${unexpected.join(', ') || 'none'})`,
    );
  }
}

function parseGitmodules(payload) {
  if (payload.encoding !== 'base64' || typeof payload.content !== 'string') {
    fail('aws-crt-cpp .gitmodules response is not base64 content');
  }
  const source = Buffer.from(payload.content.replaceAll('\n', ''), 'base64').toString();
  const modules = new Map();
  for (const section of source.split(/(?=^\[submodule\s+")/m)) {
    const path = section.match(/^\s*path\s*=\s*(\S+)\s*$/m)?.[1];
    const url = section.match(/^\s*url\s*=\s*(\S+)\s*$/m)?.[1];
    if (path == null && url == null) continue;
    if (path == null || url == null || modules.has(path)) {
      fail('aws-crt-cpp .gitmodules has an invalid or duplicate entry');
    }
    modules.set(path, url);
  }
  return modules;
}

const legalFileName =
  /^(?:(?:LICENSES?|NOTICES?|COPYING|COPYRIGHT)(?:[._-].*)?|THIRD[-_]PARTY[-_](?:LICENSES?|NOTICES?)(?:[._-].*)?)$/i;

function verifyLegalFiles(repository, ref, expected, response) {
  const tree = response ?? ghApi(`repos/${repository}/git/trees/${ref}`);
  if (tree.truncated === true || !Array.isArray(tree.tree)) {
    fail(`${repository} legal-file tree response is missing or truncated`);
  }
  const actual = new Map(
    tree.tree
      .filter(({ type, path }) =>
        type === 'blob' && legalFileName.test(path),
      )
      .map(({ path, sha }) => [path, requireSha(sha, `${repository} ${path}`)]),
  );
  assertSameKeys(actual, expected, `${repository} legal-file inventory`);
  for (const [path, expectedSha] of expected) {
    if (actual.get(path) !== expectedSha) {
      fail(
        `${repository} ${path} changed at ${ref}; refresh the bundled license/notice payload before updating its reviewed blob SHA`,
      );
    }
  }
}

function verifyReviewedFiles(repository, ref, expected) {
  for (const [path, expectedSha] of expected) {
    const file = ghApi(`repos/${repository}/contents/${path}?ref=${ref}`);
    if (file.type !== 'file' || file.path !== path) {
      fail(`${repository} reviewed source ${path} is missing or is not a file at ${ref}`);
    }
    const actualSha = requireSha(file.sha, `${repository} ${path}`);
    if (actualSha !== expectedSha) {
      fail(
        `${repository} reviewed source ${path} changed at ${ref}; review its embedded dependency version and license, refresh the bundled legal payload, and update its reviewed blob SHA`,
      );
    }
  }
}

try {
  const crt = ghApi(
    `repos/aws/aws-sdk-cpp/contents/crt/aws-crt-cpp?ref=${version}`,
  );
  const crtCommit = requireSha(crt.sha, 'aws-crt-cpp gitlink');
  if (crt.submodule_git_url !== 'https://github.com/awslabs/aws-crt-cpp.git') {
    fail(`unexpected aws-crt-cpp repository: ${crt.submodule_git_url ?? '<missing>'}`);
  }

  const expectedRepositories = new Map(
    [...gitlinkComponents].map(([path, { repository }]) => [
      path,
      `https://github.com/${repository}.git`,
    ]),
  );
  for (const [path, repository] of excludedGitlinks) {
    expectedRepositories.set(path, repository);
  }
  const modules = parseGitmodules(
    ghApi(
      `repos/awslabs/aws-crt-cpp/contents/.gitmodules?ref=${crtCommit}`,
    ),
  );
  assertSameKeys(modules, expectedRepositories, 'AWS CRT repository inventory');
  for (const [path, expectedUrl] of expectedRepositories) {
    if (modules.get(path) !== expectedUrl) {
      fail(
        `AWS CRT repository for ${path} changed from ${expectedUrl} to ${modules.get(path)}; review its identity and license`,
      );
    }
  }

  const tree = ghApi(
    `repos/awslabs/aws-crt-cpp/git/trees/${crtCommit}?recursive=1`,
  );
  if (tree.truncated === true || !Array.isArray(tree.tree)) {
    fail('aws-crt-cpp tree response is missing or truncated');
  }

  const allGitlinks = new Map(
    tree.tree
      .filter(({ mode }) => mode === '160000')
      .map(({ path, sha }) => [path, requireSha(sha, `${path} gitlink`)]),
  );
  assertSameKeys(allGitlinks, expectedRepositories, 'AWS CRT dependency graph');
  const gitlinks = new Map(allGitlinks);
  for (const path of excludedGitlinks.keys()) gitlinks.delete(path);

  verifyLegalFiles('aws/aws-sdk-cpp', version, sdkLegalFiles);
  verifyReviewedFiles('aws/aws-sdk-cpp', version, sdkReviewedFiles);
  verifyLegalFiles('awslabs/aws-crt-cpp', crtCommit, crtLegalFiles, tree);

  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.components)) {
    fail('third_party/components.json has an unsupported shape');
  }
  const components = new Map();
  for (const component of manifest.components) {
    if (typeof component.name !== 'string' || components.has(component.name)) {
      fail('third_party/components.json has a missing or duplicate component name');
    }
    components.set(component.name, component);
  }
  for (const [name, expected] of reviewedComponentDeclarations) {
    const component = components.get(name);
    if (component == null) {
      fail(`third_party/components.json is missing reviewed component ${name}`);
    }
    for (const [field, expectedValue] of Object.entries(expected)) {
      if (component[field] !== expectedValue) {
        fail(
          `third_party/components.json ${name} ${field} changed; review the pinned upstream source and bundled legal payload`,
        );
      }
    }
  }

  const appleSpiComponent = components.get('apple-commoncrypto-spi');
  if (typeof appleSpiComponent.commit !== 'string') {
    fail('third_party/components.json apple-commoncrypto-spi commit is missing');
  }

  for (const name of [
    'aws-cpp-sdk-core',
    'aws-cpp-sdk-kms',
  ]) {
    const component = components.get(name);
    if (component == null || typeof component.version !== 'string') {
      fail(`third_party/components.json is missing versioned component ${name}`);
    }
    component.version = version;
  }

  const crtComponent = components.get('aws-crt-cpp');
  if (crtComponent == null || typeof crtComponent.commit !== 'string') {
    fail('third_party/components.json is missing aws-crt-cpp');
  }
  crtComponent.commit = crtCommit;

  for (const [path, details] of gitlinkComponents) {
    const component = components.get(details.name);
    if (component == null || typeof component.commit !== 'string') {
      fail(`third_party/components.json is missing git component ${details.name}`);
    }
    const commit = gitlinks.get(path);
    if (details.reviewedFiles != null) {
      verifyReviewedFiles(details.repository, commit, details.reviewedFiles);
    }
    if (component.commit !== commit) {
      verifyLegalFiles(
        details.repository,
        commit,
        details.legalFiles,
      );
    }
    component.commit = commit;
    if (details.name === 'aws-c-cal') appleSpiComponent.commit = commit;
  }
  manifest.awsSdkTag = version;

  const temporaryPath = `${manifestPath}.${process.pid}.tmp`;
  try {
    writeFileSync(temporaryPath, `${JSON.stringify(manifest, null, 2)}\n`, {
      flag: 'wx',
      mode: statSync(manifestPath).mode & 0o777,
    });
    renameSync(temporaryPath, manifestPath);
  } finally {
    rmSync(temporaryPath, { force: true });
  }

  console.log(
    `updated AWS SDK component graph to ${version} (${gitlinks.size + 1} gitlinks)`,
  );
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exitCode = 1;
}
