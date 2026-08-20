import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join, resolve } from 'node:path'
import test from 'node:test'

import {
  assembleRelease,
  packBuildPackages,
  stageTargetLegalPayload,
  targets,
} from '../lib/npm-packaging.mjs'

const repository = resolve(import.meta.dirname, '..', '..')
const fixtureVersion = '1.2.3'

function copyPath(sourceRoot, fixtureRoot, path) {
  const source = join(sourceRoot, ...path.split('/'))
  const destination = join(fixtureRoot, ...path.split('/'))
  mkdirSync(join(destination, '..'), { recursive: true })
  cpSync(source, destination, { recursive: true })
}

function makeFixtureRoot(parent, version = fixtureVersion) {
  const root = join(parent, 'repository')
  for (const path of [
    'LICENSE',
    'THIRD_PARTY_NOTICES.md',
    'docs/INSTALL.md',
    'npm/core',
    'npm/platform',
    'scripts/check.mjs',
    'third_party/components.json',
    'third_party/licenses',
  ]) {
    copyPath(repository, root, path)
  }
  writeFileSync(join(root, 'README.md'), '# fixture\n')
  const manifestPath = join(root, 'npm', 'core', 'package.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  manifest.version = version
  for (const name of Object.keys(manifest.optionalDependencies)) {
    manifest.optionalDependencies[name] = version
  }
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
  return root
}

function elfModule(target, version, backend = 'aws') {
  const module = Buffer.alloc(512)
  module.set([0x7f, 0x45, 0x4c, 0x46, 2, 1], 0)
  module.writeUInt16LE(target.cpu === 'x64' ? 62 : 183, 18)
  module.write(`${version} backend=${backend}\0`, 64, 'ascii')
  if (target.libc === 'glibc') module.write('GLIBC_2.28\0', 128, 'ascii')
  return module
}

function machModule(version, backend = 'aws') {
  const module = Buffer.alloc(512)
  module.writeUInt32LE(0xfeedfacf, 0)
  module.writeUInt32LE(0x0100000c, 4)
  module.writeUInt32LE(1, 16)
  module.writeUInt32LE(24, 20)
  module.writeUInt32LE(0x32, 32)
  module.writeUInt32LE(24, 36)
  module.writeUInt32LE(1, 40)
  module.writeUInt32LE((13 << 16) | (5 << 8), 44)
  module.write(`${version} backend=${backend}\0`, 96, 'ascii')
  return module
}

function moduleFor(target, version, backend = 'aws') {
  return target.os === 'darwin'
    ? machModule(version, backend)
    : elfModule(target, version, backend)
}

function stageArchivePayload({ root, stage, target, version, overrides = {} }) {
  const top = `awskms-${version}-${target.name}`
  const destination = join(stage, top)
  mkdirSync(join(destination, 'docs'), { recursive: true })
  copyPath(root, destination, 'docs/INSTALL.md')
  copyPath(root, destination, 'scripts/check.mjs')
  cpSync(join(destination, 'scripts', 'check.mjs'), join(destination, 'check.mjs'))
  rmSync(join(destination, 'scripts'), { recursive: true })
  stageTargetLegalPayload({ root, destination, targetName: target.name })
  writeFileSync(join(destination, target.module), overrides.module ?? moduleFor(target, version))
  writeFileSync(join(destination, 'awskms.cnf'), overrides.config ?? 'relocatable config\n')
  for (const [path, bytes] of Object.entries(overrides.files ?? {})) {
    writeFileSync(join(destination, ...path.split('/')), bytes)
  }
  for (const path of overrides.removeFiles ?? []) {
    rmSync(join(destination, ...path.split('/')))
  }
  return top
}

function createArchive({ artifacts, root, target, version, overrides, duplicateLicense = false }) {
  const stage = mkdtempSync(join(tmpdir(), 'awskms-archive-fixture.'))
  try {
    const top = stageArchivePayload({ root, stage, target, version, overrides })
    const archive = join(artifacts, `${top}.tar.gz`)
    const entries = duplicateLicense ? [top, `${top}/LICENSE`] : [top]
    execFileSync('tar', ['-czf', archive, '-C', stage, ...entries])
    return archive
  } finally {
    rmSync(stage, { force: true, recursive: true })
  }
}

function makeReleaseFixture() {
  const directory = mkdtempSync(join(tmpdir(), 'awskms-release-fixture.'))
  const root = makeFixtureRoot(directory)
  const artifacts = join(directory, 'artifacts')
  const output = join(directory, 'dist')
  mkdirSync(artifacts)
  for (const target of targets) {
    createArchive({ artifacts, root, target, version: fixtureVersion })
  }
  return { artifacts, directory, output, root }
}

function replaceArchive(fixture, targetName, options = {}) {
  const target = targets.find(({ name }) => name === targetName)
  createArchive({
    artifacts: fixture.artifacts,
    root: fixture.root,
    target,
    version: fixtureVersion,
    ...options,
  })
}

function tarEntry(archive, path) {
  return execFileSync('tar', ['-xOzf', archive, path])
}

function tarEntries(archive) {
  return execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' })
    .trimEnd()
    .split('\n')
}

function referencedLegalFiles(components) {
  return [
    ...new Set(
      components.flatMap((component) =>
        ['license', 'exception', 'notice']
          .map((field) => component[field])
          .filter((value) => value != null),
      ),
    ),
  ].sort()
}

test('build package staging uses the shared target implementation', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'awskms-build-pack.'))
  t.after(() => rmSync(directory, { force: true, recursive: true }))
  const build = join(directory, 'build')
  const output = join(directory, 'output')
  const target = targets[0]
  const version = JSON.parse(
    readFileSync(join(repository, 'npm', 'core', 'package.json'), 'utf8'),
  ).version
  mkdirSync(build)
  writeFileSync(join(build, target.module), moduleFor(target, version))
  writeFileSync(join(build, 'awskms.relocatable.cnf'), 'relocatable config\n')
  writeFileSync(join(build, 'awskms-backend'), 'aws\n')
  const components = JSON.parse(
    readFileSync(join(repository, 'third_party', 'components.json'), 'utf8'),
  )
  writeFileSync(join(build, 'awskms-dependencies'), `aws-sdk-cpp=${components.awsSdkTag}\n`)

  const result = packBuildPackages({
    root: repository,
    buildDirectory: build,
    outputDirectory: output,
    targetName: target.name,
  })
  assert.equal(basename(result.coreTarball), `keyobject-aws-kms-${version}.tgz`)
  assert.equal(
    basename(result.satelliteTarball),
    `keyobject-aws-kms-darwin-arm64-${version}.tgz`,
  )
  assert.deepEqual(
    JSON.parse(tarEntry(result.satelliteTarball, 'package/package.json')),
    JSON.parse(readFileSync(join(output, 'platform', 'package.json'))),
  )
  const legalEntries = tarEntries(result.satelliteTarball).filter((entry) =>
    entry.startsWith('package/third_party/licenses/'),
  )
  assert.ok(!legalEntries.some((entry) => /GPL|GCC-RUNTIME/u.test(entry)))
})

test('target legal staging rejects source inventory and target drift', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'awskms-legal-source.'))
  t.after(() => rmSync(directory, { force: true, recursive: true }))

  for (const [name, mutate, expected] of [
    [
      'missing',
      (root) => rmSync(join(root, 'third_party', 'licenses', 'Apache-2.0.txt')),
      /component dependency graph and license inventory differ/u,
    ],
    [
      'unexpected',
      (root) =>
        writeFileSync(join(root, 'third_party', 'licenses', 'UNEXPECTED.txt'), 'nope\n'),
      /component dependency graph and license inventory differ/u,
    ],
    [
      'wrong-target',
      (root) => {
        const path = join(root, 'third_party', 'components.json')
        const manifest = JSON.parse(readFileSync(path, 'utf8'))
        manifest.components.find(({ name }) => name === 'libgcc').targets = 'all'
        writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`)
      },
      /libgcc has the wrong target group/u,
    ],
  ]) {
    const root = makeFixtureRoot(join(directory, name))
    const output = join(directory, `${name}-out`)
    mutate(root)
    assert.throws(
      () =>
        stageTargetLegalPayload({
          root,
          destination: output,
          targetName: 'darwin-arm64',
        }),
      expected,
    )
    assert.throws(() => readdirSync(output), /ENOENT/u)
  }
})

test('native archive packaging stages the target legal payload', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'awskms-native-archive.'))
  t.after(() => rmSync(directory, { force: true, recursive: true }))
  const build = join(directory, 'build')
  const output = join(directory, 'output')
  mkdirSync(build)
  mkdirSync(output)
  writeFileSync(join(build, 'aws-kms.dylib'), 'darwin fixture\n')
  writeFileSync(join(build, 'aws-kms.so'), 'linux fixture\n')
  writeFileSync(join(build, 'awskms.relocatable.cnf'), 'relocatable config\n')
  writeFileSync(join(build, 'awskms-backend'), 'aws\n')
  const components = JSON.parse(
    readFileSync(join(repository, 'third_party', 'components.json'), 'utf8'),
  )
  writeFileSync(join(build, 'awskms-dependencies'), `aws-sdk-cpp=${components.awsSdkTag}\n`)
  const version = JSON.parse(
    readFileSync(join(repository, 'npm', 'core', 'package.json'), 'utf8'),
  ).version

  for (const targetName of ['darwin-arm64', 'linux-x64']) {
    execFileSync(
      join(repository, 'scripts', 'package-archive.sh'),
      [build, targetName, output],
      { cwd: repository },
    )
  }

  const darwin = join(output, `awskms-${version}-darwin-arm64.tar.gz`)
  const linux = join(output, `awskms-${version}-linux-x64.tar.gz`)
  const darwinEntries = tarEntries(darwin)
  const linuxEntries = tarEntries(linux)
  assert.ok(!darwinEntries.some((entry) => /GPL-3\.0|GCC-RUNTIME/u.test(entry)))
  assert.ok(linuxEntries.some((entry) => entry.endsWith('/GPL-3.0.txt')))
  assert.ok(
    linuxEntries.some((entry) =>
      entry.endsWith('/GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt'),
    ),
  )
  const darwinComponents = JSON.parse(
    tarEntry(
      darwin,
      `awskms-${version}-darwin-arm64/third_party/components.json`,
    ),
  )
  const linuxComponents = JSON.parse(
    tarEntry(linux, `awskms-${version}-linux-x64/third_party/components.json`),
  )
  assert.ok(darwinComponents.components.every(({ targets }) => targets !== 'linux'))
  assert.ok(linuxComponents.components.every(({ targets }) => targets !== 'darwin'))
})

test('shell release verification accepts the generated five-archive payload', (t) => {
  const fixture = makeReleaseFixture()
  t.after(() => rmSync(fixture.directory, { force: true, recursive: true }))
  execFileSync(
    join(repository, 'scripts', 'ci-verify-release.sh'),
    [fixture.artifacts, fixtureVersion],
    { cwd: repository },
  )
})

test('release assembly emits the exact twelve-file payload from unchanged archives', (t) => {
  const fixture = makeReleaseFixture()
  t.after(() => rmSync(fixture.directory, { force: true, recursive: true }))
  const originalArchives = new Map(
    readdirSync(fixture.artifacts).map((name) => [
      name,
      readFileSync(join(fixture.artifacts, name)),
    ]),
  )

  const result = assembleRelease({
    root: fixture.root,
    artifactsDirectory: fixture.artifacts,
    outputDirectory: fixture.output,
    version: fixtureVersion,
    runPolicy: false,
  })

  assert.equal(result.files.length, 12)
  assert.deepEqual(readdirSync(fixture.output).sort(), result.files)
  for (const [name, bytes] of originalArchives) {
    assert.deepEqual(readFileSync(join(fixture.output, name)), bytes)
  }
  const checksumNames = readFileSync(join(fixture.output, 'SHA256SUMS'), 'utf8')
    .trimEnd()
    .split('\n')
    .map((line) => line.slice(66))
  assert.deepEqual(checksumNames, [...checksumNames].sort())
  assert.equal(checksumNames.length, 11)

  for (const target of targets) {
    const satellite = join(
      fixture.output,
      `keyobject-aws-kms-${target.name}-${fixtureVersion}.tgz`,
    )
    const archive = join(
      fixture.artifacts,
      `awskms-${fixtureVersion}-${target.name}.tar.gz`,
    )
    const top = `awskms-${fixtureVersion}-${target.name}`
    assert.deepEqual(
      tarEntry(satellite, `package/${target.module}`),
      tarEntry(archive, `${top}/${target.module}`),
    )
    assert.deepEqual(
      tarEntry(satellite, 'package/awskms.cnf'),
      tarEntry(archive, `${top}/awskms.cnf`),
    )
    const manifest = JSON.parse(tarEntry(satellite, 'package/package.json'))
    assert.equal(manifest.name, `@keyobject/aws-kms-${target.name}`)
    assert.equal(manifest.version, fixtureVersion)

    const sourceComponents = JSON.parse(
      readFileSync(join(fixture.root, 'third_party', 'components.json'), 'utf8'),
    )
    const expectedComponents = sourceComponents.components.filter(
      (component) => component.targets === 'all' || component.targets === target.os,
    )
    const archiveComponents = JSON.parse(
      tarEntry(archive, `${top}/third_party/components.json`),
    )
    const satelliteComponents = JSON.parse(
      tarEntry(satellite, 'package/third_party/components.json'),
    )
    assert.deepEqual(archiveComponents, {
      ...sourceComponents,
      components: expectedComponents,
    })
    assert.deepEqual(satelliteComponents, archiveComponents)

    const expectedLegalNames = referencedLegalFiles(expectedComponents)
    const archiveLegalNames = tarEntries(archive)
      .filter(
        (entry) =>
          entry.startsWith(`${top}/third_party/licenses/`) && !entry.endsWith('/'),
      )
      .map((entry) => basename(entry))
      .sort()
    const satelliteLegalNames = tarEntries(satellite)
      .filter(
        (entry) =>
          entry.startsWith('package/third_party/licenses/') && !entry.endsWith('/'),
      )
      .map((entry) => basename(entry))
      .sort()
    assert.deepEqual(archiveLegalNames, expectedLegalNames)
    assert.deepEqual(satelliteLegalNames, expectedLegalNames)
    for (const name of [
      'cJSON-MIT.txt',
      'libcbor-MIT.txt',
      'tinyxml2-zlib.txt',
      'xxHash-BSD-2-Clause.txt',
    ]) {
      assert.ok(expectedLegalNames.includes(name), `${target.name} is missing ${name}`)
    }

    if (target.os === 'darwin') {
      assert.ok(expectedLegalNames.includes('APSL-2.0.txt'))
      assert.ok(expectedLegalNames.includes('Apple-CommonCrypto-SPI-NOTICE.txt'))
      assert.ok(!expectedLegalNames.includes('GPL-3.0.txt'))
      assert.ok(!expectedLegalNames.includes('GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt'))
      assert.ok(archiveComponents.components.every(({ targets }) => targets !== 'linux'))
    } else {
      assert.ok(expectedLegalNames.includes('GPL-3.0.txt'))
      assert.ok(expectedLegalNames.includes('GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt'))
      assert.ok(!expectedLegalNames.includes('APSL-2.0.txt'))
      assert.ok(!expectedLegalNames.includes('Apple-CommonCrypto-SPI-NOTICE.txt'))
      assert.ok(archiveComponents.components.every(({ targets }) => targets !== 'darwin'))
    }
  }
})

for (const [description, mutate, expected] of [
  [
    'missing archive',
    (fixture) => rmSync(join(fixture.artifacts, `awskms-${fixtureVersion}-linux-x64.tar.gz`)),
    /missing, duplicate, or unexpected files/u,
  ],
  [
    'unexpected input',
    (fixture) => writeFileSync(join(fixture.artifacts, 'sentinel'), 'do not publish\n'),
    /missing, duplicate, or unexpected files/u,
  ],
  [
    'duplicate archive entry',
    (fixture) => replaceArchive(fixture, 'linux-x64', { duplicateLicense: true }),
    /unexpected or duplicate file inventory/u,
  ],
  [
    'wrong architecture',
    (fixture) =>
      replaceArchive(fixture, 'linux-x64', {
        overrides: {
          module: moduleFor(
            targets.find(({ name }) => name === 'linux-arm64'),
            fixtureVersion,
          ),
        },
      }),
    /wrong ELF architecture/u,
  ],
  [
    'wrong libc target',
    (fixture) =>
      replaceArchive(fixture, 'linuxmusl-x64', {
        overrides: {
          module: moduleFor(
            targets.find(({ name }) => name === 'linux-x64'),
            fixtureVersion,
          ),
        },
      }),
    /does not match its libc target/u,
  ],
  [
    'stub backend',
    (fixture) =>
      replaceArchive(fixture, 'linux-x64', {
        overrides: {
          module: moduleFor(
            targets.find(({ name }) => name === 'linux-x64'),
            fixtureVersion,
            'stub',
          ),
        },
      }),
    /is not the 1\.2\.3 AWS backend/u,
  ],
  [
    'altered project license',
    (fixture) =>
      replaceArchive(fixture, 'linux-x64', {
        overrides: { files: { LICENSE: 'foreign license\n' } },
      }),
    /LICENSE differs from the authoritative source/u,
  ],
  [
    'missing target license',
    (fixture) =>
      replaceArchive(fixture, 'darwin-arm64', {
        overrides: { removeFiles: ['third_party/licenses/Apache-2.0.txt'] },
      }),
    /unexpected or duplicate file inventory/u,
  ],
  [
    'unexpected target license',
    (fixture) =>
      replaceArchive(fixture, 'darwin-arm64', {
        overrides: {
          files: {
            'third_party/licenses/GPL-3.0.txt': readFileSync(
              join(fixture.root, 'third_party', 'licenses', 'GPL-3.0.txt'),
            ),
          },
        },
      }),
    /unexpected or duplicate file inventory/u,
  ],
  [
    'altered target license',
    (fixture) =>
      replaceArchive(fixture, 'linux-x64', {
        overrides: { files: { 'third_party/licenses/Apache-2.0.txt': 'foreign text\n' } },
      }),
    /Apache-2\.0\.txt differs from the authoritative source/u,
  ],
  [
    'altered component graph',
    (fixture) =>
      replaceArchive(fixture, 'linux-x64', {
        overrides: {
          files: {
            'third_party/components.json': '{"schemaVersion":1,"components":[]}',
          },
        },
      }),
    /components\.json differs from the authoritative source/u,
  ],
]) {
  test(`release assembly rejects ${description} before creating output`, (t) => {
    const fixture = makeReleaseFixture()
    t.after(() => rmSync(fixture.directory, { force: true, recursive: true }))
    mutate(fixture)
    assert.throws(
      () =>
        assembleRelease({
          root: fixture.root,
          artifactsDirectory: fixture.artifacts,
          outputDirectory: fixture.output,
          version: fixtureVersion,
          runPolicy: false,
        }),
      expected,
    )
    assert.throws(() => readdirSync(fixture.output), /ENOENT/u)
  })
}

test('release assembly rejects package version skew and the placeholder version', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'awskms-release-version.'))
  t.after(() => rmSync(directory, { force: true, recursive: true }))
  const root = makeFixtureRoot(directory, '1.2.4')
  const artifacts = join(directory, 'artifacts')
  mkdirSync(artifacts)
  assert.throws(
    () =>
      assembleRelease({
        root,
        artifactsDirectory: artifacts,
        outputDirectory: join(directory, 'out'),
        version: fixtureVersion,
        runPolicy: false,
      }),
    /core package version 1\.2\.4 does not match 1\.2\.3/u,
  )

  const placeholderRoot = makeFixtureRoot(join(directory, 'placeholder'), '0.0.0')
  assert.throws(
    () =>
      assembleRelease({
        root: placeholderRoot,
        artifactsDirectory: artifacts,
        outputDirectory: join(directory, 'placeholder-out'),
        version: '0.0.0',
        runPolicy: false,
      }),
    /refusing placeholder version/u,
  )
})

test('release assembly rejects nested input and output paths', (t) => {
  const fixture = makeReleaseFixture()
  t.after(() => rmSync(fixture.directory, { force: true, recursive: true }))
  assert.throws(
    () =>
      assembleRelease({
        root: fixture.root,
        artifactsDirectory: fixture.artifacts,
        outputDirectory: join(fixture.artifacts, 'dist'),
        version: fixtureVersion,
        runPolicy: false,
      }),
    /must not contain one another/u,
  )
  assert.throws(
    () =>
      assembleRelease({
        root: fixture.root,
        artifactsDirectory: fixture.artifacts,
        outputDirectory: fixture.directory,
        version: fixtureVersion,
        runPolicy: false,
      }),
    /must not contain one another/u,
  )
})

test('satellite rendering replaces only template tokens and preserves scoped metadata', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'awskms-template-pack.'))
  t.after(() => rmSync(directory, { force: true, recursive: true }))
  const root = makeFixtureRoot(directory, '0.0.0')
  const build = join(directory, 'build')
  const output = join(directory, 'output')
  const target = targets[0]
  mkdirSync(build)
  writeFileSync(join(build, target.module), moduleFor(target, '0.0.0'))
  writeFileSync(join(build, 'awskms.relocatable.cnf'), 'relocatable config\n')
  writeFileSync(join(build, 'awskms-backend'), 'aws\n')
  const components = JSON.parse(
    readFileSync(join(root, 'third_party', 'components.json'), 'utf8'),
  )
  writeFileSync(join(build, 'awskms-dependencies'), `aws-sdk-cpp=${components.awsSdkTag}\n`)

  packBuildPackages({
    root,
    buildDirectory: build,
    outputDirectory: output,
    targetName: target.name,
  })
  const text = readFileSync(join(output, 'platform', 'package.json'), 'utf8')
  assert.match(text, /"name": "@keyobject\/aws-kms-darwin-arm64"/u)
  assert.match(text, /panva\.ip@gmail\.com/u)
  assert.doesNotMatch(text, /@(TARGET|VERSION|OS|CPU|MODULE|LIBC)@/u)
})

test('release assembly refuses status-note publication and never clobbers output', (t) => {
  const fixture = makeReleaseFixture()
  t.after(() => rmSync(fixture.directory, { force: true, recursive: true }))
  const marker = `> [!NOTE]\n> **${['Work', 'in progress.'].join(' ')}**\n`
  writeFileSync(join(fixture.root, 'README.md'), marker)
  assert.throws(
    () =>
      assembleRelease({
        root: fixture.root,
        artifactsDirectory: fixture.artifacts,
        outputDirectory: fixture.output,
        version: fixtureVersion,
        runPolicy: false,
      }),
    /README status notice/u,
  )

  writeFileSync(join(fixture.root, 'README.md'), '# fixture\n')
  mkdirSync(fixture.output)
  writeFileSync(join(fixture.output, 'sentinel'), 'keep me\n')
  assert.throws(
    () =>
      assembleRelease({
        root: fixture.root,
        artifactsDirectory: fixture.artifacts,
        outputDirectory: fixture.output,
        version: fixtureVersion,
        runPolicy: false,
      }),
    /must be empty/u,
  )
  assert.equal(readFileSync(join(fixture.output, 'sentinel'), 'utf8'), 'keep me\n')
})
