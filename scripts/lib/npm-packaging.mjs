import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  rmdirSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'

const MAX_ARCHIVE_ENTRY = 512 * 1024 * 1024
const STABLE_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u

export const targets = Object.freeze([
  Object.freeze({
    name: 'darwin-arm64',
    os: 'darwin',
    cpu: 'arm64',
    module: 'aws-kms.dylib',
    minimumMacos: '13.5',
  }),
  Object.freeze({
    name: 'linux-arm64',
    os: 'linux',
    cpu: 'arm64',
    libc: 'glibc',
    module: 'aws-kms.so',
  }),
  Object.freeze({
    name: 'linux-x64',
    os: 'linux',
    cpu: 'x64',
    libc: 'glibc',
    module: 'aws-kms.so',
  }),
  Object.freeze({
    name: 'linuxmusl-arm64',
    os: 'linux',
    cpu: 'arm64',
    libc: 'musl',
    module: 'aws-kms.so',
  }),
  Object.freeze({
    name: 'linuxmusl-x64',
    os: 'linux',
    cpu: 'x64',
    libc: 'musl',
    module: 'aws-kms.so',
  }),
])

const targetByName = new Map(targets.map((target) => [target.name, target]))
const satelliteNames = targets.map(({ name }) => `@keyobject/aws-kms-${name}`).sort()
const componentNames = [
  'ada',
  'aws-cpp-sdk-core',
  'aws-cpp-sdk-kms',
  'aws-sdk-cpp-third-party',
  'aws-crt-cpp',
  'aws-c-auth',
  'aws-c-cal',
  'aws-c-common',
  'aws-c-compression',
  'aws-c-event-stream',
  'aws-c-http',
  'aws-c-io',
  'aws-c-mqtt',
  'aws-c-s3',
  'aws-c-sdkutils',
  'aws-checksums',
  's2n-tls',
  'libstdc++',
  'libgcc',
].sort()

const coreInventory = [
  'package/LICENSE',
  'package/README.md',
  'package/bin/awskms.js',
  'package/check.mjs',
  'package/index.d.ts',
  'package/index.js',
  'package/package.json',
  'package/register.d.ts',
  'package/register.js',
].sort()

function invariant(condition, message) {
  if (!condition) throw new Error(message)
}

function sorted(values) {
  return [...values].sort()
}

function sameStrings(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected)
}

function readRegularFile(path, label = path) {
  let stat
  try {
    stat = lstatSync(path)
  } catch {
    throw new Error(`${label} is missing`)
  }
  invariant(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular file`)
  return readFileSync(path)
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'))
  } catch (cause) {
    throw new Error(`${label} is not valid JSON`, { cause })
  }
}

function assertExactBytes(actual, expected, label) {
  invariant(actual.equals(expected), `${label} differs from the authoritative source`)
}

function validateStableVersion(version, { release = false } = {}) {
  invariant(STABLE_VERSION.test(version), `version must be stable numeric semver, got ${version}`)
  if (release) invariant(version !== '0.0.0', 'refusing placeholder version 0.0.0')
}

export function getTarget(name) {
  const target = targetByName.get(name)
  invariant(target, `unsupported npm target: ${name}`)
  return target
}

function validateCoreManifest(root, requestedVersion, { release = false } = {}) {
  const path = join(root, 'npm', 'core', 'package.json')
  const manifest = parseJson(readRegularFile(path), 'npm/core/package.json')
  const version = requestedVersion ?? manifest.version
  validateStableVersion(version, { release })
  invariant(manifest.version === version, `core package version ${manifest.version} does not match ${version}`)

  const keywords = [
    'aws',
    'aws-kms',
    'crypto',
    'cryptography',
    'ecdsa',
    'ed25519',
    'fips',
    'keyobject',
    'kms',
    'ml-dsa',
    'node',
    'nodejs',
    'openssl',
    'openssl-provider',
    'rsa',
    'sign',
    'signature',
    'webcrypto',
  ]
  invariant(
    manifest.description === 'AWS KMS asymmetric signing keys as Node.js KeyObject instances' &&
      manifest.homepage === 'https://github.com/panva/keyobject-aws-kms' &&
      manifest.repository?.directory === 'npm/core' &&
      manifest.funding?.url === 'https://github.com/sponsors/panva' &&
      manifest.author === 'Filip Skokan <panva.ip@gmail.com>' &&
      manifest.main === './index.js' &&
      sameStrings(manifest.sideEffects, ['./register.js']) &&
      sameStrings(manifest.keywords, keywords),
    'core public metadata differs from the project convention',
  )
  invariant(
    sameStrings(manifest.engines, { node: '>=26.7.0' }),
    'npm/core/package.json must require exactly Node.js >=26.7.0',
  )
  invariant(
    sameStrings(sorted(Object.keys(manifest.optionalDependencies ?? {})), satelliteNames),
    'the optional platform package set is incomplete or unexpected',
  )
  for (const name of satelliteNames) {
    invariant(
      manifest.optionalDependencies[name] === version,
      `${name} must be pinned exactly to core ${version}`,
    )
  }
  invariant(
    manifest.publishConfig?.access === 'public',
    'the scoped core package must publish as public',
  )
  return manifest
}

function validateLegalSource(root) {
  const licenseDirectory = join(root, 'third_party', 'licenses')
  const licenseEntries = readdirSync(licenseDirectory, { withFileTypes: true })
  invariant(
    licenseEntries.every((entry) => entry.isFile() && !entry.isSymbolicLink()),
    'third_party/licenses must contain only regular files',
  )
  const licenseNames = sorted(licenseEntries.map(({ name }) => name))
  const componentsBytes = readRegularFile(join(root, 'third_party', 'components.json'))
  const components = parseJson(componentsBytes, 'third_party/components.json')
  invariant(components.schemaVersion === 1, 'unsupported component manifest schema')
  invariant(
    typeof components.awsSdkTag === 'string' && components.awsSdkTag.length > 0,
    'component manifest has no AWS SDK tag',
  )
  invariant(Array.isArray(components.components), 'component manifest has no component list')

  const actualComponentNames = components.components.map(({ name }) => name)
  invariant(
    actualComponentNames.every((name) => typeof name === 'string' && name.length > 0) &&
      new Set(actualComponentNames).size === actualComponentNames.length,
    'component names must be nonempty and unique',
  )
  invariant(
    sameStrings(sorted(actualComponentNames), componentNames),
    'component dependency graph is incomplete or unexpected',
  )
  for (const component of components.components) {
    if (component.commit != null) {
      invariant(
        typeof component.commit === 'string' && /^[0-9a-f]{40}$/u.test(component.commit),
        `${component.name} commit is not an exact Git object id`,
      )
    }
  }
  for (const name of [
    'aws-cpp-sdk-core',
    'aws-cpp-sdk-kms',
    'aws-sdk-cpp-third-party',
  ]) {
    const component = components.components.find((entry) => entry.name === name)
    invariant(component?.version === components.awsSdkTag, `${name} version does not match awsSdkTag`)
  }

  const referenced = new Set()
  for (const component of components.components) {
    for (const field of ['license', 'exception', 'notice']) {
      const file = component[field]
      if (file == null) continue
      invariant(
        typeof file === 'string' && basename(file) === file,
        `${component.name} ${field} must be a filename`,
      )
      referenced.add(file)
    }
  }
  invariant(
    sameStrings(sorted(referenced), licenseNames),
    'component dependency graph and license inventory differ',
  )

  const files = new Map([
    ['LICENSE', readRegularFile(join(root, 'LICENSE'))],
    ['THIRD_PARTY_NOTICES.md', readRegularFile(join(root, 'THIRD_PARTY_NOTICES.md'))],
    ['third_party/components.json', componentsBytes],
  ])
  for (const name of licenseNames) {
    files.set(
      `third_party/licenses/${name}`,
      readRegularFile(join(licenseDirectory, name), `third_party/licenses/${name}`),
    )
  }
  return { components, files, licenseNames }
}

function replaceToken(text, token, replacement, label) {
  invariant(text.includes(token), `${label} has no ${token} token`)
  return text.replaceAll(token, replacement)
}

function renderSatellite(root, target, version) {
  let packageText = readRegularFile(join(root, 'npm', 'platform', 'package.json.in')).toString('utf8')
  packageText = replaceToken(packageText, '@TARGET@', target.name, 'platform manifest template')
  packageText = replaceToken(packageText, '@VERSION@', version, 'platform manifest template')
  packageText = replaceToken(packageText, '@OS@', target.os, 'platform manifest template')
  packageText = replaceToken(packageText, '@CPU@', target.cpu, 'platform manifest template')
  packageText = replaceToken(packageText, '@MODULE@', target.module, 'platform manifest template')
  if (target.libc) {
    packageText = replaceToken(
      packageText,
      '@LIBC@',
      JSON.stringify([target.libc]),
      'platform manifest template',
    )
  } else {
    const lines = packageText.split('\n')
    const index = lines.findIndex((line) => line.includes('"libc": @LIBC@,'))
    invariant(index !== -1, 'platform manifest template has no removable libc field')
    lines.splice(index, 1)
    packageText = lines.join('\n')
  }
  invariant(
    !/@(?:TARGET|VERSION|OS|CPU|MODULE|LIBC)@/u.test(packageText),
    'platform manifest contains an unrendered token',
  )

  let readme = readRegularFile(join(root, 'npm', 'platform', 'README.md.in')).toString('utf8')
  readme = replaceToken(readme, '@TARGET@', target.name, 'platform README template')
  invariant(!readme.includes('@TARGET@'), 'platform README contains an unrendered target')

  const manifest = parseJson(Buffer.from(packageText), 'generated satellite package.json')
  validateSatelliteManifest(manifest, readme, target, version)
  return { manifest, packageText, readme }
}

function validateSatelliteManifest(manifest, readme, target, version) {
  const name = `@keyobject/aws-kms-${target.name}`
  invariant(manifest.name === name && manifest.version === version, 'generated satellite name/version mismatch')
  invariant(
    manifest.description === `Prebuilt OpenSSL provider for @keyobject/aws-kms on ${target.name}` &&
      manifest.homepage === 'https://github.com/panva/keyobject-aws-kms' &&
      manifest.repository?.directory === 'npm/platform' &&
      manifest.funding?.url === 'https://github.com/sponsors/panva' &&
      manifest.author === 'Filip Skokan <panva.ip@gmail.com>',
    'satellite public metadata differs from the project convention',
  )
  invariant(
    readme.startsWith(`# @keyobject/aws-kms-${target.name}\n`) && !readme.includes('@TARGET@'),
    'satellite README was not rendered for its target',
  )
  const exact = (value, expected) =>
    Array.isArray(value) && value.length === 1 && value[0] === expected
  invariant(exact(manifest.os, target.os), 'generated satellite os mismatch')
  invariant(exact(manifest.cpu, target.cpu), 'generated satellite cpu mismatch')
  invariant(
    target.libc ? exact(manifest.libc, target.libc) : !('libc' in manifest),
    'generated satellite libc mismatch',
  )
  invariant(
    sameStrings(manifest.engines, { node: '>=26.7.0' }),
    'satellite must require exactly Node.js >=26.7.0',
  )
  invariant(manifest.publishConfig?.access === 'public', 'satellite must publish as public')
}

function writeTreeFile(root, relativePath, bytes) {
  const path = join(root, ...relativePath.split('/'))
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, bytes)
}

function stageSatellite({ root, destination, target, version, source, legal }) {
  invariant(!existsSync(destination), `refusing to reuse satellite stage: ${destination}`)
  mkdirSync(destination, { recursive: true })
  const rendered = renderSatellite(root, target, version)
  writeTreeFile(destination, 'package.json', `${JSON.stringify(rendered.manifest, null, 2)}\n`)
  writeTreeFile(destination, 'README.md', rendered.readme)
  writeTreeFile(destination, target.module, source.module)
  writeTreeFile(destination, 'awskms.cnf', source.config)
  for (const [path, bytes] of legal.files) writeTreeFile(destination, path, bytes)

  for (const [path, expected] of legal.files) {
    assertExactBytes(readRegularFile(join(destination, ...path.split('/'))), expected, `staged ${path}`)
  }
  return rendered.manifest
}

function stageCore({ root, destination }) {
  invariant(!existsSync(destination), `refusing to reuse core stage: ${destination}`)
  mkdirSync(join(destination, 'bin'), { recursive: true })
  const files = [
    ['npm/core/package.json', 'package.json'],
    ['npm/core/index.js', 'index.js'],
    ['npm/core/register.js', 'register.js'],
    ['npm/core/index.d.ts', 'index.d.ts'],
    ['npm/core/register.d.ts', 'register.d.ts'],
    ['npm/core/bin/awskms.js', 'bin/awskms.js'],
    ['scripts/check.mjs', 'check.mjs'],
    ['README.md', 'README.md'],
    ['LICENSE', 'LICENSE'],
  ]
  for (const [source, output] of files) {
    writeTreeFile(destination, output, readRegularFile(join(root, ...source.split('/')), source))
  }
}

function tarListing(archive) {
  const stdout = execFileSync('tar', ['-tzf', archive], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  })
  return stdout.endsWith('\n') ? stdout.slice(0, -1).split('\n') : stdout.split('\n')
}

function tarTypes(archive) {
  const stdout = execFileSync('tar', ['-tvzf', archive], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  })
  const lines = stdout.trimEnd().split('\n')
  return lines.map((line) => line[0])
}

function readTarEntry(archive, path) {
  return execFileSync('tar', ['-xOzf', archive, path], {
    encoding: 'buffer',
    maxBuffer: MAX_ARCHIVE_ENTRY,
  })
}

function assertTarInventory(archive, expected, label) {
  const listing = tarListing(archive)
  invariant(
    sameStrings(sorted(listing), sorted(expected)),
    `${label} has an unexpected or duplicate file inventory`,
  )
  const expectedTypes = new Map(expected.map((path) => [path, path.endsWith('/') ? 'd' : '-']))
  const types = tarTypes(archive)
  invariant(types.length === listing.length, `${label} type inventory is incomplete`)
  for (let index = 0; index < listing.length; index += 1) {
    invariant(
      types[index] === expectedTypes.get(listing[index]),
      `${label} contains a non-regular or incorrectly typed entry: ${listing[index]}`,
    )
  }
}

function satelliteInventory(target, licenseNames) {
  return [
    'package/LICENSE',
    'package/README.md',
    'package/THIRD_PARTY_NOTICES.md',
    `package/${target.module}`,
    'package/awskms.cnf',
    'package/package.json',
    'package/third_party/components.json',
    ...licenseNames.map((name) => `package/third_party/licenses/${name}`),
  ].sort()
}

function npmTarballName(name, version) {
  return `${name.replace(/^@/u, '').replace('/', '-')}-${version}.tgz`
}

function packStagedPackage({ destination, expectedName, version, inventory, cacheDirectory }) {
  mkdirSync(cacheDirectory, { recursive: true })
  const npmrc = join(cacheDirectory, 'empty.npmrc')
  writeFileSync(npmrc, '')
  const expectedFilename = npmTarballName(expectedName, version)
  execFileSync(
    'npm',
    ['pack', '--silent', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'],
    {
      cwd: destination,
      env: {
        ...process.env,
        npm_config_cache: cacheDirectory,
        npm_config_userconfig: npmrc,
        npm_config_registry: 'http://127.0.0.1:9',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )
  const tarballs = readdirSync(destination).filter((entry) => entry.endsWith('.tgz'))
  invariant(
    sameStrings(tarballs, [expectedFilename]),
    `npm pack produced an unexpected tarball for ${expectedName}`,
  )
  const tarball = join(destination, expectedFilename)
  assertTarInventory(tarball, inventory, `${expectedName} tarball`)
  const packedManifest = parseJson(
    readTarEntry(tarball, 'package/package.json'),
    `${expectedName} packed manifest`,
  )
  invariant(
    packedManifest.name === expectedName && packedManifest.version === version,
    `${expectedName} packed name/version mismatch`,
  )
  return tarball
}

function readUInt32Version(value) {
  const major = value >>> 16
  const minor = (value >>> 8) & 0xff
  const patch = value & 0xff
  return patch === 0 ? `${major}.${minor}` : `${major}.${minor}.${patch}`
}

function machMinimumVersion(module) {
  invariant(module.length >= 32, 'Mach-O module header is truncated')
  invariant(module.readUInt32LE(0) === 0xfeedfacf, 'module is not a thin 64-bit Mach-O image')
  const commands = module.readUInt32LE(16)
  const commandsSize = module.readUInt32LE(20)
  invariant(32 + commandsSize <= module.length, 'Mach-O load commands are truncated')
  let offset = 32
  for (let index = 0; index < commands; index += 1) {
    invariant(offset + 8 <= module.length, 'Mach-O load command is truncated')
    const command = module.readUInt32LE(offset)
    const size = module.readUInt32LE(offset + 4)
    invariant(size >= 8 && offset + size <= module.length, 'Mach-O load command size is invalid')
    if (command === 0x32) {
      invariant(size >= 24, 'Mach-O LC_BUILD_VERSION is truncated')
      return readUInt32Version(module.readUInt32LE(offset + 12))
    }
    if (command === 0x24) {
      invariant(size >= 16, 'Mach-O LC_VERSION_MIN_MACOSX is truncated')
      return readUInt32Version(module.readUInt32LE(offset + 8))
    }
    offset += size
  }
  throw new Error('Mach-O module has no minimum macOS version')
}

function assertModuleTarget(module, target, version) {
  const buildInformation = Buffer.from(`\0${version} backend=aws\0`)
  invariant(
    module.includes(buildInformation),
    `${target.name} module is not the ${version} AWS backend`,
  )
  invariant(
    !module.includes(Buffer.from(`${version} backend=stub`)),
    `${target.name} module contains the stub backend`,
  )

  if (target.os === 'darwin') {
    invariant(module.length >= 12, `${target.name} module is truncated`)
    invariant(module.readUInt32LE(4) === 0x0100000c, `${target.name} module is not arm64 Mach-O`)
    invariant(
      machMinimumVersion(module) === target.minimumMacos,
      `${target.name} module does not target macOS ${target.minimumMacos}`,
    )
    return
  }

  invariant(
    module.length >= 20 &&
      module[0] === 0x7f &&
      module.subarray(1, 4).equals(Buffer.from('ELF')) &&
      module[4] === 2 &&
      module[5] === 1,
    `${target.name} module is not a little-endian 64-bit ELF image`,
  )
  const expectedMachine = target.cpu === 'x64' ? 62 : 183
  invariant(
    module.readUInt16LE(18) === expectedMachine,
    `${target.name} module has the wrong ELF architecture`,
  )
  const hasGlibcVersions = /GLIBC_(?:\d|PRIVATE)/u.test(module.toString('latin1'))
  invariant(
    target.libc === 'glibc' ? hasGlibcVersions : !hasGlibcVersions,
    `${target.name} module does not match its libc target`,
  )
}

function validateBuildSource({ buildDirectory, target, version, legal }) {
  const backend = readRegularFile(join(buildDirectory, 'awskms-backend'), 'awskms-backend')
  invariant(backend.equals(Buffer.from('aws\n')), 'distributed npm packages require AWSKMS_BACKEND=aws')
  const dependencies = readRegularFile(
    join(buildDirectory, 'awskms-dependencies'),
    'awskms-dependencies',
  )
  invariant(
    dependencies.equals(Buffer.from(`aws-sdk-cpp=${legal.components.awsSdkTag}\n`)),
    'AWS SDK dependency graph is not covered by third_party/components.json',
  )
  const module = readRegularFile(join(buildDirectory, target.module), target.module)
  const config = readRegularFile(
    join(buildDirectory, 'awskms.relocatable.cnf'),
    'awskms.relocatable.cnf',
  )
  assertModuleTarget(module, target, version)
  return { module, config }
}

export function packBuildPackages({ root, buildDirectory, targetName, outputDirectory }) {
  root = resolve(root)
  buildDirectory = resolve(buildDirectory)
  outputDirectory = resolve(outputDirectory)
  const target = getTarget(targetName)
  const manifest = validateCoreManifest(root)
  const legal = validateLegalSource(root)
  const source = validateBuildSource({
    buildDirectory,
    target,
    version: manifest.version,
    legal,
  })

  mkdirSync(outputDirectory, { recursive: true })
  const cacheDirectory = join(outputDirectory, 'npm-cache')
  const satelliteDirectory = join(outputDirectory, 'platform')
  const coreDirectory = join(outputDirectory, 'core')
  stageSatellite({
    root,
    destination: satelliteDirectory,
    target,
    version: manifest.version,
    source,
    legal,
  })
  const satelliteTarball = packStagedPackage({
    destination: satelliteDirectory,
    expectedName: `@keyobject/aws-kms-${target.name}`,
    version: manifest.version,
    inventory: satelliteInventory(target, legal.licenseNames),
    cacheDirectory,
  })

  stageCore({ root, destination: coreDirectory })
  const coreTarball = packStagedPackage({
    destination: coreDirectory,
    expectedName: '@keyobject/aws-kms',
    version: manifest.version,
    inventory: coreInventory,
    cacheDirectory,
  })
  assertExactBytes(
    readTarEntry(coreTarball, 'package/README.md'),
    readRegularFile(join(root, 'README.md')),
    'packed core README',
  )
  assertExactBytes(
    readTarEntry(satelliteTarball, `package/${target.module}`),
    source.module,
    'packed satellite module',
  )
  assertExactBytes(
    readTarEntry(satelliteTarball, 'package/awskms.cnf'),
    source.config,
    'packed satellite config',
  )
  return { coreTarball, satelliteTarball, target, version: manifest.version }
}

function archiveInventory(version, target, legal) {
  const name = `awskms-${version}-${target.name}`
  return [
    `${name}/`,
    `${name}/LICENSE`,
    `${name}/THIRD_PARTY_NOTICES.md`,
    `${name}/${target.module}`,
    `${name}/awskms.cnf`,
    `${name}/check.mjs`,
    `${name}/docs/`,
    `${name}/docs/INSTALL.md`,
    `${name}/third_party/`,
    `${name}/third_party/components.json`,
    `${name}/third_party/licenses/`,
    ...legal.licenseNames.map((license) => `${name}/third_party/licenses/${license}`),
  ].sort()
}

function assertDirectoryContainsExactly(directory, expected, label) {
  let stat
  let entries
  try {
    stat = lstatSync(directory)
    entries = readdirSync(directory, { withFileTypes: true })
  } catch {
    throw new Error(`${label} is missing or unreadable`)
  }
  invariant(stat.isDirectory() && !stat.isSymbolicLink(), `${label} must be a real directory`)
  invariant(
    entries.every((entry) => entry.isFile() && !entry.isSymbolicLink()),
    `${label} must contain only regular files`,
  )
  invariant(
    sameStrings(sorted(entries.map(({ name }) => name)), sorted(expected)),
    `${label} has missing, duplicate, or unexpected files`,
  )
}

function runArchivePolicy(root, archive) {
  execFileSync(join(root, 'scripts', 'ci-policy-gate.sh'), ['archive', archive], {
    cwd: root,
    stdio: ['ignore', 'ignore', 'pipe'],
  })
}

export function verifyReleaseArchives({
  root,
  artifactsDirectory,
  version,
  runPolicy = true,
}) {
  root = resolve(root)
  artifactsDirectory = resolve(artifactsDirectory)
  const manifest = validateCoreManifest(root, version, { release: true })
  const readme = readRegularFile(join(root, 'README.md')).toString('utf8')
  const incompleteNotice = `**${['Work', 'in progress.'].join(' ')}**`
  invariant(
    !readme.includes(incompleteNotice),
    'refusing release while the README status notice remains',
  )
  const legal = validateLegalSource(root)
  const expectedNames = targets.map(
    ({ name }) => `awskms-${version}-${name}.tar.gz`,
  )
  assertDirectoryContainsExactly(artifactsDirectory, expectedNames, 'release artifact directory')

  const projectFiles = new Map([
    ['LICENSE', readRegularFile(join(root, 'LICENSE'))],
    ['THIRD_PARTY_NOTICES.md', readRegularFile(join(root, 'THIRD_PARTY_NOTICES.md'))],
    ['check.mjs', readRegularFile(join(root, 'scripts', 'check.mjs'))],
    ['docs/INSTALL.md', readRegularFile(join(root, 'docs', 'INSTALL.md'))],
    ...legal.files,
  ])
  const archives = []
  for (const target of targets) {
    const archiveName = `awskms-${version}-${target.name}.tar.gz`
    const archivePath = join(artifactsDirectory, archiveName)
    const archive = readRegularFile(archivePath, archiveName)
    const top = `awskms-${version}-${target.name}`
    assertTarInventory(
      archivePath,
      archiveInventory(version, target, legal),
      archiveName,
    )
    const module = readTarEntry(archivePath, `${top}/${target.module}`)
    const config = readTarEntry(archivePath, `${top}/awskms.cnf`)
    assertModuleTarget(module, target, version)
    for (const [path, expected] of projectFiles) {
      const archivePathName = `${top}/${path}`
      assertExactBytes(
        readTarEntry(archivePath, archivePathName),
        expected,
        `${archiveName} ${path}`,
      )
    }
    if (runPolicy) runArchivePolicy(root, archivePath)
    archives.push({ archive, archiveName, archivePath, config, module, target })
  }
  return { archives, legal, manifest }
}

function pathContains(parent, child) {
  const path = relative(parent, child)
  return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !isAbsolute(path))
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function moveFile(source, destination) {
  invariant(!existsSync(destination), `refusing to overwrite ${destination}`)
  renameSync(source, destination)
}

function validateReleaseOutput(directory, expectedNames) {
  assertDirectoryContainsExactly(directory, expectedNames, 'assembled release directory')
  const subjectNames = expectedNames.filter((name) => name !== 'SHA256SUMS').sort()
  const expected = `${subjectNames
    .map((name) => `${sha256(readRegularFile(join(directory, name)))}  ${name}`)
    .join('\n')}\n`
  invariant(
    readRegularFile(join(directory, 'SHA256SUMS')).equals(Buffer.from(expected)),
    'SHA256SUMS is not sorted or does not match the release payload',
  )
}

export function assembleRelease({
  root,
  artifactsDirectory,
  outputDirectory,
  version,
  runPolicy = true,
}) {
  root = resolve(root)
  artifactsDirectory = resolve(artifactsDirectory)
  outputDirectory = resolve(outputDirectory)
  invariant(
    !pathContains(artifactsDirectory, outputDirectory) &&
      !pathContains(outputDirectory, artifactsDirectory),
    'artifact and output directories must not contain one another',
  )

  // Validate every input before creating or changing the requested output.
  const verified = verifyReleaseArchives({ root, artifactsDirectory, version, runPolicy })
  if (existsSync(outputDirectory)) {
    const stat = lstatSync(outputDirectory)
    invariant(stat.isDirectory() && !stat.isSymbolicLink(), 'release output must be a directory')
    invariant(readdirSync(outputDirectory).length === 0, 'release output directory must be empty')
  }

  mkdirSync(dirname(outputDirectory), { recursive: true })
  const workingDirectory = mkdtempSync(join(tmpdir(), 'awskms-release-pack.'))
  const assembled = mkdtempSync(join(dirname(outputDirectory), '.awskms-release.'))
  let completed = false
  try {
    const cacheDirectory = join(workingDirectory, 'npm-cache')
    const coreDirectory = join(workingDirectory, 'core')
    stageCore({ root, destination: coreDirectory })
    const coreTarball = packStagedPackage({
      destination: coreDirectory,
      expectedName: '@keyobject/aws-kms',
      version,
      inventory: coreInventory,
      cacheDirectory,
    })
    moveFile(coreTarball, join(assembled, basename(coreTarball)))

    for (const entry of verified.archives) {
      const satelliteDirectory = join(workingDirectory, entry.target.name)
      stageSatellite({
        root,
        destination: satelliteDirectory,
        target: entry.target,
        version,
        source: entry,
        legal: verified.legal,
      })
      const satelliteTarball = packStagedPackage({
        destination: satelliteDirectory,
        expectedName: `@keyobject/aws-kms-${entry.target.name}`,
        version,
        inventory: satelliteInventory(entry.target, verified.legal.licenseNames),
        cacheDirectory,
      })
      assertExactBytes(
        readTarEntry(satelliteTarball, `package/${entry.target.module}`),
        entry.module,
        `${entry.target.name} npm module`,
      )
      assertExactBytes(
        readTarEntry(satelliteTarball, 'package/awskms.cnf'),
        entry.config,
        `${entry.target.name} npm config`,
      )
      moveFile(satelliteTarball, join(assembled, basename(satelliteTarball)))

      const outputArchive = join(assembled, entry.archiveName)
      copyFileSync(entry.archivePath, outputArchive)
      assertExactBytes(readRegularFile(outputArchive), entry.archive, `${entry.archiveName} output`)
    }

    const subjectNames = readdirSync(assembled).sort()
    invariant(subjectNames.length === 11, 'assembled release must contain eleven tarballs')
    invariant(
      subjectNames.every((name) => name.endsWith('.tgz') || name.endsWith('.tar.gz')),
      'assembled release contains a non-tarball subject',
    )
    const checksums = `${subjectNames
      .map((name) => `${sha256(readRegularFile(join(assembled, name)))}  ${name}`)
      .join('\n')}\n`
    writeFileSync(join(assembled, 'SHA256SUMS'), checksums)

    const expectedNames = [
      ...targets.map(({ name }) => `awskms-${version}-${name}.tar.gz`),
      npmTarballName('@keyobject/aws-kms', version),
      ...targets.map(({ name }) =>
        npmTarballName(`@keyobject/aws-kms-${name}`, version),
      ),
      'SHA256SUMS',
    ].sort()
    validateReleaseOutput(assembled, expectedNames)

    if (existsSync(outputDirectory)) rmdirSync(outputDirectory)
    renameSync(assembled, outputDirectory)
    completed = true
    return { files: expectedNames, outputDirectory }
  } finally {
    rmSync(workingDirectory, { force: true, recursive: true })
    if (!completed) rmSync(assembled, { force: true, recursive: true })
  }
}
