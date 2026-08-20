/*
 * Runtime support for the npm distribution.
 *
 * The native provider is published as an exact-version optional dependency for
 * each supported platform. Nothing executes at install time: this module finds
 * that package, validates it, and prepares the files OpenSSL needs at runtime.
 */
import { createHash, createPrivateKey } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { arch, platform } from 'node:process';

const require = createRequire(import.meta.url);

export const version = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;

const PLATFORM_PACKAGES = {
  'darwin-arm64': '@keyobject/aws-kms-darwin-arm64',
  'linux-arm64': '@keyobject/aws-kms-linux-arm64',
  'linux-x64': '@keyobject/aws-kms-linux-x64',
  'linuxmusl-arm64': '@keyobject/aws-kms-linuxmusl-arm64',
  'linuxmusl-x64': '@keyobject/aws-kms-linuxmusl-x64',
};

function targetKey() {
  if (platform !== 'linux') return `${platform}-${arch}`;
  const musl = !process.report.getReport().header.glibcVersionRuntime;
  return `linux${musl ? 'musl' : ''}-${arch}`;
}

const target = targetKey();

function awskmsError(code, message, cause) {
  const error = new Error(message);
  error.code = code;
  if (cause !== undefined) error.cause = cause;
  return error;
}

function moduleNotFound(pkg, cause) {
  const problems = [];
  if (pkg === undefined) {
    problems.push(
      `This platform is not published. Supported: ${Object.keys(PLATFORM_PACKAGES).join(', ')}.`);
  } else {
    problems.push(
      `${pkg} is not installed (${cause?.code ?? cause?.message ?? 'not found'}).\n` +
      '     If you used --omit=optional or --no-optional, reinstall with:\n' +
      '       npm install --include=optional\n' +
      '     If you installed on a different platform than you are running on:\n' +
      `       npm install --os=${platform} --cpu=${arch}` +
      (platform === 'linux' ?
        ` --libc=${target.startsWith('linuxmusl') ? 'musl' : 'glibc'}` : ''));
  }

  if (!import.meta.url.includes('aws-kms')) {
    problems.push(
      'This package appears to have been bundled. Mark @keyobject/aws-kms and\n' +
      '     its platform package external so they can resolve native files at runtime.');
  }

  return awskmsError(
    'ERR_AWSKMS_MODULE_NOT_FOUND',
    `Could not load the aws-kms provider for ${target}.\n\n` +
      problems.map((problem, index) => `  ${index + 1}. ${problem}`).join('\n\n') + '\n',
    cause);
}

/* Keep every specifier literal. This lets package managers and bundlers see the
 * complete optional-dependency graph; a computed require.resolve() hides it. */
function resolveSatelliteFiles() {
  switch (target) {
    case 'darwin-arm64':
      return {
        manifest: require.resolve('@keyobject/aws-kms-darwin-arm64/package.json'),
        module: require.resolve('@keyobject/aws-kms-darwin-arm64/aws-kms.dylib'),
        config: require.resolve('@keyobject/aws-kms-darwin-arm64/awskms.cnf'),
      };
    case 'linux-arm64':
      return {
        manifest: require.resolve('@keyobject/aws-kms-linux-arm64/package.json'),
        module: require.resolve('@keyobject/aws-kms-linux-arm64/aws-kms.so'),
        config: require.resolve('@keyobject/aws-kms-linux-arm64/awskms.cnf'),
      };
    case 'linux-x64':
      return {
        manifest: require.resolve('@keyobject/aws-kms-linux-x64/package.json'),
        module: require.resolve('@keyobject/aws-kms-linux-x64/aws-kms.so'),
        config: require.resolve('@keyobject/aws-kms-linux-x64/awskms.cnf'),
      };
    case 'linuxmusl-arm64':
      return {
        manifest: require.resolve('@keyobject/aws-kms-linuxmusl-arm64/package.json'),
        module: require.resolve('@keyobject/aws-kms-linuxmusl-arm64/aws-kms.so'),
        config: require.resolve('@keyobject/aws-kms-linuxmusl-arm64/awskms.cnf'),
      };
    case 'linuxmusl-x64':
      return {
        manifest: require.resolve('@keyobject/aws-kms-linuxmusl-x64/package.json'),
        module: require.resolve('@keyobject/aws-kms-linuxmusl-x64/aws-kms.so'),
        config: require.resolve('@keyobject/aws-kms-linuxmusl-x64/awskms.cnf'),
      };
    default:
      throw moduleNotFound(undefined);
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function snapshot(path) {
  const bytes = readFileSync(path);
  return { path, bytes, digest: sha256(bytes) };
}

function validateSnapshot(file, label) {
  let actual;
  try {
    actual = readFileSync(file.path);
  } catch (cause) {
    throw awskmsError(
      'ERR_AWSKMS_PACKAGE_INTEGRITY', `${label} disappeared after it was resolved: ${file.path}`, cause);
  }
  if (actual.length !== file.bytes.length || sha256(actual) !== file.digest) {
    throw awskmsError(
      'ERR_AWSKMS_PACKAGE_INTEGRITY', `${label} changed after it was resolved: ${file.path}`);
  }
}

let cachedSatellite;

function resolveSatellite() {
  if (cachedSatellite !== undefined) {
    validateSnapshot(cachedSatellite.manifestFile, 'platform package manifest');
    validateSnapshot(cachedSatellite.moduleFile, 'provider module');
    validateSnapshot(cachedSatellite.configFile, 'OpenSSL config template');
    return cachedSatellite;
  }

  const expectedName = PLATFORM_PACKAGES[target];
  if (expectedName === undefined) throw moduleNotFound(undefined);

  let paths;
  try {
    paths = resolveSatelliteFiles();
  } catch (cause) {
    if (cause?.code?.startsWith('ERR_AWSKMS_')) throw cause;
    throw moduleNotFound(expectedName, cause);
  }

  let manifest;
  let manifestFile;
  try {
    manifestFile = snapshot(paths.manifest);
    manifest = JSON.parse(manifestFile.bytes.toString('utf8'));
  } catch (cause) {
    throw awskmsError(
      'ERR_AWSKMS_INVALID_PLATFORM_PACKAGE',
      `${expectedName} has an unreadable or invalid package.json`, cause);
  }

  if (manifest.name !== expectedName) {
    throw awskmsError(
      'ERR_AWSKMS_INVALID_PLATFORM_PACKAGE',
      `Resolved ${expectedName}, but its package.json identifies it as ${JSON.stringify(manifest.name)}.`);
  }
  if (manifest.version !== version) {
    throw awskmsError(
      'ERR_AWSKMS_VERSION_MISMATCH',
      `@keyobject/aws-kms is ${version}, but ${expectedName} is ${manifest.version ?? 'unversioned'}. ` +
      'Reinstall both packages together without overriding optional dependency versions.');
  }

  const expectedOs = target.startsWith('darwin-') ? 'darwin' : 'linux';
  const expectedLibc = target.startsWith('linuxmusl-') ? 'musl' :
    target.startsWith('linux-') ? 'glibc' : undefined;
  const exactSingleton = (value, expected) =>
    Array.isArray(value) && value.length === 1 && value[0] === expected;
  if (!exactSingleton(manifest.os, expectedOs) || !exactSingleton(manifest.cpu, arch) ||
      (expectedLibc === undefined ? 'libc' in manifest :
        !exactSingleton(manifest.libc, expectedLibc))) {
    throw awskmsError(
      'ERR_AWSKMS_INVALID_PLATFORM_PACKAGE',
      `${expectedName} has platform metadata that does not match ${target}.`);
  }

  if (dirname(paths.manifest) !== dirname(paths.module) ||
      dirname(paths.manifest) !== dirname(paths.config)) {
    throw awskmsError(
      'ERR_AWSKMS_INVALID_PLATFORM_PACKAGE',
      `${expectedName} resolved its manifest, module, and config from different locations.`);
  }

  let moduleFile;
  let configFile;
  try {
    moduleFile = snapshot(paths.module);
    configFile = snapshot(paths.config);
  } catch (cause) {
    throw awskmsError(
      'ERR_AWSKMS_INVALID_PLATFORM_PACKAGE',
      `${expectedName} has an unreadable native module or OpenSSL config template.`, cause);
  }

  cachedSatellite = { name: expectedName, manifestFile, moduleFile, configFile };
  return cachedSatellite;
}

let tempDirectory;

const processIdentity = `${process.pid}-${sha256(Buffer.from(
  `${process.pid}\0${performance.timeOrigin}`, 'utf8'))}`;
const directoryPrefix = `runtime-${processIdentity}-`;
const rendezvousName = `process-${processIdentity}.path`;

function uidMatches(stat) {
  return typeof process.getuid !== 'function' || stat.uid === process.getuid();
}

function assertPrivateDirectory(path, expected) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch (cause) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY', `Private runtime directory disappeared: ${path}`, cause);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink() || !uidMatches(stat) ||
      (stat.mode & 0o777) !== 0o700 ||
      (expected !== undefined && (stat.dev !== expected.dev || stat.ino !== expected.ino))) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      `Private runtime directory changed or has unsafe permissions: ${path}`);
  }
  return stat;
}

function rendezvousRoot() {
  if (typeof process.getuid !== 'function') {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      'The aws-kms runtime package requires a POSIX user identity.');
  }
  const path = join(tmpdir(), `keyobject-aws-kms-${process.getuid()}`);
  let created = false;
  try {
    mkdirSync(path, { mode: 0o700 });
    created = true;
  } catch (cause) {
    if (cause?.code !== 'EEXIST') {
      throw awskmsError(
        'ERR_AWSKMS_TEMP_INTEGRITY',
        `Could not create the private aws-kms rendezvous directory: ${path}`, cause);
    }
  }
  if (created) chmodSync(path, 0o700);
  return { path, stat: assertPrivateDirectory(path) };
}

function noFollowRead(path) {
  if (constants.O_NOFOLLOW === undefined) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      'This platform cannot inspect private runtime files without following symbolic links.');
  }
  let fd;
  try {
    fd = openSync(path,
      constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0));
    const stat = fstatSync(fd);
    const bytes = readFileSync(fd);
    return { stat, bytes };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function readRendezvous(root, markerPath) {
  let marker;
  try {
    marker = noFollowRead(markerPath);
  } catch (cause) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      `Could not read the aws-kms process rendezvous: ${markerPath}`, cause);
  }
  const name = marker.bytes.toString('utf8');
  const suffix = name.slice(directoryPrefix.length);
  if (!marker.stat.isFile() || !uidMatches(marker.stat) ||
      (marker.stat.mode & 0o777) !== 0o400 ||
      name !== basename(name) || !name.startsWith(directoryPrefix) ||
      !/^[A-Za-z0-9]{6}$/u.test(suffix)) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      `The aws-kms process rendezvous is malformed or unsafe: ${markerPath}`);
  }
  const path = join(root.path, name);
  const stat = assertPrivateDirectory(path);
  return {
    path,
    dev: stat.dev,
    ino: stat.ino,
    root: { path: root.path, dev: root.stat.dev, ino: root.stat.ino },
    marker: {
      path: markerPath,
      dev: marker.stat.dev,
      ino: marker.stat.ino,
      bytes: marker.bytes,
      digest: sha256(marker.bytes),
    },
  };
}

function publishRendezvous(root, markerPath) {
  let candidate;
  let publication;
  let fd;
  let published = false;
  try {
    candidate = mkdtempSync(join(root.path, directoryPrefix));
    chmodSync(candidate, 0o700);
    assertPrivateDirectory(candidate);

    publication = join(candidate, '.publish');
    const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
      constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0);
    fd = openSync(publication, flags, 0o600);
    writeFileSync(fd, Buffer.from(basename(candidate), 'utf8'));
    fchmodSync(fd, 0o400);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;

    /* link(2) is a no-replace, atomic publication: readers see either no
     * rendezvous or the complete, fsynced marker. */
    linkSync(publication, markerPath);
    published = true;
    try { unlinkSync(publication); } catch { /* the published marker is authoritative */ }
    publication = undefined;
    return readRendezvous(root, markerPath);
  } catch (cause) {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* preserve the original failure */ }
    }
    if (!published && publication !== undefined) {
      try { unlinkSync(publication); } catch { /* best-effort unpublished cleanup */ }
    }
    if (!published && candidate !== undefined) {
      try { rmdirSync(candidate); } catch { /* another isolate may have published it */ }
    }
    if (cause?.code === 'EEXIST') return readRendezvous(root, markerPath);
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      'Could not publish a private aws-kms process directory.', cause);
  }
}

function validateTempDirectory() {
  assertPrivateDirectory(tempDirectory.root.path, tempDirectory.root);
  let marker;
  try {
    marker = noFollowRead(tempDirectory.marker.path);
  } catch (cause) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      `The aws-kms process rendezvous disappeared: ${tempDirectory.marker.path}`, cause);
  }
  if (!marker.stat.isFile() || !uidMatches(marker.stat) ||
      marker.stat.dev !== tempDirectory.marker.dev || marker.stat.ino !== tempDirectory.marker.ino ||
      (marker.stat.mode & 0o777) !== 0o400 ||
      marker.bytes.length !== tempDirectory.marker.bytes.length ||
      sha256(marker.bytes) !== tempDirectory.marker.digest ||
      marker.bytes.toString('utf8') !== basename(tempDirectory.path)) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      `The aws-kms process rendezvous changed: ${tempDirectory.marker.path}`);
  }
  assertPrivateDirectory(tempDirectory.path, tempDirectory);
  return tempDirectory.path;
}

function privateTempDirectory() {
  if (tempDirectory !== undefined) return validateTempDirectory();
  const root = rendezvousRoot();
  const markerPath = join(root.path, rendezvousName);
  try {
    tempDirectory = readRendezvous(root, markerPath);
  } catch (cause) {
    if (cause?.cause?.code !== 'ENOENT') throw cause;
    tempDirectory = publishRendezvous(root, markerPath);
  }
  return validateTempDirectory();
}

function privateFileSnapshot(path, bytes, finalMode) {
  let actual;
  try {
    actual = noFollowRead(path);
  } catch (cause) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY', `Private runtime file disappeared: ${path}`, cause);
  }
  const file = {
    path,
    dev: actual.stat.dev,
    ino: actual.stat.ino,
    mode: finalMode,
    bytes,
    digest: sha256(bytes),
  };
  validatePrivateFile(file, actual);
  return file;
}

const publicationWait = new Int32Array(new SharedArrayBuffer(4));

function awaitPrivateFile(path, bytes, finalMode) {
  /* O_EXCL makes a file visible before its creator finishes writing it. The
   * creator keeps mode 0600 until the bytes are fsynced; other isolates wait
   * only for that private, in-progress state and then validate exact content. */
  for (let attempt = 0; attempt < 1_000; attempt++) {
    let stat;
    try {
      stat = lstatSync(path);
    } catch (cause) {
      if (cause?.code !== 'ENOENT') {
        throw awskmsError(
          'ERR_AWSKMS_TEMP_INTEGRITY', `Could not inspect private runtime file ${path}`, cause);
      }
    }
    const pending = stat !== undefined && stat.isFile() && !stat.isSymbolicLink() &&
      uidMatches(stat) && stat.nlink === 1 && (stat.mode & 0o777) !== finalMode;
    if (stat !== undefined && !pending) {
      return privateFileSnapshot(path, bytes, finalMode);
    }
    Atomics.wait(publicationWait, 0, 0, 5);
  }
  throw awskmsError(
    'ERR_AWSKMS_TEMP_INTEGRITY', `Timed out waiting for private runtime file ${path}`);
}

function writePrivateFile(name, bytes, finalMode) {
  const path = join(privateTempDirectory(), name);
  if (constants.O_NOFOLLOW === undefined) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY',
      'This platform cannot create private runtime files without following symbolic links.');
  }
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
    constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0);
  let fd;
  try {
    fd = openSync(path, flags, 0o600);
  } catch (cause) {
    if (cause?.code === 'EEXIST') return awaitPrivateFile(path, bytes, finalMode);
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY', `Could not create private runtime file ${path}`, cause);
  }
  try {
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    fchmodSync(fd, finalMode);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
  } catch (cause) {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* preserve the original, typed failure */ }
    }
    try { unlinkSync(path); } catch { /* best-effort cleanup inside our private directory */ }
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY', `Could not create private runtime file ${path}`, cause);
  }
  return privateFileSnapshot(path, bytes, finalMode);
}

function validatePrivateFile(file, snapshot) {
  validateTempDirectory();
  let actual = snapshot;
  try {
    actual ??= noFollowRead(file.path);
  } catch (cause) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY', `Private runtime file disappeared: ${file.path}`, cause);
  }
  const { stat, bytes } = actual;
  if (!stat.isFile() || stat.nlink !== 1 || !uidMatches(stat) ||
      stat.dev !== file.dev || stat.ino !== file.ino || (stat.mode & 0o777) !== file.mode ||
      bytes.length !== file.bytes.length || sha256(bytes) !== file.digest) {
    throw awskmsError(
      'ERR_AWSKMS_TEMP_INTEGRITY', `Private runtime file changed after creation: ${file.path}`);
  }
}

let cachedModule;

function resolveModule() {
  const satellite = resolveSatellite();
  const insideArchive = /(?:^|\/)[^/]+\.zip\//u.test(satellite.moduleFile.path);
  if (insideArchive) {
    const moduleName = platform === 'darwin' ? 'aws-kms.dylib' : 'aws-kms.so';
    const copied = writePrivateFile(moduleName, satellite.moduleFile.bytes, 0o500);
    return { path: copied.path, privateFile: copied };
  }
  return { path: satellite.moduleFile.path, privateFile: undefined };
}

/** Absolute path to the provider module. Throws if it cannot be found or verified. */
export function modulePath() {
  if (cachedModule === undefined) cachedModule = resolveModule();
  resolveSatellite();
  if (cachedModule.privateFile !== undefined) validatePrivateFile(cachedModule.privateFile);
  return cachedModule.path;
}

function quoteOpenSSLConfigValue(value) {
  if (/[\u0000-\u001f\u007f]/u.test(value)) {
    throw awskmsError(
      'ERR_AWSKMS_UNSAFE_MODULE_PATH',
      'The provider module path contains a control character that cannot be encoded safely in openssl.cnf.');
  }
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$')}"`;
}

function renderConfig(template, module) {
  const moduleLine = /^([ \t]*module[ \t]*=[ \t]*)\$ENV::AWSKMS_MODULE[ \t]*$/gmu;
  if ([...template.matchAll(moduleLine)].length !== 1) {
    throw awskmsError(
      'ERR_AWSKMS_BAD_CONFIG_TEMPLATE',
      'The shipped awskms.cnf must contain exactly one module = $ENV::AWSKMS_MODULE line.');
  }
  moduleLine.lastIndex = 0;
  return template.replace(moduleLine,
    (_line, prefix) => `${prefix}${quoteOpenSSLConfigValue(module)}`);
}

let cachedConfig;

/**
 * Absolute path to a private OpenSSL config that activates the provider. The
 * path is stable and shared by every Worker for the life of this process.
 */
export function opensslConfigPath() {
  const module = modulePath();
  const satellite = resolveSatellite();
  const template = satellite.configFile.bytes.toString('utf8');
  const rendered = Buffer.from(renderConfig(template, module), 'utf8');

  if (cachedConfig === undefined) {
    cachedConfig = writePrivateFile('awskms.cnf', rendered, 0o400);
  } else {
    if (cachedConfig.digest !== sha256(rendered) || cachedConfig.bytes.length !== rendered.length) {
      throw awskmsError(
        'ERR_AWSKMS_TEMP_INTEGRITY', 'The generated OpenSSL config changed within this process.');
    }
    validatePrivateFile(cachedConfig);
  }
  return cachedConfig.path;
}

let registered = false;

/** Activate the provider in this process without an OpenSSL config flag. */
export function register() {
  if (registered) return;
  const module = { exports: {} };
  process.dlopen(module, modulePath());
  registered = true;
}

function runtimeCapabilityFailure() {
  try {
    createPrivateKey({ key: new URL('aws-kms:') });
    return {
      ok: false,
      code: 'ERR_AWSKMS_RUNTIME_PROBE_FAILED',
      reason: 'The URL-key capability probe unexpectedly accepted an invalid aws-kms: URI.',
    };
  } catch (error) {
    if (error?.code === 'ERR_INVALID_ARG_TYPE') {
      return {
        ok: false,
        code: 'ERR_AWSKMS_UNSUPPORTED_RUNTIME',
        reason: `node ${process.versions.node} cannot load private keys from URL objects; ` +
          'this Node build does not include the OpenSSL STORE key loader.',
      };
    }
    if (error?.code === 'ERR_ACCESS_DENIED') {
      return {
        ok: false,
        code: 'ERR_AWSKMS_PERMISSION_DENIED',
        reason: 'Node denied the OpenSSLStore permission; start it with --allow-openssl-store.',
      };
    }
    if (error?.code === 'ERR_OSSL_OSSL_STORE_UNSUPPORTED' ||
        error?.code === 'ERR_OSSL_AWSKMS_INVALID_URI') {
      return undefined;
    }
    return {
      ok: false,
      code: 'ERR_AWSKMS_RUNTIME_PROBE_FAILED',
      reason: `The URL-key capability probe failed unexpectedly: ${error?.code ?? error?.message ?? String(error)}`,
    };
  }
}

function permissionFailure(error) {
  for (let current = error; current !== undefined; current = current?.cause) {
    if (current?.code === 'EACCES' || current?.code === 'EPERM' ||
        current?.code === 'ERR_ACCESS_DENIED') {
      return {
        ok: false,
        code: 'ERR_AWSKMS_PERMISSION_DENIED',
        reason: current?.message ?? 'Permission to inspect the installed provider package was denied.',
      };
    }
  }
  return undefined;
}

/** Non-throwing runtime and package compatibility check. */
export function isSupported() {
  const unsupported = runtimeCapabilityFailure();
  if (unsupported !== undefined) return unsupported;
  try {
    modulePath();
  } catch (error) {
    const denied = permissionFailure(error);
    if (denied !== undefined) return denied;
    return {
      ok: false,
      code: error?.code ?? 'ERR_AWSKMS_UNKNOWN',
      reason: error?.message ?? String(error),
    };
  }
  return { ok: true };
}
