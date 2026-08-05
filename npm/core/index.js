/*
 * Locating the native module, and turning it into something node can use.
 *
 * The package is ESM-only. That is safe rather than exclusionary: the floor is
 * Node 26.7.0 (where the OSSL_STORE loader shipped) and require(ESM) has been
 * unflagged since well before it, so CJS consumers can require() this. Shipping
 * a dual build would double the surface to serve nobody.
 *
 * ONE native artifact per platform, published as an optional dependency, so a
 * user downloads only their own. The alternative -- a postinstall that fetches --
 * is what esbuild does and is the origin of its version-skew bug; it also does
 * not run under `ignore-scripts`, which many people set. Nothing here executes
 * at install time.
 */
import { createRequire } from 'node:module';
import { arch, platform } from 'node:process';
import { readFileSync, writeFileSync, mkdirSync, renameSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

const require = createRequire(import.meta.url);

export const version = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;

/*
 * A LITERAL map, not a template string. Bundlers resolve `require.resolve` only
 * when they can see the specifier statically; `@scope/${platform}-${arch}` is
 * invisible to them and silently produces a broken bundle. Every reference
 * package (esbuild, sharp) does it this way for the same reason.
 *
 * The keys are exactly `${process.platform}-${process.arch}`, which is also how
 * the release artifacts are named, so there is no mapping table to drift.
 */
const PLATFORM_PACKAGES = {
  'darwin-arm64': '@awskms-openssl-provider/darwin-arm64',
  'darwin-x64': '@awskms-openssl-provider/darwin-x64',
  'linux-arm64': '@awskms-openssl-provider/linux-arm64',
  'linux-x64': '@awskms-openssl-provider/linux-x64',
};

/* The module keeps its canonical name in every tier -- the release tarball and
 * the npm satellite ship byte-identical files -- so `openssl list -provider-path`
 * works against an npm install too. A `.node` name would also load (measured:
 * an explicit `module =` path is used verbatim, no extension appended), but it
 * would break that debugging path for no gain, since nothing here uses
 * require() on the binary. */
const MODULE_FILE = platform === 'darwin' ? 'awskms.dylib' : 'awskms.so';

const target = `${platform}-${arch}`;

function fail(problems) {
  const e = new Error(
    `Could not load the awskms provider for ${target}.\n\n` +
    problems.map((p, i) => `  ${i + 1}. ${p}`).join('\n\n') + '\n');
  e.code = 'ERR_AWSKMS_MODULE_NOT_FOUND';
  throw e;
}

/*
 * Every failure mode gets NAMED, with the command that fixes it. This is not
 * politeness: `--omit=optional` installs cleanly with no signal at all and
 * defers everything to first use, so this message IS the entire user experience
 * of that failure. sharp accumulates and lists; esbuild throws on the first
 * cause and is routinely misdiagnosed as a result.
 */
function resolveModule() {
  const pkg = PLATFORM_PACKAGES[target];
  if (!pkg) {
    fail([
      `This platform is not published. Supported: ${Object.keys(PLATFORM_PACKAGES).join(', ')}.`,
      'Build from source instead -- see the project README. The provider itself ' +
      'has no platform restriction; only the prebuilt artifacts do.',
    ]);
  }

  const problems = [];
  try {
    const resolved = require.resolve(`${pkg}/${MODULE_FILE}`);
    /* Yarn PnP keeps files inside zip archives, and dlopen cannot read those.
     * esbuild copies out to a cache dir; so do we, rather than failing. */
    if (resolved.includes('/.zip/') || resolved.includes('\\.zip\\')) {
      return copyOut(resolved);
    }
    return resolved;
  } catch (err) {
    problems.push(
      `${pkg} is not installed (${err.code ?? err.message}).\n` +
      '     If you used --omit=optional or --no-optional, reinstall with:\n' +
      '       npm install --include=optional\n' +
      '     If you installed on a different platform than you are running on:\n' +
      `       npm install --os=${platform} --cpu=${arch}`);
  }

  /* A bundler that inlined this file rather than treating it as external. The
   * check is cheap and the error is otherwise baffling. */
  if (!import.meta.url.includes('awskms')) {
    problems.push(
      'This package appears to have been bundled. It cannot be: it resolves a\n' +
      '     native binary at runtime. Mark it external in your bundler config.');
  }

  fail(problems);
}

function copyOut(inside) {
  const dir = join(tmpdir(), `awskms-${version}-${target}`);
  mkdirSync(dir, { recursive: true });
  const out = join(dir, MODULE_FILE);
  try {
    writeFileSync(out, readFileSync(inside), { mode: 0o755 });
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }
  return out;
}

let cachedPath;

/** Absolute path to the provider module. Throws if it cannot be found. */
export function modulePath() {
  return (cachedPath ??= resolveModule());
}

/*
 * The cnf has to name an ABSOLUTE module path, so it is machine-specific and
 * cannot be shipped ready-made. Rather than template a fifth copy of the file --
 * there are already several, and they drift -- the satellite ships the
 * RELOCATABLE cnf and this substitutes its one $ENV::AWSKMS_MODULE token. One
 * canonical source, specialised here.
 *
 * Written once to a deterministic path keyed by module path and version, and
 * atomically, so concurrent callers cannot observe a half-written file.
 */
export function opensslConfigPath() {
  const mod = modulePath();
  const key = createHash('sha256').update(`${version}\0${mod}`).digest('hex').slice(0, 16);
  const dir = join(tmpdir(), `awskms-cnf-${key}`);
  const out = join(dir, 'awskms.cnf');
  try {
    readFileSync(out);
    return out;
  } catch { /* not written yet */ }

  const template = readFileSync(join(dirname(mod), 'awskms.cnf'), 'utf8');
  if (!template.includes('$ENV::AWSKMS_MODULE')) {
    const e = new Error('the shipped awskms.cnf is not the relocatable one');
    e.code = 'ERR_AWSKMS_BAD_CONFIG_TEMPLATE';
    throw e;
  }
  mkdirSync(dir, { recursive: true });
  const tmp = `${out}.${process.pid}`;
  writeFileSync(tmp, template.replaceAll('$ENV::AWSKMS_MODULE', mod));
  renameSync(tmp, out);
  return out;
}

let registered = false;

/*
 * Activate the provider IN THIS PROCESS, with no openssl.cnf and no CLI flag.
 *
 * The module is its own N-API addon: one artifact exports both
 * OSSL_provider_init and napi_register_module_v1, so this costs no second
 * binary. Loading it runs the same four steps the cnf does declaratively --
 * set the default property query, add the provider as built-in, load `default`,
 * load `awskms`.
 *
 * process.dlopen rather than require(): the file keeps its canonical
 * awskms.dylib / awskms.so name across all three distribution tiers, and the CJS
 * loader would insist on a `.node` extension. dlopen does not care, and keeping
 * one name means `openssl list -provider-path` works against an npm install too.
 *
 * WHAT THIS COSTS, because it is not free and the docs should not pretend it is:
 * under --permission this route needs --allow-addons, --allow-openssl-store AND
 * --allow-fs-read (the last because resolving the satellite reads node_modules),
 * where the openssl.cnf route needs only --allow-openssl-store. That is not
 * merely three grants against one -- --allow-openssl-store is a scoped
 * capability and --allow-addons is arbitrary native code. If you run under
 * --permission, prefer opensslConfigPath().
 *
 * Idempotent: OpenSSL would refuse a second registration of the same name, and a
 * second require() of this subpath is a no-op anyway.
 */
export function register() {
  if (registered) return;
  const m = { exports: {} };
  /* A failed registration THROWS out of here rather than returning quietly.
   * That is the entire advantage over the cnf route, whose failure mode is
   * total silence followed by a confusing error at the first createPrivateKey. */
  process.dlopen(m, modulePath());
  registered = true;
}

/*
 * Non-throwing, because the two ways this can be unusable are completely
 * different problems and a caller may want to branch rather than catch.
 */
export function isSupported() {
  try {
    modulePath();
  } catch (e) {
    return { ok: false, reason: e.message };
  }
  /* The loader is what makes the provider reachable at all. Probing for it here
   * costs nothing and turns "it silently did nothing" into a sentence. */
  const [maj, min] = process.versions.node.split('.').map(Number);
  if (maj < 26 || (maj === 26 && min < 7)) {
    return {
      ok: false,
      reason: `node ${process.versions.node} has no OSSL_STORE loader for ` +
        'crypto.createPrivateKey({ key: new URL(...) }); needs >= 26.7.0',
    };
  }
  return { ok: true };
}
