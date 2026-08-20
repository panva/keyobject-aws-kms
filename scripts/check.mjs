#!/usr/bin/env node
//
// Says whether the awskms provider is actually working, and if not, why.
//
//   node --openssl-config=/abs/awskms.cnf scripts/check.mjs
//       is it working, here, now?
//
//   node scripts/check.mjs --openssl-config=/abs/awskms.cnf
//       inspect a cnf WITHOUT activating it. Note the flag has moved after the
//       script name, so node does not consume it. Useful before you commit to a
//       config, and the only way to reach some diagnoses -- an unset $ENV:: in
//       `module =` is fatal at OpenSSL init, so with the cnf actually active
//       node exits before any JS runs.
//
// Exit codes:  0 working / 1 broken / 2 cannot tell (Node lacks the capability).
// 2 is separate so a caller can skip rather than fail: scripts/check-load.sh
// can run against a Node build without the loader.
//
// Provider load failures are otherwise silent until the first
// createPrivateKey(). A wrong module path, an unread config, and a Node build
// without the STORE URL-key capability require different diagnostics.
//
// It has no dependencies and imports nothing outside node: core, so it can be
// copied verbatim into a release archive or an npm package and run anywhere.

import { createPrivateKey } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';

const BOLD = '\x1b[1m', RED = '\x1b[31m', GREEN = '\x1b[32m', YELLOW = '\x1b[33m', OFF = '\x1b[0m';
const useColour = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (useColour ? `${code}${s}${OFF}` : s);

const ok = (s) => console.log(`  ${c(GREEN, 'ok')}   ${s}`);
const bad = (s) => console.log(`  ${c(RED, 'FAIL')} ${s}`);
const warn = (s) => console.log(`  ${c(YELLOW, 'warn')} ${s}`);
const note = (s) => console.log(`       ${s}`);

// --- level 0: is the provider there? ---------------------------------------
//
// The probe is a bare "aws-kms:" URI. src/store.c parses the URI BEFORE it calls
// awskms_kms_get_public_key, so an invalid one is rejected during parsing: no
// network call, no credentials, no IAM permission, no AWS account, and nothing
// billable. That is what makes this safe to tell users to run.
//
// Each outcome names a different failure, which is the whole point -- these are
// otherwise indistinguishable from "it didn't work".
export function probeProvider() {
  try {
    createPrivateKey({ key: new URL('aws-kms:') });
    // Unreachable: a URI with no key-id cannot produce a key. If it ever
    // happens, something is very wrong and silence would be worse.
    return { status: 'unexpected', detail: 'the probe URI was accepted' };
  } catch (e) {
    switch (e.code) {
      case 'ERR_OSSL_AWSKMS_INVALID_URI':
        // Our store loader ran and rejected the URI. That is a pass: nothing
        // else in the process answers for the awskms scheme.
        return { status: 'ready', err: e };
      case 'ERR_OSSL_OSSL_STORE_UNSUPPORTED':
        // Node accepts URL keys, so the STORE loader is present -- but no
        // provider claims "awskms".
        return { status: 'not-loaded', err: e };
      case 'ERR_INVALID_ARG_TYPE':
        // A URL is not an accepted key type: this Node build lacks the required
        // OSSL_STORE URL-key capability.
        return { status: 'unsupported-node', err: e };
      case 'ERR_ACCESS_DENIED':
        return { status: 'permission', err: e };
      default:
        return { status: 'unknown', err: e };
    }
  }
}

// --- level 1: which config was in play, and is it sane? ---------------------

function configInPlay() {
  const fromArgv = [...process.execArgv, ...process.argv.slice(2)]
    .find((a) => a.startsWith('--openssl-config='));
  if (fromArgv) return { path: fromArgv.slice('--openssl-config='.length), via: '--openssl-config' };
  if (process.env.OPENSSL_CONF) return { path: process.env.OPENSSL_CONF, via: 'OPENSSL_CONF' };
  const fromNodeOptions = (process.env.NODE_OPTIONS ?? '').split(/\s+/)
    .find((a) => a.startsWith('--openssl-config='));
  if (fromNodeOptions) {
    return { path: fromNodeOptions.slice('--openssl-config='.length), via: 'NODE_OPTIONS' };
  }
  return null;
}

// OpenSSL expands $ENV::NAME and ${ENV::NAME} inside values. We use that in the
// relocatable cnf so one file works from any unpack directory, which means this
// check has to expand it too or it would report a path nobody wrote.
function expandEnv(value) {
  /* Collect unset names separately because no sentinel value is guaranteed to
   * be absent from every valid filesystem path. */
  const unset = [];
  const expanded = value.replace(
    /\$\{ENV::([A-Za-z_][A-Za-z0-9_]*)\}|\$ENV::([A-Za-z_][A-Za-z0-9_]*)/g,
    (whole, a, b) => {
      const name = a ?? b;
      const v = process.env[name];
      if (v === undefined) {
        unset.push(name);
        return whole;
      }
      return v;
    });
  return { expanded, unset };
}

function inspectCnf(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    bad(`cannot read ${path}: ${e.code}`);
    return;
  }

  // A deliberately small parser: enough to see the shape, not a reimplementation
  // of OpenSSL's. Section names and key=value, comments stripped.
  const lines = text.split('\n').map((l) => l.replace(/#.*$/, '').trim());
  let section = null;                 // null == the default section
  const sections = new Map([[null, new Map()]]);
  for (const line of lines) {
    if (!line) continue;
    const header = line.match(/^\[\s*([^\]]+?)\s*\]$/);
    if (header) { section = header[1]; if (!sections.has(section)) sections.set(section, new Map()); continue; }
    const kv = line.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (kv) sections.get(section).set(kv[1].trim(), kv[2].trim());
  }
  const top = sections.get(null);

  // Checked in the order they bite.

  // 1. nodejs_conf. Node reads this key, not openssl_conf (src/node.cc). It must
  //    be in the DEFAULT section, above the first [header] -- a literal
  //    [nodejs_conf] section does nothing, silently.
  const appname = top.get('nodejs_conf');
  if (!appname) {
    bad('no "nodejs_conf" in the default section');
    note('node reads nodejs_conf, not openssl_conf. A cnf with only openssl_conf is');
    note('silently ignored unless node is started with --openssl-shared-config.');
    note('It must appear ABOVE the first [section] header.');
    return;
  }
  ok(`nodejs_conf = ${appname}`);

  const init = sections.get(appname);
  if (!init) { bad(`section [${appname}] does not exist`); return; }

  const provSect = init.get('providers');
  if (!provSect || !sections.has(provSect)) {
    bad(`[${appname}] has no usable "providers" key`);
    return;
  }
  const providers = sections.get(provSect);

  // 2. The default provider. Activating ANY provider from config disables
  //    fallback loading, so omitting this aborts node at startup with an
  //    ncrypto::CSPRNG assertion -- before any JS runs, which is exactly why
  //    this has to be a static read rather than a runtime check.
  const defSect = providers.get('default');
  if (!defSect) {
    bad(`[${provSect}] does not list "default"`);
    note('Activating a provider from config disables OpenSSL fallback loading, so');
    note('without an explicit default section node aborts at startup:');
    note('  Assertion failed: ncrypto::CSPRNG(nullptr, 0)');
    return;
  }
  const defActivate = sections.get(defSect)?.get('activate');
  if (defActivate === '1') ok(`default provider activated via [${defSect}]`);
  else warn(`[${defSect}] does not set activate = 1`);

  // 3. Our own section and the module path.
  const ourSect = providers.get('aws-kms');
  if (!ourSect) { bad(`[${provSect}] does not list "aws-kms"`); return; }
  const ours = sections.get(ourSect);
  if (!ours) { bad(`section [${ourSect}] does not exist`); return; }
  if (ours.get('activate') !== '1') warn(`[${ourSect}] does not set activate = 1`);

  const raw = ours.get('module');
  if (!raw) { bad(`[${ourSect}] has no "module"`); return; }

  const { expanded, unset } = expandEnv(raw);
  if (unset.length) {
    bad(`module refers to $ENV::${unset[0]}, which is not set`);
    note(`Set it to the absolute path of the provider module, e.g.`);
    note(`  export ${unset[0]}=/path/to/aws-kms.so`);
    return;
  }
  if (expanded !== raw) ok(`module = ${raw} -> ${expanded}`);

  // A relative path resolves against OpenSSL's module search dir, never the cwd
  // and never the cnf's own directory -- so it almost never means what it looks
  // like it means.
  if (!isAbsolute(expanded)) {
    bad(`module path is relative: ${expanded}`);
    note('OpenSSL resolves it against its module search directory, not the cwd');
    note("and not the cnf's own directory. Use an absolute path.");
    return;
  }
  // No platform extension is appended once a search dir is involved, so the
  // path must carry it.
  if (!/\.(so|dylib|dll)$/.test(expanded)) {
    bad(`module path has no platform extension: ${expanded}`);
    note('OpenSSL does not append one here. Use aws-kms.so / aws-kms.dylib.');
    return;
  }
  try {
    const st = statSync(expanded);
    ok(`module exists (${st.size} bytes)`);
  } catch (e) {
    bad(`module path does not exist: ${expanded} (${e.code})`);
    note('This is the most common cause: the cnf was generated for a different');
    note('install location, or the archive was unpacked somewhere else.');
  }
}

// --- programmatic use -------------------------------------------------------

/** Throws unless the provider is loaded and reachable. */
export function assertProviderReady() {
  const r = probeProvider();
  if (r.status !== 'ready') {
    const e = new Error(`awskms provider is not usable (${r.status})`);
    e.cause = r.err;
    throw e;
  }
}

// --- CLI --------------------------------------------------------------------

function main() {
  console.log(`${c(BOLD, 'aws-kms check')}`);
  console.log(`  node ${process.version}, openssl ${process.versions.openssl}`);

  const cfg = configInPlay();
  console.log(`  config: ${cfg ? `${cfg.path} (via ${cfg.via})` : c(YELLOW, 'none in this process')}`);
  console.log();

  const r = probeProvider();
  switch (r.status) {
    case 'ready':
      ok('provider is loaded and reachable');
      console.log();
      console.log(c(GREEN, 'aws-kms is working.'));
      return 0;

    case 'unsupported-node':
      bad(`this Node build cannot load keys from a URL (${process.version})`);
      note('crypto.createPrivateKey({ key: new URL(...) }) needs the OSSL_STORE');
      note('URL-key capability. Use a Node build whose functional probe supports it.');
      note('Nothing about the provider install can be diagnosed until then.');
      return 2;   // cannot tell, not broken -- see the exit codes at the top

    case 'permission':
      bad('blocked by the permission model');
      note('Loading a key through a STORE loader needs --allow-openssl-store.');
      note('Note the CLI flag is hyphenated but the runtime scope is not:');
      note("  process.permission.has('openssl.store')   <- a DOT");
      return 1;

    case 'not-loaded':
      bad('node supports URL keys, but no provider answers for "aws-kms:"');
      note('The module did not load. OpenSSL reports nothing when that happens,');
      note('which is why this check exists. Diagnosing the config:');
      console.log();
      if (!cfg) {
        bad('no OpenSSL config is in effect in this process');
        note('A provider cannot be activated from inside a running process via a');
        note('config file -- OpenSSL reads it once at library init. Start node with');
        note('  node --openssl-config=/abs/path/to/awskms.cnf your-app.mjs');
        note('or use the npm package, which registers programmatically instead.');
      } else {
        inspectCnf(cfg.path);
      }
      return 1;

    default:
      bad(`unexpected probe result: ${r.err?.code ?? r.detail}`);
      if (r.err?.message) note(r.err.message);
      if (r.err?.opensslErrorStack) for (const l of r.err.opensslErrorStack) note(l);
      return 1;
  }
}

/*
 * Use import.meta.main because comparing import.meta.url with argv[1] is not
 * symlink-safe: the ESM loader resolves symlinks while argv[1] remains as typed.
 */
if (import.meta.main) {
  process.exit(main());
}
