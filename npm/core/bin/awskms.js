#!/usr/bin/env node
/*
 * The ergonomic half of the package. Everything here is reachable
 * programmatically too; this exists so the common cases are one command and no
 * code.
 *
 *   awskms-openssl-provider doctor        is it working, and if not, why
 *   awskms-openssl-provider config-path   print the --openssl-config path
 *   awskms-openssl-provider exec -- node app.mjs
 *                                         run something with the provider active
 *
 * `exec` exists because the provider cannot be activated from inside a running
 * process via a config file -- OpenSSL reads its config once at library init --
 * so the flag has to be on the command line that starts node. Making the user
 * compose that by hand is where the four silent-failure traps live.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { isSupported, modulePath, opensslConfigPath, version } from '../index.js';

const [cmd, ...rest] = process.argv.slice(2);

function usage(code) {
  console.log(`awskms-openssl-provider ${version}

  doctor          check whether the provider is loaded and reachable
  config-path     print the path to a generated openssl.cnf
  module-path     print the path to the native module
  exec -- <cmd>   run <cmd> with the provider activated`);
  process.exit(code);
}

switch (cmd) {
  case 'module-path':
    console.log(modulePath());
    break;

  case 'config-path':
    console.log(opensslConfigPath());
    break;

  case 'doctor': {
    /* The doctor has to run in a process where the provider is ACTIVE, and this
     * one is not -- so re-exec rather than import it. Same reason `exec` exists. */
    const doctor = fileURLToPath(new URL('../awskms-doctor.mjs', import.meta.url));
    const r = spawnSync(process.execPath,
      [`--openssl-config=${opensslConfigPath()}`, doctor],
      { stdio: 'inherit' });
    process.exit(r.status ?? 1);
  }

  case 'exec': {
    /* `--` is required rather than optional: without it, a command that happens
     * to start with a flag would be eaten as one of ours. */
    const sep = rest.indexOf('--');
    const argv = sep === -1 ? rest : rest.slice(sep + 1);
    if (!argv.length) usage(1);
    const support = isSupported();
    if (!support.ok) {
      console.error(`awskms-openssl-provider: ${support.reason}`);
      process.exit(1);
    }
    const r = spawnSync(argv[0], argv.slice(1), {
      stdio: 'inherit',
      env: { ...process.env, OPENSSL_CONF: opensslConfigPath() },
    });
    if (r.error) {
      console.error(`awskms-openssl-provider: ${r.error.message}`);
      process.exit(1);
    }
    process.exit(r.status ?? 1);
  }

  case '--version':
  case '-v':
    console.log(version);
    break;

  case undefined:
  case '--help':
  case '-h':
    usage(0);
    break;

  default:
    console.error(`unknown command: ${cmd}`);
    usage(1);
}
