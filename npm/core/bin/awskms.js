#!/usr/bin/env node
/*
 * The ergonomic half of the package. Everything here is reachable
 * programmatically too; this exists so the common cases are one command and no
 * code.
 *
 *   @keyobject/aws-kms check        is it working, and if not, why
 *   @keyobject/aws-kms config-path   print the --openssl-config path
 *   @keyobject/aws-kms exec -- node app.mjs
 *                                         run something with the provider active
 *
 * `exec` exists because the provider cannot be activated from inside a running
 * process via a config file -- OpenSSL reads its config once at library init --
 * so the flag has to be on the command line that starts node. Making the user
 * compose that by hand is where the four silent-failure traps live.
 */
import { spawnSync } from 'node:child_process';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isSupported, modulePath, opensslConfigPath, version } from '../index.js';

const [cmd, ...rest] = process.argv.slice(2);

function usage(code) {
  console.log(`@keyobject/aws-kms ${version}

  check [--replace-openssl-config]
                  whether the packaged provider is loadable and reachable
  config-path     print the path to a generated openssl.cnf
  module-path     print the path to the native module
  exec [--replace-openssl-config] -- <cmd>
                  run <cmd> with the provider activated

The check and exec commands refuse to replace an existing OpenSSL config unless
--replace-openssl-config is explicit.`);
  process.exit(code);
}

function parseReplaceOption(args) {
  let replace = false;
  for (const arg of args) {
    if (arg === '--replace-openssl-config') replace = true;
    else {
      console.error(`unknown option: ${arg}`);
      usage(1);
    }
  }
  return replace;
}

function hasOpenSSLConfig(args) {
  return args.some((arg) => arg === '--openssl-config' ||
    arg.startsWith('--openssl-config='));
}

function existingConfigSources(targetArguments = []) {
  const sources = [];
  if (process.env.OPENSSL_CONF) sources.push('OPENSSL_CONF');
  if (hasOpenSSLConfig(parseNodeOptions(process.env.NODE_OPTIONS))) {
    sources.push('NODE_OPTIONS');
  }
  if (hasOpenSSLConfig(process.execArgv)) {
    sources.push('the current node command line');
  }
  if (hasOpenSSLConfig(targetArguments)) sources.push('the target command line');
  return sources;
}

function requireConfigPermission(replace, targetArguments) {
  const sources = existingConfigSources(targetArguments);
  if (sources.length !== 0 && !replace) {
    console.error(
      `ERR_AWSKMS_OPENSSL_CONFIG_EXISTS: refusing to replace the OpenSSL config from ${sources.join(', ')}.`);
    console.error('Pass --replace-openssl-config to make that replacement explicit.');
    process.exit(1);
  }
}

function parseNodeOptions(value) {
  const args = [];
  let current = '';
  let quote;
  let escaped = false;

  for (const character of value ?? '') {
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === '\\' && quote !== "'") {
      escaped = true;
    } else if (quote !== undefined) {
      if (character === quote) quote = undefined;
      else current += character;
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (/\s/u.test(character)) {
      if (current !== '') {
        args.push(current);
        current = '';
      }
    } else {
      current += character;
    }
  }
  if (escaped) current += '\\';
  if (quote !== undefined) throw new Error('NODE_OPTIONS contains an unmatched quote');
  if (current !== '') args.push(current);
  return args;
}

function withoutOpenSSLConfig(args) {
  const retained = [];
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--openssl-config') {
      index++;
    } else if (!args[index].startsWith('--openssl-config=')) {
      retained.push(args[index]);
    }
  }
  return retained;
}

function nodeOptionsWithConfig(path) {
  const retained = withoutOpenSSLConfig(parseNodeOptions(process.env.NODE_OPTIONS));
  retained.push(`--openssl-config=${path}`);
  return retained.map((argument) => JSON.stringify(argument)).join(' ');
}

function isNodeTarget(command) {
  const name = basename(command).toLowerCase();
  return command === process.execPath || name === basename(process.execPath).toLowerCase() ||
    name === 'node' || name === 'node.exe' || name === 'nodejs' || name === 'nodejs.exe';
}

function environmentWithConfig(path, replace) {
  const env = { ...process.env, OPENSSL_CONF: path };
  if (replace) {
    env.NODE_OPTIONS = nodeOptionsWithConfig(path);
  }
  return env;
}

switch (cmd) {
  case 'module-path':
    console.log(modulePath());
    break;

  case 'config-path':
    console.log(opensslConfigPath());
    break;

  case 'check': {
    const replace = parseReplaceOption(rest);
    requireConfigPermission(replace);
    /* The check has to run in a process where the provider is ACTIVE, and this
     * one is not -- so re-exec rather than import it. Same reason `exec` exists. */
    const check = fileURLToPath(new URL('../check.mjs', import.meta.url));
    const config = opensslConfigPath();
    const r = spawnSync(process.execPath,
      [`--openssl-config=${config}`, check],
      { stdio: 'inherit', env: environmentWithConfig(config, replace) });
    process.exit(r.status ?? 1);
  }

  case 'exec': {
    const sep = rest.indexOf('--');
    if (sep === -1) usage(1);
    const replace = parseReplaceOption(rest.slice(0, sep));
    let argv = rest.slice(sep + 1);
    if (!argv.length) usage(1);
    requireConfigPermission(replace, argv.slice(1));
    if (replace && isNodeTarget(argv[0])) {
      argv = [argv[0], ...withoutOpenSSLConfig(argv.slice(1))];
    }
    const support = isSupported();
    if (!support.ok) {
      console.error(`@keyobject/aws-kms: ${support.code}: ${support.reason}`);
      process.exit(1);
    }
    const config = opensslConfigPath();
    const r = spawnSync(argv[0], argv.slice(1), {
      stdio: 'inherit',
      env: environmentWithConfig(config, replace),
    });
    if (r.error) {
      console.error(`@keyobject/aws-kms: ${r.error.message}`);
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
