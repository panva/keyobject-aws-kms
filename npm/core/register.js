/*
 * Side-effect entry point:
 *
 *   import 'awskms-openssl-provider/register';
 *   node --import awskms-openssl-provider/register app.mjs
 *
 * Exists so activation is one line with no call to remember. It is deliberately
 * a separate subpath rather than a side effect of the main module: importing a
 * package should not silently register an OpenSSL provider in the process.
 *
 * "sideEffects" in package.json names this file, so a bundler cannot tree-shake
 * the import away on the grounds that nothing is used from it -- which is the
 * whole point of the module.
 */
import { register } from './index.js';

register();
