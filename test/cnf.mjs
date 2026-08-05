/*
 * The openssl.cnf that activates this provider.
 *
 * Shared by the test driver and the CloudTrail audit so the two cannot drift.
 * Three properties of this file are load-bearing and each fails in a way that
 * looks like something else:
 *
 *   nodejs_conf          Node reads this key; a file declaring only
 *                        `openssl_conf` is silently ignored.
 *   default activated    Node aborts at startup otherwise, in ncrypto's CSPRNG
 *                        assertion, with nothing pointing at the config.
 *   default_properties   without it a bare-name algorithm fetch can resolve to
 *                        this provider and break unrelated crypto in the
 *                        process.
 */
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export async function writeCnf(modulePath) {
  const dir = await mkdtemp(join(tmpdir(), 'awskms-cnf-'));
  const cnf = join(dir, 'awskms.cnf');
  await writeFile(
    cnf,
    `openssl_conf = awskms_init
nodejs_conf  = awskms_init

[awskms_init]
providers   = provider_sect
alg_section = algs_sect

[algs_sect]
default_properties = ?provider!=awskms

[provider_sect]
default = default_sect
awskms  = awskms_sect

[default_sect]
activate = 1

[awskms_sect]
module   = ${modulePath}
activate = 1
`,
  );
  return cnf;
}
