# Installation and configuration

The supported installation path is the `@keyobject/aws-kms` npm package. Source
builds are intended for contributors and do not define an install target; see
[Contributing](https://github.com/panva/keyobject-aws-kms/blob/main/CONTRIBUTING.md).

## Runtime requirements

The package currently advertises Node.js `>=26.7.0`, the first supported
release whose `crypto.createPrivateKey()` accepts a `URL` and dispatches it
through OpenSSL STORE. The engine range will expand when that capability is
backported. The installer and `check` command still probe the capability so a
custom build that omits it fails clearly.
Stock Node distributions use their bundled OpenSSL; npm users do not need to
install a separate system OpenSSL package.

Check the runtime and installed native package without throwing:

```js
import { isSupported } from '@keyobject/aws-kms';

const support = isSupported();
if (!support.ok) {
  console.error(support.code, support.reason);
}
```

Or run the end-to-end activation check:

```console
npx @keyobject/aws-kms check
```

The readiness probe uses an intentionally incomplete `aws-kms:` URI. Parsing
fails before credential resolution or a KMS call, so the check requires no AWS
account, makes no network request, and incurs no KMS charge.

Prebuilt packages are published for exactly six targets:

| Target | Status |
| --- | --- |
| `darwin-arm64` | supported |
| `darwin-x64` | supported |
| `linux-arm64` | supported, glibc |
| `linux-x64` | supported, glibc |
| `linuxmusl-arm64` | experimental, musl |
| `linuxmusl-x64` | experimental, musl |

The core and native package versions must be identical. The runtime validates
the native package name, version, OS, CPU, libc metadata, config template, and
module contents. Reinstall with optional dependencies enabled if the platform
package is absent:

```console
npm install --include=optional
```

### GitHub binary archives

Versioned GitHub release archives are a secondary distribution for the same six
targets. Select `awskms-<version>-<target>.tar.gz`, then verify its published
checksum and attestation before extraction. The archive contains one matching
top-level directory with the provider module, `awskms.cnf`, `check.mjs`, this
guide, the project license, the component manifest, and all third-party notices
and license texts.

The archive config is relocatable through `AWSKMS_MODULE`, which must be the
absolute path to the extracted module. For a Linux archive:

```console
cd awskms-<version>-linux-x64
export AWSKMS_MODULE="$(pwd -P)/aws-kms.so"
node --openssl-config="$(pwd -P)/awskms.cnf" "$(pwd -P)/check.mjs"
```

Use `aws-kms.dylib` for a Darwin archive. Keep `AWSKMS_MODULE` set when starting
the application, and apply the existing-config merge procedure below when the
process already has an OpenSSL configuration. The archive checker uses the same
zero-network readiness probe as the npm CLI.

## Activation routes

OpenSSL must activate the provider before Node attempts to load a key URL.

### OpenSSL config

This route supports OpenSSL 3.0 and later:

```console
node --openssl-config="$(npx @keyobject/aws-kms config-path)" app.mjs
```

For a one-command child process:

```console
npx @keyobject/aws-kms exec -- node app.mjs
```

`opensslConfigPath()` creates an owner-only config, shared by the main thread
and every Worker in one process, with the verified absolute module path
embedded in it. The file is created without following symbolic links and is
revalidated on every call.

```js
import { opensslConfigPath } from '@keyobject/aws-kms';

console.log(opensslConfigPath());
```

The generated config is standalone. Supplying it through `--openssl-config` or
`OPENSSL_CONF` replaces the process's other OpenSSL configuration; it does not
merge with it. The `check` and `exec` commands therefore refuse to replace an
existing config unless `--replace-openssl-config` is explicit.

### Startup registration

This route requires OpenSSL 3.5 or later:

```console
node --import @keyobject/aws-kms/register app.mjs
```

Use a startup preload instead of a late, conditional import. Registration must
preserve the process's existing default property policy and must happen before
application crypto code or Workers fetch algorithms. It mutates OpenSSL's
process-wide default property query through an API OpenSSL documents as not
thread-safe. The OpenSSL API needed to read that
policy, `EVP_get1_default_properties()`, was added in OpenSSL 3.5. On OpenSSL
3.0--3.4, use the config route.

The equivalent explicit API is:

```js
import { register } from '@keyobject/aws-kms';

register();
```

`register()` is idempotent after a successful call and throws when the provider
cannot be loaded. It operates on the process default OpenSSL library context.

### Node permission model

Loading any `aws-kms:` URL needs `--allow-openssl-store`. Startup registration
also loads a native addon and reads the installed packages, so it additionally
needs `--allow-addons` and appropriate filesystem-read permission. A restricted
deployment can use the config route to avoid granting addon loading.

```console
node --permission --allow-openssl-store \
  --openssl-config="$(npx @keyobject/aws-kms config-path)" app.mjs
```

Load required keys during startup. An application can then drop the
`openssl.store` permission if it will never load another key; already loaded
keys continue to sign.

## Package API and CLI

The package exports:

| API | Result |
| --- | --- |
| `version` | Version of the core package |
| `isSupported()` | `{ ok: true }` or `{ ok: false, code, reason }` |
| `modulePath()` | Verified absolute provider-module path |
| `opensslConfigPath()` | Verified private config path for this process |
| `register()` | In-process provider registration |

The side-effect subpath `@keyobject/aws-kms/register` invokes `register()`.

CLI commands are:

```console
npx @keyobject/aws-kms check
npx @keyobject/aws-kms module-path
npx @keyobject/aws-kms config-path
npx @keyobject/aws-kms exec -- node app.mjs
```

The CLI's `check` command uses the same `check.mjs` readiness probe as source
and binary-package validation. From a source checkout, a specific config can be
checked directly:

```console
node --openssl-config=/absolute/path/to/openssl.cnf scripts/check.mjs
```

To inspect a config without activating it, put the option after the script:

```console
node scripts/check.mjs --openssl-config=/absolute/path/to/openssl.cnf
```

## Merging into an existing OpenSSL config

Do not point `--openssl-config` at the generated standalone file if the process
already relies on FIPS settings, PKCS#11, legacy-provider configuration, or
another OpenSSL policy. Merge the AWS KMS provider into that config instead.

An OpenSSL `.include` of two standalone configs is insufficient. The default
section maps `nodejs_conf` to one initialization section, and that section's
`providers` and `alg_section` keys each point to one section. A later assignment
replaces a pointer; it does not combine two provider lists or two default
property policies.

Use this procedure:

1. Obtain the verified module path with
   `npx @keyobject/aws-kms module-path`.
2. Keep the existing top-level `nodejs_conf` assignment. If the same file also
   serves the OpenSSL CLI, keep its `openssl_conf` assignment too.
3. In the initialization section referenced by `nodejs_conf`, retain its
   `providers` section and add an `aws-kms` entry to that existing provider
   list. Do not remove FIPS, base, default, PKCS#11, or other providers.
4. Retain the existing algorithm section. Append
   `?keyobject.aws_kms!=yes` to its `default_properties` expression. For
   example, preserve FIPS as
   `fips=yes,?keyobject.aws_kms!=yes`.
5. Add a uniquely named AWS KMS section with the absolute module path and
   `activate = 1`. Add `region`, `profile`, or `endpoint` only if provider-wide
   fallbacks are desired.
6. If the original config activated no providers, explicitly activate the
   `default` provider as shown below. If it intentionally uses a different
   provider set, such as `base` plus `fips`, preserve that set instead.
7. Run `check.mjs` with the merged file before deployment.

A minimal non-FIPS merge looks like this:

```ini
openssl_conf = application_init
nodejs_conf  = application_init

[application_init]
providers   = application_providers
alg_section = application_algorithms

[application_algorithms]
default_properties = ?keyobject.aws_kms!=yes

[application_providers]
default = default_section
aws-kms = application_awskms

[default_section]
activate = 1

[application_awskms]
module   = /absolute/path/to/aws-kms.so
activate = 1
# region  = eu-central-1
# profile = production
# endpoint = http://127.0.0.1:4566
```

On macOS the module filename ends in `.dylib`. A FIPS config should keep its
existing provider activation and combine, rather than replace, its property
policy:

```ini
[application_algorithms]
default_properties = fips=yes,?keyobject.aws_kms!=yes
```

The optional marker prevents bare algorithm-name fetches for ordinary keys from
being captured by this provider. Explicitly loaded `aws-kms:` keys remain usable.

## URI and AWS configuration precedence

The URI grammar is:

```text
aws-kms:key-id=<key id | key ARN | alias | alias ARN>[;region=<region>][?profile=<profile>&endpoint=<URL>]
```

Path values use percent encoding. Query values use standard WHATWG
`URLSearchParams` decoding. Unknown, repeated, empty required, or conflicting
attributes are rejected.

Settings are selected independently in the following order; the first present
value wins:

| Setting | Precedence |
| --- | --- |
| profile | URI `?profile` -> `AWS_DEFAULT_PROFILE` -> `AWS_PROFILE` -> an available shared `default` profile -> provider `profile` -> SDK default |
| region | URI `;region` or the region in a KMS ARN -> `AWS_DEFAULT_REGION` -> `AWS_REGION` -> selected shared-profile `region` -> provider `region` -> SDK default |
| endpoint | URI `?endpoint` -> `AWS_ENDPOINT_URL_KMS` -> `AWS_ENDPOINT_URL` -> selected shared profile's KMS service endpoint -> that profile's global `endpoint_url` -> provider `endpoint` -> normal regional KMS endpoint |

These rules select client settings. Credential values still come from the AWS
SDK default credential chain, including environment credentials, shared config
and credentials files, SSO and assume-role profiles, ECS/EKS credentials, and
EC2 instance metadata.

`AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` or the selected profile's
`ignore_configured_endpoint_urls=true` suppresses the AWS endpoint entries in
the table, after which a provider `endpoint` fallback can still apply. In FIPS
mode, every resolved endpoint override is rejected regardless of its source.

Provider-section defaults exist only when the provider is config-loaded. The
startup-registration route has no provider config section, so use URI or AWS
configuration with that route.

Treat the complete URI as trusted configuration. `profile` can select a
different AWS identity and `endpoint` can route signed requests to another
server. Applications accepting tenant input should construct the URI from
allowlisted key identifiers and regions and should not expose `profile` or
`endpoint` as user-controlled fields.

## FIPS deployments

An OpenSSL default or operation property query containing `fips=yes` activates
the provider's composite FIPS routing:

- internal digest, SHAKE, SPKI, and verification fetches require `fips=yes` and
  exclude the AWS KMS provider itself;
- the AWS SDK is told to use a KMS FIPS endpoint;
- URI, environment, shared-profile, and provider endpoint overrides are
  rejected;
- China regions are rejected because this route requires the documented
  CMVP-validated service boundary.

The host is responsible for installing and configuring an OpenSSL FIPS module.
This provider binary is not independently CMVP certified. Its `fips=yes`
algorithm property is a statement about the composite routing above, not a
certificate for the binary.

Verify regional service support against the official
[AWS KMS endpoints](https://docs.aws.amazon.com/general/latest/gr/kms.html) and
[AWS KMS data-protection boundary](https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html).
AWS states that KMS ML-DSA operations run in FIPS 140-3 Security Level 3
validated HSMs in its
[ML-DSA documentation](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html).

## IAM minimum

Grant the application only `kms:GetPublicKey` and `kms:Sign` on the intended
key ARNs. The provider does not need `kms:Verify`, `kms:DescribeKey`, decryption,
or key-administration permissions. KMS key policies must also permit the chosen
principal.

## AWS error diagnostics

Node exposes the provider's stable OpenSSL error code, but not the detailed AWS
SDK exception attached to that error. To diagnose a connection, endpoint, or
service failure, set `AWSKMS_AWS_LOG_ERRORS=1` before the process starts. The
provider then writes the AWS exception name and message to standard error for
failed KMS calls. The text is made single-line but can contain AWS resource,
account, and endpoint details; handle it as operational log data. Leave the
flag unset during normal operation.
