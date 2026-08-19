# @keyobject/aws-kms

Use AWS KMS asymmetric signing keys from Node.js `crypto` as ordinary
`KeyObject`s. Private key material never leaves KMS.

```js
import { createPrivateKey, sign } from 'node:crypto';
import { promisify } from 'node:util';

const signAsync = promisify(sign);

const key = createPrivateKey({
  key: new URL('aws-kms:key-id=alias/my-signing-key;region=eu-central-1'),
});
const signature = await signAsync('sha256', Buffer.from('message'), key);
```

## Requirements

- Node.js `>=26.7.0` **with the OpenSSL STORE URL-key loader**. The npm engine
  range will expand when the feature is backported; the package also exercises
  the API so custom builds that omit the loader fail clearly.
- OpenSSL 3.0 or later for config-based provider loading. In-process
  `register()` additionally requires OpenSSL 3.5 or later. Stock Node uses its
  bundled OpenSSL; no system OpenSSL package is needed.
- AWS credentials and region configuration accepted by the normal AWS SDK
  credential chain.

Run `npx @keyobject/aws-kms check` or call `isSupported()` for the functional
runtime result.

## Install

```console
npm install @keyobject/aws-kms
```

One exact-version optional dependency supplies the native binary for the current
platform. Nothing runs or downloads code at install time, so installation also
works with `--ignore-scripts`. At runtime the core package verifies the
satellite package name, version, OS, CPU, libc, config template, and module
contents before loading anything.

Prebuilt targets are `darwin-{arm64,x64}`, `linux-{arm64,x64}`, and
`linuxmusl-{arm64,x64}`. The two musl targets are experimental. Other platforms
are not supported by the npm package.

## Activate the provider

OpenSSL must load the provider before `createPrivateKey()` sees an `aws-kms:`
URL. Choose one route.

### Config route

```console
node --openssl-config="$(npx @keyobject/aws-kms config-path)" app.js
```

Or resolve it in code before starting a child process:

```js
import { opensslConfigPath } from '@keyobject/aws-kms';

console.log(opensslConfigPath());
```

The generated config lives in a randomized, owner-only process directory. It is
created without following links, is readable only by its owner, and is validated
on every call. Its path is stable and shared by the main thread and every Worker
for the life of the process. The module path is quoted and escaped for OpenSSL
config syntax.

Under Node's permission model, this route needs `--allow-openssl-store`.

### In-process route

```console
node --import @keyobject/aws-kms/register app.mjs
```

Use this as a startup preload, before application crypto code or Workers fetch
OpenSSL algorithms. Registration mutates OpenSSL's process-wide default
property query through an API OpenSSL documents as not thread-safe. It requires
OpenSSL 3.5 or later so registration can preserve the
existing default property policy. It throws if loading fails and is idempotent
after the first successful registration. Under the permission model it
additionally needs `--allow-addons` and filesystem read access to the installed
packages, so the config route is preferable for restricted processes or
OpenSSL 3.0--3.4.

## CLI

```console
npx @keyobject/aws-kms check
npx @keyobject/aws-kms module-path
npx @keyobject/aws-kms config-path
npx @keyobject/aws-kms exec -- node app.js
```

`check` and `exec` refuse to replace an OpenSSL config supplied through
`OPENSSL_CONF`, `NODE_OPTIONS`, or the current Node command line. If replacing it
is intentional, say so explicitly:

```console
npx @keyobject/aws-kms exec --replace-openssl-config -- node app.js
```

## Compatibility check

```js
import { isSupported } from '@keyobject/aws-kms';

const support = isSupported();
if (!support.ok) {
  console.error(support.code, support.reason);
}
```

The result is a discriminated TypeScript union:

```ts
{ ok: true }
{ ok: false; code: AwsKmsSupportFailureCode; reason: string }
```

Important failure codes include:

- `ERR_AWSKMS_UNSUPPORTED_RUNTIME`: this Node build cannot load URL keys.
- `ERR_AWSKMS_PERMISSION_DENIED`: Node or the filesystem denied the required access.
- `ERR_AWSKMS_RUNTIME_PROBE_FAILED`: the functional URL-key probe failed unexpectedly.
- `ERR_AWSKMS_MODULE_NOT_FOUND`: the platform optional dependency is absent.
- `ERR_AWSKMS_VERSION_MISMATCH`: core and native satellite versions differ.
- `ERR_AWSKMS_INVALID_PLATFORM_PACKAGE`: satellite identity or platform
  metadata is wrong.
- `ERR_AWSKMS_PACKAGE_INTEGRITY` / `ERR_AWSKMS_TEMP_INTEGRITY`: a validated
  package or private runtime file changed.

## Package API

| Export | Purpose |
| --- | --- |
| `version` | Core package version |
| `isSupported()` | Non-throwing runtime and platform-package check |
| `modulePath()` | Verified absolute native module path |
| `opensslConfigPath()` | Private config path that activates the provider |
| `register()` | Idempotent startup registration on OpenSSL 3.5+ |

On OpenSSL 3.0 through 3.4, `register()` throws
`ERR_AWSKMS_OPENSSL_VERSION`; use config-file activation on those runtimes.

The side-effect subpath `@keyobject/aws-kms/register` calls `register()`.

## URI security and configuration

The URI form is:

```text
aws-kms:key-id=<key id | key ARN | alias | alias ARN>[;region=<region>][?profile=<profile>&endpoint=<URL>]
```

URI settings win over AWS environment/shared-profile settings, which win over
provider-config defaults. Credential values still follow the AWS SDK default
credential chain. Treat the URI as trusted configuration: `profile` can select
a different AWS identity and `endpoint` changes the destination of signed KMS
requests. Do not accept those fields from untrusted users.

Applications need only `kms:GetPublicKey` and `kms:Sign` on the intended key
ARNs. Verification is local.

## FIPS boundary

With `fips=yes`, local digest, SHAKE, SPKI, and verification work is routed to
another FIPS-capable provider and the AWS SDK is forced to use an AWS KMS FIPS
endpoint. Endpoint overrides and China regions are rejected. The host must
provide its OpenSSL FIPS module. This provider binary is not independently
CMVP certified; its `fips=yes` property describes composite routing, not a
certification. See the official
[AWS KMS endpoint table](https://docs.aws.amazon.com/general/latest/gr/kms.html)
and [data-protection documentation](https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html).
AWS also documents that its KMS ML-DSA operations run in FIPS 140-3 Security
Level 3 validated HSMs in
[ML-DSA keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html).

## Bundlers

Mark `@keyobject/aws-kms` and its optional platform packages as external. They
resolve native files at runtime and cannot be inlined into a JavaScript bundle.

## Scope

The provider supports signing and public-key export for AWS KMS RSA, NIST EC,
Ed25519, and ML-DSA signing keys. Decryption and key agreement are not
implemented. AWS documents ML-DSA behavior and regional availability in
[ML-DSA keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html).

## License

The JavaScript package is MIT licensed. Native satellite packages include the
licenses and attribution notices for their statically linked dependencies.
