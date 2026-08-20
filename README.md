# @keyobject/aws-kms

`@keyobject/aws-kms` uses AWS KMS asymmetric signing keys as ordinary Node.js
`KeyObject` instances. Private key material stays in KMS; signing calls KMS,
while public-key export and verification use the public key cached when the key
is loaded.

## [💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is
welcome. If you find the module useful, please consider supporting the project
by [becoming a sponsor](https://github.com/sponsors/panva).

## Quick Start

```js
import '@keyobject/aws-kms/register'
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { promisify } from 'node:util'

const signAsync = promisify(sign)

const key = createPrivateKey({
  key: new URL('aws-kms:key-id=alias/my-rsa-signer;region=eu-central-1'),
})
const data = Buffer.from('message')
const signature = await signAsync('sha256', data, key)

verify('sha256', data, createPublicKey(key), signature) // true, no KMS call
```

The alias in this example must identify an RSA `SIGN_VERIFY` key. See
[Supported Keys](#supported-keys) for the parameters used by other key types.

`promisify(sign)` also turns validation errors that `sign()` throws before it
queues its callback into promise rejections, so one `await`/`try` boundary handles
both synchronous validation failures and asynchronous signing failures.

## Performance and Concurrency

An `aws-kms:` key is deliberately much more expensive than an ordinary local
private key:

- `createPrivateKey()` makes a synchronous KMS `GetPublicKey` request and parses
  the result. It blocks the calling JavaScript thread, so load each key once at
  startup and cache its `KeyObject` instead of loading it per request.
- Every signature makes a remote, billable KMS `Sign` request. Use the callback
  form of `sign()` (promisified as above) or `crypto.subtle.sign()` so the main
  event loop does not wait synchronously for the network round trip. Avoid
  callback-free `sign()` and `createSign().sign()` on a server request path.
- Async signing still occupies Node's shared crypto work queue and remains
  subject to KMS latency, quotas, and cost. Apply backpressure and a bounded
  concurrency limit; unbounded `Promise.all()` does not increase capacity.
  `UV_THREADPOOL_SIZE` is another process-startup tuning option, but that pool is
  shared with other Node operations and should be changed only after measuring.
- To isolate blocking calls from both the main event loop and its async crypto
  queue, run synchronous key loading and signing in a bounded `Worker` pool. A
  Worker may retain and sign with the key itself. Alternatively, it may load the
  key and send the resulting `KeyObject` back to the main thread with
  `postMessage(key)`, moving just the synchronous `GetPublicKey` step off the
  main thread. Node clones `KeyObject`s for `postMessage()`; do not put the key in
  the transfer list.

Workers isolate blocking work but do not make KMS faster. Choose and measure a
bounded design appropriate for the application's latency target and KMS quota.

## Requirements

- Node.js `>=26.7.0` with the OpenSSL STORE URL-key loader. A functional probe
  also detects custom builds that omit it.
- OpenSSL 3.0 or later for config-based activation. In-process `register()`
  additionally requires OpenSSL 3.5 or later. Stock Node uses its bundled
  OpenSSL; no system OpenSSL package is needed.
- AWS credentials available through the SDK credential chain, plus a region in
  the key URI or supported AWS/provider configuration.

## Install

```console
npm install @keyobject/aws-kms
npx @keyobject/aws-kms check
```

The core package selects one exact-version native package at runtime. Prebuilt
targets are:

- `darwin-arm64` (macOS 13.5+)
- `linux-arm64` (glibc 2.28+)
- `linux-x64` (glibc 2.28+)
- `linuxmusl-arm64` (experimental)
- `linuxmusl-x64` (experimental)

No lifecycle script runs during `npm install`, and the package performs no
secondary downloads. The package advertises Node.js `>=26.7.0` as its runtime
floor for URL-key support. `isSupported()` and the `check` command still
exercise the required capability with a functional probe instead of relying on
the version number alone.

See [Installation and configuration](https://github.com/panva/keyobject-aws-kms/blob/main/docs/INSTALL.md)
for platform details, OpenSSL configuration merging, the Node permission model,
and troubleshooting.

## Activate the Provider

OpenSSL must know about the provider before an `aws-kms:` key is loaded. Choose
one route.

The config route works with OpenSSL 3.0 and later:

```console
node --openssl-config="$(npx @keyobject/aws-kms config-path)" app.mjs
```

The in-process route requires OpenSSL 3.5 or later and must run as a startup
preload, before application crypto code or Workers. It mutates OpenSSL's
process-wide default property query through an API OpenSSL documents as not
thread-safe:

```console
node --import @keyobject/aws-kms/register app.mjs
```

The preload throws if registration fails. Use the config route on OpenSSL
3.0--3.4 or when Node's permission model should not grant native-addon loading.

## CLI

```console
npx @keyobject/aws-kms check
npx @keyobject/aws-kms module-path
npx @keyobject/aws-kms config-path
npx @keyobject/aws-kms exec -- node app.mjs
```

`check` and `exec` refuse to replace an OpenSSL config supplied through
`OPENSSL_CONF`, `NODE_OPTIONS`, or the current or target Node command line. If
replacing it is intentional, say so explicitly:

```console
npx @keyobject/aws-kms exec --replace-openssl-config -- node app.mjs
```

## Compatibility Check

```js
import { isSupported } from '@keyobject/aws-kms'

const support = isSupported()
if (!support.ok) {
  console.error(support.code, support.reason)
}
```

The result is a discriminated TypeScript union:

```ts
{ ok: true }
{ ok: false; code: AwsKmsSupportFailureCode; reason: string }
```

Important failure codes include:

- `ERR_AWSKMS_UNSUPPORTED_RUNTIME`: this Node build cannot load URL keys.
- `ERR_AWSKMS_PERMISSION_DENIED`: Node or the filesystem denied the required
  access.
- `ERR_AWSKMS_RUNTIME_PROBE_FAILED`: the functional URL-key probe failed
  unexpectedly.
- `ERR_AWSKMS_MODULE_NOT_FOUND`: the platform is not published or its optional
  dependency is absent.
- `ERR_AWSKMS_VERSION_MISMATCH`: core and native platform package versions
  differ.
- `ERR_AWSKMS_INVALID_PLATFORM_PACKAGE`: platform package identity or metadata
  is wrong.
- `ERR_AWSKMS_PACKAGE_INTEGRITY` / `ERR_AWSKMS_TEMP_INTEGRITY`: a validated
  package or private runtime file changed.

## URI Syntax

```text
aws-kms:key-id=<key id | key ARN | alias | alias ARN>[;region=<region>][?profile=<profile>&endpoint=<URL>]
```

Examples:

```text
aws-kms:key-id=alias/my-signer
aws-kms:key-id=alias/my-signer;region=eu-central-1
aws-kms:key-id=arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
aws-kms:key-id=alias/my-signer;region=eu-west-1?profile=production
```

Client settings resolve in this order: URI attributes, then AWS environment and
the selected shared profile, then defaults in the provider's OpenSSL config
section. A KMS ARN supplies its region; an explicit conflicting region is
rejected. Credential material itself follows the AWS SDK default credential
chain.

The URI is trusted configuration, not an untrusted request parameter. In
particular, `profile` selects credentials and `endpoint` changes the network
destination for signed AWS requests. See the
[Security Policy](https://github.com/panva/keyobject-aws-kms/blob/main/SECURITY.md).

## Supported Keys

Pass the object in the last column as the first argument to
`key.toCryptoKey(algorithm, false, ['sign'])`:

For RSA, choose `hash` independently as `'SHA-256'`, `'SHA-384'`, or
`'SHA-512'`. Every listed RSA key size supports every listed hash.

| AWS KMS key spec | Supported signing | WebCrypto algorithm for `toCryptoKey()` |
| --- | --- | --- |
| `RSA_2048` | PKCS#1 v1.5 and PSS | `{ name: 'RSASSA-PKCS1-v1_5', hash }` or `{ name: 'RSA-PSS', hash }` |
| `RSA_3072` | PKCS#1 v1.5 and PSS | `{ name: 'RSASSA-PKCS1-v1_5', hash }` or `{ name: 'RSA-PSS', hash }` |
| `RSA_4096` | PKCS#1 v1.5 and PSS | `{ name: 'RSASSA-PKCS1-v1_5', hash }` or `{ name: 'RSA-PSS', hash }` |
| `ECC_NIST_P256` | ECDSA with SHA-256 | `{ name: 'ECDSA', namedCurve: 'P-256' }` |
| `ECC_NIST_P384` | ECDSA with SHA-384 | `{ name: 'ECDSA', namedCurve: 'P-384' }` |
| `ECC_NIST_P521` | ECDSA with SHA-512 | `{ name: 'ECDSA', namedCurve: 'P-521' }` |
| `ECC_NIST_EDWARDS25519` | Ed25519 (`ED25519_SHA_512`) | `{ name: 'Ed25519' }` |
| `ML_DSA_44` | ML-DSA (`ML_DSA_SHAKE_256`) | `{ name: 'ML-DSA-44' }` |
| `ML_DSA_65` | ML-DSA (`ML_DSA_SHAKE_256`) | `{ name: 'ML-DSA-65' }` |
| `ML_DSA_87` | ML-DSA (`ML_DSA_SHAKE_256`) | `{ name: 'ML-DSA-87' }` |

RSA-PSS also requires `saltLength` of 32, 48, or 64 for SHA-256, SHA-384, or
SHA-512 respectively in the algorithm passed to `subtle.sign()`. For ECDSA, the
operation algorithm is
`{ name: 'ECDSA', hash: 'SHA-256' }`, `SHA-384`, or `SHA-512` respectively; the
curve belongs only to the `toCryptoKey()` algorithm shown above. A public key uses
the same conversion algorithm with `createPublicKey(key).toCryptoKey(algorithm,
true, ['verify'])`.

Ed25519 messages must be between 1 and 4096 bytes. RSA and ECDSA send a digest,
and ML-DSA sends a locally computed 64-byte external representative, so those
paths do not inherit that message-size limit. AWS documents current ML-DSA
behavior and regional availability in
[ML-DSA keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html).

The provider implements signing and public-key export. It does not implement
decryption or key agreement. Node WebCrypto can use a loaded key through
`KeyObject#toCryptoKey()` where Node supports the corresponding algorithm.

## IAM

An application needs only these permissions on the keys it uses:

- `kms:GetPublicKey` when a key is loaded;
- `kms:Sign` when a signature is produced.

Verification is local, so the provider does not call `kms:Verify` or
`kms:DescribeKey`. Scope both actions to the intended key ARNs and retain normal
KMS key-policy controls.

## FIPS Boundary

When the OpenSSL operation requests `fips=yes`, the provider applies a composite
routing policy:

- its KMS key operations remain selectable under the FIPS property policy;
- digest, SHAKE, SPKI parsing, and local verification are fetched from another
  provider with `fips=yes`;
- AWS SDK clients are forced to AWS KMS FIPS endpoints;
- endpoint overrides and China regions are rejected for that operation.

The host must supply and correctly configure an OpenSSL FIPS implementation.
The `@keyobject/aws-kms` provider binary is not independently CMVP certified;
its `fips=yes` declaration describes this routing contract, not a certification
of the provider binary. Consult the official
[AWS KMS endpoint table](https://docs.aws.amazon.com/general/latest/gr/kms.html)
and [AWS KMS data-protection documentation](https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html)
for the service boundary. AWS also states that KMS ML-DSA operations run in
FIPS 140-3 Security Level 3 validated HSMs in its
[ML-DSA documentation](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html).

## Package API

```js
import {
  isSupported,
  modulePath,
  opensslConfigPath,
  register,
  version,
} from '@keyobject/aws-kms'
```

| Export | Purpose |
| --- | --- |
| `version` | Core package version |
| `isSupported()` | Non-throwing runtime and native-package capability check |
| `modulePath()` | Verified absolute path to the platform provider module |
| `opensslConfigPath()` | Private config shared by the main thread and Workers in one process |
| `register()` | Idempotent in-process registration; requires OpenSSL 3.5+ |

The side-effect entry point `@keyobject/aws-kms/register` calls `register()`.
The CLI also exposes `check`, `module-path`, `config-path`, and `exec`.

The package is ESM. Node's `require(esm)` support is enabled throughout the
declared runtime range, so `require('@keyobject/aws-kms')` also works.

On OpenSSL 3.0 through 3.4, `register()` throws
`ERR_AWSKMS_OPENSSL_VERSION`; use config-file activation on those runtimes.

## Bundlers

Mark `@keyobject/aws-kms` and its optional platform packages as external. They
resolve native files at runtime and cannot be inlined into a JavaScript bundle.

## Documentation

Source builds are contributor workflows, not the installation interface. They
require CMake 3.25 or newer, an explicit `AWSKMS_BACKEND=stub|aws`, and have no
CMake install target. See
[Contributing](https://github.com/panva/keyobject-aws-kms/blob/main/CONTRIBUTING.md).

- [Documentation index](https://github.com/panva/keyobject-aws-kms/blob/main/docs/README.md)
- [Installation and configuration](https://github.com/panva/keyobject-aws-kms/blob/main/docs/INSTALL.md)
- [Security policy and deployment guidance](https://github.com/panva/keyobject-aws-kms/blob/main/SECURITY.md)
- [Real AWS KMS test setup](https://github.com/panva/keyobject-aws-kms/blob/main/docs/real-kms-setup.md)
- [Code of Conduct](https://github.com/panva/keyobject-aws-kms/blob/main/CODE_OF_CONDUCT.md)
- [Third-party notices](https://github.com/panva/keyobject-aws-kms/blob/main/THIRD_PARTY_NOTICES.md)

## License

The project is MIT licensed. Native packages include licenses and attribution
notices for statically linked dependencies.
