# tiny-aws-kms-openssl-provider

An OpenSSL provider that lets **Node.js** use AWS KMS asymmetric keys through the
ordinary `node:crypto` and WebCrypto APIs, so a private key that never leaves KMS
looks like any other `KeyObject`.

```js
const key = createPrivateKey({
  key: new URL('awskms:key-id=alias/my-signer;region=eu-central-1'),
});
createSign('sha256').update(data).sign(key);          // -> kms:Sign
createPublicKey(key).export({ type: 'spki', format: 'pem' });   // cached, no network
```

Signing is the only thing that goes to AWS. Verification runs locally against the
public key fetched once at load, so it needs no `kms:Verify` permission, costs
nothing, and works offline.

## Scope

**This targets Node.js specifically.** It is technically an OpenSSL provider and
nothing stops another program loading it, but the supported surface is the subset
Node reaches, and that is what is designed for and tested. It is not intended as a
general-purpose AWS KMS provider — no `openssl` CLI workflows, no TLS, no
engine-style drop-in for arbitrary applications.

> **Requires a Node.js with OSSL_STORE loader support**, i.e. the ability to pass a
> `URL` to `crypto.createPrivateKey()`. That landed in Node main on 2026-08-02 and
> is in the nightly builds; it is not in a released Node yet. The test driver
> detects it and reports when it is missing.

> **Status: in development.** Signing works for every key spec below and is
> verified against both a local KMS stub and the real AWS SDK. Distribution is
> undecided, so the build instructions below are developer-facing rather than an
> install guide.

## Supported keys

| KMS key spec | signing algorithm | notes |
| --- | --- | --- |
| `RSA_2048` / `RSA_3072` / `RSA_4096` | `RSASSA_PKCS1_V1_5_SHA_*`, `RSASSA_PSS_SHA_*` | PSS salt length is always the digest length — KMS offers no choice |
| `ECC_NIST_P256` / `P384` / `P521` | `ECDSA_SHA_256` / `384` / `512` | one digest per curve |
| `ECC_SECG_P256K1` | `ECDSA_SHA_256` | signatures are **not** low-S normalised; consumers requiring BIP-62/EIP-2 canonical form must normalise them |
| `ECC_NIST_EDWARDS25519` | `ED25519_SHA_512` | **messages are limited to 4096 bytes** — see below |
| `ML_DSA_44` / `ML_DSA_65` / `ML_DSA_87` | `ML_DSA_SHAKE_256` | no message size limit |

`SM2` is not supported.

### Ed25519 is capped at 4096 bytes

Ed25519 cannot be pre-hashed, so the whole message has to reach KMS, and KMS
caps `Sign`'s `Message` at 4096 bytes. Signing more than that fails with
`ERR_OSSL_AWSKMS_MESSAGE_TOO_LARGE`. This is inherent, not an implementation
limit: the alternative algorithm `ED25519_PH_SHA_512` cannot help, because KMS
performs the SHA-512 prehash itself, so handing it `SHA-512(M)` produces a
signature over `SHA-512(SHA-512(M))` that no standard verifier accepts.

Every other key spec is unaffected. RSA and ECDSA send only a digest, and ML-DSA
sends a 64-byte FIPS 204 μ computed locally, so all of them sign inputs of any
size.

## Building

There is no libcrypto on the link line. The module compiles against OpenSSL
*headers* only and binds its OpenSSL symbols at `dlopen()` time to whatever
OpenSSL the host process already has. That is what lets one binary work both in a
stock nodejs.org build, whose OpenSSL is statically linked into the executable,
and in a `node` built `--shared-openssl` against a system libcrypto.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel
```

To build against a particular OpenSSL's headers — this sets the *floor* of the
supported runtime range, not a pin:

```bash
cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
```

The module is built for size rather than speed, taking it from 5.1 MB to
**2.1 MB**: `-Oz`/`-Os`, `-ffunction-sections`/`-fdata-sections` paired with
`-dead_strip` or `--gc-sections`, `-Wl,-x` in Release, and `-ffile-prefix-map` so
build paths do not ship. Nothing here is CPU-bound — the time goes to a KMS round
trip — and only two KMS operations are reachable from `OSSL_provider_init`, so the
linker can discard most of the SDK.

What remains is about 1.1 MB of code, of which **13 KB is this provider**. The
rest is what a self-contained AWS client costs: a TLS 1.2/1.3 implementation
(232 KB), the SDK's generic client machinery (263 KB), and static
initialisers and registries (277 KB), plus 359 KB of error and exception strings.

The credential chain is the shape of it. `aws-c-auth` itself is only 18 KB, but
resolving credentials from IMDS, ECS, SSO or STS means making HTTPS calls, so it
pulls in TLS, HTTP/1.1+2, an event loop and sockets. Roughly 300 KB exists so that
18 KB can establish who you are — the price of not reimplementing credential
resolution.

Verified to compile clean and load correctly with headers from OpenSSL 3.0.21,
3.5.7, 3.6.3 and 4.0.1, in every combination of build-header and host version
tested.

The static and shared cases are both exercised, not just the linkage. The full
suite passes identically against three hosts at the same OpenSSL version, so
linkage is the only variable between them:

- a Node built `--shared-openssl` against a system libcrypto;
- a Node built with the bundled OpenSSL statically linked in;
- a **stock nodejs.org nightly**, which is the actual deployment target — the
  binary is unmodified and its OpenSSL is statically linked.

### Verifying a build

A provider that fails to load from `openssl.cnf` produces **no diagnostic**: the
process starts normally and then fails at the first key load. Two scripts cover
that gap.

```bash
scripts/check-load.sh build /path/to/node
```

That asserts the module exports only `OSSL_provider_init`, pulls in no second
crypto or TLS stack, loads into the `openssl` CLI, and — the part version numbers
cannot establish — that every OpenSSL symbol the module needs is actually exported
by the target host. Two node builds reporting the same OpenSSL version can export
different symbol sets, and a missing symbol is a silent all-or-nothing load
failure.

```bash
scripts/check-openssl-matrix.sh
```

compiles against every OpenSSL header tree it can find, to keep the
"3.0 floor, no upper bound" claim honest.

## Configuration

Point OpenSSL at the generated config (`build/awskms.cnf`, or
`$sysconfdir/awskms/awskms.cnf` after install):

```bash
node --openssl-config=/usr/local/etc/awskms/awskms.cnf app.mjs
```

`OPENSSL_CONF=…` and `NODE_OPTIONS=--openssl-config=…` work too. Three properties
of that file are load-bearing, and are commented in place: it declares
`nodejs_conf` (Node silently ignores a file declaring only `openssl_conf`), it
activates the `default` provider explicitly (Node otherwise aborts at startup),
and `module =` is an absolute path including the platform extension.

Credentials, region and endpoint resolution are the AWS SDK's own — environment,
`~/.aws/config` profiles including SSO and assume-role, ECS/EKS, IMDS. Nothing
about that is reimplemented here. A `region` attribute in the URI wins over the
environment; the region is otherwise taken from a key ARN when one is given, and
failing that from the normal AWS chain.

If no region resolves anywhere, **aws-sdk-cpp silently uses `us-east-1`** — it
substitutes that default inside `ClientConfiguration`'s constructor, so an unset
region is indistinguishable from a deliberate `us-east-1` by the time this
provider sees it, and detecting it would mean duplicating the SDK's resolution
order. The symptom is `ERR_OSSL_AWSKMS_KEY_NOT_FOUND` at `createPrivateKey()` for
a key that plainly exists; an explicit region or a key ARN avoids it.

## URI syntax

RFC 7512-flavoured, chosen so it survives `new URL(x).href` unchanged:

```
awskms:key-id=<key id | key ARN | alias | alias ARN>[;region=<region>][?profile=<profile>&endpoint=<url>]
```

```
awskms:key-id=alias/my-signer
awskms:key-id=alias/my-signer;region=eu-central-1
awskms:key-id=arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
awskms:key-id=mrk-1234abcd12ab34cd56ef1234567890ab;region=eu-west-1?profile=prod
```

## IAM

`kms:Sign` and `kms:GetPublicKey` on the keys in use. Nothing else — not
`kms:Verify`, not `kms:DescribeKey`.

## Errors

Failures arrive as ordinary Node crypto errors carrying `err.code`, `err.library`
and `err.reason`:

```js
try { createPrivateKey({ key: new URL('awskms:key-id=alias/nope') }); }
catch (err) {
  err.code;    // 'ERR_OSSL_AWSKMS_KEY_NOT_FOUND'
  err.library; // 'awskms'
  err.reason;  // 'awskms key not found'
}
```

| `err.code` | when |
| --- | --- |
| `ERR_OSSL_AWSKMS_INVALID_URI` | the `awskms:` URI does not parse |
| `ERR_OSSL_AWSKMS_REGION_CONFLICT` | a `region` attribute contradicts the region in a key ARN |
| `ERR_OSSL_AWSKMS_KEY_NOT_FOUND` | KMS `NotFoundException` — including the wrong-region case above |
| `ERR_OSSL_AWSKMS_KEY_DISABLED` / `_KEY_PENDING_DELETION` | the key is not usable |
| `ERR_OSSL_AWSKMS_INVALID_KEY_USAGE` | not a `SIGN_VERIFY` key |
| `ERR_OSSL_AWSKMS_UNSUPPORTED_KEY_SPEC` | a key spec this provider does not implement, e.g. `SM2` |
| `ERR_OSSL_AWSKMS_ACCESS_DENIED` / `_NO_CREDENTIALS` / `_THROTTLED` | IAM, credential chain, quota |
| `ERR_OSSL_AWSKMS_MESSAGE_TOO_LARGE` | Ed25519 over 4096 bytes |
| `ERR_OSSL_AWSKMS_EMPTY_MESSAGE` | Ed25519 with a zero-length message; KMS requires at least one byte |
| `ERR_OSSL_AWSKMS_UNSUPPORTED_DIGEST` | a digest KMS has no algorithm for, including the wrong digest for an EC curve |
| `ERR_OSSL_AWSKMS_UNSUPPORTED_SALT_LENGTH` | a PSS salt length other than the digest length |
| `ERR_OSSL_AWSKMS_UNSUPPORTED_PARAMETER` | something with no KMS equivalent, e.g. an Ed25519 context string |
| `ERR_OSSL_AWSKMS_PRIVATE_KEY_NOT_EXPORTABLE` | any attempt to export private material |
| `ERR_OSSL_AWSKMS_GET_PUBLIC_KEY_FAILED` / `_SIGN_FAILED` | any other KMS error |

Two properties of how this surfaces:

- **The reason string is the whole diagnosis.** Node builds `err.message` with
  `ERR_error_string_n()`, which renders only `error:<code>:<library>::<reason>`.
  The file, line, function and detail text this provider attaches to every error
  are dropped — visible in `openssl` CLI output, never in Node. `err.code` is
  therefore the entire diagnosis a caller receives, and the only stable thing to
  match on.
- **`err.opensslErrorStack` contains an unrelated entry on every load failure**:
  `error:80000002:system library::No such file or directory`. That is libcrypto's
  built-in `file` store loader doing `stat("awskms:…")` before any other loader is
  consulted; `OSSL_STORE_open_ex()` always probes it first. Node deliberately
  reads the newest error rather than the oldest so that `err.code` is still ours.

WebCrypto wraps the same error in a `DOMException`, with the original on
`err.cause` — `code`, `library` and `reason` intact.

## Testing against real AWS KMS

The suite runs offline against a stub by default. To run the same test files against
a real account, see [docs/real-kms-setup.md](docs/real-kms-setup.md) — it walks
through the two IAM principals, the profiles, and the GitHub Actions setup.

```bash
node scripts/real-kms-keys.mjs setup --smoke --profile awskms-admin --dry-run
```

Keys are created fresh per run and scheduled for deletion afterwards; deletion is
never cancelled, which keeps a full pass at roughly `$0.73` rather than `$22`/month.

## Continuous integration

Four workflows, each answering one question. Only one of them costs anything.

| workflow | answers | runs on | cost |
| --- | --- | --- | --- |
| [`ci.yml`](.github/workflows/ci.yml) | does it build, load and pass its tests — on Linux x64/arm64 and macOS arm64, against OpenSSL 3.0/3.5/4.0 headers, and is it formatted | every push and PR; the aws backend on the schedule and on demand | free |
| [`real-kms.yml`](.github/workflows/real-kms.yml) | does it still work against the **actual** service | daily; a PR labelled `real-kms`; manual dispatch | ~`$0.13` a pass |
| [`real-kms-reaper.yml`](.github/workflows/real-kms-reaper.yml) | did any run leave keys behind | daily; manual dispatch | free |
| [`vendored.yml`](.github/workflows/vendored.yml) | is `third_party/` byte-identical to the release it claims, and is a newer one out | on changes to `third_party/`, `src/` or the updater; weekly | free |

The division that matters: **`ci.yml` runs per commit, `real-kms.yml` does not.**
"Does it still work against the real service" is a question worth answering
periodically and on demand, not once per push — the daily run covers the first and
the `real-kms` label covers the second. Everything worth checking per commit is
free and lives in `ci.yml`.

`ci.yml` builds the stub backend on pull requests and both backends on the
schedule, because the aws backend fetches ~206 MB of aws-sdk-cpp. That fetch is
cached, and the schedule is also what keeps the cache entry from being evicted.

## Hardening with the permission model

Node gates STORE loaders behind `--allow-openssl-store`, so a key load needs it:

```bash
node --permission --allow-openssl-store --openssl-config=/path/awskms.cnf app.mjs
```

That grant is broader than it looks — its own documentation notes a loader "may
access files, devices, tokens, or the network", and that such access is *not*
constrained by the `fs` or `net` permission scopes. It is worth holding for as
little time as possible.

Permissions can be dropped at runtime and never regained, and a key that is
already loaded keeps working, because signing uses the loaded `EVP_PKEY` rather
than the store:

```js
const key = createPrivateKey({ key: new URL('awskms:key-id=alias/my-signer') });
process.permission.drop('openssl.store');   // no further key loads, ever
process.permission.drop('worker');          // see below
createSign('sha256').update(data).sign(key); // still works
```

After that, a later compromise cannot load any KMS key — not even the same URI.

Two things about this fail **silently** if you get them wrong:

- **The scope is `openssl.store`, with a dot**, while the flag is
  `--allow-openssl-store` with hyphens. Passing `'openssl-store'` to `drop()` is
  a no-op on an unknown scope, and `has('openssl-store')` then returns `false` —
  which looks exactly like a successful drop.
- **Drops are per-thread.** A `Worker` spawned afterwards starts from the
  original command-line grants, so it can load keys again. Dropping `worker` too
  is what makes the first drop meaningful; otherwise it is theatre. A worker
  created *before* the drop keeps its own grants.

`KeyObject`s transfer to a `Worker` after the drop and sign there normally — the
key moves as a shared handle, not by re-loading from the store. That allows a
useful split: hand a worker one signing key while denying it the ability to load
any other.

## Operational notes

Numbers below were measured against real KMS in `eu-central-1` from a laptop.
Latency is dominated by network distance, so treat the shape as transferable and
the absolute values as not: in-region on EC2 they will be far lower.

### Load keys at startup, never on a request path

`createPrivateKey()` performs one `kms:GetPublicKey`, and there is **no
asynchronous form of it**. It blocks:

| | |
| --- | --- |
| first key load | **~850 ms** — SDK init, credential resolution, TLS handshake, then `GetPublicKey` |
| subsequent loads | **~60 ms** — the round trip alone, on a warm connection |

That first load is expensive because the whole credential chain runs then: profile
resolution, any assume-role hop, and the TLS handshake. Loading lazily on the first
request means one unlucky request wears all of it, and every request wears 60 ms.

Load every key during startup, before accepting traffic. That also composes with
[dropping `openssl.store`](#hardening-with-the-permission-model), which requires
exactly the same thing.

### Use the asynchronous APIs

`kms:Sign` is a network round trip, and the synchronous form holds the event loop
for the whole of it. Measured over 10 signatures:

| | per signature | event loop |
| --- | --- | --- |
| `crypto.sign(alg, data, key)` sync, `createSign().sign()` | ~65 ms | **blocked ~654 ms total** |
| `crypto.sign(…, callback)`, WebCrypto `subtle.sign` | ~65 ms | blocked ~6 ms total |

In a server the synchronous form stalls *every* pending request for ~65 ms per
signature. Reserve it for CLIs and batch jobs.

### Concurrency ceiling

The async forms run on the libuv threadpool, so `UV_THREADPOOL_SIZE` (default 4)
is the ceiling — and it is shared with `fs`, `dns` and zlib:

| `UV_THREADPOOL_SIZE` | throughput |
| --- | --- |
| 4 (default) | ~60 signatures/s |
| 16 | ~200+ signatures/s |

Raising it is the first lever if signing throughput matters. Worker threads are
*not* needed for parallelism — the threadpool already provides it — but they are
useful to stop signing starving `fs`/`dns` of the same pool, and a `KeyObject`
transfers to a worker via `postMessage`, so a key can be loaded once in the main
thread and shared.
- **A throttled request blocks for the whole retry sequence, not one round trip.**
  The AWS SDK retries `ThrottlingException` with backoff, so
  `ERR_OSSL_AWSKMS_THROTTLED` surfaces only once retries are exhausted — measured
  at roughly 4 seconds for a sign. In the synchronous form that is 4 seconds of
  blocked event loop. The callback form and WebCrypto avoid that, and matter at any
  signing rate that can trip the per-region cryptographic-operations quota.
- Signatures are randomised (KMS uses hedged signing), so the same message
  yields different bytes each call, so signatures cannot be cached or compared.
- KMS applies per-second `Sign` quotas and per-request charges.
