# Contributing to @keyobject/aws-kms

Please follow the project [Code of Conduct](CODE_OF_CONDUCT.md) in all
interactions.

Before proposing a pull request, discuss substantial changes in
[GitHub Discussions](https://github.com/panva/keyobject-aws-kms/discussions).
Bug fixes and changes to URI parsing, cryptographic behavior, IAM requirements,
or the public package surface should include focused acceptance coverage.

Never include AWS credentials, session tokens, production key identifiers,
production `aws-kms:` URIs, or private configuration in an issue, discussion,
test fixture, or reproduction.

The npm packages are the user installation interface. Building from source is a
contributor workflow for development, testing, and release validation; this
project intentionally has no CMake install target.

## Prerequisites

- CMake 3.25 or newer;
- a C11 compiler and a C++20 compiler;
- OpenSSL 3.0 or newer headers and libraries for unit tests;
- Node.js 26.7.0 or newer with the OpenSSL STORE URL-key capability for
  JavaScript tests;
- `clang-format` 22.1.8 for native formatting;
- the AWS CLI only for opt-in real-service tests.

The test driver probes the Node capability rather than assuming every custom
build with a qualifying version includes the loader.

## Choose a backend explicitly

CMake never chooses a KMS backend implicitly. Every configure command must set
one of:

- `-DAWSKMS_BACKEND=stub`: an in-provider, offline fake for native tests;
- `-DAWSKMS_BACKEND=aws`: the production AWS SDK implementation.

The stub backend must not be used for production artifacts.

### Offline development build

```console
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DAWSKMS_BACKEND=stub
cmake --build build --parallel
ctest --test-dir build -R '^unit$' --no-tests=error --output-on-failure
scripts/check-load.sh build
node test/run.mjs
```

`ctest` exercises the native unit suite. `test/run.mjs` activates the built
provider in a child Node process and runs the JavaScript integration suite.

### Production-backend development build

The default AWS SDK mode fetches the pinned SDK sources. Network access is
required on the first configure:

```console
cmake -S . -B build-aws \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DAWSKMS_BACKEND=aws \
  -DAWSKMS_AWS_SDK=FETCH
cmake --build build-aws --parallel
ctest --test-dir build-aws -R '^unit$' --no-tests=error --output-on-failure
```

Use `-DAWSKMS_AWS_SDK=SYSTEM` to require a compatible installed AWS SDK instead.
Without `AWSKMS_TEST_REAL=1`, the JavaScript driver starts a local HTTP KMS stub,
so the production client path can be tested without credentials or network
access to AWS:

```console
# Linux
AWSKMS_MODULE="$PWD/build-aws/aws-kms.so" node test/run.mjs

# macOS
AWSKMS_MODULE="$PWD/build-aws/aws-kms.dylib" node test/run.mjs
```

To choose a specific OpenSSL header/library installation, pass
`-DOPENSSL_ROOT_DIR=/absolute/prefix`. Release compatibility is determined by
the APIs and symbols used, not only by the reported OpenSSL version.

## Validate provider loading

An OpenSSL config can fail to activate a provider without making Node fail at
startup. Run both the native load checks and the readiness probe:

```console
scripts/check-load.sh build /absolute/path/to/node
node --openssl-config="$PWD/build/awskms.cnf" scripts/check.mjs
```

`scripts/check-load.sh` checks the export set, native dependencies, OpenSSL CLI
loading, host symbol availability, and provider reachability. `check.mjs` uses
an invalid `aws-kms:` URI that reaches the STORE loader but fails before any
credential or network operation.

The generated `build/awskms.relocatable.cnf` is a binary-packaging artifact and
expects `AWSKMS_MODULE` to name the absolute module path. There is no
`cmake --install` workflow.

## Formatting and focused tests

Format touched native files with the repository's pinned style:

```console
clang-format -i src/*.c src/*.h src/*.cc test/unit_*.c test/unit.h
```

Before submitting a change, run at least:

```console
cmake --build build --parallel
ctest --test-dir build -R '^unit$' --no-tests=error --output-on-failure
node --check scripts/check.mjs
node test/run.mjs
```

Limit formatting changes to files relevant to the contribution. Do not edit
vendored code to satisfy first-party style; vendored source has its own update
and verification process.

## Real AWS KMS tests

Real-service tests are opt-in because they create billable resources and make
network calls. They use separate provisioning and signing roles and require an
explicit profile or CI-assumed role. Follow
[The real-KMS test pass](docs/real-kms-setup.md), start with `--dry-run`, and
always run teardown.

## Changes that affect the public contract

Keep these surfaces synchronized:

- URI grammar and precedence in `src/uri.c`, tests, and documentation;
- supported AWS KMS key specs in `src/keyspec.c`, fixtures, and documentation;
- OpenSSL dispatch metadata and its direct unit tests;
- core/native npm package versions and platform metadata;
- config-template behavior and `scripts/check.mjs` diagnostics;
- error reason codes, Node-visible error expectations, and security guidance.

Do not add new AWS permissions for convenience. If an implementation change
needs more than `kms:GetPublicKey` and `kms:Sign`, call out the security and IAM
impact explicitly.

## Reporting security issues

Do not use a public pull request for an unpatched vulnerability. Follow
[Security](SECURITY.md) for private reporting.

## Discussions

Be clear and transparent, keep discussion in English and on topic, and maintain
a professional and respectful tone.
