# Documentation

`@keyobject/aws-kms` exposes a small JavaScript API around a native OpenSSL
provider. Start with the [project README](../README.md) for the signing example,
supported keys, WebCrypto mappings, and performance guidance.

## Guides

- [Installation and configuration](INSTALL.md) covers runtime requirements,
  provider activation, existing OpenSSL configuration, permissions, FIPS, and
  troubleshooting.
- [Security Policy](../SECURITY.md) defines the trust boundary, minimum IAM
  permissions, URI risks, FIPS routing, and private reporting process.
- [Real AWS KMS tests](real-kms-setup.md) documents the opt-in provisioning,
  least-privilege roles, cleanup, and CI setup used by maintainers.
- [Contributing](../CONTRIBUTING.md) covers source builds and validation.
- [Third-party notices](../THIRD_PARTY_NOTICES.md) identifies statically linked
  native dependencies and their licenses.

## Package API

The public declarations are tracked in [`npm/core/index.d.ts`](../npm/core/index.d.ts)
and [`npm/core/register.d.ts`](../npm/core/register.d.ts).

| Export | Purpose |
| --- | --- |
| `version` | Core npm package version |
| `isSupported()` | Non-throwing runtime and native-package capability check |
| `modulePath()` | Verified absolute path to the platform provider module |
| `opensslConfigPath()` | Private OpenSSL config path for the current process |
| `register()` | Idempotent startup registration on OpenSSL 3.5+ |
| `@keyobject/aws-kms/register` | Side-effect preload that calls `register()` |

The command-line interface exposes:

```console
npx @keyobject/aws-kms check
npx @keyobject/aws-kms module-path
npx @keyobject/aws-kms config-path
npx @keyobject/aws-kms exec -- node app.mjs
```

The stable `isSupported()` failure codes and bundler requirements are documented
in the [README package API](../README.md#package-api) and
[compatibility check](../README.md#compatibility-check) sections.
