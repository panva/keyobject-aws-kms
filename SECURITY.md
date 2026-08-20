# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it with a
[private GitHub security advisory](https://github.com/panva/keyobject-aws-kms/security/advisories/new).
Include the affected platform and Node/OpenSSL versions, a minimal reproducer,
expected impact, and whether the issue requires control of local files,
environment variables, an `aws-kms:` URI, AWS credentials, or a KMS key policy.

Do not include live AWS credentials, session tokens, private configuration, or
production key identifiers. Revoke any credential accidentally disclosed in a
report.

Please allow time to investigate and coordinate a fix before public disclosure.
If the problem is in Node.js, OpenSSL, the AWS SDK, AWS KMS, or another
dependency rather than this package, the report may need to be coordinated with
that project.

## Supported Versions

Only the latest release is supported. Unreleased development builds, including
`0.0.0`, and prerelease versions do not carry a production support commitment;
their API or security model may change. Users should update before reporting an
issue or relying on a fix.

## Security model

The provider is a bridge between Node's OpenSSL library context and AWS KMS:

- `kms:GetPublicKey` runs when an `aws-kms:` private key is loaded.
- `kms:Sign` runs for a signature operation.
- Private key material is never returned by KMS and cannot be exported through
  the provider.
- Public-key export and signature verification are local after the public key
  has been loaded.
- The AWS SDK supplies credential, region, proxy, TLS, retry, and endpoint
  behavior.

AWS describes its encryption and HSM boundary in
[AWS KMS data protection](https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html).

## IAM and key policy

The minimum application permissions are:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:GetPublicKey", "kms:Sign"],
    "Resource": ["arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"]
  }]
}
```

The KMS key policy must also allow the principal. Do not grant applications
`kms:Verify`, `kms:DescribeKey`, decryption, data-key generation, or key
administration merely to use this provider; it does not call those APIs. Scope
resources to the intended key ARNs and use separate roles when applications
serve different trust domains.

## Treat key URIs as trusted configuration

An `aws-kms:` URI can contain more than a key identifier:

```text
aws-kms:key-id=alias/example;region=eu-central-1?profile=production&endpoint=https%3A%2F%2Fexample.invalid
```

The `profile` parameter selects an AWS profile and therefore can change the
identity used by the SDK. The `endpoint` parameter changes the destination of a
SigV4-signed KMS request. An attacker who controls the whole URI may redirect
traffic or cause the process to exercise credentials and keys outside the
application's intended scope.

Do not accept complete key URIs from untrusted users. Prefer one of these
patterns:

- map an application-level key name to a fixed URI in trusted configuration;
- construct the URI from an allowlisted key ARN and region;
- reject user-controlled `profile` and `endpoint` values;
- restrict egress and IAM so a parser or configuration mistake cannot expand
  the set of usable keys.

URI values are not a place for AWS access keys, secret keys, or session tokens.
Use the normal AWS SDK credential chain and short-lived role credentials.

## Configuration and endpoint precedence

URI settings take precedence over AWS environment/shared-profile settings,
which take precedence over defaults in the provider's OpenSSL config section.
See [Installation and configuration](docs/INSTALL.md#uri-and-aws-configuration-precedence)
for the per-field order.

Review `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_REGION`,
`AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL_KMS`, `AWS_ENDPOINT_URL`,
`AWS_IGNORE_CONFIGURED_ENDPOINT_URLS`, shared AWS config, `OPENSSL_CONF`,
`NODE_OPTIONS`, and command-line `--openssl-config` as part of the deployment's
trusted configuration. Avoid inheriting them from a user-controlled shell or
service manager.

The package CLI refuses to replace an existing OpenSSL config unless the
replacement is explicit. If the process already has FIPS, PKCS#11, or another
provider policy, merge the AWS KMS provider into the existing sections. A plain
`.include` of two standalone configs does not compose their single
`nodejs_conf`, `providers`, or `alg_section` pointers.

## FIPS boundary

When an operation requires `fips=yes`, the provider:

- requires FIPS implementations for local digest, SHAKE, public-key parsing,
  and verification work;
- forces the AWS SDK to select an AWS KMS FIPS endpoint;
- rejects every endpoint override, including URI, environment, shared-profile,
  and provider-config overrides;
- rejects China regions for this route.

The deployment must provide a correctly installed and configured OpenSSL FIPS
module and must select a region listed in the official
[AWS KMS endpoint table](https://docs.aws.amazon.com/general/latest/gr/kms.html).
The provider binary is not independently CMVP certified. Its `fips=yes`
algorithm declaration identifies this composite routing behavior; it is not a
claim that the provider binary itself is a validated cryptographic module.

ML-DSA support and availability are described by AWS in
[ML-DSA keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html).

## Node process hardening

- Activate the provider before application crypto code. Prefer
  `node --import @keyobject/aws-kms/register` for the registration route.
- Use the config route on OpenSSL 3.0--3.4. In-process registration requires
  OpenSSL 3.5+ so it can preserve an existing default property policy.
- Under Node's permission model, grant `--allow-openssl-store` only to processes
  that must load provider-backed keys. The registration route also requires
  native-addon and filesystem-read permissions.
- Load a bounded set of keys during startup. If no later loads are needed, drop
  the `openssl.store` permission before accepting untrusted work.
- Use asynchronous signing in servers. Synchronous KMS signing blocks the event
  loop for the network request and any SDK retry delay.

## Native package integrity

The npm package executes no install script. At runtime it validates the selected
platform package's identity, exact version, OS/CPU/libc metadata, config
template, and module bytes. Temporary config or archive-extracted native files
are created in a randomized owner-only directory with exclusive, no-follow
file creation and are revalidated before use.

Those checks detect local replacement after resolution; they do not replace
normal package-manager lockfiles, registry provenance, host filesystem
protection, or review of dependency updates. Native packages include their
third-party licenses and notices.
