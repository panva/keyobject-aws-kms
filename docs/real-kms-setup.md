# The real AWS KMS test pass

The default native and JavaScript suites run offline. This opt-in pass provisions
temporary asymmetric signing keys in a real AWS account, runs the same provider
paths against AWS KMS, and schedules every created key for deletion.

Real-service tests create billable resources and requests. Review current
[AWS KMS pricing](https://aws.amazon.com/kms/pricing/) before running them. Start
with the smoke subset and a dry run.

## Safety model

Use a dedicated test account when possible. The harness:

- uses a collision-resistant run identifier;
- tags every key at creation with `awskms-provider-test=1` and run metadata;
- records exact key and alias identities in `build/real-kms-keys.json`;
- validates account, region, aliases, ARNs, and ownership tags before the first
  destructive cleanup call;
- schedules deletion rather than cancelling and reusing keys;
- keeps provisioning credentials separate from the signer credentials used by
  the provider tests.

Normal teardown acts on the manifest for the current run. `reap` and `--sweep`
act on every resource carrying the ownership tag, including resources outside
that manifest. Use them only in a dedicated test account after independently
reviewing the tagged resources.

AWS KMS supports a minimum pending-deletion window of seven days. Scheduling a
key for deletion is destructive and is not instantaneous; see
[Deleting AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html).

## Prerequisites

- a built `AWSKMS_BACKEND=aws` provider module;
- a Node runtime that passes the STORE URL-key capability probe;
- AWS CLI v2 on `PATH`;
- an existing AWS profile with permission to create the two IAM test roles for
  the one-time bootstrap;
- an AWS region that supports the key specs being tested.

ML-DSA availability varies. The provisioner records unavailable ML-DSA specs in
the manifest and the tests skip them. See
[ML-DSA keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html).

## Roles and least privilege

The bootstrap creates two roles:

| Role | Purpose |
| --- | --- |
| `AwskmsTestAdmin` | Create/tag test keys, manage test aliases, inspect lifecycle, schedule owned keys for deletion, and assume the signer role |
| `AwskmsTestSigner` | Run the provider with only `kms:GetPublicKey` and `kms:Sign` |

The admin role has an explicit deny for signing and other key-use operations.
The signer role cannot provision, describe, delete, decrypt, or verify through
KMS. This separation makes the provider's minimum IAM claim testable.
Every run creates fresh keys. The harness never cancels pending deletion or
reuses a key, and the admin role has no `kms:CancelKeyDeletion` permission.

The runtime permission is equivalent to:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:GetPublicKey", "kms:Sign"],
    "Resource": "arn:aws:kms:REGION:ACCOUNT:key/*",
    "Condition": {
      "StringEquals": { "kms:KeyUsage": "SIGN_VERIFY" }
    }
  }]
}
```

Scope `Resource` more narrowly outside this disposable test harness. There is no
`kms:Verify` permission because verification is local, and no
`kms:DescribeKey` permission because the provider never calls it. A
`kms:MessageType = DIGEST` condition is not suitable for the complete matrix:
Ed25519 uses `RAW`, and ML-DSA uses `RAW` or `EXTERNAL_MU`.

The bootstrap's current inline policies are the source of truth. Review the
printed dry run and the policy definitions in
`scripts/real-kms-bootstrap.mjs` before applying them to an account.

## One-time IAM bootstrap

Use an existing administrative profile only for this one-time step:

```console
node scripts/real-kms-bootstrap.mjs \
  --profile organization-admin \
  --region eu-central-1 \
  --dry-run
```

After reviewing the output, remove `--dry-run`:

```console
node scripts/real-kms-bootstrap.mjs \
  --profile organization-admin \
  --region eu-central-1
```

The command creates or updates the roles and prints two profile entries to add
manually to `~/.aws/config`. It does not modify the shared config file. The
result has this shape:

```ini
[profile awskms-admin]
region = eu-central-1
role_arn = arn:aws:iam::111122223333:role/AwskmsTestAdmin
source_profile = organization-admin

[profile awskms-signer]
region = eu-central-1
role_arn = arn:aws:iam::111122223333:role/AwskmsTestSigner
source_profile = awskms-admin
```

Confirm both roles before provisioning:

```console
aws sts get-caller-identity --profile awskms-admin
aws sts get-caller-identity --profile awskms-signer
```

## Run locally

The smoke subset provisions two keys for each of four representative specs.
First inspect the planned calls:

```console
node scripts/real-kms-keys.mjs setup \
  --smoke \
  --profile awskms-admin \
  --region eu-central-1 \
  --dry-run
```

Provision the keys:

```console
node scripts/real-kms-keys.mjs setup \
  --smoke \
  --profile awskms-admin \
  --region eu-central-1
```

Run the tests with the signer profile and an AWS-backend module:

```console
AWSKMS_TEST_REAL=1 \
AWS_PROFILE=awskms-signer \
AWS_REGION=eu-central-1 \
AWSKMS_MODULE="$PWD/build-aws/aws-kms.so" \
node test/run.mjs
```

On macOS use `build-aws/aws-kms.dylib`. The real-service driver requires an
explicit profile outside CI, requires `AWS_REGION`, validates it against the
manifest, and runs test files serially to avoid bursting KMS operation quotas.

Always schedule cleanup, even after a test failure:

```console
node scripts/real-kms-keys.mjs teardown \
  --profile awskms-admin \
  --region eu-central-1 \
  --window 7
```

Inspect the manifest's resources at any time:

```console
node scripts/real-kms-keys.mjs status \
  --profile awskms-admin \
  --region eu-central-1
```

To provision the full matrix, omit `--smoke`. The same manifest must be used by
setup, test, status, and teardown; override its location consistently with
`--manifest` and `AWSKMS_TEST_MANIFEST` only when necessary.

## CI with GitHub OIDC

The bootstrap can also register GitHub's OIDC provider and add repository trust
without creating long-lived AWS secrets:

```console
node scripts/real-kms-bootstrap.mjs \
  --profile organization-admin \
  --region eu-central-1 \
  --github-repo OWNER/REPOSITORY \
  --dry-run
```

After review, run it without `--dry-run`. The command prints values for these
repository variables:

| Variable | Value |
| --- | --- |
| `AWSKMS_TEST_REGION` | Test region |
| `AWSKMS_ADMIN_ROLE_ARN` | Provisioning role ARN |
| `AWSKMS_SIGNER_ROLE_ARN` | Sign-only role ARN |

The workflow assumes the admin role, provisions keys, assumes the signer role
only for the test command, and runs teardown with the retained admin credentials
in an `always()` step.

Review the OIDC trust boundary before enabling it. The generated trust permits
the configured branch subject and the repository's `pull_request` subject. The
latter cannot be narrowed by branch in AWS; repository workflow controls and
the same-repository/maintainer-label gates are therefore part of the security
boundary. Use an approval-protected GitHub Environment and a corresponding
environment subject if that boundary is not acceptable.

## FIPS-mode real tests

For an operation selected with `fips=yes`, the provider forces the AWS SDK to
use a KMS FIPS endpoint. It rejects endpoint overrides from the URI, AWS
environment, shared profile, or provider config, and it rejects China regions.
Choose a non-China region listed in the official
[AWS KMS endpoint table](https://docs.aws.amazon.com/general/latest/gr/kms.html)
and remove all endpoint overrides before the run.

The host must separately install and configure its OpenSSL FIPS module. The
provider binary is not independently CMVP certified; see the
[AWS KMS data-protection boundary](https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html).

## Recovery and diagnostics

- If setup is interrupted, run `status` with the same manifest, then run
  `teardown`. To inventory tagged leftovers outside the manifest, use the AWS
  Resource Groups Tagging API before considering `reap`; `reap --dry-run` only
  prints the calls it would make and does not enumerate live resources.
- `reap` uses a valid implicit `build/real-kms-keys.json` alongside its
  ownership-tag sweep. It warns and continues with tags alone when that default
  is stale or unreadable. A path supplied with `--manifest` is always validated
  strictly.
- If a key is reported as foreign or its ownership tags do not match, stop and
  investigate. The harness intentionally refuses partial cleanup.
- `PendingDeletion` is the expected final key state. An enabled test key still
  needs teardown.
- `ERR_OSSL_AWSKMS_THROTTLED` means SDK retries were exhausted. Keep real tests
  serial and reduce provisioning concurrency if account quotas are tight.
- A region mismatch fails before the suite. Use the same explicit region for
  bootstrap, setup, signer profile, test environment, and teardown.
