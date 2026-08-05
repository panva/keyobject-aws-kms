# The real-KMS test pass

Everything else in this repository runs offline against a stub. This is the one
part that touches a real AWS account, so it is opt-in and tears itself down.

## Cost model

Keys are created fresh at the start of every run and scheduled for deletion at the
end; deletion is never cancelled. That follows from three properties of KMS
pricing:

| | |
| --- | --- |
| a key **scheduled for deletion** | not charged |
| a **disabled** key | charged at the full rate |
| **cancelling** a deletion | re-bills the entire elapsed waiting period, "as though it was never scheduled" |

The `$1`/key/month is prorated hourly, so a pass that lives a few hours costs about
`$0.73` for all 22 keys, or `$0.13` for the 8-key smoke subset. Persisting keys
between runs and reviving them would cost about `$22`/month, because each revive
back-bills the gap.

Request charges are cents at test volumes: `$0.03` per 10,000 for `RSA_2048` (at
parity with symmetric), `$0.15` per 10,000 for every other asymmetric spec. ML-DSA
is not priced on the AWS KMS pricing page; `$0.15` is inference, not an AWS
statement. The free tier excludes asymmetric operations entirely, so every request
is billed from the first. `kms:GetPublicKey` is billable — it is named in that
exclusion — but no per-request rate is published for it. The provider makes one
`GetPublicKey` call per key *load*, not per signature.

## The two principals

The claim this suite exists to test is that the provider needs only `kms:Sign` and
`kms:GetPublicKey`. Running the tests under the same credentials that create keys
would make that claim untestable, so provisioning and testing use separate roles.

| role | can | cannot |
| --- | --- | --- |
| `AwskmsTestAdmin` | create keys, manage aliases, schedule deletion, tag | sign |
| `AwskmsTestSigner` | `kms:Sign`, `kms:GetPublicKey` | anything else |

The explicit `Deny` on signing in the admin policy is load-bearing rather than
decorative: the admin holds `kms:PutKeyPolicy` and could otherwise grant itself
signing rights, and an identity-policy `Deny` is the only thing a key-policy edit
cannot override.

The signer has no `kms:Verify`, because verification is local and that is the
property under test, and no `kms:DescribeKey`, because the provider never calls it
— an `AccessDenied` from `DescribeKey` is therefore a signal that something started
calling it.

### No explicit key policy

`CreateKey` is called without a `Policy` parameter, which attaches the default key
policy granting the account root full access — the condition that allows IAM
policies to govern the key at all. A hand-written policy adds no capability here
and opens three routes to an unmanageable key:

- a statement missing its `Action` or `Resource` is accepted silently and is
  completely ineffective; only the console flags it;
- a principal that does not yet exist (a role created seconds earlier) fails with
  `MalformedPolicyDocumentException`;
- omitting the account-root statement and then deleting the admin role makes the
  key unmanageable, recoverable only through AWS Support.

An IAM policy alone is never sufficient in KMS. The default key policy is what
makes it sufficient.

## Local configuration

`reap` schedules deletion for every key carrying the test tag, which is safe by
construction only in a dedicated account. See [Shared accounts](#shared-accounts)
otherwise.

Two profiles, neither of them `[default]` — the tooling refuses ambient credentials
so that a stray shell cannot create keys:

```ini
# ~/.aws/config
[profile awskms-admin]
region = eu-central-1
# sso_session, source_profile + role_arn, credential_process -- whatever the
# organisation uses. None of it is reimplemented anywhere in this repository.

[profile awskms-signer]
region = eu-central-1
role_arn = arn:aws:iam::111122223333:role/AwskmsTestSigner
source_profile = awskms-admin
```

The policies are [below](#policies). `111122223333` stands in for the account id.

### Running a pass

`--dry-run` prints every API call and makes none:

```bash
node scripts/real-kms-keys.mjs setup --smoke --profile awskms-admin --dry-run
```

```bash
node scripts/real-kms-keys.mjs setup --smoke --profile awskms-admin
```

```bash
AWSKMS_TEST_REAL=1 AWS_PROFILE=awskms-signer node test/run.mjs
```

```bash
node scripts/real-kms-keys.mjs teardown --smoke --sweep --profile awskms-admin
```

`status` reports what is left. `PendingDeletion` is free; anything `Enabled` or
`Disabled` is billing:

```bash
node scripts/real-kms-keys.mjs status --profile awskms-admin
```

## CI configuration

Two workflows: [real-kms.yml](../.github/workflows/real-kms.yml) provisions, tests
and tears down; [real-kms-reaper.yml](../.github/workflows/real-kms-reaper.yml) is
the backstop for a runner that dies before teardown.

### Repository variables

| variable | example |
| --- | --- |
| `AWSKMS_TEST_REGION` | `eu-central-1` |
| `AWSKMS_ADMIN_ROLE_ARN` | `arn:aws:iam::111122223333:role/AwskmsTestAdmin` |
| `AWSKMS_SIGNER_ROLE_ARN` | `arn:aws:iam::111122223333:role/AwskmsTestSigner` |

No secrets are involved; credentials come from GitHub's OIDC provider, so there is
nothing long-lived to leak.

### Trust policies

The admin role trusts GitHub OIDC:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
      "StringLike":   { "token.actions.githubusercontent.com:sub": [
        "repo:ORG/tiny-aws-kms-openssl-provider*:ref:refs/heads/main",
        "repo:ORG/tiny-aws-kms-openssl-provider*:pull_request"
      ]}
    }
  }]
}
```

Multiple values for one condition key are OR-ed by IAM. The first covers pushes to
`main`, the schedule and `workflow_dispatch`; the second covers a pull request.

### What the `pull_request` subject costs, precisely

It widens this role, and the widening cannot be narrowed on the AWS side. A
`pull_request` event's subject is `repo:ORG/REPO:pull_request` — it carries no
branch and no label — so the trust policy either allows the entire event type or
none of it.

What is left holding the line is entirely in
[real-kms.yml](../.github/workflows/real-kms.yml):

- the PR must come from this repository, not a fork. This one is robust
  independently of the `if:`, because a fork PR receives no OIDC token at all on a
  `pull_request` event;
- the PR must carry the **`real-kms`** label, which only someone with write access
  can apply.

The second gate is the real one, and it exists only in the workflow file. Be clear
about what that means: a job running pull-request-authored code can mint its own
OIDC token — `id-token: write` puts `ACTIONS_ID_TOKEN_REQUEST_URL` and
`ACTIONS_ID_TOKEN_REQUEST_TOKEN` in the environment — and assume this role, which
can create and delete KMS keys. Assuming the role and then clearing the `AWS_*`
variables before running that code is **not** a mitigation; the code re-mints the
token.

The alternative that removes this structurally instead of gating it is a GitHub
Environment. Adding `environment:` rewrites the subject to
`repo:ORG/REPO:environment:NAME`, so a separate sign-only role can be bound to
exactly that subject while this role stays unreachable from any job running PR
code. That was considered and deliberately not taken here, in favour of a
one-line policy change; see `TODO.txt` Q6 if the trade is ever revisited.

Three constraints on that condition block:

- IAM requires `:sub` to be evaluated and its value not to be solely a wildcard;
  role creation otherwise fails with `MalformedPolicyDocument`.
- `ForAllValues:` operators return true when the claim is absent or misspelled, so
  they are unsafe in an `Allow`.
- The `*` after the repository name absorbs a possible immutable-subject suffix
  (`repo:owner@<ownerId>/repo@<repoId>:...`) that newer repositories may emit. The
  authoritative form is whatever `sub` a real token carries; this is unverified
  against a live token.

Adding `environment:` to the job changes `:sub` to `repo:ORG/REPO:environment:NAME`
and invalidates the condition above.

### Applying the change to an existing role

Re-run the bootstrap. It is idempotent by design: an existing role has its trust
document and inline policy updated in place rather than being recreated, so this
is the normal way to apply any policy edit. It creates no KMS keys, so it costs
nothing.

```bash
node scripts/real-kms-bootstrap.mjs --profile <your-admin-profile> \
  --github-repo ORG/tiny-aws-kms-openssl-provider --dry-run   # prints every call, makes none
node scripts/real-kms-bootstrap.mjs --profile <your-admin-profile> \
  --github-repo ORG/tiny-aws-kms-openssl-provider
```

**`--github-repo` is not optional here.** The OIDC statement is only emitted when
it is present, and `update-assume-role-policy` replaces the whole trust document
rather than merging into it — so re-running without that flag would quietly strip
GitHub's access and break CI. The failure would show up later, as a workflow that
cannot assume the role.

To apply the same document by hand instead:

```bash
aws iam update-assume-role-policy --role-name AwskmsTestAdmin \
  --policy-document file://trust.json --profile <your-admin-profile>
```

Verify what is actually attached afterwards, rather than assuming the write took:

```bash
aws iam get-role --role-name AwskmsTestAdmin \
  --query 'Role.AssumeRolePolicyDocument.Statement[?Action==`sts:AssumeRoleWithWebIdentity`].Condition' \
  --profile <your-admin-profile>
```

The `real-kms` label also has to exist in the repository before it can be applied
to a pull request:

```bash
gh label create real-kms --description "run the real-KMS suite on this PR (spends money)" --color B60205
```

The signer role is unreachable from GitHub directly — it trusts only the admin
role, which is why the workflow chains into it with `sts assume-role` inside a
single step:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::111122223333:role/AwskmsTestAdmin" },
    "Action": "sts:AssumeRole"
  }]
}
```

Chaining inside one step keeps the admin credentials in the job environment, so
the teardown step cannot fail for want of them.

## Policies

### `AwskmsTestAdmin`

Scoped to the calls the provisioner makes. `kms:CancelKeyDeletion` appears only for
manual rescue; nothing in this repository calls it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateOnlySingleRegionSigningKeys",
      "Effect": "Allow",
      "Action": ["kms:CreateKey", "kms:ListKeys", "kms:ListAliases"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "kms:KeyUsage": "SIGN_VERIFY", "kms:KeyOrigin": "AWS_KMS" },
        "Bool": { "kms:MultiRegion": "false" }
      }
    },
    {
      "Sid": "TagsOnTheCreateKeyCall",
      "Effect": "Allow",
      "Action": ["kms:TagResource", "kms:UntagResource", "kms:ListResourceTags"],
      "Resource": "arn:aws:kms:*:111122223333:key/*"
    },
    {
      "Sid": "OurAliasNamesOnly",
      "Effect": "Allow",
      "Action": ["kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias"],
      "Resource": [
        "arn:aws:kms:*:111122223333:alias/test-*",
        "arn:aws:kms:*:111122223333:alias/other-*",
        "arn:aws:kms:*:111122223333:key/*"
      ]
    },
    {
      "Sid": "Lifecycle",
      "Effect": "Allow",
      "Action": ["kms:DescribeKey", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"],
      "Resource": "arn:aws:kms:*:111122223333:key/*"
    },
    {
      "Sid": "TagSweep",
      "Effect": "Allow",
      "Action": "tag:GetResources",
      "Resource": "*"
    },
    {
      "Sid": "ChainToSigner",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::111122223333:role/AwskmsTestSigner"
    },
    {
      "Sid": "NeverSign",
      "Effect": "Deny",
      "Action": [
        "kms:Sign", "kms:Verify", "kms:Decrypt", "kms:GenerateDataKey*",
        "kms:DeriveSharedSecret", "kms:ReplicateKey", "kms:ImportKeyMaterial"
      ],
      "Resource": "*"
    },
    {
      "Sid": "NeverBypassLockout",
      "Effect": "Deny",
      "Action": ["kms:CreateKey", "kms:PutKeyPolicy"],
      "Resource": "*",
      "Condition": { "Bool": { "kms:BypassPolicyLockoutSafetyCheck": "true" } }
    }
  ]
}
```

Three constraints shape that document:

- `kms:CreateKey` has no resource-level permissions, so `Resource` must be `*` and
  the scoping is done with condition keys.
- The create-time `Tags` parameter requires `kms:TagResource` in the *IAM* policy;
  granting it in the new key's key policy is explicitly not sufficient. Tags have
  to be applied at `CreateKey` time in any case, because `TagResource` fails once a
  key is pending deletion, and the tag is what the reaper matches on.
- Alias operations require the grant on both the alias and the key resource, which
  is why `key/*` appears in the alias statement.

### `AwskmsTestSigner`

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SignAndFetchPublicKeys",
    "Effect": "Allow",
    "Action": ["kms:Sign", "kms:GetPublicKey"],
    "Resource": "arn:aws:kms:*:111122223333:key/*",
    "Condition": { "StringEquals": { "kms:KeyUsage": "SIGN_VERIFY" } }
  }]
}
```

A `kms:MessageType` condition pinning `DIGEST` would break the suite:
`ED25519_SHA_512` requires `RAW`, and ML-DSA uses `RAW` and `EXTERNAL_MU`. Those
are three separate code paths in the provider and all three are exercised.

## Shared accounts

`reap` schedules deletion for every key tagged `awskms-provider-test=1`, which is
only safe in a dedicated account. In a shared one, `status` shows what `reap` would
act on, and the signer policy can be scoped by alias so it cannot sign with
production keys even given an ARN:

```json
"ForAnyValue:StringLike": { "kms:ResourceAliases": ["alias/test-*", "alias/other-*"] }
```

`kms:ResourceAliases` is IAM-policy-only and subject to a documented five-minute
authorization propagation delay. That is harmless for day-old aliases but produces
a transient `AccessDenied` on the first run after a key is recreated.
`kms:RequestAlias` is not a substitute in a `Deny`, because a caller bypasses it by
passing the key id.

## Failure modes

**Two overlapping runs.** One run's teardown schedules keys while another is
mid-test. The signing failure surfaces as either `ERR_OSSL_AWSKMS_KEY_DISABLED` or
`ERR_OSSL_AWSKMS_KEY_PENDING_DELETION`; AWS documents "[2] or [3]" without stating
which, so no test asserts on exactly one. The shared `concurrency` group is the
actual prevention.

**A local run during the reaper's window** sees its keys scheduled and starts
failing. Re-running setup restores it. This is documented rather than engineered
around, because the alternative is a distributed lock for a test fixture.

**ML-DSA unavailable in the region.** Setup records it under `unavailable` in the
manifest and exits 0; the suites skip those specs with that reason. It never
reaches a test as `NotFoundException`, which would be indistinguishable from a
provisioning failure.

**Key ARNs change every run**, so no ARN can be cached across runs. Tests needing a
real ARN read it from `build/real-kms-keys.json`.

**Throttling.** `node --test` runs files concurrently, and a 22-spec matrix can
burst past the per-region cryptographic-operations request-rate quota — which
arrives as `ERR_OSSL_AWSKMS_THROTTLED` and resembles a provider bug. Real mode
therefore runs with `--test-concurrency=1`. The quota values are in the Service
Quotas console; commonly cited figures are not in first-party documentation.
`CreateKey` is separately limited to 5 requests/second, which is why the
provisioner defaults to `--concurrency 4`.
