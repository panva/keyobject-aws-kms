#!/usr/bin/env node
/*
 * One-time IAM setup for the real-KMS test pass.
 *
 * Creates the two principals the harness needs and nothing else:
 *
 *   AwskmsTestAdmin   provisions keys, aliases and deletions. Explicitly DENIED
 *                     signing, because it holds kms:PutKeyPolicy and could
 *                     otherwise grant itself that -- an identity-policy Deny is
 *                     the only thing a key-policy edit cannot override.
 *   AwskmsTestSigner  kms:Sign and kms:GetPublicKey only. The suite runs as this,
 *                     which is what makes "the provider needs nothing else" a
 *                     tested claim rather than an assumption.
 *
 * With --github-repo it also registers the GitHub OIDC provider and lets the
 * admin role be assumed from that repository's main branch, so CI needs no
 * long-lived secrets.
 *
 * REQUIRES an identity that can administer IAM (iam:CreateRole, iam:PutRolePolicy,
 * iam:CreateOpenIDConnectProvider). That is a one-time elevated step, separate
 * from everything the harness does afterwards.
 *
 * What is created where:
 *   --profile <p>      an EXISTING local profile; authenticates these calls
 *   AwskmsTest{Admin,Signer}   IAM ROLES, created here
 *   awskms-{admin,signer}      local PROFILES assuming those roles -- printed
 *                              at the end for you to add to ~/.aws/config;
 *                              this script does not write that file
 *
 * Idempotent: existing roles have their policies updated in place rather than
 * being recreated, so re-running after an edit is the normal way to apply it.
 *
 * USAGE
 *   node scripts/real-kms-bootstrap.mjs --profile <admin-profile> [options]
 *
 * OPTIONS
 *   --profile <p>       an EXISTING profile from ~/.aws/config, used to make
 *                       these IAM calls. Nothing is created with this name.
 *                       It becomes the source_profile of the two new profiles
 *                       this prints at the end. (required)
 *   --region <r>        region for the KMS keys (default eu-central-1)
 *   --github-repo <o/r> also wire GitHub OIDC for that repository
 *   --github-ref <ref>  git ref allowed to assume the role
 *                       (default refs/heads/main)
 *   --dry-run           print every call, make none
 */
import { spawnSync } from 'node:child_process';
import { aws, awsTry, hasAwsCli } from './aws-cli.mjs';

const ADMIN_ROLE = 'AwskmsTestAdmin';
const SIGNER_ROLE = 'AwskmsTestSigner';
const OIDC_HOST = 'token.actions.githubusercontent.com';

function parseArgs(argv) {
  const o = { region: 'eu-central-1', githubRef: 'refs/heads/main', dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${argv[i - 1]} needs a value`);
      return v;
    };
    switch (argv[i]) {
      case '--profile': o.profile = next(); break;
      case '--region': o.region = next(); break;
      case '--github-repo': o.githubRepo = next(); break;
      case '--github-ref': o.githubRef = next(); break;
      case '--dry-run': o.dryRun = true; break;
      default: throw new Error(`unknown option ${argv[i]}`);
    }
  }
  return o;
}

const J = (v) => JSON.stringify(v);

/* ------------------------------------------------------------------ policies */

const adminPolicy = (acct) => ({
  Version: '2012-10-17',
  Statement: [
    {
      /* CreateKey has no resource-level permissions, so it is scoped by
       * condition keys instead: single-region SIGN_VERIFY keys with AWS-generated
       * material, and nothing else. */
      Sid: 'CreateOnlySingleRegionSigningKeys',
      Effect: 'Allow',
      Action: ['kms:CreateKey', 'kms:ListKeys', 'kms:ListAliases'],
      Resource: '*',
      Condition: {
        StringEquals: { 'kms:KeyUsage': 'SIGN_VERIFY', 'kms:KeyOrigin': 'AWS_KMS' },
        Bool: { 'kms:MultiRegion': 'false' },
      },
    },
    {
      /* The create-time Tags parameter needs this in the IAM policy; granting it
       * in the new key's key policy is documented as insufficient. The tag is
       * what the reaper matches on, and TagResource fails once a key is pending
       * deletion, so it has to happen at CreateKey time. */
      Sid: 'TagsOnTheCreateKeyCall',
      Effect: 'Allow',
      Action: ['kms:TagResource', 'kms:UntagResource', 'kms:ListResourceTags'],
      Resource: `arn:aws:kms:*:${acct}:key/*`,
    },
    {
      /* Alias operations need the grant on the alias AND the key resource. */
      Sid: 'OurAliasNamesOnly',
      Effect: 'Allow',
      Action: ['kms:CreateAlias', 'kms:UpdateAlias', 'kms:DeleteAlias'],
      Resource: [
        `arn:aws:kms:*:${acct}:alias/test-*`,
        `arn:aws:kms:*:${acct}:alias/other-*`,
        `arn:aws:kms:*:${acct}:key/*`,
      ],
    },
    {
      /* CancelKeyDeletion is here for manual rescue only; nothing in this
       * repository calls it, because reviving a key re-bills the whole window. */
      Sid: 'Lifecycle',
      Effect: 'Allow',
      Action: ['kms:DescribeKey', 'kms:ScheduleKeyDeletion', 'kms:CancelKeyDeletion'],
      Resource: `arn:aws:kms:*:${acct}:key/*`,
    },
    { Sid: 'TagSweep', Effect: 'Allow', Action: 'tag:GetResources', Resource: '*' },
    {
      /* Read-only, and the only way to verify "one kms:Sign per signature"
       * against the real service: the stub's HTTP request log has no equivalent
       * there. CloudTrail's free 90-day Event history needs no trail, just this
       * permission. Deliberately on the ADMIN role, not the signer -- the signer
       * must keep holding nothing but kms:Sign and kms:GetPublicKey, since that
       * is the claim the suite exists to test. */
      Sid: 'AuditOwnCalls',
      Effect: 'Allow',
      Action: 'cloudtrail:LookupEvents',
      Resource: '*',
    },
    {
      Sid: 'ChainToSigner',
      Effect: 'Allow',
      Action: 'sts:AssumeRole',
      Resource: `arn:aws:iam::${acct}:role/${SIGNER_ROLE}`,
    },
    {
      Sid: 'NeverSign',
      Effect: 'Deny',
      Action: [
        'kms:Sign', 'kms:Verify', 'kms:Decrypt', 'kms:GenerateDataKey*',
        'kms:DeriveSharedSecret', 'kms:ReplicateKey', 'kms:ImportKeyMaterial',
      ],
      Resource: '*',
    },
    {
      /* Stops this role ever creating a key nobody can manage. */
      Sid: 'NeverBypassLockout',
      Effect: 'Deny',
      Action: ['kms:CreateKey', 'kms:PutKeyPolicy'],
      Resource: '*',
      Condition: { Bool: { 'kms:BypassPolicyLockoutSafetyCheck': 'true' } },
    },
  ],
});

/* No kms:Verify -- verification is local, which is the property under test. No
 * kms:DescribeKey -- the provider never calls it, so an AccessDenied from it is a
 * wanted tripwire. No kms:MessageType condition: ED25519_SHA_512 requires RAW and
 * ML-DSA uses RAW and EXTERNAL_MU, so pinning DIGEST would break the suite. */
const signerPolicy = (acct) => ({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'SignAndFetchPublicKeys',
      Effect: 'Allow',
      Action: ['kms:Sign', 'kms:GetPublicKey'],
      Resource: `arn:aws:kms:*:${acct}:key/*`,
      Condition: { StringEquals: { 'kms:KeyUsage': 'SIGN_VERIFY' } },
    },
  ],
});

const signerTrust = (acct) => ({
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Principal: { AWS: `arn:aws:iam::${acct}:role/${ADMIN_ROLE}` },
      Action: 'sts:AssumeRole',
    },
  ],
});

/*
 * The subject prefix GitHub will actually put in the token, asked of GitHub
 * rather than guessed.
 *
 * Repositories created after 2026-07-15 emit IMMUTABLE subjects, which embed
 * owner and repository IDs:
 *
 *   classic     repo:owner/repo:ref:refs/heads/main
 *   immutable   repo:owner@241506/repo@1323939733:ref:refs/heads/main
 *
 * Guessing this is how the first real run failed with "Not authorized to perform
 * sts:AssumeRoleWithWebIdentity": the policy carried `repo:owner/repo*:ref:...`,
 * whose wildcard sits after the REPO name and so cannot absorb the `@<id>` that
 * follows the OWNER. GitHub reports the exact prefix, so ask it and use the
 * answer verbatim -- no wildcard, nothing to get subtly wrong.
 *
 * The IDs are immutable, which is the point: this survives renaming the repo or
 * the owner, where a name-based subject would silently stop matching.
 */
function githubSubPrefix(repo) {
  const r = spawnSync('gh', ['api', `repos/${repo}/actions/oidc/customization/sub`,
    '--jq', '.sub_claim_prefix'], { encoding: 'utf8' });
  const prefix = r.status === 0 ? r.stdout.trim() : '';
  if (prefix) return prefix;
  /* No gh, not authenticated, or an older GitHub: fall back to the classic
   * form. Say so, because a wrong guess here fails at assume-role time with an
   * error that names none of this. */
  console.log(`  WARNING: could not read the OIDC subject prefix from GitHub;`);
  console.log(`           falling back to the classic form. If the workflow later`);
  console.log(`           fails with "Not authorized to perform`);
  console.log(`           sts:AssumeRoleWithWebIdentity", read the real prefix with`);
  console.log(`             gh api repos/${repo}/actions/oidc/customization/sub`);
  console.log(`           and re-run this.`);
  return `repo:${repo}`;
}

/*
 * Admin trust: the caller themself (so the local pass works), plus optionally
 * GitHub OIDC.
 *
 * IAM requires the :sub condition to be present and not solely a wildcard.
 *
 * TWO subjects are allowed, and the second one widens this role materially --
 * read this before regenerating the policy:
 *
 *   <prefix>:ref:refs/heads/main   pushes, the schedule, workflow_dispatch
 *   <prefix>:pull_request          a pull request
 *
 * A pull_request event's subject carries no branch, so it cannot be narrowed
 * further here: the whole event type is either allowed or it is not. That means
 * AWS can no longer distinguish "a PR the maintainer chose to test" from "any PR
 * job in this repository" -- the ONLY thing making that distinction is the
 * `real-kms` label gate on ci.yml's real-kms job, backed by the
 * same-repo check that keeps fork PRs out (a fork gets no OIDC token at all on
 * a pull_request event, so it cannot reach this regardless).
 *
 * Accept this only knowing what it means: a job running PR-authored code can
 * mint its own OIDC token -- id-token:write puts ACTIONS_ID_TOKEN_REQUEST_URL and
 * ...REQUEST_TOKEN in the environment -- and assume this role, which can create
 * and delete KMS keys. "Assume the role, then unset the AWS_* vars before running
 * PR code" is NOT a mitigation, because the code simply re-mints the token.
 *
 * The alternative that removes the risk structurally, rather than gating it, is a
 * GitHub Environment: that rewrites the subject to repo:<repo>:environment:<name>,
 * which lets a separate sign-only role be bound to exactly that subject while
 * this one stays unreachable from any job running PR code. See TODO.txt Q6.
 */
const adminTrust = (acct, callerArn, repo, ref) => {
  const st = [
    { Effect: 'Allow', Principal: { AWS: callerArn }, Action: 'sts:AssumeRole' },
  ];
  if (repo) {
    st.push({
      Effect: 'Allow',
      Principal: { Federated: `arn:aws:iam::${acct}:oidc-provider/${OIDC_HOST}` },
      Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: {
        /* StringEquals, not StringLike: the prefix comes from GitHub verbatim,
         * so there is nothing to wildcard. Multiple values for one condition key
         * are OR-ed by IAM. */
        StringEquals: {
          [`${OIDC_HOST}:aud`]: 'sts.amazonaws.com',
          [`${OIDC_HOST}:sub`]: [
            `${githubSubPrefix(repo)}:ref:${ref}`,
            `${githubSubPrefix(repo)}:pull_request`,
          ],
        },
      },
    });
  }
  return { Version: '2012-10-17', Statement: st };
};

/* --------------------------------------------------------------------- apply */

/*
 * IAM validates that every Principal named in a trust policy already exists, and
 * a role created moments earlier is not immediately visible to that validation --
 * both surface as MalformedPolicyDocument. Retrying that one error covers the
 * propagation delay without masking a genuinely malformed document, which fails
 * identically on every attempt and so still surfaces after the last one.
 */
async function withPrincipalRetry(fn, { attempts = 8, what = 'call' } = {}) {
  let delay = 1000;
  for (let i = 1; ; i++) {
    const r = fn();
    if (r.ok) return r.value;
    if (r.error.errorCode !== 'MalformedPolicyDocument' || i >= attempts) throw r.error;
    console.log(`    principal not visible yet, retrying in ${delay}ms (${i}/${attempts})`);
    await new Promise((res) => setTimeout(res, delay));
    delay = Math.min(delay * 2, 8000);
  }
}

async function upsertRole(name, trust, policy, opts) {
  const exists = awsTry(['iam', 'get-role', '--role-name', name], opts).ok;
  if (exists) {
    console.log(`  ${name}: exists, updating trust policy and inline policy`);
    await withPrincipalRetry(
      () => awsTry(['iam', 'update-assume-role-policy', '--role-name', name,
        '--policy-document', J(trust)], opts),
      { what: name });
  } else {
    console.log(`  ${name}: creating`);
    await withPrincipalRetry(
      () => awsTry(['iam', 'create-role', '--role-name', name,
        '--description', 'tiny-aws-kms-openssl-provider test harness',
        '--assume-role-policy-document', J(trust)], opts),
      { what: name });
  }
  aws(['iam', 'put-role-policy', '--role-name', name,
    '--policy-name', `${name}Policy`, '--policy-document', J(policy)], opts);
}

function ensureOidcProvider(acct, opts) {
  const arn = `arn:aws:iam::${acct}:oidc-provider/${OIDC_HOST}`;
  if (awsTry(['iam', 'get-open-id-connect-provider', '--open-id-connect-provider-arn', arn], opts).ok) {
    console.log(`  OIDC provider: already registered`);
    return;
  }
  console.log(`  OIDC provider: registering ${OIDC_HOST}`);
  /* IAM still requires a thumbprint argument, but no longer uses it for
   * providers whose certificate chains to a well-known CA, which GitHub's does.
   * The value below is GitHub's published thumbprint. */
  aws(['iam', 'create-open-id-connect-provider',
    '--url', `https://${OIDC_HOST}`,
    '--client-id-list', 'sts.amazonaws.com',
    '--thumbprint-list', '6938fd4d98bab03faadb97b34396831e3780aea1'], opts);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!hasAwsCli()) {
    console.error('the `aws` CLI is required and was not found on PATH');
    console.error('  macOS: brew install awscli');
    process.exit(2);
  }
  if (!opts.profile) {
    console.error('--profile is required: an existing profile from ~/.aws/config.');
    console.error('It authenticates these IAM calls; nothing is created with that name.');
    process.exit(2);
  }

  const who = aws(['sts', 'get-caller-identity'], { ...opts, dryRun: false });
  const acct = who.Account;
  console.log(`account ${acct}`);
  console.log(`caller  ${who.Arn}`);
  console.log(`region  ${opts.region}\n`);

  if (opts.githubRepo) ensureOidcProvider(acct, opts);

  /*
   * ADMIN FIRST. The dependency runs this way round because IAM validates
   * Principals, not Resources:
   *
   *   signerTrust names AwskmsTestAdmin as a PRINCIPAL  -> admin must exist
   *   adminPolicy names AwskmsTestSigner as a RESOURCE  -> never validated
   *
   * and adminTrust names only the calling identity and the OIDC provider, both of
   * which exist by now. Creating the signer first fails with
   * MalformedPolicyDocument: Invalid principal in policy.
   */
  await upsertRole(
    ADMIN_ROLE,
    adminTrust(acct, who.Arn, opts.githubRepo, opts.githubRef),
    adminPolicy(acct),
    opts,
  );
  await upsertRole(SIGNER_ROLE, signerTrust(acct), signerPolicy(acct), opts);

  const adminArn = `arn:aws:iam::${acct}:role/${ADMIN_ROLE}`;
  const signerArn = `arn:aws:iam::${acct}:role/${SIGNER_ROLE}`;

  console.log(`\ndone.\n`);
  console.log(`Add these to ~/.aws/config yourself -- this script does not write it.`);
  console.log(`Check the names do not collide with profiles you already have.\n`);
  console.log(`[profile awskms-admin]`);
  console.log(`region = ${opts.region}`);
  console.log(`role_arn = ${adminArn}`);
  console.log(`source_profile = ${opts.profile}\n`);
  console.log(`[profile awskms-signer]`);
  console.log(`region = ${opts.region}`);
  console.log(`role_arn = ${signerArn}`);
  console.log(`source_profile = awskms-admin\n`);

  if (opts.githubRepo) {
    console.log(`Set these repository variables (Settings -> Secrets and variables -> Actions -> Variables):\n`);
    console.log(`  AWSKMS_TEST_REGION      ${opts.region}`);
    console.log(`  AWSKMS_ADMIN_ROLE_ARN   ${adminArn}`);
    console.log(`  AWSKMS_SIGNER_ROLE_ARN  ${signerArn}\n`);
    console.log(`  gh variable set AWSKMS_TEST_REGION --body ${opts.region}`);
    console.log(`  gh variable set AWSKMS_ADMIN_ROLE_ARN --body ${adminArn}`);
    console.log(`  gh variable set AWSKMS_SIGNER_ROLE_ARN --body ${signerArn}\n`);
  }
  console.log(`Then, still making no keys:`);
  console.log(`  node scripts/real-kms-keys.mjs setup --smoke --profile awskms-admin --dry-run`);
}

main().catch((err) => {
  console.error(`\n${err.message}`);
  process.exit(1);
});
