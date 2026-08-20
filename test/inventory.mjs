/*
 * The single source of truth for which KMS keys the suite needs.
 *
 * This exists because the provisioning script and the tests must not be able to
 * disagree. Everything that resolves a key goes through alias(), which throws on
 * an unknown spec or role -- so a test cannot quietly reference a key that setup
 * does not create, and setup cannot create a set the tests do not use.
 *
 * Two keys per spec:
 *   test-<SPEC>    the key under test
 *   other-<SPEC>   a DIFFERENT key of the SAME spec, so negative tests can prove
 *                  a signature does not verify under the wrong key. A second key
 *                  of a different spec would not prove it -- the verify would
 *                  fail on the key type alone.
 *
 * Against the stub these aliases are resolved by pattern, so nothing has to be
 * provisioned. Against real KMS they are real aliases on real keys; see
 * scripts/real-kms-keys.mjs.
 */
import { isReal, realAlias } from './real-keys.mjs';

/*
 * `spec` is the literal KMS KeySpec, which is also the alias suffix and the label
 * the test files already use. `pqc` marks the specs whose regional availability
 * is not guaranteed, so setup can report them as unavailable and the suites can
 * skip rather than fail.
 */
export const KEY_SPECS = [
  { spec: 'RSA_2048', family: 'rsa', smoke: true },
  { spec: 'RSA_3072', family: 'rsa' },
  { spec: 'RSA_4096', family: 'rsa' },
  { spec: 'ECC_NIST_P256', family: 'ec', smoke: true },
  { spec: 'ECC_NIST_P384', family: 'ec' },
  { spec: 'ECC_NIST_P521', family: 'ec' },
  { spec: 'ECC_NIST_EDWARDS25519', family: 'ed25519', smoke: true },
  { spec: 'ML_DSA_44', family: 'ml-dsa', pqc: true, smoke: true },
  { spec: 'ML_DSA_65', family: 'ml-dsa', pqc: true },
  { spec: 'ML_DSA_87', family: 'ml-dsa', pqc: true },
];

/*
 * What the focused real-service pass must prove.  Keep this independent from
 * the per-KeySpec list above: if a smoke flag is accidentally removed, or a new
 * family replaces an old one, the real-KMS lane must fail instead of quietly
 * running a smaller matrix.
 *
 * Most error handling is more precisely covered by the HTTP stub, where the
 * exact response and request count are observable.  key-not-found is the one
 * retained service error: it proves the real SDK maps an actual KMS error into
 * the provider's public reason code.
 */
export const REAL_KMS_COVERAGE = Object.freeze({
  families: Object.freeze(['rsa', 'ec', 'ed25519', 'ml-dsa']),
  interfaces: Object.freeze(['node-crypto', 'webcrypto']),
  signatureModes: Object.freeze([
    'rsa-pkcs1-v1_5',
    'rsa-pss',
    'ecdsa',
    'ed25519',
    'ml-dsa',
  ]),
  serviceErrors: Object.freeze(['key-not-found']),
});

export const ROLES = ['test', 'other'];

const BY_SPEC = new Map(KEY_SPECS.map((k) => [k.spec, k]));

/*
 * The single way to name a key. Throwing rather than returning a plausible alias
 * means a typo, or a spec added to a test but not here, fails at test time instead
 * of becoming a NotFoundException from a real AWS account -- which is
 * indistinguishable from a provisioning failure.
 */
export function alias(role, spec) {
  if (!ROLES.includes(role)) {
    throw new Error(`unknown key role "${role}"; expected one of ${ROLES.join(', ')}`);
  }
  if (!BY_SPEC.has(spec)) {
    throw new Error(
      `unknown key spec "${spec}"; add it to test/inventory.mjs so it gets provisioned`,
    );
  }
  return `alias/${role}-${spec}`;
}

/* The URI the provider takes, for the common case. */
export function uri(role, spec, attrs = '') {
  /* Real runs use only the collision-resistant namespace recorded for this
   * manifest. Omitted smoke specs resolve to inert names in that same namespace
   * so top-level fixture construction stays harmless before the test skips. */
  const keyId = isReal ? realAlias(role, spec) ?? 'alias/awskms-missing-manifest' : alias(role, spec);
  return `aws-kms:key-id=${keyId}${attrs}`;
}

export function specsFor({ smokeOnly = false } = {}) {
  return smokeOnly ? KEY_SPECS.filter((k) => k.smoke) : KEY_SPECS;
}

/* Every (role, spec) pair that must exist. This is what setup provisions and
 * teardown schedules for deletion -- nothing else decides the set. */
export function required({ smokeOnly = false, roles = ROLES } = {}) {
  if (!Array.isArray(roles) || roles.length === 0 ||
      new Set(roles).size !== roles.length) {
    throw new Error('key roles must be a non-empty list without duplicates');
  }
  for (const role of roles) {
    if (!ROLES.includes(role)) {
      throw new Error(`unknown key role "${role}"; expected one of ${ROLES.join(', ')}`);
    }
  }
  return specsFor({ smokeOnly }).flatMap((k) =>
    roles.map((role) => ({ role, ...k, alias: alias(role, k.spec) })),
  );
}
