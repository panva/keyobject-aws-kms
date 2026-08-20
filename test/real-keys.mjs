/*
 * The only module that knows real KMS exists.
 *
 * In stub mode every accessor returns null/true-ish defaults so the existing
 * fixtures stand unchanged -- both modes run the same test files, which is the
 * whole point. Divergence between "what we test offline" and "what we test against
 * AWS" is exactly the gap the real-KMS pass exists to close, so the files must not
 * fork.
 */
import { readFileSync } from 'node:fs';

export const isReal = process.env.AWSKMS_TEST_REAL === '1';

const manifestPath = process.env.AWSKMS_TEST_MANIFEST ?? 'build/real-kms-keys.json';

const manifest = (() => {
  if (!isReal) return null;
  try {
    return JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    return null;
  }
})();

export const region = process.env.AWS_REGION ?? null;

/*
 * The real ARN of a provisioned key, or null.
 *
 * Never hardcode one of these: keys are recreated every run, so the ARN
 * legitimately changes. A cached ARN is a test that passes until it doesn't.
 */
export function realArn(role, spec) {
  return manifest?.keys?.[`${role}-${spec}`]?.arn ?? null;
}

/* The collision-resistant alias recorded for this exact provisioning run. */
export function realAlias(role, spec) {
  const exact = manifest?.keys?.[`${role}-${spec}`]?.alias;
  if (exact) return exact;
  if (!manifest?.runId) return null;
  /* A smoke manifest intentionally omits most specs. Keep even those inert
   * fixture URIs inside this run's collision-resistant namespace so a missed
   * skip can never fall back to a generic account alias. */
  return `alias/awskms-${manifest.runId}-${role}-${spec}`
    .toLowerCase()
    .replaceAll('_', '-');
}

/*
 * Whether a spec is usable this run.
 *
 * In real mode a spec is provisioned or it is not, with two innocent reasons for
 * "not": unsupported in this region, or outside the --smoke subset. Both skip.
 * Treating either as a failure would make a --smoke run report 14 specs' worth of
 * failures, which devalues the whole suite's output.
 */
export function provisioned(spec) {
  if (!isReal) return true;
  if (!manifest) return false;
  return Object.values(manifest.keys ?? {}).some((k) => k.spec === spec);
}

export function skipReason(spec) {
  if (!isReal) return null;
  if (!manifest) return `no manifest at ${manifestPath}; run scripts/real-kms-keys.mjs setup`;
  if (manifest.unavailable?.includes(spec)) return `${spec} unavailable in ${manifest.region}`;
  if (!provisioned(spec)) return `${spec} not provisioned (smoke subset?)`;
  return null;
}

/*
 * The skip reason for a block that needs SEVERAL specs -- the first one missing
 * wins. Blocks that name specs inline rather than looping over a case list need
 * this, and getting it wrong is invisible offline (where everything is
 * provisioned) and only shows up as KEY_NOT_FOUND against a --smoke real run.
 */
export function skipForAny(specs, otherReason = false) {
  for (const spec of specs) {
    const r = skipReason(spec);
    if (r) return r;
  }
  return otherReason;
}

/* Composes the provisioning skip with any other reason (e.g. the host OpenSSL
 * lacking ML-DSA), and reports WHICH applied -- "skipped" with no reason is how a
 * spec silently stops being tested. */
export function skipFor(spec, otherReason = false) {
  return skipReason(spec) ?? otherReason;
}

/*
 * A `;region=` attribute that is correct in both modes.
 *
 * The stub accepts anything; real KMS does not, and a URI pinning a region the
 * test bed is not in fails in a way that looks like a provisioning bug. In real
 * mode this also covers the redundant-but-consistent case: an explicit region
 * equal to the ambient one must be accepted, not rejected as a conflict.
 */
export function regionAttr(stubRegion = 'eu-central-1') {
  return `;region=${isReal ? region : stubRegion}`;
}

export const unavailable = manifest?.unavailable ?? [];
export const manifestRegion = manifest?.region ?? null;
export const hasManifest = manifest != null;
