/*
 * What this build can actually be tested for.
 *
 * ML-DSA availability is TWO questions, and conflating them cost a confusing CI
 * failure -- twenty tests failing with a bare ERR_OSSL_AWSKMS_SIGN_FAILED and no
 * explanation:
 *
 *   1. can the HOST node's OpenSSL do ML-DSA at all?  A runtime question,
 *      answered by trying to generate a key. Below OpenSSL 3.5 there is no
 *      ML-DSA, so there is nothing to test anywhere.
 *   2. can the STUB backend SIGN ML-DSA?  A BUILD-TIME question. src/kms_stub.c
 *      needs EVP_PKEY_sign_message_init for EXTERNAL_MU -- a 3.5 linker symbol --
 *      and compiles that path out against older headers. CMake records the answer
 *      next to the module.
 *
 * The two disagree exactly when the headers are older than the runtime, which is
 * the normal case on any distro shipping OpenSSL 3.0 (Ubuntu 24.04, RHEL 9,
 * Debian 12) under a node bundling 3.5. Asking only (1) there says "ML-DSA is
 * available", and then every ML-DSA signature fails against a fake that cannot
 * produce one.
 *
 * Only the STUB is affected. The real backend never signs locally -- KMS does --
 * and computes mu with SHAKE256, which is 3.0-era. So this narrows what the test
 * FAKE can demonstrate; it says nothing about the provider.
 */
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/* (1) the runtime question. */
const hostHasMlDsa = (() => {
  try {
    generateKeyPairSync('ml-dsa-44');
    return true;
  } catch {
    return false;
  }
})();

/* (2) the build-time question, from the marker CMake writes beside the module. */
function stubCanSignMlDsa() {
  const modulePath = process.env.AWSKMS_MODULE;
  if (!modulePath) return true; /* not a cmake build tree; assume capable */
  try {
    return readFileSync(join(dirname(modulePath), 'awskms-stub-mldsa'), 'utf8').trim() !== 'no';
  } catch {
    /* Older build tree with no marker. Assume capable rather than skipping
     * silently: a false failure is loud and gets fixed, a false skip is not. */
    return true;
  }
}

/*
 * (3) the HTTP-stub question, for the aws backend.
 *
 * With AWSKMS_BACKEND=aws the tests talk to test/kms-stub.mjs over HTTP, and it
 * signs by shelling out to the `openssl` CLI -- so what that CLI supports is a
 * THIRD, independent answer. Ubuntu ships 3.0.13, which has no ML-DSA, while
 * homebrew or a self-built 3.5+ does; AWSKMS_OPENSSL selects which one.
 * test/run.mjs passes the stub's own verdict down, since the stub runs in the
 * parent process and the tests run in a child.
 */
const stubUnsupported = new Set(
  (process.env.AWSKMS_STUB_UNSUPPORTED ?? '').split(',').filter(Boolean));

/** Specs the HTTP stub cannot serve here. Empty unless it is in use. */
export const unsupportedSpecs = stubUnsupported;

/*
 * True when ML-DSA can be exercised end to end here. Use the reason too, so a
 * skipped test says WHICH of the three reasons applied rather than just
 * "skipped" -- they are genuinely different problems and only one of them is
 * ever worth acting on.
 */
export const hasMlDsa =
  hostHasMlDsa && stubCanSignMlDsa() && !stubUnsupported.has('ML_DSA_44');

export const mlDsaSkipReason = !hostHasMlDsa
  ? 'needs OpenSSL 3.5+'
  : !stubCanSignMlDsa()
    ? 'the stub backend was built against OpenSSL < 3.5 and cannot sign ML-DSA'
    : stubUnsupported.has('ML_DSA_44')
      ? 'the HTTP stub\'s openssl CLI has no ML-DSA (set AWSKMS_OPENSSL to a 3.5+ one)'
      : false;
