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
 * True when ML-DSA can be exercised end to end here. Use it for the skip
 * REASON as well, so a skipped test says which of the two reasons applied
 * rather than just "skipped".
 */
export const hasMlDsa = hostHasMlDsa && stubCanSignMlDsa();

export const mlDsaSkipReason = hostHasMlDsa
  ? (stubCanSignMlDsa()
      ? false
      : 'the stub backend was built against OpenSSL < 3.5 and cannot sign ML-DSA')
  : 'needs OpenSSL 3.5+';
