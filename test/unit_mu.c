/*
 * Cross-checks awskms_mu() against OpenSSL's own EVP_MD "ML-DSA-MU".
 *
 * mu is the most security-critical arithmetic in this codebase: get it wrong and
 * KMS returns perfectly well-formed signatures that simply never verify, with no
 * error anywhere. So rather than trust a round trip, this compares our value
 * against OpenSSL's independent implementation whenever the host has one.
 *
 * ML-DSA-MU arrived in OpenSSL 4.0 and is fetched by NAME, so depending on it
 * here costs no linker symbol and the test simply skips on older hosts. The
 * provider itself never uses it -- it must work on 3.5, where ML-DSA first exists
 * but ML-DSA-MU does not.
 *
 * Per docs.openssl.org/4.0/man7/EVP_MD-ML-DSA-MU the public key is a MANDATORY
 * parameter on EVP_DigestInit_ex2 ("pub"), the digest derives tr and applies the
 * M' = 0x00 || ctxlen || ctx || message framing itself, the message is streamed
 * with EVP_DigestUpdate, and the 64 bytes come out of EVP_DigestFinalXOF.
 */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "compat.h"
#include "spki.h"
#include "unit.h"

/* mu via OpenSSL. Returns 0 when ML-DSA-MU is unavailable (pre-4.0). */
static int openssl_mu(const unsigned char *pk, size_t pk_len,
                      const unsigned char *ctxs, size_t ctxs_len,
                      const unsigned char *msg, size_t msg_len,
                      unsigned char out[64]) {
  EVP_MD *md = EVP_MD_fetch(NULL, "ML-DSA-MU", NULL);
  EVP_MD_CTX *ctx = NULL;
  OSSL_PARAM params[3];
  size_t n = 0;
  int ok = 0;

  if (md == NULL) return 0;
  if ((ctx = EVP_MD_CTX_new()) == NULL) goto out;

  params[n++] = OSSL_PARAM_construct_octet_string(OSSL_DIGEST_PARAM_MU_PUB_KEY,
                                                  (void *)pk, pk_len);
  if (ctxs_len > 0)
    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_DIGEST_PARAM_MU_CONTEXT_STRING, (void *)ctxs, ctxs_len);
  params[n] = OSSL_PARAM_construct_end();

  /* Split the update deliberately: the message must be streamable. */
  if (EVP_DigestInit_ex2(ctx, md, params) == 1 &&
      (msg_len == 0 || (EVP_DigestUpdate(ctx, msg, msg_len / 2) == 1 &&
                        EVP_DigestUpdate(ctx, msg + msg_len / 2,
                                         msg_len - msg_len / 2) == 1)) &&
      EVP_DigestFinalXOF(ctx, out, 64) == 1)
    ok = 1;

out:
  EVP_MD_CTX_free(ctx);
  EVP_MD_free(md);
  return ok;
}

/* tr = SHAKE256(pk, 64), the same value spki.c caches at key load. */
static int compute_tr(const unsigned char *pk, size_t pk_len,
                      unsigned char tr[64]) {
  EVP_MD *shake = EVP_MD_fetch(NULL, "SHAKE256", NULL);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = shake != NULL && ctx != NULL &&
           EVP_DigestInit_ex2(ctx, shake, NULL) == 1 &&
           EVP_DigestUpdate(ctx, pk, pk_len) == 1 &&
           EVP_DigestFinalXOF(ctx, tr, 64) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_MD_free(shake);
  return ok;
}

static void compare(const char *alg, const unsigned char *ctxs, size_t ctxs_len,
                    size_t msg_len) {
  EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg);
  unsigned char pk[4096], tr[64], ours[64], theirs[64];
  unsigned char *msg = NULL;
  size_t pk_len = 0;

  if (pkey == NULL) return; /* no ML-DSA on this host */

  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pk,
                                      sizeof(pk), &pk_len) != 1) {
    CHECK(0, "%s: could not read the raw public key", alg);
    goto out;
  }
  if (!compute_tr(pk, pk_len, tr)) {
    CHECK(0, "%s: SHAKE256 unavailable", alg);
    goto out;
  }

  if (msg_len > 0) {
    if ((msg = OPENSSL_malloc(msg_len)) == NULL) goto out;
    for (size_t i = 0; i < msg_len; i++) msg[i] = (unsigned char)(i * 31 + 7);
  }

  /* Our own computation must always work, oracle or not. */
  CHECK(
      awskms_mu(NULL, NULL, tr, ctxs, ctxs_len, msg, msg_len, ours, NULL) == 1,
      "%s: awskms_mu failed (ctx=%zu, msg=%zu)", alg, ctxs_len, msg_len);

  /*
   * ML-DSA-MU in OpenSSL 4.0.1 SEGFAULTS when the message is empty -- both with
   * no EVP_DigestUpdate call and with a zero-length one; a 1-byte message is
   * fine. Minimal reproduction:
   *
   *   md = EVP_MD_fetch(NULL, "ML-DSA-MU", NULL);
   *   params[0] = OSSL_PARAM_construct_octet_string("pub", pk, pk_len);
   *   EVP_DigestInit_ex2(ctx, md, params);
   *   EVP_DigestFinalXOF(ctx, out, 64);        // <-- crash
   *
   * Signing an empty message is legitimate under FIPS 204, and our own SHAKE256
   * path handles it (asserted just above), so the oracle is simply skipped for
   * that case rather than crashing the test run.
   */
  if (msg_len == 0) goto out;

  if (!openssl_mu(pk, pk_len, ctxs, ctxs_len, msg, msg_len, theirs)) {
    /* Pre-4.0 hosts have no ML-DSA-MU at all; nothing to compare against. */
    goto out;
  }
  CHECK(memcmp(ours, theirs, 64) == 0,
        "%s: mu differs from OpenSSL's ML-DSA-MU (ctx=%zu, msg=%zu)", alg,
        ctxs_len, msg_len);

out:
  OPENSSL_free(msg);
  EVP_PKEY_free(pkey);
}

void test_mu(void) {
  static const unsigned char ctx_short[] = {0x41};
  unsigned char ctx_max[255];
  int have_oracle;

  for (size_t i = 0; i < sizeof(ctx_max); i++) ctx_max[i] = (unsigned char)i;

  {
    EVP_MD *md = EVP_MD_fetch(NULL, "ML-DSA-MU", NULL);
    have_oracle = md != NULL;
    EVP_MD_free(md);
    printf("  ML-DSA-MU oracle: %s\n",
           have_oracle ? "available" : "unavailable (OpenSSL < 4.0)");
  }

  for (const char *alg = NULL, **p = (const char *[]){"ML-DSA-44", "ML-DSA-65",
                                                      "ML-DSA-87", NULL};
       (alg = *p) != NULL; p++) {
    compare(alg, NULL, 0, 100);        /* no context */
    compare(alg, ctx_max, 0, 100);     /* explicitly empty context */
    compare(alg, ctx_short, 1, 100);   /* 1-byte context */
    compare(alg, ctx_max, 255, 100);   /* the FIPS 204 maximum */
    compare(alg, NULL, 0, 0);          /* empty message */
    compare(alg, ctx_short, 1, 0);     /* empty message with a context */
    compare(alg, NULL, 0, 100 * 1024); /* far past KMS's Message limit */
  }

  /* Over-long contexts must be refused rather than truncated. */
  {
    unsigned char tr[64] = {0}, out[64];
    CHECK(awskms_mu(NULL, NULL, tr, ctx_max, 256, (const unsigned char *)"x", 1,
                    out, NULL) == 0,
          "a 256-byte context string must be rejected");
    CHECK(awskms_mu(NULL, NULL, tr, ctx_max, 255, (const unsigned char *)"x", 1,
                    out, NULL) == 1,
          "a 255-byte context string must be accepted");
  }
}
