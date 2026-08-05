/*
 * A local stand-in for AWS KMS: no network, no credentials, no SDK.
 *
 * This exists so the provider can be developed and tested offline, and so the
 * store/keymgmt/signature machinery can be exercised without an AWS account. It
 * is NOT a production backend and is only compiled when AWSKMS_BACKEND=stub.
 *
 * The key spec is taken from the key id: any KMS KeySpec name appearing in it
 * selects that spec, so realistic URIs work --
 *   awskms:key-id=alias/my-RSA_2048-signer
 *   awskms:key-id=arn:aws:kms:eu-central-1:111122223333:key/ECC_NIST_P256
 * A key pair is generated on first use and cached under the key id for the life
 * of the process, so a load, a sign and a verify all agree with each other.
 */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

#include "err.h"
#include "keyspec.h"
#include "kms.h"

const char *awskms_kms_backend(void) { return "stub"; }

void awskms_public_key_cleanup(AWSKMS_PUBLIC_KEY *p) {
  if (p == NULL) return;
  OPENSSL_free(p->key_spec);
  OPENSSL_free(p->spki);
  memset(p, 0, sizeof(*p));
}

/* ------------------------------------------------------------ the fake token */

struct entry {
  char *key_id;
  const AWSKMS_KEYSPEC *spec;
  EVP_PKEY *pkey;
  struct entry *next;
};

static struct entry *entries;
static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *lock;

static void init_lock(void) { lock = CRYPTO_THREAD_lock_new(); }

/* Case-insensitive search for a KeySpec name anywhere in the key id. */
static const AWSKMS_KEYSPEC *spec_from_key_id(const char *key_id) {
  for (const AWSKMS_KEYSPEC *s = awskms_keyspec_all(); s->kms_key_spec != NULL;
       s++) {
    size_t n = strlen(s->kms_key_spec);
    for (const char *p = key_id; *p != '\0'; p++)
      if (OPENSSL_strncasecmp(p, s->kms_key_spec, n) == 0) return s;
  }
  return NULL;
}

static EVP_PKEY *generate(const AWSKMS_KEYSPEC *spec) {
  switch (spec->family) {
    case AWSKMS_FAMILY_RSA: {
      size_t bits = 2048;
      if (strcmp(spec->kms_key_spec, "RSA_3072") == 0) bits = 3072;
      if (strcmp(spec->kms_key_spec, "RSA_4096") == 0) bits = 4096;
      return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", bits);
    }
    case AWSKMS_FAMILY_EC:
      return EVP_PKEY_Q_keygen(NULL, NULL, "EC", spec->group_name);
    case AWSKMS_FAMILY_ED25519:
      return EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    case AWSKMS_FAMILY_ML_DSA:
      return EVP_PKEY_Q_keygen(NULL, NULL, spec->keytype);
  }
  return NULL;
}

/* Returns a borrowed entry, generating it on first use. */
static struct entry *lookup(AWSKMS_PROV_CTX *provctx, const char *key_id) {
  const AWSKMS_KEYSPEC *spec;
  struct entry *e;

  CRYPTO_THREAD_run_once(&once, init_lock);
  if (!CRYPTO_THREAD_write_lock(lock)) return NULL;

  for (e = entries; e != NULL; e = e->next)
    if (strcmp(e->key_id, key_id) == 0) goto out;

  if ((spec = spec_from_key_id(key_id)) == NULL) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_KEY_NOT_FOUND,
                 "stub backend: key id \"%s\" names no KMS key spec", key_id);
    goto out;
  }

  if ((e = OPENSSL_zalloc(sizeof(*e))) == NULL) goto out;
  if ((e->key_id = OPENSSL_strdup(key_id)) == NULL ||
      (e->pkey = generate(spec)) == NULL) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_INTERNAL_ERROR,
                 "stub backend: could not generate a %s key",
                 spec->kms_key_spec);
    OPENSSL_free(e->key_id);
    EVP_PKEY_free(e->pkey);
    OPENSSL_free(e);
    e = NULL;
    goto out;
  }
  e->spec = spec;
  e->next = entries;
  entries = e;

out:
  CRYPTO_THREAD_unlock(lock);
  return e;
}

/* ------------------------------------------------------------ fault injection */

/*
 * A key id containing one of these markers makes GetPublicKey return something
 * malformed, which is what exercises the provider's own validation.
 *
 * Those paths are otherwise unreachable offline. They guard against a key spec
 * this provider does not implement (SM2, HMAC) and against a SubjectPublicKeyInfo
 * that does not match the KeySpec reported alongside it -- both producible only by
 * the real service. A marker in the key id is the least invasive way to reach
 * them, and is test-only by construction, since this file is compiled for the stub
 * backend alone.
 */
static int has_fault(const char *key_id, const char *name) {
  return strstr(key_id, name) != NULL;
}

int awskms_kms_get_public_key(AWSKMS_PROV_CTX *provctx, const AWSKMS_URI *uri,
                              AWSKMS_PUBLIC_KEY *out) {
  struct entry *e = lookup(provctx, uri->key_id);
  unsigned char *der = NULL;
  int len;

  if (e == NULL) return 0;

  if ((len = i2d_PUBKEY(e->pkey, &der)) <= 0) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_GET_PUBLIC_KEY_FAILED,
                 "stub backend: could not encode the public key");
    return 0;
  }
  /* A KeySpec this provider does not implement -- what a real SM2 or HMAC key
   * would report. Must surface as UNSUPPORTED_KEY_SPEC at load. */
  if (has_fault(uri->key_id, "fault-badspec")) {
    out->key_spec = OPENSSL_strdup("SM2");
  } else if (has_fault(uri->key_id, "fault-wrongtype")) {
    /* Claim RSA while serving whatever the key id actually named. Catches the
     * KeySpec/SPKI disagreement in EVP_PKEY_is_a. */
    out->key_spec = OPENSSL_strdup("RSA_2048");
  } else if (has_fault(uri->key_id, "fault-wronggroup")) {
    /* Right key type, wrong curve -- the one a lazy is_a() check would miss. */
    out->key_spec = OPENSSL_strdup(
        strcmp(e->spec->kms_key_spec, "ECC_NIST_P256") == 0 ? "ECC_NIST_P384"
                                                            : "ECC_NIST_P256");
  } else {
    out->key_spec = OPENSSL_strdup(e->spec->kms_key_spec);
  }
  if (out->key_spec == NULL) {
    OPENSSL_free(der);
    return 0;
  }

  /* SPKI that does not match the KeySpec alongside it. Each must surface as
   * MALFORMED_PUBLIC_KEY rather than as a key that half-works. */
  if (has_fault(uri->key_id, "fault-emptyspki")) {
    OPENSSL_free(der);
    out->spki = NULL;
    out->spki_len = 0;
    return 1;
  }
  if (has_fault(uri->key_id, "fault-truncspki")) {
    out->spki = der;
    out->spki_len = (size_t)len / 2;
    return 1;
  }
  if (has_fault(uri->key_id, "fault-badspki")) {
    /* Corrupt the body but leave the leading SEQUENCE tag, so this fails in the
     * parser rather than being rejected as obviously-not-DER. */
    for (int i = len / 2; i < len; i++) der[i] ^= 0xff;
    out->spki = der;
    out->spki_len = (size_t)len;
    return 1;
  }

  /* i2d_PUBKEY allocates with OPENSSL_malloc, so ownership transfers cleanly. */
  out->spki = der;
  out->spki_len = (size_t)len;
  return 1;
}

/* Mirrors KMS's own semantics for a SigningAlgorithm: which digest it implies and
 * whether it is PSS. */
static int parse_algorithm(const char *algorithm, const char **md_name,
                           int *pss) {
  const char *suffix;

  *pss = 0;
  if ((suffix = strstr(algorithm, "_SHA_")) != NULL) {
    suffix += 5;
    if (strcmp(suffix, "256") == 0)
      *md_name = "SHA2-256";
    else if (strcmp(suffix, "384") == 0)
      *md_name = "SHA2-384";
    else if (strcmp(suffix, "512") == 0)
      *md_name = "SHA2-512";
    else
      return 0;
    *pss = strncmp(algorithm, "RSASSA_PSS_", 11) == 0;
    return 1;
  }
  return 0;
}

int awskms_kms_sign(AWSKMS_PROV_CTX *provctx, const AWSKMS_URI *uri,
                    const char *signing_algorithm, const char *message_type,
                    const unsigned char *msg, size_t msg_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len) {
  struct entry *e = lookup(provctx, uri->key_id);
  EVP_PKEY_CTX *pctx = NULL;
  EVP_MD *md = NULL;
  const char *md_name = NULL;
  int pss = 0;
  size_t out_len = sig_size;
  int ok = 0;

  if (e == NULL) return 0;

  /* KMS's documented Message limit. The provider is expected to have rejected
   * oversize input already, so reaching this means a bug upstream of here. */
  if (msg_len < 1 || msg_len > 4096) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_SIGN_FAILED,
                 "stub backend: Message must be 1-4096 bytes, got %zu",
                 msg_len);
    return 0;
  }

  /* MessageType=RAW means "sign the message itself", which for Ed25519 is a
   * one-shot EVP_DigestSign with no digest -- exactly what KMS does. */
  if (strcmp(message_type, "RAW") == 0) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    size_t raw_len = sig_size;

    if (mdctx != NULL &&
        EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL, e->pkey, NULL) ==
            1 &&
        EVP_DigestSign(mdctx, sig, &raw_len, msg, msg_len) == 1) {
      *sig_len = raw_len;
      ok = 1;
    }
    EVP_MD_CTX_free(mdctx);
    if (!ok)
      AWSKMS_raise(provctx->handle, AWSKMS_R_SIGN_FAILED,
                   "stub backend: RAW signing with %s failed",
                   signing_algorithm);
    return ok;
  }

  /*
   * MessageType=EXTERNAL_MU: the Message already IS the 64-byte FIPS 204 mu, and
   * KMS skips the public-key/message hashing it would normally do. The matching
   * OpenSSL operation is EVP_PKEY_sign_message_init() with the "mu" parameter
   * set -- verified to be the only route that works: plain EVP_PKEY_sign_init and
   * EVP_PKEY_sign_init_ex2 both fail for ML-DSA on 3.5 and 3.6, and the resulting
   * signature verifies as ordinary pure ML-DSA.
   *
   * EVP_PKEY_sign_message_init is an OpenSSL 3.5 linker symbol, so it is guarded.
   * That costs nothing: ML-DSA does not exist before 3.5 either, so on an older
   * host there is no ML-DSA key to sign. (Only this test-only backend references
   * it; the aws backend, which is what ships, does not.)
   */
  if (strcmp(message_type, "EXTERNAL_MU") == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    EVP_SIGNATURE *alg = NULL;
    int one = 1;
    OSSL_PARAM params[2];

    if (msg_len != 64) {
      AWSKMS_raise(
          provctx->handle, AWSKMS_R_SIGN_FAILED,
          "stub backend: EXTERNAL_MU requires a 64-byte Message, got %zu",
          msg_len);
      return 0;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MU, &one);
    params[1] = OSSL_PARAM_construct_end();

    alg = EVP_SIGNATURE_fetch(NULL, e->spec->keytype, NULL);
    if (alg != NULL &&
        (pctx = EVP_PKEY_CTX_new_from_pkey(NULL, e->pkey, NULL)) != NULL &&
        EVP_PKEY_sign_message_init(pctx, alg, params) > 0 &&
        EVP_PKEY_sign(pctx, sig, &out_len, msg, msg_len) > 0) {
      *sig_len = out_len;
      ok = 1;
    }
    EVP_SIGNATURE_free(alg);
    EVP_PKEY_CTX_free(pctx);
    if (!ok)
      AWSKMS_raise(provctx->handle, AWSKMS_R_SIGN_FAILED,
                   "stub backend: EXTERNAL_MU signing with %s failed",
                   signing_algorithm);
    return ok;
#else
    AWSKMS_raise(
        provctx->handle, AWSKMS_R_SIGN_FAILED,
        "stub backend: EXTERNAL_MU needs OpenSSL 3.5 headers, which is "
        "also the floor for ML-DSA");
    return 0;
#endif
  }

  if (strcmp(message_type, "DIGEST") != 0) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_SIGN_FAILED,
                 "stub backend: MessageType %s is not implemented",
                 message_type);
    return 0;
  }
  if (!parse_algorithm(signing_algorithm, &md_name, &pss)) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_SIGN_FAILED,
                 "stub backend: unknown SigningAlgorithm %s",
                 signing_algorithm);
    return 0;
  }

  /* EVP_PKEY_sign on a pre-computed digest is exactly what MessageType=DIGEST
   * means, so the stub and the real service agree by construction. */
  if ((md = EVP_MD_fetch(NULL, md_name, NULL)) == NULL) goto out;
  if ((pctx = EVP_PKEY_CTX_new_from_pkey(NULL, e->pkey, NULL)) == NULL)
    goto out;
  if (EVP_PKEY_sign_init(pctx) <= 0) goto out;
  if (e->spec->family == AWSKMS_FAMILY_RSA) {
    int padding = pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, padding) <= 0) goto out;
    /* KMS always uses a salt length equal to the digest length. */
    if (pss &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
      goto out;
  }
  if (EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0) goto out;
  if (EVP_PKEY_sign(pctx, sig, &out_len, msg, msg_len) <= 0) goto out;

  *sig_len = out_len;
  ok = 1;

out:
  if (!ok)
    AWSKMS_raise(provctx->handle, AWSKMS_R_SIGN_FAILED,
                 "stub backend: signing with %s failed", signing_algorithm);
  EVP_PKEY_CTX_free(pctx);
  EVP_MD_free(md);
  return ok;
}
