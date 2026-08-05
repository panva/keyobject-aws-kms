#include "spki.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <string.h>

#include "err.h"
#include "provider.h"

/* tr = SHAKE256(pk, 64), per FIPS 204.
 *
 * EVP_DigestFinalXOF, not EVP_DigestFinal_ex: OpenSSL's SHAKE256 EVP_MD reports
 * md_size == 32, so EVP_DigestFinal_ex would silently produce 32 bytes and every
 * signature would be over the wrong mu. */
static int compute_tr(AWSKMS_PUBKEY *p, OSSL_LIB_CTX *libctx,
                      const OSSL_CORE_HANDLE *handle) {
  EVP_MD *shake = NULL;
  EVP_MD_CTX *ctx = NULL;
  int ok = 0;

  if ((shake = EVP_MD_fetch(libctx, "SHAKE256", AWSKMS_EXCLUDE_SELF)) == NULL) {
    AWSKMS_raise(handle, AWSKMS_R_INTERNAL_ERROR,
                 "SHAKE256 is unavailable, so ML-DSA mu cannot be computed");
    goto out;
  }
  if ((ctx = EVP_MD_CTX_new()) == NULL) goto out;
  if (EVP_DigestInit_ex2(ctx, shake, NULL) != 1 ||
      EVP_DigestUpdate(ctx, p->raw, p->raw_len) != 1 ||
      EVP_DigestFinalXOF(ctx, p->tr, sizeof(p->tr)) != 1) {
    AWSKMS_raise(handle, AWSKMS_R_INTERNAL_ERROR,
                 "SHAKE256 of the public key failed");
    goto out;
  }
  p->have_tr = 1;
  ok = 1;

out:
  EVP_MD_CTX_free(ctx);
  EVP_MD_free(shake);
  return ok;
}

static int load_raw_public(AWSKMS_PUBKEY *p, const OSSL_CORE_HANDLE *handle) {
  size_t len = 0;

  if (EVP_PKEY_get_octet_string_param(p->pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                      &len) != 1 ||
      len == 0) {
    AWSKMS_raise(handle, AWSKMS_R_MALFORMED_PUBLIC_KEY,
                 "%s public key exposes no raw public value",
                 p->spec->kms_key_spec);
    return 0;
  }
  if ((p->raw = OPENSSL_malloc(len)) == NULL) return 0;
  if (EVP_PKEY_get_octet_string_param(p->pkey, OSSL_PKEY_PARAM_PUB_KEY, p->raw,
                                      len, &p->raw_len) != 1) {
    AWSKMS_raise(handle, AWSKMS_R_MALFORMED_PUBLIC_KEY,
                 "could not read the raw public value");
    return 0;
  }
  /* An exact length check is what catches the classic mistake of including the
   * BIT STRING's leading unused-bits octet: mu would then be computed over
   * pk_len + 1 bytes, KMS would return a well-formed signature, and it would
   * never verify anywhere. */
  if (p->spec->pub_len != 0 && p->raw_len != p->spec->pub_len) {
    AWSKMS_raise(handle, AWSKMS_R_MALFORMED_PUBLIC_KEY,
                 "%s public key is %zu bytes, expected %zu",
                 p->spec->kms_key_spec, p->raw_len, p->spec->pub_len);
    return 0;
  }
  return 1;
}

static int check_group(AWSKMS_PUBKEY *p, const OSSL_CORE_HANDLE *handle) {
  char group[80] = {0};
  size_t len = 0;

  if (EVP_PKEY_get_utf8_string_param(p->pkey, OSSL_PKEY_PARAM_GROUP_NAME, group,
                                     sizeof(group), &len) != 1) {
    AWSKMS_raise(handle, AWSKMS_R_MALFORMED_PUBLIC_KEY,
                 "EC public key exposes no group name");
    return 0;
  }
  if (strcmp(group, p->spec->group_name) != 0) {
    AWSKMS_raise(handle, AWSKMS_R_MALFORMED_PUBLIC_KEY,
                 "%s public key is on curve \"%s\", expected \"%s\"",
                 p->spec->kms_key_spec, group, p->spec->group_name);
    return 0;
  }
  return 1;
}

int awskms_pubkey_from_spki(AWSKMS_PUBKEY *out, const unsigned char *der,
                            size_t der_len, const char *kms_key_spec,
                            OSSL_LIB_CTX *libctx,
                            const OSSL_CORE_HANDLE *handle) {
  const unsigned char *p = der;

  if ((out->spec = awskms_keyspec_by_name(kms_key_spec)) == NULL) {
    AWSKMS_raise(handle, AWSKMS_R_UNSUPPORTED_KEY_SPEC,
                 "key spec \"%s\" is not supported",
                 kms_key_spec != NULL ? kms_key_spec : "(none)");
    goto err;
  }

  if (der == NULL || der_len == 0) {
    AWSKMS_raise(handle, AWSKMS_R_MALFORMED_PUBLIC_KEY, "empty public key");
    goto err;
  }

  /* Excluding ourselves is not merely tidy: our own keymgmt cannot construct a
   * key from foreign material (it has no `import`), so re-entering here would
   * simply fail. */
  out->pkey =
      d2i_PUBKEY_ex(NULL, &p, (long)der_len, libctx, AWSKMS_EXCLUDE_SELF);
  if (out->pkey == NULL) {
    AWSKMS_raise(handle, AWSKMS_R_MALFORMED_PUBLIC_KEY,
                 "could not parse the %s SubjectPublicKeyInfo",
                 out->spec->kms_key_spec);
    goto err;
  }

  /* KMS told us the spec and the SPKI told us the key type; if they disagree,
   * something is wrong upstream and guessing would be worse than failing. */
  if (EVP_PKEY_is_a(out->pkey, out->spec->keytype) != 1) {
    AWSKMS_raise(handle, AWSKMS_R_MALFORMED_PUBLIC_KEY,
                 "%s public key is not a %s key", out->spec->kms_key_spec,
                 out->spec->keytype);
    goto err;
  }

  switch (out->spec->family) {
    case AWSKMS_FAMILY_EC:
      if (!check_group(out, handle)) goto err;
      break;
    case AWSKMS_FAMILY_ED25519:
      if (!load_raw_public(out, handle)) goto err;
      break;
    case AWSKMS_FAMILY_ML_DSA:
      if (!load_raw_public(out, handle)) goto err;
      if (!compute_tr(out, libctx, handle)) goto err;
      break;
    case AWSKMS_FAMILY_RSA:
      /* Nothing extra: n and e are read straight off pkey when asked for. */
      break;
  }

  return 1;

err:
  awskms_pubkey_cleanup(out);
  return 0;
}

int awskms_mu(OSSL_LIB_CTX *libctx, const char *propq,
              const unsigned char tr[64], const unsigned char *ctx_string,
              size_t ctx_string_len, const unsigned char *msg, size_t msg_len,
              unsigned char out[64], const OSSL_CORE_HANDLE *handle) {
  EVP_MD *shake = NULL;
  EVP_MD_CTX *mdctx = NULL;
  unsigned char prefix[2];
  int ok = 0;

  if (ctx_string_len > 255) {
    AWSKMS_raise(handle, AWSKMS_R_UNSUPPORTED_PARAMETER,
                 "an ML-DSA context string may be at most 255 bytes, got %zu",
                 ctx_string_len);
    return 0;
  }

  shake = EVP_MD_fetch(libctx, "SHAKE256",
                       propq != NULL ? propq : AWSKMS_EXCLUDE_SELF);
  if (shake == NULL) {
    AWSKMS_raise(handle, AWSKMS_R_INTERNAL_ERROR,
                 "SHAKE256 is unavailable, so ML-DSA mu cannot be computed");
    goto out;
  }
  if ((mdctx = EVP_MD_CTX_new()) == NULL) goto out;

  prefix[0] = 0x00; /* pure ML-DSA domain separator; 0x01 would be HashML-DSA */
  prefix[1] = (unsigned char)ctx_string_len;

  /* EVP_DigestFinalXOF, not EVP_DigestFinal_ex: SHAKE256's EVP_MD reports
   * md_size == 32, so the latter would silently yield half a mu. */
  if (EVP_DigestInit_ex2(mdctx, shake, NULL) != 1 ||
      EVP_DigestUpdate(mdctx, tr, 64) != 1 ||
      EVP_DigestUpdate(mdctx, prefix, sizeof(prefix)) != 1 ||
      (ctx_string_len != 0 &&
       EVP_DigestUpdate(mdctx, ctx_string, ctx_string_len) != 1) ||
      EVP_DigestUpdate(mdctx, msg, msg_len) != 1 ||
      EVP_DigestFinalXOF(mdctx, out, 64) != 1) {
    AWSKMS_raise(handle, AWSKMS_R_INTERNAL_ERROR, "computing ML-DSA mu failed");
    goto out;
  }
  ok = 1;

out:
  EVP_MD_CTX_free(mdctx);
  EVP_MD_free(shake);
  return ok;
}

void awskms_pubkey_cleanup(AWSKMS_PUBKEY *p) {
  if (p == NULL) return;
  EVP_PKEY_free(p->pkey);
  OPENSSL_clear_free(p->raw, p->raw_len);
  memset(p, 0, sizeof(*p));
}
