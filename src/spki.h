/*
 * The public half of a KMS key.
 *
 * kms:GetPublicKey returns a DER SubjectPublicKeyInfo, which is handed straight
 * to d2i_PUBKEY_ex() with a property query that excludes this provider. The
 * resulting non-AWS EVP_PKEY then serves three purposes at once, which is why
 * there is no hand-rolled DER anywhere in this codebase:
 *
 *   - it answers keymgmt get_params (bits, security-bits, max-size, n/e,
 *     group, pub) by simple delegation, so EVP_PKEY_size() and
 *     asymmetricKeyDetails come out right without a table of our own;
 *   - EVP_PKEY_todata() produces exactly the OSSL_PARAMs the default provider's
 *     encoder wants, so SPKI export is correct by construction;
 *   - it is the key local verification runs against, so verifying costs no KMS
 *     call and needs no kms:Verify permission.
 */
#ifndef AWSKMS_SPKI_H
#define AWSKMS_SPKI_H

#include <openssl/core.h>
#include <openssl/evp.h>

#include "keyspec.h"

typedef struct awskms_pubkey_st {
  /* Exact DER returned by KMS. Owned. A signature operation can request FIPS
   * after this key was loaded without it; retaining the source bytes lets that
   * operation parse and validate a separate public view under fips=yes instead
   * of reusing a key produced by an unconstrained decoder. */
  unsigned char *der;
  size_t der_len;

  /* Non-AWS-provider public key parsed from the SPKI. Owned. */
  EVP_PKEY *pkey;
  const AWSKMS_KEYSPEC *spec;

  /* Raw public key bytes, for the specs where we need them ourselves
   * (Ed25519 length validation, ML-DSA mu). NULL otherwise. Owned. */
  unsigned char *raw;
  size_t raw_len;

  /* ML-DSA only: tr = SHAKE256(pk, 64), cached because it depends only on the
   * public key, leaving one streaming SHAKE256 pass per signature. */
  unsigned char tr[64];
  int have_tr;
} AWSKMS_PUBKEY;

/*
 * Parses and validates the SPKI against the KeySpec that KMS reported.
 *
 * `out` must be zeroed. Cross-checks that the key type and, for EC, the curve
 * actually match the advertised spec, and that raw public keys have exactly the
 * expected length -- so a mismatch surfaces at load time rather than as
 * signatures that never verify. `fips_required` constrains every dependency
 * fetch used while decoding and precomputing ML-DSA state.
 */
int awskms_pubkey_from_spki(AWSKMS_PUBKEY *out, const unsigned char *der,
                            size_t der_len, const char *kms_key_spec,
                            OSSL_LIB_CTX *libctx, int fips_required,
                            const OSSL_CORE_HANDLE *handle);

/* Copies an immutable public view, retaining the EVP_PKEY by reference and
 * duplicating every owned byte buffer. `out` must be zeroed. */
int awskms_pubkey_dup(AWSKMS_PUBKEY *out, const AWSKMS_PUBKEY *src);

void awskms_pubkey_cleanup(AWSKMS_PUBKEY *p);

/*
 * mu = SHAKE256( tr || 0x00 || |ctx| || ctx || M , 64 ), per FIPS 204, where
 * tr = SHAKE256(pk, 64) is the value cached in AWSKMS_PUBKEY at load time.
 *
 * Computing mu ourselves rather than sending the message is what frees ML-DSA
 * from KMS's 4096-byte Message limit -- mu is 64 bytes whatever the message size.
 * An empty context string makes the result identical to a KMS MessageType=RAW
 * signature, which is what pure ML-DSA verifiers expect.
 *
 * Exposed rather than kept private to the signature code so it can be unit
 * tested directly: on OpenSSL 4.0+ the tests cross-check it against the
 * EVP_MD "ML-DSA-MU", which computes the same value. This is the most
 * security-critical arithmetic here, and a wrong mu produces well-formed
 * signatures that simply never verify.
 * `fips_required` likewise constrains the internal SHAKE256 fetch.
 */
int awskms_mu(OSSL_LIB_CTX *libctx, int fips_required,
              const unsigned char tr[64], const unsigned char *ctx_string,
              size_t ctx_string_len, const unsigned char *msg, size_t msg_len,
              unsigned char out[64], const OSSL_CORE_HANDLE *handle);

#endif /* AWSKMS_SPKI_H */
