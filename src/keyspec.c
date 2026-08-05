#include "keyspec.h"

#include <string.h>

#include "compat.h"

/*
 * Sources for every column, so this can be re-checked against AWS without
 * reverse-engineering the code:
 *
 *   KeySpec / SigningAlgorithm pairings and the "one curve, one digest" rule
 *     https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
 *   MessageType semantics and the 1..4096 byte Message limit
 *     https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
 *
 * SM2 is intentionally absent (China partitions only, and OpenSSL's SM2 digest
 * signing is not equivalent to a prehashed sign, so it could not use this path).
 */
static const AWSKMS_KEYSPEC specs[] = {
    /* RSA: the caller chooses the digest and the padding mode. KMS fixes the PSS
     * salt length at the digest length and MGF1 to the same digest. */
    {"RSA_2048", AWSKMS_FAMILY_RSA, AWSKMS_MSG_DIGEST, "RSA", NULL,
     AWSKMS_DIGEST_NONE, 0, 0},
    {"RSA_3072", AWSKMS_FAMILY_RSA, AWSKMS_MSG_DIGEST, "RSA", NULL,
     AWSKMS_DIGEST_NONE, 0, 0},
    {"RSA_4096", AWSKMS_FAMILY_RSA, AWSKMS_MSG_DIGEST, "RSA", NULL,
     AWSKMS_DIGEST_NONE, 0, 0},

    /* ECDSA: exactly one digest per curve. */
    {"ECC_NIST_P256", AWSKMS_FAMILY_EC, AWSKMS_MSG_DIGEST, "EC", "prime256v1",
     AWSKMS_DIGEST_SHA256, 0, 0},
    {"ECC_NIST_P384", AWSKMS_FAMILY_EC, AWSKMS_MSG_DIGEST, "EC", "secp384r1",
     AWSKMS_DIGEST_SHA384, 0, 0},
    {"ECC_NIST_P521", AWSKMS_FAMILY_EC, AWSKMS_MSG_DIGEST, "EC", "secp521r1",
     AWSKMS_DIGEST_SHA512, 0, 0},
    {"ECC_SECG_P256K1", AWSKMS_FAMILY_EC, AWSKMS_MSG_DIGEST, "EC", "secp256k1",
     AWSKMS_DIGEST_SHA256, 0, 0},

    /* Ed25519: PureEdDSA, so the whole message has to reach KMS and the 4096-byte
     * Message cap applies. ED25519_PH_SHA_512 cannot avoid that -- KMS performs
     * the SHA-512 prehash itself, so sending SHA-512(M) signs SHA-512(SHA-512(M)),
     * which no standard verifier computes. */
    {"ECC_NIST_EDWARDS25519", AWSKMS_FAMILY_ED25519, AWSKMS_MSG_RAW, "ED25519",
     NULL, AWSKMS_DIGEST_NONE, 32, 64},

    /* ML-DSA: mu is computed locally and sent as EXTERNAL_MU, so no size cap. */
    {"ML_DSA_44", AWSKMS_FAMILY_ML_DSA, AWSKMS_MSG_EXTERNAL_MU, "ML-DSA-44",
     NULL, AWSKMS_DIGEST_NONE, 1312, 2420},
    {"ML_DSA_65", AWSKMS_FAMILY_ML_DSA, AWSKMS_MSG_EXTERNAL_MU, "ML-DSA-65",
     NULL, AWSKMS_DIGEST_NONE, 1952, 3309},
    {"ML_DSA_87", AWSKMS_FAMILY_ML_DSA, AWSKMS_MSG_EXTERNAL_MU, "ML-DSA-87",
     NULL, AWSKMS_DIGEST_NONE, 2592, 4627},

    {NULL, 0, 0, NULL, NULL, 0, 0, 0}};

const AWSKMS_KEYSPEC *awskms_keyspec_by_name(const char *kms_key_spec) {
  if (kms_key_spec == NULL) return NULL;
  for (const AWSKMS_KEYSPEC *s = specs; s->kms_key_spec != NULL; s++)
    if (strcmp(s->kms_key_spec, kms_key_spec) == 0) return s;
  return NULL;
}

const AWSKMS_KEYSPEC *awskms_keyspec_all(void) { return specs; }

AWSKMS_DIGEST awskms_digest_of(const EVP_MD *md) {
  if (md == NULL) return AWSKMS_DIGEST_NONE;
  /* EVP_MD_is_a() resolves every alias OpenSSL knows for these, so a caller
   * passing "SHA256", "SHA2-256", "SHA-256" or the OID all land here. */
  if (EVP_MD_is_a(md, "SHA2-256")) return AWSKMS_DIGEST_SHA256;
  if (EVP_MD_is_a(md, "SHA2-384")) return AWSKMS_DIGEST_SHA384;
  if (EVP_MD_is_a(md, "SHA2-512")) return AWSKMS_DIGEST_SHA512;
  return AWSKMS_DIGEST_OTHER;
}

size_t awskms_digest_length(AWSKMS_DIGEST digest) {
  switch (digest) {
    case AWSKMS_DIGEST_SHA256:
      return 32;
    case AWSKMS_DIGEST_SHA384:
      return 48;
    case AWSKMS_DIGEST_SHA512:
      return 64;
    default:
      return 0;
  }
}

const char *awskms_digest_name(AWSKMS_DIGEST digest) {
  switch (digest) {
    case AWSKMS_DIGEST_SHA256:
      return "SHA2-256";
    case AWSKMS_DIGEST_SHA384:
      return "SHA2-384";
    case AWSKMS_DIGEST_SHA512:
      return "SHA2-512";
    default:
      return NULL;
  }
}

const char *awskms_signing_algorithm(const AWSKMS_KEYSPEC *spec,
                                     AWSKMS_DIGEST digest, int pss) {
  if (spec == NULL) return NULL;

  switch (spec->family) {
    case AWSKMS_FAMILY_RSA:
      switch (digest) {
        case AWSKMS_DIGEST_SHA256:
          return pss ? "RSASSA_PSS_SHA_256" : "RSASSA_PKCS1_V1_5_SHA_256";
        case AWSKMS_DIGEST_SHA384:
          return pss ? "RSASSA_PSS_SHA_384" : "RSASSA_PKCS1_V1_5_SHA_384";
        case AWSKMS_DIGEST_SHA512:
          return pss ? "RSASSA_PSS_SHA_512" : "RSASSA_PKCS1_V1_5_SHA_512";
        default:
          return NULL;
      }

    case AWSKMS_FAMILY_EC:
      /* The curve dictates the digest; anything else has no KMS equivalent. */
      if (digest != spec->digest) return NULL;
      switch (digest) {
        case AWSKMS_DIGEST_SHA256:
          return "ECDSA_SHA_256";
        case AWSKMS_DIGEST_SHA384:
          return "ECDSA_SHA_384";
        case AWSKMS_DIGEST_SHA512:
          return "ECDSA_SHA_512";
        default:
          return NULL;
      }

    case AWSKMS_FAMILY_ED25519:
      /* PureEdDSA: no digest may be supplied. */
      return digest == AWSKMS_DIGEST_NONE ? "ED25519_SHA_512" : NULL;

    case AWSKMS_FAMILY_ML_DSA:
      return digest == AWSKMS_DIGEST_NONE ? "ML_DSA_SHAKE_256" : NULL;
  }
  return NULL;
}
