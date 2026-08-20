/*
 * The KMS key spec table: the one place the KMS <-> OpenSSL correspondence lives.
 *
 * Everything downstream (which keymgmt name to advertise, which SigningAlgorithm
 * to ask KMS for, which MessageType, which digests are legal) is derived from
 * here, so there is exactly one table to audit against the AWS documentation.
 */
#ifndef AWSKMS_KEYSPEC_H
#define AWSKMS_KEYSPEC_H

#include <openssl/evp.h>
#include <stddef.h>

/* How the message reaches kms:Sign. The distinction exists because KMS caps
 * `Message` at 1..4096 bytes, so anything that cannot be reduced to a short
 * digest or representative has to live with that cap. */
typedef enum {
  /* Hash locally, send the digest. No limit on the input size. */
  AWSKMS_MSG_DIGEST,
  /* Send the message itself. Subject to KMS's 1..4096 byte Message limit. */
  AWSKMS_MSG_RAW,
  /* Send the 64-byte FIPS 204 mu we compute locally. No limit. */
  AWSKMS_MSG_EXTERNAL_MU
} AWSKMS_MSG_TYPE;

typedef enum {
  AWSKMS_FAMILY_RSA,
  AWSKMS_FAMILY_EC,
  AWSKMS_FAMILY_ED25519,
  AWSKMS_FAMILY_ML_DSA
} AWSKMS_FAMILY;

/* Digests are compared as canonical identities rather than by name: OpenSSL
 * calls SHA-256 "SHA2-256", "SHA-256", "SHA256" and an OID interchangeably, and
 * `mdname` arrives as whichever spelling the caller happened to use. */
typedef enum {
  AWSKMS_DIGEST_NONE = 0,
  AWSKMS_DIGEST_SHA256,
  AWSKMS_DIGEST_SHA384,
  AWSKMS_DIGEST_SHA512,
  AWSKMS_DIGEST_OTHER /* a real digest, but not one KMS signs with */
} AWSKMS_DIGEST;

typedef struct awskms_keyspec_st {
  /* The KMS KeySpec string, exactly as GetPublicKey reports it. */
  const char *kms_key_spec;
  AWSKMS_FAMILY family;
  AWSKMS_MSG_TYPE msg_type;
  /* The keymgmt/signature algorithm name we register. Node derives
   * asymmetricKeyType from EVP_PKEY_id(), which for a provider key resolves
   * purely from this name, so these are load-bearing, not cosmetic. */
  const char *keytype;
  /* OSSL_PKEY_PARAM_GROUP_NAME value, NULL for non-EC. Note OpenSSL spells
   * P-256 `prime256v1` where AWS spells the same curve `secp256r1`. */
  const char *group_name;
  /* The single digest KMS binds to this spec; AWSKMS_DIGEST_NONE when the caller
   * chooses (RSA) or there is none (Ed25519, ML-DSA). */
  AWSKMS_DIGEST digest;
  /* Exact raw public key length where we must validate it, else 0. Guards
   * against handing mu the BIT STRING's leading unused-bits octet, which yields
   * a plausible-but-wrong mu and signatures that never verify. */
  size_t pub_len;
  /* Exact signature length where it is fixed, else 0 (RSA/ECDSA report
   * OSSL_PKEY_PARAM_MAX_SIZE from the public key instead). */
  size_t sig_len;
} AWSKMS_KEYSPEC;

/* Looks up by KMS KeySpec string. NULL when unsupported. */
const AWSKMS_KEYSPEC *awskms_keyspec_by_name(const char *kms_key_spec);

/* Every spec, for building the algorithm tables. Terminated by a NULL
 * kms_key_spec. */
const AWSKMS_KEYSPEC *awskms_keyspec_all(void);

/* Canonical identity of an EVP_MD, resolving OpenSSL's name aliases. */
AWSKMS_DIGEST awskms_digest_of(const EVP_MD *md);

/* Digest length in bytes, or 0 for NONE/OTHER. */
size_t awskms_digest_length(AWSKMS_DIGEST digest);

/* The OpenSSL name for a digest, for fetching it. NULL for NONE/OTHER. */
const char *awskms_digest_name(AWSKMS_DIGEST digest);

/*
 * The KMS SigningAlgorithm to request, or NULL when KMS has no such
 * combination -- an ECDSA key asked for a digest other than its curve's, or an
 * RSA hash KMS does not offer.
 *
 * `pss` selects RSASSA_PSS_* over RSASSA_PKCS1_V1_5_* and is ignored for
 * non-RSA specs.
 */
const char *awskms_signing_algorithm(const AWSKMS_KEYSPEC *spec,
                                     AWSKMS_DIGEST digest, int pss);

#endif /* AWSKMS_KEYSPEC_H */
