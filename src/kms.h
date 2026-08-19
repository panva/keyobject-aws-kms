/*
 * Everything that talks to AWS, behind two calls.
 *
 * Keeping the surface this narrow means the AWS SDK is confined to one
 * translation unit, and it makes an offline backend possible for development and
 * tests without the provider itself knowing the difference.
 *
 * Backends (selected at build time by AWSKMS_BACKEND):
 *   aws  -- the real thing, via the AWS SDK for C++ (kms_aws.cc)
 *   stub -- a self-contained local fake, no network and no credentials
 *           (kms_stub.c). For tests and offline work only.
 */
#ifndef AWSKMS_KMS_H
#define AWSKMS_KMS_H

#include <stddef.h>

#include "provider.h"
#include "uri.h"

typedef struct awskms_public_key_st {
  char *key_spec;      /* the KMS KeySpec string. Owned. */
  unsigned char *spki; /* DER SubjectPublicKeyInfo. Owned. */
  size_t spki_len;
} AWSKMS_PUBLIC_KEY;

void awskms_public_key_cleanup(AWSKMS_PUBLIC_KEY *p);

/*
 * kms:GetPublicKey. `out` must be zeroed.
 *
 * Called once, at key load, never lazily: ML-DSA's mu cannot be computed without
 * the public key, and every family needs the KeySpec to know what to ask for. The
 * public key of a KMS key never changes, so the result is cached for the life of
 * the key object.
 *
 * Raises an error and returns 0 on failure.
 */
int awskms_kms_get_public_key(AWSKMS_PROV_CTX *provctx, const AWSKMS_URI *uri,
                              int fips_required, AWSKMS_PUBLIC_KEY *out);

/*
 * kms:Sign.
 *
 * `message_type` is "DIGEST", "RAW" or "EXTERNAL_MU" and `msg` is whatever that
 * implies -- a digest, the message itself, or the 64-byte mu. Writes the
 * signature into `sig` (at most `sig_size` bytes) and sets `*sig_len`.
 *
 * Callers must have dealt with the size probe before getting here: this always
 * performs a billable request.
 */
int awskms_kms_sign(AWSKMS_PROV_CTX *provctx, const AWSKMS_URI *uri,
                    int fips_required, const char *signing_algorithm,
                    const char *message_type, const unsigned char *msg,
                    size_t msg_len, unsigned char *sig, size_t sig_size,
                    size_t *sig_len);

/* Which backend was compiled in, for diagnostics and for the provider's
 * buildinfo. */
const char *awskms_kms_backend(void);

#endif /* AWSKMS_KMS_H */
