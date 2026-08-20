/*
 * The opaque keydata behind a KMS-backed EVP_PKEY.
 *
 * Immutable once built, deliberately: Node calls sign on one refcount-shared
 * EVP_PKEY from several libuv threadpool threads at once, so anything mutable
 * here would need locking. Per-operation state lives in the signature algctx
 * instead.
 */
#ifndef AWSKMS_KEY_H
#define AWSKMS_KEY_H

#include "provider.h"
#include "spki.h"
#include "uri.h"

typedef struct awskms_key_st {
  /* Borrowed; outlives every key, since keys are freed before provider
   * teardown. */
  AWSKMS_PROV_CTX *provctx;

  AWSKMS_URI uri;    /* how to reach the key */
  AWSKMS_PUBKEY pub; /* its public half, and what verification uses */
  /* Immutable after STORE open. It follows the key because Node retains the
   * EVP_PKEY but not the STORE property query used to create it. */
  int fips_required;

  int refcnt;
  CRYPTO_RWLOCK *lock;
} AWSKMS_KEY;

/* Creates an empty key. The caller fills in `uri` and `pub` before publishing it
 * and must not touch either afterwards. */
AWSKMS_KEY *awskms_key_new(AWSKMS_PROV_CTX *provctx);

int awskms_key_up_ref(AWSKMS_KEY *key);
void awskms_key_free(AWSKMS_KEY *key);

/* Convenience accessors used across keymgmt and signature. */
static inline const AWSKMS_KEYSPEC *awskms_key_spec(const AWSKMS_KEY *key) {
  return key->pub.spec;
}

#endif /* AWSKMS_KEY_H */
