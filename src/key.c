#include "key.h"

#include <openssl/crypto.h>

AWSKMS_KEY *awskms_key_new(AWSKMS_PROV_CTX *provctx) {
  AWSKMS_KEY *key = OPENSSL_zalloc(sizeof(*key));

  if (key == NULL) return NULL;
  if ((key->lock = CRYPTO_THREAD_lock_new()) == NULL) {
    OPENSSL_free(key);
    return NULL;
  }
  key->provctx = provctx;
  key->refcnt = 1;
  return key;
}

int awskms_key_up_ref(AWSKMS_KEY *key) {
  int ref = 0;

  if (key == NULL) return 0;
  return CRYPTO_atomic_add(&key->refcnt, 1, &ref, key->lock);
}

void awskms_key_free(AWSKMS_KEY *key) {
  int ref = 0;

  if (key == NULL) return;
  if (!CRYPTO_atomic_add(&key->refcnt, -1, &ref, key->lock)) return;
  if (ref > 0) return;

  awskms_pubkey_cleanup(&key->pub);
  awskms_uri_cleanup(&key->uri);
  CRYPTO_THREAD_lock_free(key->lock);
  OPENSSL_free(key);
}
