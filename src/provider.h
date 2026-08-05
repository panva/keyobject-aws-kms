#ifndef AWSKMS_PROVIDER_H
#define AWSKMS_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>

#include "compat.h"

/* The provider name, and the property every algorithm we register carries.
 * Kept as one string so the name in openssl.cnf, the property definitions, and
 * the self-excluding property query below can never drift apart. */
#define AWSKMS_PROVIDER_NAME "awskms"
#define AWSKMS_PROPERTY_DEF "provider=" AWSKMS_PROVIDER_NAME

/*
 * Property query for every fetch we make on our own behalf -- digests for
 * prehashing, and d2i_PUBKEY_ex() when materialising the cached public key for
 * local verification. Non-optional on purpose: re-entering ourselves would be a
 * bug, not a preference.
 */
#define AWSKMS_EXCLUDE_SELF "provider!=" AWSKMS_PROVIDER_NAME

typedef struct awskms_prov_ctx_st {
  /* Needed for error reporting: core_vset_error() dereferences it for reasons
   * whose ERR_LIB bits are zero, which is all of ours. */
  const OSSL_CORE_HANDLE *handle;
  /* The application's libctx, from the core_get_libctx upcall. Not a child
   * libctx: a child would mirror us and invite re-entrancy. */
  OSSL_LIB_CTX *libctx;

  /* Defaults from our openssl.cnf section. Owned, may be NULL.
   * These are defaults only -- a URI attribute and then the real AWS
   * environment chain both take precedence. */
  char *region;
  char *profile;
  char *endpoint;
} AWSKMS_PROV_CTX;

/* Per-operation algorithm tables, defined by their own translation units.
 * Each returns NULL while that operation is unimplemented. */
const OSSL_ALGORITHM *awskms_store_algorithms(void);
const OSSL_ALGORITHM *awskms_keymgmt_algorithms(void);
const OSSL_ALGORITHM *awskms_signature_algorithms(void);

#endif /* AWSKMS_PROVIDER_H */
