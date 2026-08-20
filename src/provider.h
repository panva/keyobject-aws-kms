#ifndef AWSKMS_PROVIDER_H
#define AWSKMS_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>

#include "compat.h"

/* The provider name, and the properties every algorithm we register carries.
 * The namespaced marker lets process-wide defaults prefer ordinary key
 * implementations without making that preference depend on a provider name.
 * fips=yes deliberately makes retained KMS algorithms eligible when the host
 * has enabled the FIPS property policy. */
#define AWSKMS_PROVIDER_NAME "aws-kms"
#define AWSKMS_KEYOBJECT_PROPERTY "keyobject.aws_kms"
#define AWSKMS_PROPERTY_DEF                                      \
  "provider=" AWSKMS_PROVIDER_NAME "," AWSKMS_KEYOBJECT_PROPERTY \
  "=yes,fips="                                                   \
  "yes"

/*
 * Property query for every fetch we make on our own behalf -- digests for
 * prehashing, and d2i_PUBKEY_ex() when materialising the cached public key for
 * local verification. Non-optional on purpose: re-entering ourselves would be a
 * bug, not a preference.
 */
#define AWSKMS_EXCLUDE_SELF "provider!=" AWSKMS_PROVIDER_NAME
#define AWSKMS_EXCLUDE_SELF_FIPS "provider!=" AWSKMS_PROVIDER_NAME ",fips=yes"

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

/* True when the process defaults or the supplied local property query request
 * FIPS implementations. Local queries are inspected separately because STORE
 * properties are not retained by Node on the later signature operation. */
int awskms_fips_requested(OSSL_LIB_CTX *libctx, const char *propq);

/* Property query for public-key parsing, hashing, SHAKE and verification. */
static inline const char *awskms_dependency_propq(int fips_required) {
  return fips_required ? AWSKMS_EXCLUDE_SELF_FIPS : AWSKMS_EXCLUDE_SELF;
}

#endif /* AWSKMS_PROVIDER_H */
