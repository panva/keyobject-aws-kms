/*
 * OSSL_OP_STORE loader for the `aws-kms:` scheme.
 *
 * Two deliberate omissions, both load-bearing:
 *
 *  - No OSSL_FUNC_STORE_EXPORT_OBJECT. Omitting it is what makes libcrypto's
 *    try_key_ref() fall back to re-fetching the keymgmt from *this* provider and
 *    calling OSSL_FUNC_KEYMGMT_LOAD on our reference, rather than trying to hand
 *    the object to whichever provider a bare-name keymgmt fetch resolved to.
 *    That fallback is precisely why Node's `properties` option is optional
 *    instead of mandatory, so there is a regression test for loading both with
 *    and without it.
 *
 *  - The passphrase callback is never invoked. There is no PIN in KMS, so there is
 *    nothing to ask for, and Node's StorePasswordCallback cannot distinguish "no
 *    passphrase was supplied" from "asked and got nothing": it sets a sticky
 *    missing_passphrase flag and returns -1 whenever no passphrase was given.
 *
 *    As of the ncrypto fixup that makes a successful load win over that flag, an
 *    ordinary load would survive calling it. What it would still do is replace the
 *    reason code on every FAILING load with ERR_MISSING_PASSPHRASE, hiding the
 *    actual cause.
 */
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/store.h>
#include <string.h>

#include "err.h"
#include "key.h"
#include "kms.h"
#include "provider.h"

typedef struct awskms_store_ctx_st {
  AWSKMS_PROV_CTX *provctx;
  /* Built during open, handed to libcrypto during load. Owned. */
  AWSKMS_KEY *key;
  int emitted;
  /* OSSL_STORE_PARAM_EXPECT, or 0 for "anything". */
  int expect;
} AWSKMS_STORE_CTX;

static void awskms_store_close_ctx(AWSKMS_STORE_CTX *ctx) {
  if (ctx == NULL) return;
  awskms_key_free(ctx->key);
  OPENSSL_free(ctx);
}

static int awskms_store_apply_properties(AWSKMS_STORE_CTX *ctx,
                                         const OSSL_PARAM params[]) {
  const OSSL_PARAM *param;
  const char *propq = NULL;

  if (params != NULL &&
      (param = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES)) !=
          NULL &&
      !OSSL_PARAM_get_utf8_string_ptr(param, &propq))
    return 0;

  if (awskms_fips_requested(ctx->provctx->libctx, propq))
    ctx->key->fips_required = 1;
  return 1;
}

static void *awskms_store_open(void *provctx, const char *uri) {
  AWSKMS_PROV_CTX *pctx = provctx;
  AWSKMS_STORE_CTX *ctx;

  if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) return NULL;
  ctx->provctx = pctx;
  if ((ctx->key = awskms_key_new(pctx)) == NULL) goto err;

  /* SET_CTX_PARAMS is optional. In particular, a caller using plain
   * OSSL_STORE_open() supplies no local property query at all, so seed the key
   * from the process/libctx defaults before any KMS request or SPKI parse. */
  ctx->key->fips_required = awskms_fips_requested(pctx->libctx, NULL);

  if (!awskms_uri_parse(uri, &ctx->key->uri, pctx->handle)) goto err;
  return ctx;

err:
  awskms_store_close_ctx(ctx);
  return NULL;
}

static int awskms_store_load_key(AWSKMS_STORE_CTX *ctx) {
  AWSKMS_PUBLIC_KEY pub;

  if (ctx->key->pub.spec != NULL) return 1;
  memset(&pub, 0, sizeof(pub));

  if (!awskms_kms_get_public_key(ctx->provctx, &ctx->key->uri,
                                 ctx->key->fips_required, &pub))
    goto err;

  if (!awskms_pubkey_from_spki(&ctx->key->pub, pub.spki, pub.spki_len,
                               pub.key_spec, ctx->provctx->libctx,
                               ctx->key->fips_required, ctx->provctx->handle))
    goto err;

  awskms_public_key_cleanup(&pub);
  return 1;

err:
  awskms_public_key_cleanup(&pub);
  return 0;
}

static const OSSL_PARAM *awskms_store_settable_ctx_params(void *provctx) {
  static const OSSL_PARAM settable[] = {
      OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
      OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
      OSSL_PARAM_END};
  return settable;
}

/*
 * Must succeed for OSSL_STORE_PARAM_EXPECT: OSSL_STORE_expect() forwards it here
 * and treats a rejection as fatal, and Node calls
 * OSSL_STORE_expect(OSSL_STORE_INFO_PKEY) on every load.
 */
static int awskms_store_set_ctx_params(void *loaderctx,
                                       const OSSL_PARAM params[]) {
  AWSKMS_STORE_CTX *ctx = loaderctx;
  const OSSL_PARAM *p;

  if (params == NULL) return 1;

  if ((p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT)) != NULL &&
      !OSSL_PARAM_get_int(p, &ctx->expect))
    return 0;

  return awskms_store_apply_properties(ctx, params);
}

static int awskms_store_load(void *loaderctx, OSSL_CALLBACK *object_cb,
                             void *object_cbarg,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
  AWSKMS_STORE_CTX *ctx = loaderctx;
  int object_type = OSSL_OBJECT_PKEY;
  AWSKMS_KEY *ref = ctx->key;
  OSSL_PARAM object[4];

  if (ctx->emitted) return 0;

  /* A caller that asked for something other than a private key gets nothing
   * rather than an error, which is how a store loader signals "not here". */
  if (ctx->expect != 0 && ctx->expect != OSSL_STORE_INFO_PKEY) {
    ctx->emitted = 1;
    return 0;
  }

  if (!awskms_store_load_key(ctx)) return 0;

  /* The reference is the keydata pointer itself. libcrypto copies these bytes
   * and hands them to our keymgmt's load(), synchronously, inside this callback
   * -- so the pointer is valid, and load() takes its own reference. */
  object[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
  object[1] = OSSL_PARAM_construct_utf8_string(
      OSSL_OBJECT_PARAM_DATA_TYPE, (char *)awskms_key_spec(ctx->key)->keytype,
      0);
  object[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                &ref, sizeof(ref));
  object[3] = OSSL_PARAM_construct_end();

  ctx->emitted = 1;
  return object_cb(object, object_cbarg);
}

static int awskms_store_eof(void *loaderctx) {
  return ((AWSKMS_STORE_CTX *)loaderctx)->emitted;
}

static int awskms_store_close(void *loaderctx) {
  awskms_store_close_ctx(loaderctx);
  return 1;
}

static const OSSL_DISPATCH awskms_store_functions[] = {
    /* Deliberately use OPEN rather than OPEN_EX. OpenSSL then forwards both the
     * OSSL_STORE_open_ex property query and explicit params through
     * SET_CTX_PARAMS before LOAD. Provider OPEN_EX receives only explicit
     * params, so it cannot observe Node's STORE property query. */
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))awskms_store_open},
    {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
     (void (*)(void))awskms_store_settable_ctx_params},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS,
     (void (*)(void))awskms_store_set_ctx_params},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))awskms_store_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))awskms_store_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))awskms_store_close},
    /* No EXPORT_OBJECT: see the file comment. */
    {0, NULL}};

static const OSSL_ALGORITHM awskms_store_alg[] = {
    /* The algorithm name of an OSSL_OP_STORE entry IS the URI scheme OpenSSL
     * dispatches on -- distinct from AWSKMS_PROVIDER_NAME, which names the
     * provider itself and is unchanged. */
    {"aws-kms", AWSKMS_PROPERTY_DEF, awskms_store_functions,
     "AWS KMS store loader"},
    {NULL, NULL, NULL, NULL}};

const OSSL_ALGORITHM *awskms_store_algorithms(void) { return awskms_store_alg; }
