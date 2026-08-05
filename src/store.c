/*
 * OSSL_OP_STORE loader for the `awskms:` scheme.
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

/*
 * Resolves the effective connection settings.
 *
 * Precedence: what the URI says, then the ordinary AWS environment (which the
 * SDK itself consults, so it is simply left unset here), then our openssl.cnf
 * defaults. The cnf is a default and never an override, so AWS_REGION and
 * AWS_PROFILE keep working the way users expect.
 */
static int apply_conf_defaults(AWSKMS_STORE_CTX *ctx) {
  AWSKMS_PROV_CTX *p = ctx->provctx;
  AWSKMS_URI *uri = &ctx->key->uri;

  if (uri->region == NULL && p->region != NULL &&
      (uri->region = OPENSSL_strdup(p->region)) == NULL)
    return 0;
  if (uri->profile == NULL && p->profile != NULL &&
      (uri->profile = OPENSSL_strdup(p->profile)) == NULL)
    return 0;
  if (uri->endpoint == NULL && p->endpoint != NULL &&
      (uri->endpoint = OPENSSL_strdup(p->endpoint)) == NULL)
    return 0;
  return 1;
}

static void *awskms_store_open_ex(void *provctx, const char *uri,
                                  const OSSL_PARAM params[],
                                  OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                  void *pw_cbarg) {
  AWSKMS_PROV_CTX *pctx = provctx;
  AWSKMS_STORE_CTX *ctx;
  AWSKMS_PUBLIC_KEY pub;

  memset(&pub, 0, sizeof(pub));

  if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) return NULL;
  ctx->provctx = pctx;
  if ((ctx->key = awskms_key_new(pctx)) == NULL) goto err;

  if (!awskms_uri_parse(uri, &ctx->key->uri, pctx->handle)) goto err;
  if (!apply_conf_defaults(ctx)) goto err;

  /* The one network call at load time. Doing it here rather than in load()
   * means a bad key id fails at createPrivateKey() with a useful error. */
  if (!awskms_kms_get_public_key(pctx, &ctx->key->uri, &pub)) goto err;

  if (!awskms_pubkey_from_spki(&ctx->key->pub, pub.spki, pub.spki_len,
                               pub.key_spec, pctx->libctx, pctx->handle))
    goto err;

  awskms_public_key_cleanup(&pub);
  return ctx;

err:
  awskms_public_key_cleanup(&pub);
  awskms_store_close_ctx(ctx);
  return NULL;
}

static void *awskms_store_open(void *provctx, const char *uri) {
  return awskms_store_open_ex(provctx, uri, NULL, NULL, NULL);
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

  /* OSSL_STORE_PARAM_PROPERTIES is accepted and ignored: there is only one thing
   * behind an awskms: URI, so there is nothing to select between. */
  return 1;
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
    /* Node calls OSSL_STORE_open_ex(); `open` is registered as well because
     * libcrypto accepts either and the fallback costs three lines. */
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))awskms_store_open},
    {OSSL_FUNC_STORE_OPEN_EX, (void (*)(void))awskms_store_open_ex},
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
    {"awskms", AWSKMS_PROPERTY_DEF, awskms_store_functions,
     "AWS KMS store loader"},
    {NULL, NULL, NULL, NULL}};

const OSSL_ALGORITHM *awskms_store_algorithms(void) { return awskms_store_alg; }
