/*
 * keyobject aws-kms -- OpenSSL provider entry point.
 *
 * OSSL_provider_init() populates the dispatch table and does nothing else: no
 * algorithm fetches, no network, no threads, no atexit handlers, and above all
 * no AWS SDK initialisation. Constructing a KMS client here makes the process
 * couple SDK thread lifetime to provider teardown and can abort the process at
 * exit. Everything expensive is created lazily on first use.
 */
#include "provider.h"

#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>

#include "err.h"

#ifndef AWSKMS_VERSION
#define AWSKMS_VERSION "0.0.0"
#endif
#ifndef AWSKMS_BACKEND_NAME
#define AWSKMS_BACKEND_NAME "unknown"
#endif

#define AWSKMS_BUILDINFO AWSKMS_VERSION " backend=" AWSKMS_BACKEND_NAME

static int awskms_ascii_equal(const char *value, size_t value_len,
                              const char *expected) {
  size_t i;

  if (strlen(expected) != value_len) return 0;
  for (i = 0; i < value_len; i++) {
    unsigned char left = (unsigned char)value[i];
    unsigned char right = (unsigned char)expected[i];

    if (left >= 'A' && left <= 'Z') left = (unsigned char)(left + ('a' - 'A'));
    if (right >= 'A' && right <= 'Z')
      right = (unsigned char)(right + ('a' - 'A'));
    if (left != right) return 0;
  }
  return 1;
}

static int awskms_is_space(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' ||
         c == '\v';
}

/* Property queries have no public parser API. Inspect only the Boolean clause
 * we own here, respecting quotes and comma boundaries; OpenSSL remains the
 * authority for validating the complete query. */
static int awskms_propq_requests_fips(const char *propq) {
  const char *clause;
  const char *cursor;
  char quote = '\0';

  if (propq == NULL) return 0;
  clause = cursor = propq;
  for (;;) {
    if (*cursor == '\0' || (*cursor == ',' && quote == '\0')) {
      const char *begin = clause;
      const char *end = cursor;
      const char *name;
      const char *value;
      size_t name_len;
      size_t value_len;

      while (begin < end && awskms_is_space(*begin)) begin++;
      while (begin < end && awskms_is_space(end[-1])) end--;
      if (begin < end && *begin == '?') {
        begin++;
        while (begin < end && awskms_is_space(*begin)) begin++;
      }
      if (begin < end && *begin != '-') {
        name = begin;
        while (begin < end && ((*begin >= 'a' && *begin <= 'z') ||
                               (*begin >= 'A' && *begin <= 'Z') ||
                               (*begin >= '0' && *begin <= '9') ||
                               *begin == '_' || *begin == '.'))
          begin++;
        name_len = (size_t)(begin - name);
        while (begin < end && awskms_is_space(*begin)) begin++;
        if (begin < end && *begin == '=') {
          begin++;
          while (begin < end && awskms_is_space(*begin)) begin++;
          if (begin < end && (*begin == '\'' || *begin == '"')) {
            const char delimiter = *begin++;
            value = begin;
            while (begin < end && *begin != delimiter) begin++;
            value_len = (size_t)(begin - value);
            if (begin < end) begin++;
          } else {
            value = begin;
            while (begin < end && !awskms_is_space(*begin)) begin++;
            value_len = (size_t)(begin - value);
          }
          while (begin < end && awskms_is_space(*begin)) begin++;
          if (begin == end && awskms_ascii_equal(name, name_len, "fips") &&
              awskms_ascii_equal(value, value_len, "yes"))
            return 1;
        }
      }
      if (*cursor == '\0') return 0;
      clause = cursor + 1;
    } else if (quote == '\0' && (*cursor == '\'' || *cursor == '"')) {
      quote = *cursor;
    } else if (quote != '\0' && *cursor == quote) {
      quote = '\0';
    }
    cursor++;
  }
}

int awskms_fips_requested(OSSL_LIB_CTX *libctx, const char *propq) {
  return EVP_default_properties_is_fips_enabled(libctx) ||
         awskms_propq_requests_fips(propq);
}

static OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
static OSSL_FUNC_core_get_params_fn *c_get_params;

static void awskms_prov_ctx_free(AWSKMS_PROV_CTX *ctx) {
  if (ctx == NULL) return;
  OPENSSL_free(ctx->region);
  OPENSSL_free(ctx->profile);
  OPENSSL_free(ctx->endpoint);
  OPENSSL_free(ctx);
}

/*
 * Reads `key = value` lines from our own section of openssl.cnf.
 *
 * provider_conf_activate() feeds every leaf in the section to
 * OSSL_PROVIDER_add_conf_parameter() before activation, and they come back
 * through the core_get_params upcall as UTF8 *pointers* keyed by the literal cnf
 * key name. The pointers belong to the OSSL_PROVIDER, so copy anything kept.
 *
 * Note the section also contains OpenSSL's own pseudo-directives (module,
 * activate, identity, soft_load); they are simply not asked for here.
 */
static int awskms_read_conf(AWSKMS_PROV_CTX *ctx) {
  const char *region = NULL, *profile = NULL, *endpoint = NULL;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_ptr("region", (char **)&region, 0),
      OSSL_PARAM_construct_utf8_ptr("profile", (char **)&profile, 0),
      OSSL_PARAM_construct_utf8_ptr("endpoint", (char **)&endpoint, 0),
      OSSL_PARAM_construct_end()};

  if (c_get_params == NULL) return 1; /* nothing configurable; not an error */

  /* A provider with no settings at all is normal, so a failed lookup is not
   * fatal -- only a failed copy is. */
  (void)c_get_params(ctx->handle, params);

  if (region != NULL && (ctx->region = OPENSSL_strdup(region)) == NULL)
    return 0;
  if (profile != NULL && (ctx->profile = OPENSSL_strdup(profile)) == NULL)
    return 0;
  if (endpoint != NULL && (ctx->endpoint = OPENSSL_strdup(endpoint)) == NULL)
    return 0;
  return 1;
}

static void awskms_teardown(void *provctx) {
  awskms_prov_ctx_free((AWSKMS_PROV_CTX *)provctx);
}

static const OSSL_PARAM *awskms_gettable_params(void *provctx) {
  static const OSSL_PARAM gettable[] = {
      OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
      OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
      OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
      OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
      OSSL_PARAM_END};
  return gettable;
}

static int awskms_get_params(void *provctx, OSSL_PARAM params[]) {
  OSSL_PARAM *p;

  if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) != NULL &&
      !OSSL_PARAM_set_utf8_ptr(p, "AWS KMS provider"))
    return 0;
  if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL &&
      !OSSL_PARAM_set_utf8_ptr(p, AWSKMS_VERSION))
    return 0;
  if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO)) != NULL &&
      !OSSL_PARAM_set_utf8_ptr(p, AWSKMS_BUILDINFO))
    return 0;
  if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) != NULL &&
      !OSSL_PARAM_set_int(p, 1))
    return 0;
  return 1;
}

static const OSSL_ALGORITHM *awskms_query_operation(void *provctx,
                                                    int operation_id,
                                                    int *no_cache) {
  *no_cache = 0;
  switch (operation_id) {
    case OSSL_OP_STORE:
      return awskms_store_algorithms();
    case OSSL_OP_KEYMGMT:
      return awskms_keymgmt_algorithms();
    case OSSL_OP_SIGNATURE:
      return awskms_signature_algorithms();
    default:
      return NULL;
  }
}

static const OSSL_ITEM *awskms_get_reason_strings(void *provctx) {
  return awskms_err_reason_strings();
}

static const OSSL_DISPATCH awskms_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))awskms_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
     (void (*)(void))awskms_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))awskms_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION,
     (void (*)(void))awskms_query_operation},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
     (void (*)(void))awskms_get_reason_strings},
    {0, NULL}};

AWSKMS_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                                     const OSSL_DISPATCH *in,
                                     const OSSL_DISPATCH **out,
                                     void **provctx) {
  AWSKMS_PROV_CTX *ctx;

  awskms_err_init(in);

  for (; in->function_id != 0; in++) {
    switch (in->function_id) {
      case OSSL_FUNC_CORE_GET_LIBCTX:
        c_get_libctx = OSSL_FUNC_core_get_libctx(in);
        break;
      case OSSL_FUNC_CORE_GET_PARAMS:
        c_get_params = OSSL_FUNC_core_get_params(in);
        break;
      default:
        break;
    }
  }

  if (c_get_libctx == NULL) return 0;

  if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) return 0;
  ctx->handle = handle;
  /* The upcall hands back the application's libctx disguised as an
   * OSSL_CORE_HANDLE; the cast is the documented contract. */
  ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

  if (!awskms_read_conf(ctx)) {
    awskms_prov_ctx_free(ctx);
    return 0;
  }

  *provctx = ctx;
  *out = awskms_dispatch_table;
  return 1;
}
