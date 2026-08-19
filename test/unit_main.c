#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "key.h"
#include "provider.h"
#include "unit.h"

int awskms_test_failures;
int awskms_test_checks;

static const OSSL_DISPATCH *algorithm_dispatch(const OSSL_ALGORITHM *algorithms,
                                               const char *name) {
  for (const OSSL_ALGORITHM *algorithm = algorithms;
       algorithm->algorithm_names != NULL; algorithm++)
    if (strcmp(algorithm->algorithm_names, name) == 0)
      return algorithm->implementation;
  return NULL;
}

static int capture_store_fips(const OSSL_PARAM params[], void *arg) {
  const OSSL_PARAM *reference =
      OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
  int *captured = arg;
  AWSKMS_KEY *key;

  if (reference == NULL || reference->data == NULL ||
      reference->data_size != sizeof(key))
    return 0;
  key = *(AWSKMS_KEY **)reference->data;
  if (key == NULL) return 0;
  *captured = key->fips_required;
  return 1;
}

static void test_store_global_fips(void) {
  const OSSL_DISPATCH *dispatch =
      algorithm_dispatch(awskms_store_algorithms(), "aws-kms");
  OSSL_FUNC_store_open_fn *open_store = NULL;
  OSSL_FUNC_store_load_fn *load_store = NULL;
  OSSL_FUNC_store_close_fn *close_store = NULL;
  OSSL_LIB_CTX *libctx = NULL;
  OSSL_PROVIDER *default_provider = NULL;
  AWSKMS_PROV_CTX provctx = {0};
  void *store = NULL;
  int captured = 0;

  CHECK(dispatch != NULL, "store dispatch table must be present");
  if (dispatch == NULL) return;
  for (const OSSL_DISPATCH *fn = dispatch; fn->function_id != 0; fn++) {
    switch (fn->function_id) {
      case OSSL_FUNC_STORE_OPEN:
        open_store = OSSL_FUNC_store_open(fn);
        break;
      case OSSL_FUNC_STORE_LOAD:
        load_store = OSSL_FUNC_store_load(fn);
        break;
      case OSSL_FUNC_STORE_CLOSE:
        close_store = OSSL_FUNC_store_close(fn);
        break;
      default:
        break;
    }
  }
  CHECK(open_store != NULL && load_store != NULL && close_store != NULL,
        "store dispatch is incomplete");
  if (open_store == NULL || load_store == NULL || close_store == NULL) return;

  libctx = OSSL_LIB_CTX_new();
  CHECK(libctx != NULL, "could not allocate STORE FIPS test libctx");
  if (libctx == NULL) return;
  default_provider = OSSL_PROVIDER_load(libctx, "default");
  CHECK(default_provider != NULL,
        "could not load default provider in STORE FIPS test libctx");
  CHECK(EVP_set_default_properties(libctx, "fips=yes") == 1,
        "could not enable STORE FIPS test defaults");
  if (default_provider == NULL) goto out;

  provctx.libctx = libctx;
  store =
      open_store(&provctx, "aws-kms:key-id=plain-store-global-fips-RSA_2048");
  CHECK(store != NULL, "plain STORE_OPEN failed under global FIPS defaults");
  if (store != NULL)
    CHECK(load_store(store, capture_store_fips, &captured, NULL, NULL) == 1,
          "plain STORE_LOAD failed under global FIPS defaults");
  CHECK(captured == 1,
        "plain STORE_OPEN must inherit global fips=yes without SET_CTX_PARAMS");

out:
  if (store != NULL) close_store(store);
  if (default_provider != NULL) OSSL_PROVIDER_unload(default_provider);
  OSSL_LIB_CTX_free(libctx);
}

static AWSKMS_KEY *make_test_key(AWSKMS_PROV_CTX *provctx,
                                 const char *spec_name, const char *key_id) {
  const AWSKMS_KEYSPEC *spec = awskms_keyspec_by_name(spec_name);
  AWSKMS_KEY *key = awskms_key_new(provctx);

  if (spec == NULL || key == NULL) goto err;
  key->pub.spec = spec;
  if (spec->family == AWSKMS_FAMILY_RSA)
    key->pub.pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
  else if (spec->family == AWSKMS_FAMILY_EC)
    key->pub.pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", spec->group_name);
  else if (spec->family == AWSKMS_FAMILY_ED25519)
    key->pub.pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
  if (key->pub.pkey == NULL) goto err;
  {
    int der_len = i2d_PUBKEY(key->pub.pkey, &key->pub.der);

    if (der_len <= 0) goto err;
    key->pub.der_len = (size_t)der_len;
  }
  if (key_id != NULL && (key->uri.key_id = OPENSSL_strdup(key_id)) == NULL)
    goto err;
  return key;

err:
  awskms_key_free(key);
  return NULL;
}

static void test_signature_dispatch(void) {
  AWSKMS_PROV_CTX provctx = {0};
  AWSKMS_KEY *key = NULL;
  const OSSL_DISPATCH *dispatch =
      algorithm_dispatch(awskms_signature_algorithms(), "RSA");
  const OSSL_DISPATCH *oneshot =
      algorithm_dispatch(awskms_signature_algorithms(), "ED25519");
  OSSL_FUNC_signature_newctx_fn *newctx = NULL;
  OSSL_FUNC_signature_freectx_fn *freectx = NULL;
  OSSL_FUNC_signature_sign_init_fn *sign_init = NULL;
  OSSL_FUNC_signature_sign_fn *sign = NULL;
  OSSL_FUNC_signature_set_ctx_params_fn *set_params = NULL;
  OSSL_FUNC_signature_settable_ctx_params_fn *settable_params = NULL;
  OSSL_FUNC_signature_digest_sign_init_fn *oneshot_init = NULL;
  OSSL_FUNC_signature_digest_sign_fn *oneshot_sign = NULL;
  void *ctx = NULL;

  CHECK(dispatch != NULL && oneshot != NULL,
        "signature dispatch tables must be present");
  if (dispatch == NULL || oneshot == NULL) return;

  for (const OSSL_DISPATCH *fn = dispatch; fn->function_id != 0; fn++) {
    switch (fn->function_id) {
      case OSSL_FUNC_SIGNATURE_NEWCTX:
        newctx = OSSL_FUNC_signature_newctx(fn);
        break;
      case OSSL_FUNC_SIGNATURE_FREECTX:
        freectx = OSSL_FUNC_signature_freectx(fn);
        break;
      case OSSL_FUNC_SIGNATURE_SIGN_INIT:
        sign_init = OSSL_FUNC_signature_sign_init(fn);
        break;
      case OSSL_FUNC_SIGNATURE_SIGN:
        sign = OSSL_FUNC_signature_sign(fn);
        break;
      case OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS:
        set_params = OSSL_FUNC_signature_set_ctx_params(fn);
        break;
      default:
        break;
    }
  }
  for (const OSSL_DISPATCH *fn = oneshot; fn->function_id != 0; fn++) {
    switch (fn->function_id) {
      case OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT:
        oneshot_init = OSSL_FUNC_signature_digest_sign_init(fn);
        break;
      case OSSL_FUNC_SIGNATURE_DIGEST_SIGN:
        oneshot_sign = OSSL_FUNC_signature_digest_sign(fn);
        break;
      case OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS:
        settable_params = OSSL_FUNC_signature_settable_ctx_params(fn);
        break;
      default:
        break;
    }
  }

  CHECK(newctx != NULL && freectx != NULL && sign_init != NULL &&
            sign != NULL && set_params != NULL && settable_params != NULL &&
            oneshot_init != NULL && oneshot_sign != NULL,
        "signature dispatch is incomplete");
  if (newctx == NULL || freectx == NULL || sign_init == NULL || sign == NULL ||
      set_params == NULL || settable_params == NULL || oneshot_init == NULL ||
      oneshot_sign == NULL)
    return;

  {
    const OSSL_PARAM *settable = settable_params(NULL, &provctx);

    CHECK(OSSL_PARAM_locate_const(settable,
                                  OSSL_SIGNATURE_PARAM_CONTEXT_STRING) != NULL,
          "one-shot signatures must advertise context-string");
    CHECK(OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_INSTANCE) !=
              NULL,
          "one-shot signatures must advertise instance");
  }

  key = make_test_key(&provctx, "RSA_2048", "no-such-key");
  CHECK(key != NULL, "could not construct RSA dispatch fixture");
  if (key == NULL) return;

  /* This is deliberately the signature operation's own property query. It must
   * select the AWS KMS signature, but must not be reused to fetch SHA-256. */
  ctx = newctx(&provctx, "provider=aws-kms");
  CHECK(ctx != NULL, "could not allocate signature context");
  if (ctx != NULL) {
    char digest_name[] = "SHA256";
    OSSL_PARAM digest_params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                         digest_name, 0),
        OSSL_PARAM_construct_end()};

    CHECK(sign_init(ctx, key, digest_params) == 1,
          "signature propq must not constrain the internal digest fetch");

    {
      unsigned char digest[32] = {0};
      unsigned char sig[1];
      size_t siglen = 0;
      size_t required = (size_t)EVP_PKEY_get_size(key->pub.pkey);

      CHECK(sign(ctx, sig, &siglen, sizeof(sig), digest, sizeof(digest)) == 0,
            "an undersized signature buffer must be rejected");
      CHECK(siglen == required,
            "short-buffer failure must report %zu required bytes, got %zu",
            required, siglen);
    }

    {
      char invalid_salt[] = "32junk";
      OSSL_PARAM params[] = {
          OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                           invalid_salt, 0),
          OSSL_PARAM_construct_end()};
      CHECK(set_params(ctx, params) == 0,
            "a partially numeric PSS salt length must be rejected");
    }
    {
      char overflow_salt[] = "999999999999999999999999999999";
      OSSL_PARAM params[] = {
          OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                           overflow_salt, 0),
          OSSL_PARAM_construct_end()};
      CHECK(set_params(ctx, params) == 0,
            "an overflowing PSS salt length must be rejected");
    }
    {
      char embedded_nul[] = {'p', 's', 's', '\0', 'x'};
      OSSL_PARAM params[] = {
          OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                           embedded_nul, sizeof(embedded_nul)),
          OSSL_PARAM_construct_end()};
      CHECK(set_params(ctx, params) == 0,
            "a padding mode with embedded NUL data must be rejected");
    }
    {
      char invalid_mgf[] = "SHA256junk";
      OSSL_PARAM params[] = {
          OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST,
                                           invalid_mgf, 0),
          OSSL_PARAM_construct_end()};
      CHECK(set_params(ctx, params) == 0,
            "an inexact MGF1 digest name must be rejected");
    }
  }

  freectx(ctx);
  awskms_key_free(key);

  key = make_test_key(&provctx, "ECC_NIST_EDWARDS25519", "no-such-key");
  CHECK(key != NULL, "could not construct Ed25519 dispatch fixture");
  if (key != NULL) {
    unsigned char sig[1], msg[] = {0x41};
    size_t siglen = 0;

    ctx = newctx(&provctx, "provider=aws-kms");
    CHECK(ctx != NULL && oneshot_init(ctx, NULL, key, NULL) == 1,
          "could not initialise Ed25519 signing fixture");
    if (ctx != NULL) {
      CHECK(oneshot_sign(ctx, sig, &siglen, sizeof(sig), msg, sizeof(msg)) == 0,
            "an undersized one-shot signature buffer must be rejected");
      CHECK(siglen == 64,
            "Ed25519 short-buffer failure must report 64 bytes, got %zu",
            siglen);
    }
    freectx(ctx);
    awskms_key_free(key);
  }

  /* A signature can be selected with fips=yes after its shared key was loaded
   * without that policy. A libctx containing only the null provider cannot
   * decode any SPKI, so init must fail while reparsing the retained bytes;
   * succeeding here would prove the operation reused the non-FIPS EVP_PKEY. */
  {
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *null_provider = NULL;
    AWSKMS_PROV_CTX fips_provctx = {0};

    CHECK(libctx != NULL, "could not allocate FIPS-routing test libctx");
    if (libctx != NULL) {
      null_provider = OSSL_PROVIDER_load(libctx, "null");
      CHECK(null_provider != NULL,
            "could not load null provider in FIPS-routing test libctx");
    }
    if (null_provider != NULL) {
      fips_provctx.libctx = libctx;
      key = make_test_key(&fips_provctx, "ECC_NIST_EDWARDS25519",
                          "operation-local-fips");
      CHECK(key != NULL,
            "could not construct operation-local FIPS key fixture");
      if (key != NULL) {
        CHECK(key->fips_required == 0,
              "operation-local FIPS fixture must start non-FIPS");
        ctx = newctx(&fips_provctx, "fips=yes");
        CHECK(ctx != NULL, "could not allocate operation-local FIPS context");
        if (ctx != NULL)
          CHECK(oneshot_init(ctx, NULL, key, NULL) == 0,
                "fips=yes operation must not reuse a non-FIPS public parse");
        freectx(ctx);
        ctx = NULL;
        awskms_key_free(key);
        key = NULL;
      }
    }
    if (null_provider != NULL) OSSL_PROVIDER_unload(null_provider);
    OSSL_LIB_CTX_free(libctx);
  }
}

static void test_keymgmt_dispatch(void) {
  AWSKMS_PROV_CTX provctx = {0};
  const OSSL_DISPATCH *dispatch =
      algorithm_dispatch(awskms_keymgmt_algorithms(), "EC");
  OSSL_FUNC_keymgmt_free_fn *free_key = NULL;
  OSSL_FUNC_keymgmt_has_fn *has = NULL;
  OSSL_FUNC_keymgmt_match_fn *match = NULL;
  OSSL_FUNC_keymgmt_validate_fn *validate = NULL;
  OSSL_FUNC_keymgmt_dup_fn *dup = NULL;
  AWSKMS_KEY *a = NULL, *b = NULL, *other_curve = NULL;
  void *public_copy = NULL, *domain_copy = NULL, *full_copy = NULL,
       *empty_copy = NULL;

  CHECK(dispatch != NULL, "EC keymgmt dispatch table must be present");
  if (dispatch == NULL) return;
  for (const OSSL_DISPATCH *fn = dispatch; fn->function_id != 0; fn++) {
    switch (fn->function_id) {
      case OSSL_FUNC_KEYMGMT_FREE:
        free_key = OSSL_FUNC_keymgmt_free(fn);
        break;
      case OSSL_FUNC_KEYMGMT_HAS:
        has = OSSL_FUNC_keymgmt_has(fn);
        break;
      case OSSL_FUNC_KEYMGMT_MATCH:
        match = OSSL_FUNC_keymgmt_match(fn);
        break;
      case OSSL_FUNC_KEYMGMT_VALIDATE:
        validate = OSSL_FUNC_keymgmt_validate(fn);
        break;
      case OSSL_FUNC_KEYMGMT_DUP:
        dup = OSSL_FUNC_keymgmt_dup(fn);
        break;
      default:
        break;
    }
  }
  CHECK(free_key != NULL && has != NULL && match != NULL && validate != NULL &&
            dup != NULL,
        "keymgmt dispatch is incomplete");
  if (free_key == NULL || has == NULL || match == NULL || validate == NULL ||
      dup == NULL)
    return;

  a = make_test_key(&provctx, "ECC_NIST_P256", "key-a");
  b = make_test_key(&provctx, "ECC_NIST_P256", "key-b");
  other_curve = make_test_key(&provctx, "ECC_NIST_P384", "key-c");
  CHECK(a != NULL && b != NULL && other_curve != NULL,
        "could not construct EC keymgmt fixtures");
  if (a == NULL || b == NULL || other_curve == NULL) goto out;

  CHECK(has(a, OSSL_KEYMGMT_SELECT_ALL) == 1,
        "a loaded EC key must have every selected subset");
  CHECK(match(a, b, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 1,
        "different P-256 keys must match on domain parameters");
  CHECK(match(a, b, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0,
        "different P-256 keys must not match on public key");
  CHECK(match(a, other_curve, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0,
        "different EC curves must not match on domain parameters");
  CHECK(validate(a,
                 OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                     OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                 OSSL_KEYMGMT_VALIDATE_FULL_CHECK) == 1,
        "full public/domain validation must succeed");
  CHECK(validate(a, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                 OSSL_KEYMGMT_VALIDATE_QUICK_CHECK) == 1,
        "quick public validation must succeed");
  CHECK(validate(a, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, 99) == 0,
        "unknown key validation modes must be rejected");

  public_copy = dup(a, OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                           OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS);
  CHECK(public_copy != NULL, "public key duplication must succeed");
  if (public_copy != NULL) {
    AWSKMS_KEY *copy = public_copy;

    CHECK(has(public_copy, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 1,
          "public duplicate must retain the public key");
    CHECK(has(public_copy, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0,
          "public duplicate must not retain the KMS private reference");
    CHECK(match(a, public_copy, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 1,
          "public duplicate must match its source");
    CHECK(copy->pub.der != a->pub.der && copy->pub.der_len == a->pub.der_len &&
              memcmp(copy->pub.der, a->pub.der, a->pub.der_len) == 0,
          "public duplicate must own the retained SPKI bytes");
  }

  domain_copy = dup(a, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS);
  CHECK(domain_copy != NULL, "domain-parameter duplication must succeed");
  if (domain_copy != NULL) {
    CHECK(has(domain_copy, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 1,
          "domain duplicate must retain EC parameters");
    CHECK(has(domain_copy, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0,
          "domain duplicate must not gain a public key");
  }

  full_copy = dup(a, OSSL_KEYMGMT_SELECT_ALL);
  CHECK(full_copy != NULL && has(full_copy, OSSL_KEYMGMT_SELECT_KEYPAIR) == 1,
        "full duplicate must retain the keypair");
  CHECK(dup(a, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
        "an unrepresentable private-only duplicate must fail");

  empty_copy = dup(a, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS);
  CHECK(empty_copy != NULL, "irrelevant-only duplication must succeed");
  if (empty_copy != NULL) {
    CHECK(has(empty_copy, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) == 1,
          "irrelevant selections are vacuously present");
    CHECK(has(empty_copy, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0,
          "irrelevant-only duplicate must not gain a public key");
  }

out:
  free_key(public_copy);
  free_key(domain_copy);
  free_key(full_copy);
  free_key(empty_copy);
  awskms_key_free(a);
  awskms_key_free(b);
  awskms_key_free(other_curve);
}

static void test_dispatch(void) {
  test_store_global_fips();
  test_signature_dispatch();
  test_keymgmt_dispatch();
}

int main(void) {
  /* Unbuffered, so a crash inside a suite does not swallow the log telling you
   * which suite it was. */
  setvbuf(stdout, NULL, _IONBF, 0);

  struct {
    const char *name;
    void (*fn)(void);
  } suites[] = {{"uri", test_uri},
                {"keyspec", test_keyspec},
                {"spki", test_spki},
                {"mu", test_mu},
                {"dispatch", test_dispatch}};

  for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
    int before = awskms_test_failures;
    printf("%s\n", suites[i].name);
    suites[i].fn();
    printf("  %s\n", awskms_test_failures == before ? "ok" : "FAILED");
  }

  printf("\n%d checks, %d failures\n", awskms_test_checks,
         awskms_test_failures);
  return awskms_test_failures == 0 ? 0 : 1;
}
