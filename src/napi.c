/*
 * keyobject aws-kms -- N-API registrar entry point.
 *
 * This is the SECOND entry point of the same shared object. One file is both an
 * OpenSSL provider module (OSSL_provider_init, called by libcrypto) and a
 * Node.js addon (napi_register_module_v1, called by process.dlopen). Loading it
 * as an addon performs the provider registration that would otherwise require
 * an --openssl-config= file, which is what lets an npm package activate itself
 * from a plain require() with no flags.
 *
 * THE CRITICAL CONSTRAINT: this file must not make a HARD reference to any
 * napi_* symbol.
 *
 * The module deliberately links nothing -- every OpenSSL symbol stays undefined
 * and binds to the host process at dlopen() time. napi_* symbols would have to
 * do the same, but they only exist in a Node process. The `openssl` CLI, or any
 * other libcrypto consumer that dlopen()s this as a provider, has no napi_*
 * anywhere, so an eagerly-bound napi_* reference would make the file fail to
 * load in its PROVIDER role outside Node -- and silently, because a failed
 * provider load produces no diagnostic at all.
 *
 * Two things keep that from happening:
 *
 *   1. The registration sequence is pure libcrypto. The only thing needed from
 *      Node-API is the FUNCTION SIGNATURE, and napi_env and napi_value are both
 *      opaque pointer typedefs (struct napi_env__*, struct napi_value__*), so
 *      void* is ABI-identical. Returning `exports` unchanged is what node's
 *      napi_module_register_by_symbol() reads as "addon exports nothing new".
 *      So: no node headers, no node-api-headers build dependency.
 *
 *   2. The one napi_* function that IS needed -- to report failure as a JS
 *      exception rather than silently -- is declared WEAK. A weak undefined
 *      symbol resolves to NULL instead of failing the load when the host does
 *      not provide it, so the provider role is unaffected and the null check
 *      below is what actually runs in a non-Node host.
 */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <string.h>

#include "provider.h" /* also declares OSSL_provider_init, via openssl/core.h */

/*
 * Symbols that are optional at runtime. See the header comment for why
 * napi_throw_error must be weak. EVP_get1_default_properties() was added in
 * OpenSSL 3.5, while this provider remains binary-loadable on 3.0: declaring it
 * weak lets registration reject 3.0--3.4 clearly without stopping the provider
 * module itself from loading through openssl.cnf.
 *
 * macOS needs weak_import specifically -- plain `weak` on a Darwin *undefined*
 * symbol is not the same thing -- while ELF wants plain `weak`.
 */
#if defined(__APPLE__)
#define AWSKMS_WEAK __attribute__((weak_import))
#else
#define AWSKMS_WEAK __attribute__((weak))
#endif
extern char *EVP_get1_default_properties(OSSL_LIB_CTX *libctx) AWSKMS_WEAK;

/*
 * napi_throw_error has signature
 * napi_status(napi_env, const char *code, const char *msg). The status enum is
 * int-compatible and both pointer types are opaque, so this declaration is
 * ABI-correct without including node_api.h.
 */
extern int napi_throw_error(void *env, const char *code,
                            const char *msg) AWSKMS_WEAK;

#define AWSKMS_DEFAULT_PROPQ "?" AWSKMS_KEYOBJECT_PROPERTY "!=yes"

typedef enum {
  AWSKMS_MARKER_ABSENT,
  AWSKMS_MARKER_GUARD,
  AWSKMS_MARKER_CONFLICT,
} AWSKMS_MARKER_STATE;

static CRYPTO_ONCE awskms_register_once = CRYPTO_ONCE_STATIC_INIT;
static OSSL_PROVIDER *awskms_provider;
static const char *awskms_registration_error;
static const char *awskms_registration_code =
    "ERR_AWSKMS_PROVIDER_REGISTRATION";
static int awskms_registration_succeeded;

static int awskms_is_space(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' ||
         c == '\v';
}

static int awskms_is_property_name_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_' || c == '.';
}

static int awskms_ascii_equal(const char *value, size_t value_len,
                              const char *expected) {
  size_t i;

  if (strlen(expected) != value_len) return 0;
  for (i = 0; i < value_len; i++) {
    char left = value[i];
    char right = expected[i];

    if (left >= 'A' && left <= 'Z') left = (char)(left - 'A' + 'a');
    if (right >= 'A' && right <= 'Z') right = (char)(right - 'A' + 'a');
    if (left != right) return 0;
  }
  return 1;
}

/*
 * Inspect one comma-delimited property clause. The getter returns a canonical
 * query today, but accepting whitespace and case variants here keeps the
 * idempotence check independent of that representation.
 */
static AWSKMS_MARKER_STATE awskms_marker_clause(const char *begin,
                                                const char *end) {
  const char *name;
  const char *value;
  size_t name_len;
  size_t value_len;
  int optional = 0;

  while (begin < end && awskms_is_space(*begin)) begin++;
  while (begin < end && awskms_is_space(end[-1])) end--;

  if (begin < end && *begin == '?') {
    optional = 1;
    begin++;
    while (begin < end && awskms_is_space(*begin)) begin++;
  }

  /* A leading '-' is itself a property-name operation, and is a conflict. */
  if (begin < end && *begin == '-') begin++;

  name = begin;
  while (begin < end && awskms_is_property_name_char(*begin)) begin++;
  name_len = (size_t)(begin - name);
  if (!awskms_ascii_equal(name, name_len, AWSKMS_KEYOBJECT_PROPERTY))
    return AWSKMS_MARKER_ABSENT;

  while (begin < end && awskms_is_space(*begin)) begin++;
  if (!optional || end - begin < 2 || begin[0] != '!' || begin[1] != '=')
    return AWSKMS_MARKER_CONFLICT;
  begin += 2;
  while (begin < end && awskms_is_space(*begin)) begin++;

  value = begin;
  while (begin < end && !awskms_is_space(*begin)) begin++;
  value_len = (size_t)(begin - value);
  while (begin < end && awskms_is_space(*begin)) begin++;

  if (begin == end && awskms_ascii_equal(value, value_len, "yes"))
    return AWSKMS_MARKER_GUARD;
  return AWSKMS_MARKER_CONFLICT;
}

/* Values may be quoted, so only a comma outside quotes ends a clause. */
static AWSKMS_MARKER_STATE awskms_marker_state(const char *query) {
  const char *clause = query;
  const char *cursor = query;
  AWSKMS_MARKER_STATE found = AWSKMS_MARKER_ABSENT;
  char quote = '\0';

  for (;;) {
    if (*cursor == '\0' || (*cursor == ',' && quote == '\0')) {
      AWSKMS_MARKER_STATE current = awskms_marker_clause(clause, cursor);

      if (current == AWSKMS_MARKER_CONFLICT ||
          (current == AWSKMS_MARKER_GUARD && found == AWSKMS_MARKER_GUARD))
        return AWSKMS_MARKER_CONFLICT;
      if (current == AWSKMS_MARKER_GUARD) found = current;
      if (*cursor == '\0') return found;
      clause = cursor + 1;
    } else if (quote == '\0' && (*cursor == '\'' || *cursor == '"')) {
      quote = *cursor;
    } else if (quote != '\0' && *cursor == quote) {
      quote = '\0';
    }
    cursor++;
  }
}

static char *awskms_append_default_property(const char *properties) {
  const size_t old_len = strlen(properties);
  const size_t guard_len = strlen(AWSKMS_DEFAULT_PROPQ);
  const size_t separator_len = old_len == 0 ? 0 : 1;
  char *merged;

  if (old_len > (size_t)-1 - guard_len - separator_len - 1) return NULL;
  merged = OPENSSL_malloc(old_len + separator_len + guard_len + 1);
  if (merged == NULL) return NULL;

  memcpy(merged, properties, old_len);
  if (separator_len != 0) merged[old_len] = ',';
  memcpy(merged + old_len + separator_len, AWSKMS_DEFAULT_PROPQ, guard_len + 1);
  return merged;
}

/*
 * Report a registration failure to JS, so process.dlopen() throws.
 *
 * The alternative -- returning quietly -- reproduces exactly the silent-failure
 * trap that makes the openssl.cnf route hard to debug: registration appears to
 * succeed and the process only fails much later, at the first createPrivateKey,
 * with an unrelated-looking STORE "unsupported" error.
 */
static void *awskms_fail(void *env, void *exports, const char *code,
                         const char *msg) {
  if (napi_throw_error != NULL) napi_throw_error(env, code, msg);
  return exports;
}

/*
 * napi_register_module_v1 -- node's addon entry point.
 *
 * Performs the same registration the openssl.cnf route does declaratively,
 * while preserving the application's existing default property policy:
 *
 *   1. Read the existing default query and append the namespaced preference.
 *   2. Register this image's provider init function as a built-in provider.
 *   3. Apply the merged default query.
 *   4. Activate and retain aws-kms without disabling fallback providers.
 *
 * OSSL_PROVIDER_try_load(..., 1) is load()'s important counterpart here: it
 * retains OpenSSL's fallback-provider behaviour, so activation does not make
 * the process lose its default provider.
 *
 * Step 2 uses OSSL_PROVIDER_add_builtin() -- which registers the init function
 * already present in this image -- rather than
 * OSSL_PROVIDER_set_default_search_path() plus a by-name load. This avoids
 * three undesirable side effects:
 *
 *   - libcrypto never touches the filesystem, so there is no second dlopen()
 *     and no search-path state left set on the default libctx (which would
 *     change where OTHER provider loads in the process resolve).
 *   - No constraint on the filename. A by-name load appends the platform module
 *     extension, while add_builtin uses the init function already loaded from
 *     the satellite package's native module.
 *   - It cannot pick up a DIFFERENT awskms module that happens to sit in the
 *     search path.
 */
AWSKMS_EXPORT void *napi_register_module_v1(void *env, void *exports);

static void awskms_register(void) {
  char *existing = NULL;
  char *merged = NULL;
  const char *properties;
  AWSKMS_MARKER_STATE marker;
  int properties_changed = 0;

  if (EVP_get1_default_properties == NULL) {
    awskms_registration_code = "ERR_AWSKMS_OPENSSL_VERSION";
    awskms_registration_error =
        "register() requires OpenSSL 3.5 or newer: this runtime has no "
        "EVP_get1_default_properties(), so the existing default property "
        "policy cannot be preserved; use the openssl.cnf activation route on "
        "OpenSSL 3.0--3.4";
    return;
  }

  existing = EVP_get1_default_properties(NULL);
  if (existing == NULL) {
    awskms_registration_error = "EVP_get1_default_properties() failed";
    return;
  }

  marker = awskms_marker_state(existing);
  if (marker == AWSKMS_MARKER_CONFLICT) {
    awskms_registration_error =
        "the existing OpenSSL default property query already uses the "
        "reserved property " AWSKMS_KEYOBJECT_PROPERTY
        " with a conflicting value";
    goto done;
  }
  if (marker == AWSKMS_MARKER_GUARD) {
    properties = existing;
  } else {
    merged = awskms_append_default_property(existing);
    if (merged == NULL) {
      awskms_registration_error =
          "could not allocate the merged OpenSSL default property query";
      goto done;
    }
    properties = merged;
    properties_changed = 1;
  }

  /* A config-loaded instance is already registered; do not add a duplicate. */
  if (!OSSL_PROVIDER_available(NULL, AWSKMS_PROVIDER_NAME) &&
      !OSSL_PROVIDER_add_builtin(NULL, AWSKMS_PROVIDER_NAME,
                                 OSSL_provider_init)) {
    awskms_registration_error =
        "OSSL_PROVIDER_add_builtin(aws-kms) failed before activation";
    goto done;
  }

  if (properties_changed && !EVP_set_default_properties(NULL, properties)) {
    awskms_registration_error =
        "EVP_set_default_properties() rejected the merged default property "
        "query";
    goto done;
  }

  /* Retain both this handle and OpenSSL's fallback-provider behaviour. */
  awskms_provider = OSSL_PROVIDER_try_load(NULL, AWSKMS_PROVIDER_NAME, 1);
  if (awskms_provider == NULL) {
    if (properties_changed && !EVP_set_default_properties(NULL, existing)) {
      awskms_registration_error =
          "OSSL_PROVIDER_try_load(aws-kms) failed and restoring the previous "
          "OpenSSL default property query also failed";
    } else {
      awskms_registration_error =
          "OSSL_PROVIDER_try_load(aws-kms) failed; the previous OpenSSL "
          "default property query was restored";
    }
    goto done;
  }

  awskms_registration_succeeded = 1;

done:
  OPENSSL_free(merged);
  OPENSSL_free(existing);
}

AWSKMS_EXPORT void *napi_register_module_v1(void *env, void *exports) {
  if (!CRYPTO_THREAD_run_once(&awskms_register_once, awskms_register))
    return awskms_fail(env, exports, "ERR_AWSKMS_PROVIDER_REGISTRATION",
                       "CRYPTO_THREAD_run_once() failed during aws-kms "
                       "provider registration");
  if (!awskms_registration_succeeded)
    return awskms_fail(env, exports, awskms_registration_code,
                       awskms_registration_error != NULL
                           ? awskms_registration_error
                           : "aws-kms provider registration failed");

  return exports;
}
