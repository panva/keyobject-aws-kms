/*
 * tiny-aws-kms-openssl-provider -- N-API registrar entry point.
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
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "provider.h" /* also declares OSSL_provider_init, via openssl/core.h */

/*
 * ?provider!=awskms as the process default property query.
 *
 * Without it, every unqualified algorithm fetch can land on this provider,
 * because which implementation a query-less fetch gets is decided by provider
 * order in the store -- so registering keymgmt named "RSA"/"EC" shadows the
 * default provider's for unrelated callers, and crypto.generateKeyPair() starts
 * trying to generate keys in KMS. The leading '?' keeps it a preference rather
 * than a requirement. Identical to the cnf route's [algs_sect]
 * default_properties.
 */
#define AWSKMS_DEFAULT_PROPQ "?provider!=" AWSKMS_PROVIDER_NAME

/*
 * napi_throw_error, weakly. See the header comment: this is the ONLY napi entry
 * point referenced, and it must not be a hard reference.
 *
 * Signature is napi_status(napi_env, const char *code, const char *msg); the
 * status enum is int-compatible and both pointer types are opaque, so this
 * declaration is ABI-correct without including node_api.h.
 *
 * macOS needs weak_import specifically -- plain `weak` on a Darwin *undefined*
 * symbol is not the same thing -- while ELF wants plain `weak`.
 */
#if defined(__APPLE__)
#define AWSKMS_WEAK __attribute__((weak_import))
#else
#define AWSKMS_WEAK __attribute__((weak))
#endif
extern int napi_throw_error(void *env, const char *code,
                            const char *msg) AWSKMS_WEAK;

/*
 * Report a registration failure to JS, so process.dlopen() throws.
 *
 * The alternative -- returning quietly -- reproduces exactly the silent-failure
 * trap that makes the openssl.cnf route hard to debug: registration appears to
 * succeed and the process only fails much later, at the first createPrivateKey,
 * with an unrelated-looking STORE "unsupported" error.
 */
static void *awskms_fail(void *env, void *exports, const char *msg) {
  if (napi_throw_error != NULL)
    napi_throw_error(env, "ERR_AWSKMS_PROVIDER_REGISTRATION", msg);
  return exports;
}

/*
 * napi_register_module_v1 -- node's addon entry point.
 *
 * Performs the same registration the openssl.cnf route does declaratively:
 *
 *   1. EVP_set_default_properties        == [algs_sect] default_properties
 *   2. OSSL_PROVIDER_add_builtin         == (no cnf equivalent -- see below)
 *   3. OSSL_PROVIDER_load(.., "default") == [provider_sect] default = ...
 *   4. OSSL_PROVIDER_load(.., "awskms")  == [provider_sect] awskms = ...
 *
 * Step 3 is MANDATORY and its omission is not a soft failure: activating any
 * provider explicitly disables OpenSSL's implicit default-provider fallback,
 * and a process with no default provider dies on the next random byte. In the
 * cnf route the same mistake (omitting "default = default_sect") aborts node at
 * startup with "Assertion failed: ncrypto::CSPRNG(nullptr, 0)".
 *
 * Step 2 uses OSSL_PROVIDER_add_builtin() -- which registers the init function
 * already present in this image -- rather than
 * OSSL_PROVIDER_set_default_search_path() plus a by-name load. Both were
 * measured to work, but add_builtin is better in three ways:
 *
 *   - libcrypto never touches the filesystem, so there is no second dlopen()
 *     and no search-path state left set on the default libctx (which would
 *     change where OTHER provider loads in the process resolve).
 *   - No constraint on the FILENAME. A by-name load appends the platform module
 *     extension, so the search-path route only works if the file is called
 *     awskms.dylib / awskms.so -- measured: renaming it to the npm-conventional
 *     awskms.node makes the by-name route fail. add_builtin does not care, so
 *     one artifact can be named awskms.node and serve both roles.
 *   - It cannot pick up a DIFFERENT awskms module that happens to sit in the
 *     search path.
 */
AWSKMS_EXPORT void *napi_register_module_v1(void *env, void *exports);

AWSKMS_EXPORT void *napi_register_module_v1(void *env, void *exports) {
  if (!EVP_set_default_properties(NULL, AWSKMS_DEFAULT_PROPQ))
    return awskms_fail(env, exports,
                       "EVP_set_default_properties failed; refusing to "
                       "activate awskms without the ?provider!=awskms guard");

  if (!OSSL_PROVIDER_add_builtin(NULL, AWSKMS_PROVIDER_NAME,
                                 OSSL_provider_init))
    return awskms_fail(env, exports,
                       "OSSL_PROVIDER_add_builtin(awskms) failed");

  /* Not optional -- see above. */
  if (OSSL_PROVIDER_load(NULL, "default") == NULL)
    return awskms_fail(env, exports,
                       "OSSL_PROVIDER_load(default) failed; the process would "
                       "be left with no default provider");

  if (OSSL_PROVIDER_load(NULL, AWSKMS_PROVIDER_NAME) == NULL)
    return awskms_fail(env, exports, "OSSL_PROVIDER_load(awskms) failed");

  return exports;
}
