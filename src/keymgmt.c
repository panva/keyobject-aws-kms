/*
 * OSSL_OP_KEYMGMT for opaque, KMS-backed keys.
 *
 * Most of this is delegation to the cached public EVP_PKEY, which is why it is
 * short: that key already knows its bits, security-bits, max-size, RSA n/e and
 * EC group, and EVP_PKEY_todata() already produces exactly the OSSL_PARAMs the
 * default provider's encoders want. The only genuinely bespoke logic is the
 * export rule below.
 *
 * THE RULE: export must FAIL for any selection including
 * OSSL_KEYMGMT_SELECT_PRIVATE_KEY.
 *
 * EVP_PKEY_sign_init() and do_sigver_init() fetch the signature implementation by
 * name with a NULL property query, which normally resolves the *default*
 * provider's, and only retry with ours if evp_pkey_export_to_provider() -- called
 * with OSSL_KEYMGMT_SELECT_ALL -- returns NULL. Exporting the public half for
 * such a request would bind the default provider's signature to a public-only
 * copy of the key, and the failure would surface much later, deep inside code we
 * do not own. Refusing private selections also makes public SPKI export work
 * (that asks for public|domain-parameters only) and makes private-key export fail
 * cleanly, which is what callers expect of a non-exportable key. One rule, three
 * behaviours.
 *
 * Also deliberately absent: `new`, `import` and `import_types`. Keys only ever
 * arrive from our own STORE loader via `load`, so having no way to build one from
 * foreign key material is a structural guarantee that this keymgmt can never be
 * used for somebody else's key -- which matters because it is registered under
 * the same names ("RSA", "EC") as the default provider's.
 */
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

#include "err.h"
#include "key.h"
#include "provider.h"

static void awskms_keymgmt_free(void *keydata) {
  awskms_key_free((AWSKMS_KEY *)keydata);
}

/*
 * The sole constructor. `reference` holds the keydata pointer emitted by our
 * store loader; libcrypto passes it back synchronously from inside the loader's
 * object callback, so it is still valid here.
 */
static void *awskms_keymgmt_load(const void *reference, size_t reference_sz) {
  AWSKMS_KEY *key;

  if (reference == NULL || reference_sz != sizeof(AWSKMS_KEY *)) return NULL;
  key = *(AWSKMS_KEY *const *)reference;
  if (key == NULL || !awskms_key_up_ref(key)) return NULL;
  return key;
}

/*
 * A KMS key genuinely has a private half; it just cannot be extracted. Reporting
 * it is not cosmetic: if this returns 0 for SELECT_PRIVATE_KEY the STORE result
 * gets classified as a public key and createPrivateKey() fails outright.
 */
static int awskms_keymgmt_has(const void *keydata, int selection) {
  const AWSKMS_KEY *key = keydata;
  int wanted = OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

  if (key == NULL) return 0;
  if (awskms_key_spec(key)->family == AWSKMS_FAMILY_EC)
    wanted |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

  /* "Do I have everything asked for?" */
  return (selection & ~wanted) == 0;
}

static int awskms_keymgmt_match(const void *keydata1, const void *keydata2,
                                int selection) {
  const AWSKMS_KEY *a = keydata1, *b = keydata2;

  if (a == NULL || b == NULL) return 0;
  if (a == b) return 1;

  /* Two loads of the same URI are the same key. Comparing the public halves is
   * both cheaper and stricter than comparing key ids: an alias could be
   * repointed, and two different aliases could name one key. */
  return EVP_PKEY_eq(a->pub.pkey, b->pub.pkey) == 1;
}

static int awskms_keymgmt_validate(const void *keydata, int selection,
                                   int checktype) {
  /* KMS will not hand out a malformed key, and the SPKI was already parsed and
   * cross-checked against the advertised KeySpec at load time. */
  return keydata != NULL;
}

/* Immutable keydata, so sharing under a refcount is safe and a deep copy would
 * only waste a GetPublicKey result. */
static void *awskms_keymgmt_dup(const void *keydata, int selection) {
  AWSKMS_KEY *key = (AWSKMS_KEY *)keydata;

  if (key == NULL || !awskms_key_up_ref(key)) return NULL;
  return key;
}

static int awskms_keymgmt_get_params(void *keydata, OSSL_PARAM params[]) {
  AWSKMS_KEY *key = keydata;

  if (key == NULL) return 0;
  /*
   * Straight delegation. This is what makes EVP_PKEY_size() (via
   * OSSL_PKEY_PARAM_MAX_SIZE) and asymmetricKeyDetails correct without a table
   * of our own, and it is also what makes the parameters a KMS key cannot
   * answer -- OSSL_PKEY_PARAM_PRIV_KEY, and ML-DSA's seed -- fail rather than
   * quietly return something wrong, because the cached key is public-only.
   */
  return EVP_PKEY_get_params(key->pub.pkey, params) == 1;
}

/*
 * OSSL_PKEY_PARAM_GROUP_NAME carries more weight than the rest of this list, and
 * for three separate reasons: Node reads it for asymmetricKeyDetails.namedCurve,
 * libcrypto needs it for the DER <-> IEEE-P1363 dsaEncoding conversion, and
 * ncrypto's MayBeSM2Key() reads it to decide whether the prehashed sign fallback
 * is safe. That last one fails CLOSED -- a key whose curve cannot be determined is
 * assumed to be SM2 and loses the fallback -- so an EC keymgmt that stopped
 * answering this would degrade signing rather than error.
 */
static const OSSL_PARAM *awskms_keymgmt_gettable_params(void *provctx) {
  /* Advisory, and keydata-less, so it is the union over every family. */
  static const OSSL_PARAM gettable[] = {
      OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
      OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
      OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
      OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
      OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
      OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
      OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
      OSSL_PARAM_END};
  return gettable;
}

static int awskms_keymgmt_export(void *keydata, int selection,
                                 OSSL_CALLBACK *param_cb, void *cbarg) {
  AWSKMS_KEY *key = keydata;
  OSSL_PARAM *params = NULL;
  int ok = 0;

  if (key == NULL) return 0;

  /* THE RULE. See the file comment: this single refusal is what selects our
   * signature implementation, and what makes private-key export fail cleanly. */
  if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
    AWSKMS_raise(key->provctx->handle, AWSKMS_R_PRIVATE_KEY_NOT_EXPORTABLE,
                 "the private key for \"%s\" is held by AWS KMS and is not "
                 "exportable",
                 key->uri.key_id);
    return 0;
  }
  if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0) return 0;

  /* Exactly the parameters the default provider's encoders expect, because they
   * come from a default-provider key. */
  if (EVP_PKEY_todata(key->pub.pkey, selection, &params) != 1) return 0;
  ok = param_cb(params, cbarg);
  OSSL_PARAM_free(params);
  return ok;
}

static const OSSL_PARAM *awskms_keymgmt_export_types(int selection) {
  static const OSSL_PARAM public_types[] = {
      OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
      OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
      OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
      OSSL_PARAM_END};
  static const OSSL_PARAM none[] = {OSSL_PARAM_END};

  if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) return none;
  if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) return public_types;
  return none;
}

/* EC's signature operation is called ECDSA, not EC. Every other family we
 * register uses its own name, so only EC needs this. */
static const char *awskms_keymgmt_ec_query_operation_name(int operation_id) {
  return operation_id == OSSL_OP_SIGNATURE ? "ECDSA" : NULL;
}

#define AWSKMS_KEYMGMT_COMMON                                                \
  {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))awskms_keymgmt_load},             \
      {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))awskms_keymgmt_free},         \
      {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))awskms_keymgmt_has},           \
      {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))awskms_keymgmt_match},       \
      {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))awskms_keymgmt_validate}, \
      {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))awskms_keymgmt_dup},           \
      {OSSL_FUNC_KEYMGMT_GET_PARAMS,                                         \
       (void (*)(void))awskms_keymgmt_get_params},                           \
      {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
       (void (*)(void))awskms_keymgmt_gettable_params},                      \
      {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))awskms_keymgmt_export}, {   \
    OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                          \
        (void (*)(void))awskms_keymgmt_export_types                          \
  }

static const OSSL_DISPATCH awskms_keymgmt_generic[] = {AWSKMS_KEYMGMT_COMMON,
                                                       {0, NULL}};

static const OSSL_DISPATCH awskms_keymgmt_ec[] = {
    AWSKMS_KEYMGMT_COMMON,
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
     (void (*)(void))awskms_keymgmt_ec_query_operation_name},
    {0, NULL}};

/*
 * One row per key type we can serve. The names must be exactly these: Node
 * derives asymmetricKeyType from EVP_PKEY_id(), which for a provider key
 * resolves purely from the keymgmt's name.
 *
 * Only the primary name is registered -- no OID or alias list -- which keeps the
 * surface for an accidental bare-name fetch as small as possible.
 */
static const OSSL_ALGORITHM awskms_keymgmt_alg[] = {
    {"RSA", AWSKMS_PROPERTY_DEF, awskms_keymgmt_generic, "AWS KMS RSA"},
    {"EC", AWSKMS_PROPERTY_DEF, awskms_keymgmt_ec, "AWS KMS EC"},
    {"ED25519", AWSKMS_PROPERTY_DEF, awskms_keymgmt_generic, "AWS KMS Ed25519"},
    {"ML-DSA-44", AWSKMS_PROPERTY_DEF, awskms_keymgmt_generic,
     "AWS KMS ML-DSA-44"},
    {"ML-DSA-65", AWSKMS_PROPERTY_DEF, awskms_keymgmt_generic,
     "AWS KMS ML-DSA-65"},
    {"ML-DSA-87", AWSKMS_PROPERTY_DEF, awskms_keymgmt_generic,
     "AWS KMS ML-DSA-87"},
    {NULL, NULL, NULL, NULL}};

const OSSL_ALGORITHM *awskms_keymgmt_algorithms(void) {
  return awskms_keymgmt_alg;
}
