#include "err.h"

#include <openssl/err.h>

#include "compat.h"

static OSSL_FUNC_core_new_error_fn *c_new_error;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
static OSSL_FUNC_core_vset_error_fn *c_vset_error;

void awskms_err_init(const OSSL_DISPATCH *in) {
  for (; in->function_id != 0; in++) {
    switch (in->function_id) {
      case OSSL_FUNC_CORE_NEW_ERROR:
        c_new_error = OSSL_FUNC_core_new_error(in);
        break;
      case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
        c_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
        break;
      case OSSL_FUNC_CORE_VSET_ERROR:
        c_vset_error = OSSL_FUNC_core_vset_error(in);
        break;
      default:
        break;
    }
  }
}

void awskms_err_raise(const OSSL_CORE_HANDLE *handle, uint32_t reason,
                      const char *file, int line, const char *func,
                      const char *fmt, ...) {
  va_list ap;

  if (c_new_error == NULL || c_vset_error == NULL) return;

  c_new_error(handle);
  if (c_set_error_debug != NULL) c_set_error_debug(handle, file, line, func);

  va_start(ap, fmt);
  c_vset_error(handle, reason, fmt, ap);
  va_end(ap);
}

/*
 * Reason strings double as Node's `err.code`. "awskms sign failed" surfaces as
 * ERR_OSSL_AWSKMS_SIGN_FAILED, so each one is prefixed "awskms " to namespace
 * the resulting code and keep it greppable.
 */
static const OSSL_ITEM reason_strings[] = {
    {AWSKMS_R_INVALID_URI, "awskms invalid uri"},
    {AWSKMS_R_NO_REGION, "awskms no region"},
    {AWSKMS_R_REGION_CONFLICT, "awskms region conflict"},
    {AWSKMS_R_GET_PUBLIC_KEY_FAILED, "awskms get public key failed"},
    {AWSKMS_R_SIGN_FAILED, "awskms sign failed"},
    {AWSKMS_R_KEY_NOT_FOUND, "awskms key not found"},
    {AWSKMS_R_KEY_DISABLED, "awskms key disabled"},
    {AWSKMS_R_INVALID_KEY_USAGE, "awskms invalid key usage"},
    {AWSKMS_R_UNSUPPORTED_KEY_SPEC, "awskms unsupported key spec"},
    {AWSKMS_R_ACCESS_DENIED, "awskms access denied"},
    {AWSKMS_R_THROTTLED, "awskms throttled"},
    {AWSKMS_R_NO_CREDENTIALS, "awskms no credentials"},
    {AWSKMS_R_UNSUPPORTED_SALT_LENGTH, "awskms unsupported salt length"},
    {AWSKMS_R_UNSUPPORTED_DIGEST, "awskms unsupported digest"},
    {AWSKMS_R_UNSUPPORTED_PADDING, "awskms unsupported padding"},
    {AWSKMS_R_DIGEST_LENGTH_MISMATCH, "awskms digest length mismatch"},
    {AWSKMS_R_MESSAGE_TOO_LARGE, "awskms message too large"},
    {AWSKMS_R_EMPTY_MESSAGE, "awskms empty message"},
    {AWSKMS_R_PRIVATE_KEY_NOT_EXPORTABLE, "awskms private key not exportable"},
    {AWSKMS_R_UNSUPPORTED_PARAMETER, "awskms unsupported parameter"},
    {AWSKMS_R_MALFORMED_PUBLIC_KEY, "awskms malformed public key"},
    {AWSKMS_R_INTERNAL_ERROR, "awskms internal error"},
    {AWSKMS_R_OUTPUT_BUFFER_TOO_SMALL, "awskms output buffer too small"},
    {AWSKMS_R_FIPS_ROUTING, "awskms fips routing"},
    {AWSKMS_R_INVALID_KEY_STATE, "awskms invalid key state"},
    {0, NULL}};

const OSSL_ITEM *awskms_err_reason_strings(void) { return reason_strings; }
