/*
 * Error reporting.
 *
 * Errors are raised through the provider core upcalls rather than by calling
 * ERR_raise() directly. Both reach the same queue here (the module binds to the
 * host's libcrypto), but the upcalls are the documented contract.
 *
 * Node.js turns the reason STRING into `err.code`, uppercased with spaces
 * replaced by underscores and prefixed `ERR_OSSL_`, so
 * AWSKMS_R_SIGN_FAILED -> "awskms sign failed" -> ERR_OSSL_AWSKMS_SIGN_FAILED.
 * The strings below are therefore user-visible API: keep them readable and
 * stable.
 *
 * Two constraints from crypto/provider_core.c:
 *   - reason numbers must have zero ERR_LIB bits, else get_reason_strings is
 *     rejected outright at load time;
 *   - core_vset_error() dereferences the provider handle for such reasons, so
 *     the REAL OSSL_CORE_HANDLE must be passed (legacyprov.c passes NULL, which
 *     is only safe because it packs ERR_LIB_PROV into every reason).
 */
#ifndef AWSKMS_ERR_H
#define AWSKMS_ERR_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <stdarg.h>
#include <stdint.h>

#define AWSKMS_R_INVALID_URI 1
#define AWSKMS_R_NO_REGION 2
#define AWSKMS_R_REGION_CONFLICT 3
#define AWSKMS_R_GET_PUBLIC_KEY_FAILED 4
#define AWSKMS_R_SIGN_FAILED 5
#define AWSKMS_R_KEY_NOT_FOUND 6
#define AWSKMS_R_KEY_DISABLED 7
#define AWSKMS_R_INVALID_KEY_USAGE 9
#define AWSKMS_R_UNSUPPORTED_KEY_SPEC 10
#define AWSKMS_R_ACCESS_DENIED 11
#define AWSKMS_R_THROTTLED 12
#define AWSKMS_R_NO_CREDENTIALS 13
#define AWSKMS_R_UNSUPPORTED_SALT_LENGTH 14
#define AWSKMS_R_UNSUPPORTED_DIGEST 15
#define AWSKMS_R_UNSUPPORTED_PADDING 16
#define AWSKMS_R_DIGEST_LENGTH_MISMATCH 17
#define AWSKMS_R_MESSAGE_TOO_LARGE 18
#define AWSKMS_R_EMPTY_MESSAGE 19
#define AWSKMS_R_PRIVATE_KEY_NOT_EXPORTABLE 20
#define AWSKMS_R_UNSUPPORTED_PARAMETER 21
#define AWSKMS_R_MALFORMED_PUBLIC_KEY 22
#define AWSKMS_R_INTERNAL_ERROR 23
#define AWSKMS_R_OUTPUT_BUFFER_TOO_SMALL 24
#define AWSKMS_R_FIPS_ROUTING 25
#define AWSKMS_R_INVALID_KEY_STATE 26

/* Captured from the dispatch table handed to OSSL_provider_init(). */
void awskms_err_init(const OSSL_DISPATCH *in);

/* Returns the OSSL_ITEM[] for OSSL_FUNC_PROVIDER_GET_REASON_STRINGS. */
const OSSL_ITEM *awskms_err_reason_strings(void);

void awskms_err_raise(const OSSL_CORE_HANDLE *handle, uint32_t reason,
                      const char *file, int line, const char *func,
                      const char *fmt, ...);

/*
 * Raise exactly one error, at the point of failure. Node peeks the LAST error
 * on the STORE path and the OLDEST on sign/verify, so a single well-placed
 * error is what surfaces cleanly on both; and something must always be raised,
 * because an empty queue degrades to a bare ERR_CRYPTO_OPERATION_FAILED with no
 * code at all.
 */
#define AWSKMS_raise(handle, reason, fmt, ...)                     \
  awskms_err_raise((handle), (reason), OPENSSL_FILE, OPENSSL_LINE, \
                   OPENSSL_FUNC, (fmt), ##__VA_ARGS__)

#endif /* AWSKMS_ERR_H */
