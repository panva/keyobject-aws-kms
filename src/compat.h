/*
 * Definitions this provider needs that only exist in newer OpenSSL headers.
 *
 * The module is built against ONE header tree but must run against whatever
 * OpenSSL the host process has -- 3.0 at the oldest, with no upper bound: 4.x
 * hosts are supported too. Dispatch ids and OSSL_PARAM key names are
 * compile-time constants, not linker symbols, so filling in a slot that a 3.0
 * host will never call costs nothing at load time -- ML-DSA simply becomes
 * unreachable there. Defining the missing constants ourselves is what keeps
 * this to a single artifact instead of a build per OpenSSL release.
 *
 * Forward compatibility rule, and the reason there is no upper bound: this
 * provider uses only the provider/OSSL_PARAM/EVP interfaces, and NOTHING
 * deprecated in 3.0. In particular no RSA_*, no EC_KEY_*, no DSA_*, no
 * ENGINE_*, and no hand-rolled DER. Public key components are recovered by
 * handing the SubjectPublicKeyInfo from kms:GetPublicKey to d2i_PUBKEY_ex() and
 * reading them back with EVP_PKEY_get_*_param(), which is both the least code
 * and the interface least likely to move under us.
 */
#ifndef AWSKMS_COMPAT_H
#define AWSKMS_COMPAT_H

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>

/* Floor only. Deliberately no upper bound -- see above. */
#if OPENSSL_VERSION_MAJOR < 3
#error "the awskms provider requires OpenSSL 3.0 or newer headers"
#endif

/* OSSL_FUNC_STORE_OPEN_EX: OpenSSL 3.1+. We register both open and open_ex. */
#ifndef OSSL_FUNC_STORE_OPEN_EX
#define OSSL_FUNC_STORE_OPEN_EX 10
#endif

/* ML-DSA key and signature parameters: OpenSSL 3.5+. */
#ifndef OSSL_PKEY_PARAM_ML_DSA_SEED
#define OSSL_PKEY_PARAM_ML_DSA_SEED "seed"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MU
#define OSSL_SIGNATURE_PARAM_MU "mu"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING
#define OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING "message-encoding"
#endif
#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif
#ifndef OSSL_SIGNATURE_PARAM_TEST_ENTROPY
#define OSSL_SIGNATURE_PARAM_TEST_ENTROPY "test-entropy"
#endif

/* EVP_MD-ML-DSA-MU parameters: OpenSSL 4.0+. Only the tests use these -- the
 * provider computes mu itself so it works on 3.5 too -- but they are named here
 * so the test code compiles against older headers. */
#ifndef OSSL_DIGEST_PARAM_MU_PUB_KEY
#define OSSL_DIGEST_PARAM_MU_PUB_KEY "pub"
#endif
#ifndef OSSL_DIGEST_PARAM_MU_CONTEXT_STRING
#define OSSL_DIGEST_PARAM_MU_CONTEXT_STRING "context-string"
#endif

/* Present since 3.0 but spelled inconsistently across minors in some distros. */
/* 3.2+, where EdDSA instance selection arrived. It picks between Ed25519,
 * Ed25519ctx and Ed25519ph, which are different algorithms producing different
 * signatures. KMS only does the pure variant, so anything else is refused --
 * and the refusal has to compile on 3.0, where the macro does not exist, or the
 * 3.0 floor is a claim rather than a fact. */
#ifndef OSSL_SIGNATURE_PARAM_INSTANCE
#define OSSL_SIGNATURE_PARAM_INSTANCE "instance"
#endif

#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

/*
 * -fvisibility=hidden hides OSSL_provider_init too, and a linker export list
 * cannot bring back a symbol the compiler made local -- the module then loads
 * as "not a provider". Every exported entry point must carry this explicitly.
 */
#if defined(_WIN32)
#define AWSKMS_EXPORT __declspec(dllexport)
#else
#define AWSKMS_EXPORT __attribute__((visibility("default")))
#endif

#endif /* AWSKMS_COMPAT_H */
