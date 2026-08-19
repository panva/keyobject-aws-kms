/*
 * OSSL_OP_SIGNATURE.
 *
 * Signing goes to KMS; verifying never does. Verification runs locally against
 * the public key cached at load time, which costs nothing, works offline, and
 * means no kms:Verify permission is needed.
 *
 * Two shapes, because KMS has two:
 *
 *  - Prehashable (RSA, ECDSA) -> MessageType=DIGEST. Implemented here.
 *    Provides BOTH the prehashed sign/verify pair and digest_sign_init/update/
 *    final. Both are required: the streaming path (createSign().sign() in Node)
 *    reaches EVP_PKEY_sign with a digest and has no EVP_DigestSign path at all,
 *    while one-shot signing and all of WebCrypto go through EVP_DigestSignInit,
 *    which hard-fails if digest_sign_init is absent. They converge on one helper,
 *    so there is exactly one wire shape and one KMS call per signature.
 *
 *  - One-shot (Ed25519, ML-DSA) -> RAW / EXTERNAL_MU. Added separately.
 *
 * The size-probe rule: a NULL `sig` means "how big will it be?", and four separate
 * Node code paths ask. It never reaches KMS, since a KMS request costs money.
 */
#include <errno.h>
#include <limits.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>

#include "err.h"
#include "key.h"
#include "kms.h"
#include "provider.h"

typedef struct awskms_sig_ctx_st {
  AWSKMS_PROV_CTX *provctx;
  AWSKMS_KEY *key; /* reference held */
  /* A caller may select this operation with fips=yes independently of the
   * property query used to load the key. Retain only that policy bit: passing
   * the signature query verbatim to digest or SHAKE fetches would wrongly ask
   * those operations for provider=aws-kms. */
  int fips_required;
  /* When the operation asks for FIPS after the immutable key was loaded
   * without it, this view is reparsed from the retained SPKI with fips=yes.
   * Keeping it on the operation context avoids mutating or racing the shared
   * key while ensuring size, verification, and ML-DSA tr all have FIPS
   * provenance. */
  AWSKMS_PUBKEY fips_pub;

  /* The digest the caller selected, and the fetched MD for the streaming path. */
  AWSKMS_DIGEST digest;
  EVP_MD *md;
  EVP_MD_CTX *mdctx;

  /* RSA only. Defaults match OpenSSL: PKCS#1 v1.5, and a salt length of
   * "whatever the digest is". */
  int pad_mode;
  int pss_saltlen;

  /* OSSL_SIGNATURE_PARAM_CONTEXT_STRING. Node exposes this as options.context
   * and caps it at 255 bytes, which is also FIPS 204's limit.
   *
   * Only ML-DSA can honour it, and only because we compute mu ourselves -- the
   * context is folded into mu before KMS ever sees anything. Every other family
   * must reject a non-empty one rather than sign without it, which would produce
   * a signature no context-aware verifier accepts. */
  unsigned char context[255];
  size_t context_len;
  int has_context;

  /* OSSL_SIGNATURE_PARAM_INSTANCE. OpenSSL's EdDSA uses this to select between
   * Ed25519, Ed25519ctx and Ed25519ph (and Ed448/Ed448ph), which are different
   * algorithms producing different signatures.
   *
   * AWS KMS only does the pure variant: ED25519_SHA_512 with MessageType=RAW is
   * PureEdDSA, and the Sign API has no context or prehash parameter. So anything
   * other than the pure instance has to be refused -- signing pure when
   * Ed25519ctx was asked for would produce a signature the caller's verifier
   * rejects, with no error to explain why. */
  char instance[32];
  int has_instance;
} AWSKMS_SIG_CTX;

/* Defined with the one-shot code, but needed by the prehashed path too. */
static int unsupported_params_refused(AWSKMS_SIG_CTX *ctx);

/* ------------------------------------------------------------------ lifecycle */

static void *awskms_sig_newctx(void *provctx, const char *propq) {
  AWSKMS_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

  if (ctx == NULL) return NULL;
  ctx->provctx = provctx;
  ctx->pad_mode = RSA_PKCS1_PADDING;
  ctx->pss_saltlen = RSA_PSS_SALTLEN_DIGEST;
  if (ctx->provctx != NULL)
    ctx->fips_required = awskms_fips_requested(ctx->provctx->libctx, propq);
  return ctx;
}

static void awskms_sig_freectx(void *vctx) {
  AWSKMS_SIG_CTX *ctx = vctx;

  if (ctx == NULL) return;
  EVP_MD_CTX_free(ctx->mdctx);
  EVP_MD_free(ctx->md);
  awskms_pubkey_cleanup(&ctx->fips_pub);
  awskms_key_free(ctx->key);
  OPENSSL_free(ctx);
}

static void *awskms_sig_dupctx(void *vctx) {
  AWSKMS_SIG_CTX *src = vctx, *dst;

  if (src == NULL) return NULL;
  if ((dst = OPENSSL_zalloc(sizeof(*dst))) == NULL) return NULL;

  dst->provctx = src->provctx;
  dst->fips_required = src->fips_required;
  dst->digest = src->digest;
  dst->pad_mode = src->pad_mode;
  dst->pss_saltlen = src->pss_saltlen;
  dst->has_context = src->has_context;
  dst->context_len = src->context_len;
  memcpy(dst->context, src->context, src->context_len);
  dst->has_instance = src->has_instance;
  memcpy(dst->instance, src->instance, sizeof(dst->instance));

  if (src->key != NULL) {
    if (!awskms_key_up_ref(src->key)) goto err;
    dst->key = src->key;
  }
  if (src->fips_pub.pkey != NULL &&
      !awskms_pubkey_dup(&dst->fips_pub, &src->fips_pub))
    goto err;
  if (src->md != NULL) {
    if (!EVP_MD_up_ref(src->md)) goto err;
    dst->md = src->md;
  }
  /* EVP_DigestSignFinal duplicates the context before finalising so the caller
   * can keep signing, so the accumulated hash state has to come along. */
  if (src->mdctx != NULL) {
    if ((dst->mdctx = EVP_MD_CTX_new()) == NULL ||
        EVP_MD_CTX_copy_ex(dst->mdctx, src->mdctx) != 1)
      goto err;
  }
  return dst;

err:
  awskms_sig_freectx(dst);
  return NULL;
}

/* --------------------------------------------------------------------- params */

/*
 * KMS fixes the PSS salt length at the digest length and offers no way to change
 * it, so the policy is: accept anything that means "no particular requirement",
 * reject anything that explicitly demands something else. Silently signing with a
 * different salt length than was asked for would be worse than failing.
 *
 * Note Node's default for createSign(md).sign({padding: PSS}) is
 * RSA_PSS_SALTLEN_MAX_SIGN, which is the same value as _AUTO -- so rejecting
 * "auto" would break the most idiomatic PSS call in Node.
 */
static int saltlen_is_satisfiable(const AWSKMS_SIG_CTX *ctx,
                                  size_t digest_len) {
  switch (ctx->pss_saltlen) {
    case RSA_PSS_SALTLEN_DIGEST: /* -1, exactly what KMS does */
    case RSA_PSS_SALTLEN_AUTO:   /* -2, "no requirement" (== MAX_SIGN) */
      return 1;
    case RSA_PSS_SALTLEN_MAX: /* -3, an explicit demand KMS cannot meet */
      return 0;
    default:
      if (ctx->pss_saltlen < 0) return 0; /* incl. -4 auto-digest-max */
      return (size_t)ctx->pss_saltlen == digest_len;
  }
}

/* The salt length KMS will actually use, for local verification. */
static int effective_saltlen(const AWSKMS_SIG_CTX *ctx) {
  return RSA_PSS_SALTLEN_DIGEST;
}

static int operation_requires_fips(const AWSKMS_SIG_CTX *ctx) {
  return ctx->fips_required || (ctx->key != NULL && ctx->key->fips_required);
}

static const AWSKMS_PUBKEY *operation_pubkey(const AWSKMS_SIG_CTX *ctx) {
  if (ctx == NULL || ctx->key == NULL) return NULL;
  if (ctx->fips_required && !ctx->key->fips_required)
    return ctx->fips_pub.pkey != NULL ? &ctx->fips_pub : NULL;
  return &ctx->key->pub;
}

/* OSSL_PARAM UTF-8 data_size excludes the terminator. Copy through the public
 * getter into a bounded C string, and reject embedded NULs rather than letting
 * a later strcmp() inspect only a prefix. */
static int get_utf8_param(const OSSL_PARAM *p, char *out, size_t out_size) {
  char *outp = out;

  if (p->data_type != OSSL_PARAM_UTF8_STRING || p->data == NULL ||
      p->data_size >= out_size || memchr(p->data, '\0', p->data_size) != NULL)
    return 0;
  if (!OSSL_PARAM_get_utf8_string(p, &outp, out_size)) return 0;
  return strlen(out) == p->data_size;
}

static int parse_decimal_int(const char *value, int *out) {
  const char *p = value;
  char *end = NULL;
  long parsed;

  if (*p == '+' || *p == '-') p++;
  if (*p == '\0') return 0;
  for (; *p != '\0'; p++)
    if (*p < '0' || *p > '9') return 0;

  errno = 0;
  parsed = strtol(value, &end, 10);
  if (errno == ERANGE || end == value || *end != '\0' || parsed < INT_MIN ||
      parsed > INT_MAX)
    return 0;
  *out = (int)parsed;
  return 1;
}

static int set_digest(AWSKMS_SIG_CTX *ctx, const char *mdname) {
  EVP_MD *md;

  if (mdname == NULL || mdname[0] == '\0') {
    EVP_MD_free(ctx->md);
    ctx->md = NULL;
    ctx->digest = AWSKMS_DIGEST_NONE;
    return 1;
  }

  /* Excluding ourselves is not decoration: we have no digests, and a
   * self-referential fetch inside a signature operation is a bug worth making
   * impossible. */
  md = EVP_MD_fetch(ctx->provctx->libctx, mdname,
                    awskms_dependency_propq(operation_requires_fips(ctx)));
  if (md == NULL) {
    AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_DIGEST,
                 "digest \"%s\" is not available", mdname);
    return 0;
  }

  /* An XOF (SHAKE128/256) has no fixed-length output, so EVP_DigestFinal_ex()
   * cannot produce one and the prehash path is meaningless; KMS offers no
   * XOF-based signing algorithm in any case. Rejecting it here names the digest,
   * whereas letting it through makes finalisation fail later with nothing but
   * libcrypto's generic "provider signature failure".
   *
   * EVP_MD_get_flags() rather than EVP_MD_xof(), which is 3.4+ and would be an
   * unresolvable symbol on a 3.0 host. */
  if ((EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) != 0) {
    AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_DIGEST,
                 "digest \"%s\" is an XOF; AWS KMS signs over fixed-length "
                 "digests only",
                 mdname);
    EVP_MD_free(md);
    return 0;
  }

  EVP_MD_free(ctx->md);
  ctx->md = md;
  ctx->digest = awskms_digest_of(md);
  return 1;
}

static int awskms_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
  AWSKMS_SIG_CTX *ctx = vctx;
  const OSSL_PARAM *p;

  if (ctx == NULL) return 0;
  if (params == NULL) return 1;

  if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST)) !=
      NULL) {
    char name[64] = {0};
    if (!get_utf8_param(p, name, sizeof(name))) return 0;
    if (!set_digest(ctx, name)) return 0;
  }

  /* Node always sends the INTEGER form, via EVP_PKEY_CTX_set_rsa_padding().
   * The string form is accepted as hardening: OpenSSL defines both encodings for
   * this parameter, and mis-parsing a padding mode would mean signing with the
   * wrong one. Cheap insurance against a caller, or a future Node, using it. */
  if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE)) !=
      NULL) {
    int pad = 0;
    if (p->data_type == OSSL_PARAM_INTEGER) {
      if (!OSSL_PARAM_get_int(p, &pad)) return 0;
    } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
      char value[32];

      if (!get_utf8_param(p, value, sizeof(value))) return 0;
      if (strcmp(value, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
        pad = RSA_PKCS1_PADDING;
      else if (strcmp(value, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
        pad = RSA_PKCS1_PSS_PADDING;
      else
        pad = -1;
    } else {
      return 0;
    }

    if (pad != RSA_PKCS1_PADDING && pad != RSA_PKCS1_PSS_PADDING) {
      AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_PADDING,
                   "AWS KMS signs with PKCS#1 v1.5 or PSS only");
      return 0;
    }
    ctx->pad_mode = pad;
  }

  /* From Node this always arrives as a UTF-8 string: ctrl_params_translate spells
   * the sentinels "digest", "max" and "auto", and anything else as a decimal. The
   * integer form is accepted as hardening, for the same reason as pad-mode above --
   * silently misreading a salt length is exactly the failure this provider must
   * not have. */
  if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN)) !=
      NULL) {
    if (p->data_type == OSSL_PARAM_INTEGER) {
      if (!OSSL_PARAM_get_int(p, &ctx->pss_saltlen)) return 0;
    } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
      char s[32];

      if (!get_utf8_param(p, s, sizeof(s))) return 0;
      if (strcmp(s, "digest") == 0)
        ctx->pss_saltlen = RSA_PSS_SALTLEN_DIGEST;
      else if (strcmp(s, "auto") == 0)
        ctx->pss_saltlen = RSA_PSS_SALTLEN_AUTO;
      else if (strcmp(s, "max") == 0)
        ctx->pss_saltlen = RSA_PSS_SALTLEN_MAX;
      else if (!parse_decimal_int(s, &ctx->pss_saltlen))
        return 0;
    } else {
      return 0;
    }
  }

  /*
   * The context string. Recorded here for every family; whether it can actually
   * be honoured is decided at sign time, because only ML-DSA can.
   *
   * The 255-byte cap is FIPS 204's (and OpenSSL's, and Node's, which rejects
   * longer ones with ERR_OUT_OF_RANGE before they reach us). AWS KMS has no
   * context parameter at all, so it contributes no limit of its own -- the
   * context only ever affects the mu we compute locally, and mu is 64 bytes
   * however long the context is.
   */
  if ((p = OSSL_PARAM_locate_const(
           params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING)) != NULL) {
    const void *data = NULL;
    size_t len = 0;

    if (!OSSL_PARAM_get_octet_string_ptr(p, &data, &len)) return 0;
    if (len > sizeof(ctx->context)) {
      AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_PARAMETER,
                   "a context string may be at most %zu bytes, got %zu",
                   sizeof(ctx->context), len);
      return 0;
    }
    if (len != 0) memcpy(ctx->context, data, len);
    ctx->context_len = len;
    ctx->has_context = 1;
  }

  /*
   * The EdDSA instance. Node sets this to "Ed25519ctx" whenever a context string
   * is given (ncrypto's signInitWithContext), because OpenSSL otherwise ignores
   * the context silently. Recorded here and judged at sign time, alongside the
   * context, so the refusal is direct rather than a side effect of also seeing a
   * context string.
   */
  if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_INSTANCE)) !=
      NULL) {
    if (!get_utf8_param(p, ctx->instance, sizeof(ctx->instance))) {
      AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_PARAMETER,
                   "unrecognised signature instance");
      return 0;
    }
    ctx->has_instance = 1;
  }

  /* KMS uses MGF1 with the signature digest and offers no choice. OpenSSL's
   * default is the same, so this only fires if somebody asked for something
   * else -- in which case failing is the honest answer. */
  if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST)) !=
      NULL) {
    char name[64];

    if (!get_utf8_param(p, name, sizeof(name))) return 0;
    if (ctx->md == NULL || EVP_MD_is_a(ctx->md, name) != 1) {
      AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_PARAMETER,
                   "AWS KMS always uses MGF1 with the signature digest; \"%s\" "
                   "cannot be honoured",
                   name);
      return 0;
    }
  }

  return 1;
}

static const OSSL_PARAM *awskms_sig_settable_rsa(void *vctx, void *provctx) {
  static const OSSL_PARAM settable[] = {
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
      OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
      OSSL_PARAM_END};
  return settable;
}

static const OSSL_PARAM *awskms_sig_settable_ecdsa(void *vctx, void *provctx) {
  static const OSSL_PARAM settable[] = {
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
      OSSL_PARAM_END};
  return settable;
}

static int awskms_sig_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
  AWSKMS_SIG_CTX *ctx = vctx;
  OSSL_PARAM *p;

  if (ctx == NULL) return 0;

  if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL &&
      !OSSL_PARAM_set_utf8_string(
          p, ctx->md != NULL ? EVP_MD_get0_name(ctx->md) : ""))
    return 0;
  if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE)) != NULL &&
      !OSSL_PARAM_set_int(p, ctx->pad_mode))
    return 0;
  if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN)) !=
          NULL &&
      !OSSL_PARAM_set_int(p, ctx->pss_saltlen))
    return 0;
  return 1;
}

static const OSSL_PARAM *awskms_sig_gettable(void *vctx, void *provctx) {
  static const OSSL_PARAM gettable[] = {
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
      OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL),
      OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL), OSSL_PARAM_END};
  return gettable;
}

/* ------------------------------------------------------------------ init/sign */

static int bind_key(AWSKMS_SIG_CTX *ctx, void *provkey) {
  AWSKMS_KEY *key = provkey;
  AWSKMS_PUBKEY fips_pub = {0};

  if (key == NULL) return ctx->key != NULL; /* re-init keeps the current key */
  if (!awskms_key_up_ref(key)) return 0;

  if (ctx->fips_required && !key->fips_required) {
    if (key->pub.der == NULL || key->pub.der_len == 0) {
      AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_INTERNAL_ERROR,
                   "the retained SubjectPublicKeyInfo for %s is unavailable",
                   awskms_key_spec(key)->kms_key_spec);
      goto err;
    }
    if (!awskms_pubkey_from_spki(&fips_pub, key->pub.der, key->pub.der_len,
                                 awskms_key_spec(key)->kms_key_spec,
                                 ctx->provctx->libctx, 1, ctx->provctx->handle))
      goto err;
  }

  awskms_pubkey_cleanup(&ctx->fips_pub);
  awskms_key_free(ctx->key);
  ctx->key = key;
  ctx->fips_pub = fips_pub;
  return 1;

err:
  awskms_pubkey_cleanup(&fips_pub);
  awskms_key_free(key);
  return 0;
}

static size_t max_sig_size(const AWSKMS_SIG_CTX *ctx) {
  const AWSKMS_PUBKEY *pub = operation_pubkey(ctx);
  int size = pub != NULL ? EVP_PKEY_get_size(pub->pkey) : 0;
  return size > 0 ? (size_t)size : 0;
}

static size_t required_sig_size(const AWSKMS_SIG_CTX *ctx) {
  const AWSKMS_KEYSPEC *spec = awskms_key_spec(ctx->key);

  return spec->sig_len != 0 ? spec->sig_len : max_sig_size(ctx);
}

static int output_buffer_fits(AWSKMS_SIG_CTX *ctx, size_t *siglen,
                              size_t sigsize) {
  size_t required = required_sig_size(ctx);

  if (siglen == NULL || required == 0) return 0;
  if (sigsize >= required) return 1;
  *siglen = required;
  AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_OUTPUT_BUFFER_TOO_SMALL,
               "signature output buffer is %zu bytes, need at least %zu",
               sigsize, required);
  return 0;
}

static int awskms_sig_sign_init(void *vctx, void *provkey,
                                const OSSL_PARAM params[]) {
  AWSKMS_SIG_CTX *ctx = vctx;

  if (ctx == NULL || !bind_key(ctx, provkey)) return 0;
  return awskms_sig_set_ctx_params(ctx, params);
}

static int awskms_sig_verify_init(void *vctx, void *provkey,
                                  const OSSL_PARAM params[]) {
  return awskms_sig_sign_init(vctx, provkey, params);
}

/*
 * The single place a signature is produced. Everything -- the prehashed path and
 * the digest_sign path -- funnels through here, so there is one wire shape and
 * one KMS request per signature.
 */
static int sign_digest(AWSKMS_SIG_CTX *ctx, unsigned char *sig, size_t *siglen,
                       size_t sigsize, const unsigned char *digest,
                       size_t digest_len) {
  const AWSKMS_KEYSPEC *spec = awskms_key_spec(ctx->key);
  const char *algorithm;
  size_t expected;

  /* The size probe. Four Node code paths do this, and it must never become a
   * billable request. */
  if (sig == NULL) {
    if (siglen == NULL) return 0;
    *siglen = required_sig_size(ctx);
    return *siglen != 0;
  }
  if (!output_buffer_fits(ctx, siglen, sigsize)) return 0;

  if (ctx->digest == AWSKMS_DIGEST_NONE) {
    AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_DIGEST,
                 "%s signing requires a digest", spec->kms_key_spec);
    return 0;
  }

  if (!unsupported_params_refused(ctx)) return 0;

  /* Whether KMS can sign with this digest at all is checked before its length.
   * The reverse order misdiagnoses an unsupported digest as a length mismatch:
   * SHA-1 is a real digest producing 20 bytes, but KMS has no algorithm for it, so
   * awskms_digest_length() reports 0 and "expected a 0-byte digest" conveys
   * nothing. Node surfaces only the reason string and never the detail text (see
   * err.h), so the reason code is the entire diagnosis a caller receives. */
  algorithm =
      awskms_signing_algorithm(spec, ctx->digest,
                               spec->family == AWSKMS_FAMILY_RSA &&
                                   ctx->pad_mode == RSA_PKCS1_PSS_PADDING);
  if (algorithm == NULL) {
    AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_DIGEST,
                 "AWS KMS cannot sign with %s using digest \"%s\"",
                 spec->kms_key_spec,
                 ctx->md != NULL ? EVP_MD_get0_name(ctx->md) : "(none)");
    return 0;
  }

  expected = awskms_digest_length(ctx->digest);
  if (digest_len != expected) {
    /* Catches a caller handing us a message instead of a digest, which KMS would
     * otherwise reject with something much less clear. */
    AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_DIGEST_LENGTH_MISMATCH,
                 "expected a %zu-byte digest, got %zu bytes", expected,
                 digest_len);
    return 0;
  }

  if (spec->family == AWSKMS_FAMILY_RSA &&
      ctx->pad_mode == RSA_PKCS1_PSS_PADDING &&
      !saltlen_is_satisfiable(ctx, expected)) {
    AWSKMS_raise(
        ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_SALT_LENGTH,
        "AWS KMS always uses a PSS salt length equal to the digest length "
        "(%zu bytes); the requested salt length cannot be honoured",
        expected);
    return 0;
  }

  return awskms_kms_sign(ctx->provctx, &ctx->key->uri,
                         operation_requires_fips(ctx), algorithm, "DIGEST",
                         digest, digest_len, sig, sigsize, siglen);
}

static int awskms_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                           size_t sigsize, const unsigned char *tbs,
                           size_t tbslen) {
  AWSKMS_SIG_CTX *ctx = vctx;

  if (ctx == NULL || ctx->key == NULL) return 0;
  return sign_digest(ctx, sig, siglen, sigsize, tbs, tbslen);
}

/* ---------------------------------------------------------------- local verify */

/*
 * Verification is local, against the public key parsed from GetPublicKey at load
 * time. No network, no kms:Verify permission, no cost.
 *
 * Returns 0 (not -1) for a signature that simply does not match, which is what
 * the default provider does and what stops Node from turning a false into a throw.
 */
static int awskms_sig_verify(void *vctx, const unsigned char *sig,
                             size_t siglen, const unsigned char *tbs,
                             size_t tbslen) {
  AWSKMS_SIG_CTX *ctx = vctx;
  const AWSKMS_PUBKEY *pub;
  EVP_PKEY_CTX *pctx = NULL;
  int ret = 0;

  if (ctx == NULL || ctx->key == NULL) return 0;
  if ((pub = operation_pubkey(ctx)) == NULL) return 0;

  pctx = EVP_PKEY_CTX_new_from_pkey(
      ctx->provctx->libctx, pub->pkey,
      awskms_dependency_propq(operation_requires_fips(ctx)));
  if (pctx == NULL) return 0;

  if (EVP_PKEY_verify_init(pctx) <= 0) goto out;

  if (awskms_key_spec(ctx->key)->family == AWSKMS_FAMILY_RSA) {
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, ctx->pad_mode) <= 0) goto out;
    if (ctx->pad_mode == RSA_PKCS1_PSS_PADDING &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, effective_saltlen(ctx)) <= 0)
      goto out;
  }
  if (ctx->md != NULL && EVP_PKEY_CTX_set_signature_md(pctx, ctx->md) <= 0)
    goto out;

  /* A mismatch is a result, not an error, so the queue is left clean. */
  ret = EVP_PKEY_verify(pctx, sig, siglen, tbs, tbslen) == 1 ? 1 : 0;

out:
  EVP_PKEY_CTX_free(pctx);
  return ret;
}

/* ------------------------------------------------------- digest sign / verify */

static int awskms_sig_digest_sign_init(void *vctx, const char *mdname,
                                       void *provkey,
                                       const OSSL_PARAM params[]) {
  AWSKMS_SIG_CTX *ctx = vctx;

  if (ctx == NULL || !bind_key(ctx, provkey)) return 0;
  if (!awskms_sig_set_ctx_params(ctx, params)) return 0;

  /* params may already have set the digest; an explicit mdname wins. */
  if (mdname != NULL && mdname[0] != '\0' && !set_digest(ctx, mdname)) return 0;
  if (ctx->md == NULL) {
    AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_DIGEST,
                 "%s signing requires a digest",
                 awskms_key_spec(ctx->key)->kms_key_spec);
    return 0;
  }

  EVP_MD_CTX_free(ctx->mdctx);
  if ((ctx->mdctx = EVP_MD_CTX_new()) == NULL) return 0;
  return EVP_DigestInit_ex2(ctx->mdctx, ctx->md, NULL) == 1;
}

static int awskms_sig_digest_sign_update(void *vctx, const unsigned char *data,
                                         size_t datalen) {
  AWSKMS_SIG_CTX *ctx = vctx;

  if (ctx == NULL || ctx->mdctx == NULL) return 0;
  return EVP_DigestUpdate(ctx->mdctx, data, datalen) == 1;
}

static int awskms_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                        size_t *siglen, size_t sigsize) {
  AWSKMS_SIG_CTX *ctx = vctx;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;

  if (ctx == NULL || ctx->mdctx == NULL || ctx->key == NULL) return 0;

  /* The size probe again -- and here it must also not finalise the digest, or a
   * caller that probes and then signs would hash nothing. */
  if (sig == NULL) {
    if (siglen == NULL) return 0;
    *siglen = required_sig_size(ctx);
    return *siglen != 0;
  }
  if (!output_buffer_fits(ctx, siglen, sigsize)) return 0;

  if (EVP_DigestFinal_ex(ctx->mdctx, digest, &digest_len) != 1) return 0;
  return sign_digest(ctx, sig, siglen, sigsize, digest, digest_len);
}

static int awskms_sig_digest_verify_init(void *vctx, const char *mdname,
                                         void *provkey,
                                         const OSSL_PARAM params[]) {
  return awskms_sig_digest_sign_init(vctx, mdname, provkey, params);
}

static int awskms_sig_digest_verify_update(void *vctx,
                                           const unsigned char *data,
                                           size_t datalen) {
  return awskms_sig_digest_sign_update(vctx, data, datalen);
}

static int awskms_sig_digest_verify_final(void *vctx, const unsigned char *sig,
                                          size_t siglen) {
  AWSKMS_SIG_CTX *ctx = vctx;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;

  if (ctx == NULL || ctx->mdctx == NULL) return 0;
  if (EVP_DigestFinal_ex(ctx->mdctx, digest, &digest_len) != 1) return 0;
  return awskms_sig_verify(ctx, sig, siglen, digest, digest_len);
}

/* ------------------------------------------------------- one-shot (no digest) */

/*
 * Ed25519 and ML-DSA sign the message itself; there is no digest to choose and no
 * meaningful streaming form, because both need the whole message before anything
 * can be computed. Node reaches them through EVP_DigestSignInit with a NULL md
 * followed by EVP_DigestSign, and has no prehashed fallback for them, so
 * digest_sign_init + digest_sign is exactly the required pair.
 */
static int awskms_sig_oneshot_init(void *vctx, const char *mdname,
                                   void *provkey, const OSSL_PARAM params[]) {
  AWSKMS_SIG_CTX *ctx = vctx;

  if (ctx == NULL || !bind_key(ctx, provkey)) return 0;
  if (!awskms_sig_set_ctx_params(ctx, params)) return 0;

  /* Reject a supplied digest rather than ignoring it. Otherwise
   * crypto.sign('sha256', msg, key) would silently produce a pure-EdDSA
   * signature over msg -- verifiable, but not what the caller asked for. */
  if (mdname != NULL && mdname[0] != '\0') {
    AWSKMS_raise(
        ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_DIGEST,
        "%s signs the message directly and takes no digest, but \"%s\" "
        "was requested",
        awskms_key_spec(ctx->key)->kms_key_spec, mdname);
    return 0;
  }
  ctx->digest = AWSKMS_DIGEST_NONE;

  /* Judged here as well as at sign time: the key is bound by now, so an
   * unsupported instance or context can fail at init rather than later. */
  return unsupported_params_refused(ctx);
}

/*
 * A non-empty context string can only be honoured where we compute what gets
 * signed, which is ML-DSA alone. Everywhere else KMS signs the message or digest
 * directly with no context, so signing anyway would silently produce something no
 * context-aware verifier accepts.
 *
 * An absent context and a zero-length one are the same thing: FIPS 204 encodes
 * the length either way, so |ctx| = 0 both times and mu is identical.
 */
static int unsupported_params_refused(AWSKMS_SIG_CTX *ctx) {
  const AWSKMS_KEYSPEC *spec = awskms_key_spec(ctx->key);

  /*
   * The instance, if one was named, must be the pure variant. For Ed25519 that
   * is "Ed25519": "Ed25519ctx" and "Ed25519ph" are distinct algorithms KMS does
   * not offer, and no other family we serve has an instance at all.
   *
   * Note KMS's ED25519_PH_SHA_512 is NOT Ed25519ph -- it re-applies SHA-512 to
   * an already-hashed input, so it is not interchangeable with it either.
   */
  if (ctx->has_instance && ctx->instance[0] != '\0') {
    const char *pure = spec->family == AWSKMS_FAMILY_ED25519 ? "Ed25519" : NULL;

    if (pure == NULL || OPENSSL_strcasecmp(ctx->instance, pure) != 0) {
      AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_PARAMETER,
                   "AWS KMS cannot sign %s as \"%s\"; it offers only the pure "
                   "variant, and its Sign API has no context or prehash "
                   "parameter",
                   spec->kms_key_spec, ctx->instance);
      return 0;
    }
  }

  if (ctx->context_len == 0) return 1;
  if (spec->family == AWSKMS_FAMILY_ML_DSA) return 1;

  /*
   * Verified against the KMS Sign API reference: the request has exactly KeyId,
   * Message, MessageType, SigningAlgorithm, DryRun and GrantTokens -- no context
   * parameter of any kind. So for everything except ML-DSA the context would
   * simply be dropped, and dropping it silently would produce a signature that
   * no context-aware verifier accepts.
   *
   * ML-DSA is the exception only because EXTERNAL_MU makes KMS "skip the
   * concatenated hashing of the public key hash and the message", leaving that
   * framing -- and therefore the context -- entirely to us.
   */
  AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_PARAMETER,
               "AWS KMS cannot sign %s with a context string: its Sign API has "
               "no context parameter, and only ML-DSA lets us fold one into mu "
               "locally",
               spec->kms_key_spec);
  return 0;
}

/* Delegates to awskms_mu(); see spki.h for why that lives there. Only the empty
 * context string is reachable from Node, which is also what makes the result
 * interchangeable with a KMS MessageType=RAW signature. */
static int compute_mu(AWSKMS_SIG_CTX *ctx, const unsigned char *msg,
                      size_t msg_len, unsigned char out[64]) {
  const AWSKMS_PUBKEY *pub = operation_pubkey(ctx);

  if (pub == NULL || !pub->have_tr) {
    AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_INTERNAL_ERROR,
                 "no cached tr for %s",
                 awskms_key_spec(ctx->key)->kms_key_spec);
    return 0;
  }
  return awskms_mu(ctx->provctx->libctx, operation_requires_fips(ctx), pub->tr,
                   ctx->context, ctx->context_len, msg, msg_len, out,
                   ctx->provctx->handle);
}

static int awskms_sig_oneshot_sign(void *vctx, unsigned char *sig,
                                   size_t *siglen, size_t sigsize,
                                   const unsigned char *tbs, size_t tbslen) {
  AWSKMS_SIG_CTX *ctx = vctx;
  const AWSKMS_KEYSPEC *spec;
  const char *algorithm;
  unsigned char mu[64];

  if (ctx == NULL || ctx->key == NULL) return 0;
  spec = awskms_key_spec(ctx->key);

  /* Size probe: no KMS request, and for these families the length is a constant. */
  if (sig == NULL) {
    if (siglen == NULL) return 0;
    *siglen = required_sig_size(ctx);
    return *siglen != 0;
  }
  if (!output_buffer_fits(ctx, siglen, sigsize)) return 0;

  if (!unsupported_params_refused(ctx)) return 0;

  algorithm = awskms_signing_algorithm(spec, AWSKMS_DIGEST_NONE, 0);
  if (algorithm == NULL) {
    AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_UNSUPPORTED_KEY_SPEC,
                 "no KMS signing algorithm for %s", spec->kms_key_spec);
    return 0;
  }

  switch (spec->msg_type) {
    case AWSKMS_MSG_RAW:
      /*
       * Ed25519 is the one place a Node API that works for every other key spec
       * will refuse: PureEdDSA needs the whole message, and KMS caps Message at
       * 4096 bytes. ED25519_PH_SHA_512 cannot help -- it requires
       * MessageType=DIGEST and KMS "still performs the SHA-512 prehash", so
       * feeding it SHA-512(M) signs SHA-512(SHA-512(M)), which no standard
       * verifier computes.
       *
       * Note ED25519_SHA_512 + RAW is PureEdDSA (FIPS 186-5 7.6), not
       * Ed25519ctx: KMS documents RAW as "the standard signing algorithm" and
       * its Sign API has no context parameter at all. That is why a context
       * string cannot be honoured here -- see context_is_honourable().
       */
      if (tbslen == 0) {
        /*
         * AWS's own documentation contradicts itself here: the prose says
         * "Messages can be 0-4096 bytes" while the Message blob's stated
         * constraint is "Minimum length of 1". Failing locally with a clear
         * error is preferred over sending a request that may come back as an
         * opaque ValidationException. If real-KMS testing shows 0 bytes is
         * accepted, this is a one-line change.
         */
        AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_EMPTY_MESSAGE,
                     "AWS KMS documents a minimum Message length of 1 byte, so "
                     "an empty message cannot be signed with %s",
                     spec->kms_key_spec);
        return 0;
      }
      if (tbslen > 4096) {
        AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_MESSAGE_TOO_LARGE,
                     "%s signing sends the whole message to AWS KMS, which "
                     "accepts at most 4096 bytes; got %zu",
                     spec->kms_key_spec, tbslen);
        return 0;
      }
      return awskms_kms_sign(ctx->provctx, &ctx->key->uri,
                             operation_requires_fips(ctx), algorithm, "RAW",
                             tbs, tbslen, sig, sigsize, siglen);

    case AWSKMS_MSG_EXTERNAL_MU:
      if (!compute_mu(ctx, tbs, tbslen, mu)) return 0;
      return awskms_kms_sign(
          ctx->provctx, &ctx->key->uri, operation_requires_fips(ctx), algorithm,
          "EXTERNAL_MU", mu, sizeof(mu), sig, sigsize, siglen);

    case AWSKMS_MSG_DIGEST:
      break; /* not a one-shot family */
  }

  AWSKMS_raise(ctx->provctx->handle, AWSKMS_R_INTERNAL_ERROR,
               "%s is not a one-shot signing key spec", spec->kms_key_spec);
  return 0;
}

/* Local, against the cached public key -- no KMS call, and no kms:Verify. */
static int awskms_sig_oneshot_verify(void *vctx, const unsigned char *sig,
                                     size_t siglen, const unsigned char *tbs,
                                     size_t tbslen) {
  AWSKMS_SIG_CTX *ctx = vctx;
  const AWSKMS_PUBKEY *pub;
  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;

  if (ctx == NULL || ctx->key == NULL) return 0;
  if ((pub = operation_pubkey(ctx)) == NULL) return 0;
  if ((mdctx = EVP_MD_CTX_new()) == NULL) return 0;

  {
    /* The context has to be handed to the verifier too, or a context-bound
     * ML-DSA signature would appear invalid. */
    OSSL_PARAM params[2];
    size_t n = 0;

    if (ctx->context_len != 0)
      params[n++] = OSSL_PARAM_construct_octet_string(
          OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx->context, ctx->context_len);
    params[n] = OSSL_PARAM_construct_end();

    /* A NULL md is what "pure" means for these algorithms. */
    if (EVP_DigestVerifyInit_ex(
            mdctx, NULL, NULL, ctx->provctx->libctx,
            awskms_dependency_propq(operation_requires_fips(ctx)), pub->pkey,
            n > 0 ? params : NULL) != 1)
      goto out;
  }

  /* A mismatch is a result, not an error. */
  ret = EVP_DigestVerify(mdctx, sig, siglen, tbs, tbslen) == 1 ? 1 : 0;

out:
  EVP_MD_CTX_free(mdctx);
  return ret;
}

static const OSSL_PARAM *awskms_sig_settable_oneshot(void *vctx,
                                                     void *provctx) {
  /* Only the context string, and only ML-DSA can actually honour it (see
   * context_is_honourable). Deterministic mode and test entropy are deliberately
   * absent: KMS signs with hedged randomness and exposes no way to change that,
   * so accepting them would be a lie. */
  static const OSSL_PARAM settable[] = {
      OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, NULL, 0),
      OSSL_PARAM_END};
  return settable;
}

/* ------------------------------------------------------------------- dispatch */

#define AWSKMS_SIG_COMMON                                                    \
  {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))awskms_sig_newctx},           \
      {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))awskms_sig_freectx},     \
      {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))awskms_sig_dupctx},       \
      {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))awskms_sig_sign_init}, \
      {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))awskms_sig_sign},           \
      {OSSL_FUNC_SIGNATURE_VERIFY_INIT,                                      \
       (void (*)(void))awskms_sig_verify_init},                              \
      {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))awskms_sig_verify},       \
      {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                                 \
       (void (*)(void))awskms_sig_digest_sign_init},                         \
      {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,                               \
       (void (*)(void))awskms_sig_digest_sign_update},                       \
      {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,                                \
       (void (*)(void))awskms_sig_digest_sign_final},                        \
      {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,                               \
       (void (*)(void))awskms_sig_digest_verify_init},                       \
      {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,                             \
       (void (*)(void))awskms_sig_digest_verify_update},                     \
      {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,                              \
       (void (*)(void))awskms_sig_digest_verify_final},                      \
      {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                                   \
       (void (*)(void))awskms_sig_get_ctx_params},                           \
      {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                              \
       (void (*)(void))awskms_sig_gettable},                                 \
  {                                                                          \
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                      \
        (void (*)(void))awskms_sig_set_ctx_params                            \
  }

/* get/set ctx-params are validated pairwise by evp_signature_from_algorithm, so
 * each table must carry its own settable partner. */
static const OSSL_DISPATCH awskms_sig_rsa[] = {
    AWSKMS_SIG_COMMON,
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
     (void (*)(void))awskms_sig_settable_rsa},
    {0, NULL}};

static const OSSL_DISPATCH awskms_sig_ecdsa[] = {
    AWSKMS_SIG_COMMON,
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
     (void (*)(void))awskms_sig_settable_ecdsa},
    {0, NULL}};

/*
 * The one-shot table. No sign_init/sign pair: those would have to mean "sign this
 * digest", which is meaningless here, and omitting both is legal (sign_init
 * without sign is not). No digest_sign_update/final either -- both absent is
 * legal, only one of them is not.
 */
static const OSSL_DISPATCH awskms_sig_oneshot[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))awskms_sig_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))awskms_sig_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))awskms_sig_dupctx},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
     (void (*)(void))awskms_sig_oneshot_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))awskms_sig_oneshot_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
     (void (*)(void))awskms_sig_oneshot_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
     (void (*)(void))awskms_sig_oneshot_verify},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
     (void (*)(void))awskms_sig_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
     (void (*)(void))awskms_sig_gettable},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
     (void (*)(void))awskms_sig_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
     (void (*)(void))awskms_sig_settable_oneshot},
    {0, NULL}};

static const OSSL_ALGORITHM awskms_signature_alg[] = {
    {"RSA", AWSKMS_PROPERTY_DEF, awskms_sig_rsa, "AWS KMS RSA"},
    /* EC keys resolve their signature operation through the keymgmt's
     * query_operation_name, which reports "ECDSA". */
    {"ECDSA", AWSKMS_PROPERTY_DEF, awskms_sig_ecdsa, "AWS KMS ECDSA"},
    {"ED25519", AWSKMS_PROPERTY_DEF, awskms_sig_oneshot, "AWS KMS Ed25519"},
    /* One row per parameter set, sharing a single implementation: libcrypto
     * resolves the signature by NAME, and the name is what tells us which key we
     * have. Registering these on a host older than OpenSSL 3.5 is harmless --
     * nothing can ever fetch them, because an ML-DSA key cannot be parsed there. */
    {"ML-DSA-44", AWSKMS_PROPERTY_DEF, awskms_sig_oneshot, "AWS KMS ML-DSA-44"},
    {"ML-DSA-65", AWSKMS_PROPERTY_DEF, awskms_sig_oneshot, "AWS KMS ML-DSA-65"},
    {"ML-DSA-87", AWSKMS_PROPERTY_DEF, awskms_sig_oneshot, "AWS KMS ML-DSA-87"},
    {NULL, NULL, NULL, NULL}};

const OSSL_ALGORITHM *awskms_signature_algorithms(void) {
  return awskms_signature_alg;
}
