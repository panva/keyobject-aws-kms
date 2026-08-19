/*
 * A real libcrypto host for the provider-unload lifecycle.
 *
 * Unlike Node, this process owns the OSSL_PROVIDER handle, so it can release all
 * STORE, key, and signature state and then call OSSL_PROVIDER_unload() while the
 * process and its library context remain alive. The provider module still links
 * no libcrypto; only this ordinary test executable links OpenSSL::Crypto.
 */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *what) {
  fprintf(stderr, "provider-unload: %s\n", what);
  ERR_print_errors_fp(stderr);
  return 1;
}

static EVP_PKEY *load_key(OSSL_LIB_CTX *libctx, const char *uri) {
  OSSL_STORE_CTX *store = NULL;
  OSSL_STORE_INFO *info = NULL;
  EVP_PKEY *key = NULL;

  store = OSSL_STORE_open_ex(uri, libctx, "provider=aws-kms", NULL, NULL, NULL,
                             NULL, NULL);
  if (store == NULL || OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY) != 1)
    goto out;

  while (!OSSL_STORE_eof(store) && (info = OSSL_STORE_load(store)) != NULL) {
    if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
      key = OSSL_STORE_INFO_get1_PKEY(info);
      OSSL_STORE_INFO_free(info);
      info = NULL;
      break;
    }
    OSSL_STORE_INFO_free(info);
    info = NULL;
  }

out:
  OSSL_STORE_INFO_free(info);
  OSSL_STORE_close(store);
  return key;
}

static int sign_once(OSSL_LIB_CTX *libctx, EVP_PKEY *key) {
  static const unsigned char message[] = "provider unload lifecycle";
  EVP_MD_CTX *ctx = NULL;
  unsigned char *signature = NULL;
  size_t signature_len = 0;
  int ok = 0;

  if ((ctx = EVP_MD_CTX_new()) == NULL) goto out;
  if (EVP_DigestSignInit_ex(ctx, NULL, "SHA256", libctx, NULL, key, NULL) !=
          1 ||
      EVP_DigestSign(ctx, NULL, &signature_len, message, sizeof(message) - 1) !=
          1 ||
      signature_len == 0 ||
      (signature = OPENSSL_malloc(signature_len)) == NULL ||
      EVP_DigestSign(ctx, signature, &signature_len, message,
                     sizeof(message) - 1) != 1 ||
      signature_len == 0)
    goto out;
  ok = 1;

out:
  OPENSSL_free(signature);
  EVP_MD_CTX_free(ctx);
  return ok;
}

static int ordinary_crypto_survives(OSSL_LIB_CTX *libctx) {
  static const unsigned char message[] = "ordinary crypto after unload";
  static const unsigned char expected_sha256[] = {
      0x5c, 0x07, 0xe7, 0xca, 0xd1, 0x85, 0xb9, 0xad, 0xd6, 0xc3, 0x7e,
      0x7d, 0x0c, 0x9a, 0x84, 0x48, 0x97, 0xc0, 0xfe, 0x17, 0x44, 0x91,
      0x5d, 0xa4, 0x1f, 0x33, 0x35, 0x69, 0x9e, 0xd0, 0xb2, 0x77,
  };
  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t digest_len = 0;
  EVP_PKEY *key = NULL;
  int ok = 0;

  if (EVP_Q_digest(libctx, "SHA256", NULL, message, sizeof(message) - 1, digest,
                   &digest_len) != 1 ||
      digest_len != sizeof(expected_sha256) ||
      memcmp(digest, expected_sha256, sizeof(expected_sha256)) != 0)
    goto out;
  key = EVP_PKEY_Q_keygen(libctx, NULL, "ED25519");
  if (key == NULL || EVP_PKEY_get_bits(key) != 256) goto out;
  ok = 1;

out:
  EVP_PKEY_free(key);
  return ok;
}

int main(int argc, char **argv) {
  OSSL_LIB_CTX *libctx = NULL;
  OSSL_PROVIDER *default_provider = NULL;
  OSSL_PROVIDER *awskms_provider = NULL;
  EVP_PKEY *key = NULL;
  int status = 1;

  if (argc != 3) {
    fprintf(stderr, "usage: %s MODULE-DIRECTORY AWS-KMS-URI\n", argv[0]);
    return 2;
  }

  if ((libctx = OSSL_LIB_CTX_new()) == NULL)
    return fail("could not allocate a library context");
  if (OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) != 1) {
    fail("could not set the provider search path");
    goto out;
  }
  if ((default_provider = OSSL_PROVIDER_load(libctx, "default")) == NULL) {
    fail("could not load the default provider");
    goto out;
  }
  if ((awskms_provider = OSSL_PROVIDER_load(libctx, "aws-kms")) == NULL) {
    fail("could not load the AWS KMS provider");
    goto out;
  }
  puts("PROVIDER_LOADED");
  fflush(stdout);
  if (EVP_set_default_properties(libctx, "?keyobject.aws_kms!=yes") != 1) {
    fail("could not set ordinary-algorithm defaults");
    goto out;
  }

  if ((key = load_key(libctx, argv[2])) == NULL) {
    fail("could not load the AWS KMS key");
    goto out;
  }
  puts("KEY_LOADED");
  fflush(stdout);
  if (!sign_once(libctx, key)) {
    fail("AWS KMS signing failed");
    goto out;
  }
  EVP_PKEY_free(key);
  key = NULL;
  ERR_clear_error();
  puts("AWS_CLIENT_CREATED");
  fflush(stdout);

  if (OSSL_PROVIDER_unload(awskms_provider) != 1) {
    fail("OSSL_PROVIDER_unload failed");
    goto out;
  }
  awskms_provider = NULL;
  puts("PROVIDER_UNLOADED");
  fflush(stdout);
  if (OSSL_PROVIDER_available(libctx, "aws-kms") != 0) {
    fail("AWS KMS provider remained active after unload");
    goto out;
  }
  if (!ordinary_crypto_survives(libctx)) {
    fail("ordinary crypto failed after provider unload");
    goto out;
  }

  puts("ORDINARY_CRYPTO_OK");
  status = 0;

out:
  EVP_PKEY_free(key);
  if (awskms_provider != NULL) OSSL_PROVIDER_unload(awskms_provider);
  if (default_provider != NULL) OSSL_PROVIDER_unload(default_provider);
  OSSL_LIB_CTX_free(libctx);
  return status;
}
