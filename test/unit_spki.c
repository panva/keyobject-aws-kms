/*
 * Exercises the SPKI parser against real, locally generated keys, so the
 * KeySpec table and the parser are checked against what OpenSSL actually
 * produces rather than against hand-written fixtures.
 */
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdint.h>

#include "keyspec.h"
#include "spki.h"
#include "unit.h"

/* Generates a key of the shape a KMS key spec describes and returns its SPKI. */
static unsigned char *spki_for(const AWSKMS_KEYSPEC *spec, int *len,
                               EVP_PKEY **out_pkey) {
  EVP_PKEY *pkey = NULL;
  unsigned char *der = NULL;

  switch (spec->family) {
    case AWSKMS_FAMILY_RSA: {
      unsigned bits = 2048;
      if (strcmp(spec->kms_key_spec, "RSA_3072") == 0) bits = 3072;
      if (strcmp(spec->kms_key_spec, "RSA_4096") == 0) bits = 4096;
      pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)bits);
      break;
    }
    case AWSKMS_FAMILY_EC:
      pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", spec->group_name);
      break;
    case AWSKMS_FAMILY_ED25519:
      pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
      break;
    case AWSKMS_FAMILY_ML_DSA:
      /* Unavailable before OpenSSL 3.5; the caller treats NULL as "skip". */
      pkey = EVP_PKEY_Q_keygen(NULL, NULL, spec->keytype);
      break;
  }
  if (pkey == NULL) return NULL;

  *len = i2d_PUBKEY(pkey, &der);
  if (*len <= 0) {
    EVP_PKEY_free(pkey);
    return NULL;
  }
  *out_pkey = pkey;
  return der;
}

void test_spki(void) {
  int skipped = 0;

  for (const AWSKMS_KEYSPEC *spec = awskms_keyspec_all();
       spec->kms_key_spec != NULL; spec++) {
    AWSKMS_PUBKEY pub;
    EVP_PKEY *generated = NULL;
    unsigned char *der = NULL;
    int der_len = 0;

    der = spki_for(spec, &der_len, &generated);
    if (der == NULL) {
      /* ML-DSA needs OpenSSL 3.5+; anything else failing to generate is real. */
      if (spec->family == AWSKMS_FAMILY_ML_DSA) {
        skipped++;
        continue;
      }
      CHECK(0, "%s: could not generate a test key", spec->kms_key_spec);
      continue;
    }

    memset(&pub, 0, sizeof(pub));
    CHECK(awskms_pubkey_from_spki(&pub, der, (size_t)der_len,
                                  spec->kms_key_spec, NULL, 0, NULL) == 1,
          "%s: SPKI should parse", spec->kms_key_spec);

    if (pub.pkey != NULL) {
      CHECK(pub.spec == spec, "%s: wrong spec recorded", spec->kms_key_spec);
      CHECK(pub.der != der, "%s: retained DER must be an owned copy",
            spec->kms_key_spec);
      CHECK(pub.der_len == (size_t)der_len,
            "%s: retained DER is %zu bytes, expected %d", spec->kms_key_spec,
            pub.der_len, der_len);
      CHECK(pub.der != NULL && memcmp(pub.der, der, (size_t)der_len) == 0,
            "%s: retained DER bytes changed", spec->kms_key_spec);

      /* EVP_PKEY_size() backs OSSL_PKEY_PARAM_MAX_SIZE, which Node uses to size
       * the signature buffer -- if this is wrong, signatures get truncated. */
      if (spec->sig_len != 0) {
        CHECK((size_t)EVP_PKEY_get_size(pub.pkey) == spec->sig_len,
              "%s: EVP_PKEY_size is %d, spec says %zu", spec->kms_key_spec,
              EVP_PKEY_get_size(pub.pkey), spec->sig_len);
      }
      if (spec->pub_len != 0) {
        CHECK(pub.raw_len == spec->pub_len, "%s: raw pub is %zu, expected %zu",
              spec->kms_key_spec, pub.raw_len, spec->pub_len);
      }
      CHECK(pub.have_tr == (spec->family == AWSKMS_FAMILY_ML_DSA),
            "%s: tr should be cached only for ML-DSA", spec->kms_key_spec);
      /* tr must not be all zeroes -- that is what a silently failed XOF or a
       * wrong output length would look like. */
      if (pub.have_tr) {
        int nonzero = 0;
        for (size_t i = 0; i < sizeof(pub.tr); i++)
          if (pub.tr[i] != 0) nonzero = 1;
        CHECK(nonzero, "%s: tr is all zeroes", spec->kms_key_spec);
      }

      {
        AWSKMS_PUBKEY copy = {0};

        CHECK(awskms_pubkey_dup(&copy, &pub) == 1,
              "%s: public view duplication failed", spec->kms_key_spec);
        if (copy.pkey != NULL) {
          CHECK(copy.pkey == pub.pkey,
                "%s: duplicate should retain the immutable EVP_PKEY",
                spec->kms_key_spec);
          CHECK(copy.der != pub.der && copy.der_len == pub.der_len &&
                    memcmp(copy.der, pub.der, pub.der_len) == 0,
                "%s: duplicate must own an exact DER copy", spec->kms_key_spec);
          CHECK(copy.raw_len == pub.raw_len &&
                    (copy.raw_len == 0 ||
                     (copy.raw != pub.raw &&
                      memcmp(copy.raw, pub.raw, pub.raw_len) == 0)),
                "%s: duplicate must own an exact raw-key copy",
                spec->kms_key_spec);
          CHECK(copy.have_tr == pub.have_tr &&
                    memcmp(copy.tr, pub.tr, sizeof(copy.tr)) == 0,
                "%s: duplicate must retain ML-DSA tr", spec->kms_key_spec);
        }
        awskms_pubkey_cleanup(&copy);
      }
    }
    awskms_pubkey_cleanup(&pub);

    /* A spec/key-type mismatch must be caught, not guessed around. */
    {
      AWSKMS_PUBKEY bad;
      const char *other =
          spec->family == AWSKMS_FAMILY_RSA ? "ECC_NIST_P256" : "RSA_2048";
      memset(&bad, 0, sizeof(bad));
      CHECK(awskms_pubkey_from_spki(&bad, der, (size_t)der_len, other, NULL, 0,
                                    NULL) == 0,
            "%s: should not parse as %s", spec->kms_key_spec, other);
      awskms_pubkey_cleanup(&bad);
    }

    if (strcmp(spec->kms_key_spec, "RSA_2048") == 0) {
      AWSKMS_PUBKEY bad;
      unsigned char *with_trailing = OPENSSL_malloc((size_t)der_len + 1);

      memset(&bad, 0, sizeof(bad));
      CHECK(awskms_pubkey_from_spki(&bad, der, (size_t)der_len, "RSA_3072",
                                    NULL, 0, NULL) == 0,
            "an RSA_2048 SPKI must not satisfy RSA_3072");
      awskms_pubkey_cleanup(&bad);

      CHECK(with_trailing != NULL, "could not allocate trailing-DER fixture");
      if (with_trailing != NULL) {
        memcpy(with_trailing, der, (size_t)der_len);
        with_trailing[der_len] = 0;
        memset(&bad, 0, sizeof(bad));
        CHECK(awskms_pubkey_from_spki(&bad, with_trailing, (size_t)der_len + 1,
                                      "RSA_2048", NULL, 0, NULL) == 0,
              "trailing data after a valid SPKI must be rejected");
        awskms_pubkey_cleanup(&bad);
        OPENSSL_free(with_trailing);
      }
    }

    OPENSSL_free(der);
    EVP_PKEY_free(generated);
  }

  /* Unknown and malformed inputs. */
  {
    AWSKMS_PUBKEY pub;
    static const unsigned char junk[] = {0x30, 0x03, 0x02, 0x01, 0x00};

    memset(&pub, 0, sizeof(pub));
    CHECK(awskms_pubkey_from_spki(&pub, junk, sizeof(junk), "RSA_2048", NULL, 0,
                                  NULL) == 0,
          "junk DER must be rejected");
    awskms_pubkey_cleanup(&pub);

    memset(&pub, 0, sizeof(pub));
    CHECK(awskms_pubkey_from_spki(&pub, junk, sizeof(junk), "SM2", NULL, 0,
                                  NULL) == 0,
          "SM2 is out of scope and must be rejected");
    awskms_pubkey_cleanup(&pub);

    memset(&pub, 0, sizeof(pub));
    CHECK(
        awskms_pubkey_from_spki(&pub, NULL, 0, "RSA_2048", NULL, 0, NULL) == 0,
        "a NULL SPKI must be rejected");
    awskms_pubkey_cleanup(&pub);

    if (SIZE_MAX > (size_t)LONG_MAX) {
      memset(&pub, 0, sizeof(pub));
      CHECK(awskms_pubkey_from_spki(&pub, junk, (size_t)LONG_MAX + 1,
                                    "RSA_2048", NULL, 0, NULL) == 0,
            "a DER length that cannot fit in long must be rejected");
      awskms_pubkey_cleanup(&pub);
    }
  }

  if (skipped)
    printf("  (%d ML-DSA spec(s) skipped: needs OpenSSL 3.5+)\n", skipped);
}

void test_keyspec(void) {
  const AWSKMS_KEYSPEC *rsa = awskms_keyspec_by_name("RSA_2048");
  const AWSKMS_KEYSPEC *p256 = awskms_keyspec_by_name("ECC_NIST_P256");
  const AWSKMS_KEYSPEC *p384 = awskms_keyspec_by_name("ECC_NIST_P384");
  const AWSKMS_KEYSPEC *ed = awskms_keyspec_by_name("ECC_NIST_EDWARDS25519");
  const AWSKMS_KEYSPEC *ml = awskms_keyspec_by_name("ML_DSA_65");

  CHECK(rsa != NULL && p256 != NULL && p384 != NULL && ed != NULL && ml != NULL,
        "every in-scope key spec must be present");
  CHECK(awskms_keyspec_by_name("SM2") == NULL, "SM2 must not be in the table");
  CHECK(awskms_keyspec_by_name("SYMMETRIC_DEFAULT") == NULL,
        "symmetric specs must not be in the table");
  CHECK(awskms_keyspec_by_name(NULL) == NULL, "NULL must be handled");

  /* OpenSSL's curve names, not AWS's: AWS documents P-256 as secp256r1 but
   * OpenSSL only answers to prime256v1, and Node reads this value back. */
  CHECK_STR(p256->group_name, "prime256v1", "P-256 group name");
  CHECK_STR(p384->group_name, "secp384r1", "P-384 group name");

  /* RSA: the caller picks the digest and the padding. */
  CHECK_STR(awskms_signing_algorithm(rsa, AWSKMS_DIGEST_SHA256, 0),
            "RSASSA_PKCS1_V1_5_SHA_256", "RSA pkcs1 sha256");
  CHECK_STR(awskms_signing_algorithm(rsa, AWSKMS_DIGEST_SHA512, 1),
            "RSASSA_PSS_SHA_512", "RSA pss sha512");
  CHECK(awskms_signing_algorithm(rsa, AWSKMS_DIGEST_NONE, 0) == NULL,
        "RSA needs a digest");
  CHECK(awskms_signing_algorithm(rsa, AWSKMS_DIGEST_OTHER, 0) == NULL,
        "RSA with an unsupported digest must fail");

  /* ECDSA: one digest per curve, and the wrong one is an error rather than a
   * silently different signature. */
  CHECK_STR(awskms_signing_algorithm(p256, AWSKMS_DIGEST_SHA256, 0),
            "ECDSA_SHA_256", "P-256 sha256");
  CHECK(awskms_signing_algorithm(p256, AWSKMS_DIGEST_SHA384, 0) == NULL,
        "P-256 must reject sha384");
  CHECK_STR(awskms_signing_algorithm(p384, AWSKMS_DIGEST_SHA384, 0),
            "ECDSA_SHA_384", "P-384 sha384");
  /* The padding flag is meaningless off RSA and must not change anything. */
  CHECK_STR(awskms_signing_algorithm(p256, AWSKMS_DIGEST_SHA256, 1),
            "ECDSA_SHA_256", "pss flag ignored for EC");

  /* One-shot families take no digest at all. */
  CHECK_STR(awskms_signing_algorithm(ed, AWSKMS_DIGEST_NONE, 0),
            "ED25519_SHA_512", "ed25519");
  CHECK(awskms_signing_algorithm(ed, AWSKMS_DIGEST_SHA512, 0) == NULL,
        "ed25519 must reject a supplied digest");
  CHECK_STR(awskms_signing_algorithm(ml, AWSKMS_DIGEST_NONE, 0),
            "ML_DSA_SHAKE_256", "ml-dsa");
  CHECK(awskms_signing_algorithm(ml, AWSKMS_DIGEST_SHA256, 0) == NULL,
        "ml-dsa must reject a supplied digest");
  CHECK(awskms_signing_algorithm(NULL, AWSKMS_DIGEST_SHA256, 0) == NULL,
        "NULL spec must be handled");

  /* Message shapes: only Ed25519 is exposed to the 4096-byte cap. */
  CHECK(rsa->msg_type == AWSKMS_MSG_DIGEST, "RSA sends a digest");
  CHECK(p256->msg_type == AWSKMS_MSG_DIGEST, "ECDSA sends a digest");
  CHECK(ed->msg_type == AWSKMS_MSG_RAW, "Ed25519 sends the message");
  CHECK(ml->msg_type == AWSKMS_MSG_EXTERNAL_MU, "ML-DSA sends mu");

  /* Digest identity resolves OpenSSL's aliases. */
  CHECK(awskms_digest_of(NULL) == AWSKMS_DIGEST_NONE, "NULL md");
  CHECK(awskms_digest_length(AWSKMS_DIGEST_SHA256) == 32, "sha256 length");
  CHECK(awskms_digest_length(AWSKMS_DIGEST_SHA384) == 48, "sha384 length");
  CHECK(awskms_digest_length(AWSKMS_DIGEST_SHA512) == 64, "sha512 length");
  CHECK(awskms_digest_length(AWSKMS_DIGEST_NONE) == 0, "no digest, no length");
  {
    /* Every spelling of SHA-256 must land on the same identity. */
    static const char *aliases[] = {"SHA256", "SHA2-256", "SHA-256",
                                    "2.16.840.1.101.3.4.2.1"};
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++) {
      EVP_MD *md = EVP_MD_fetch(NULL, aliases[i], NULL);
      CHECK(md != NULL && awskms_digest_of(md) == AWSKMS_DIGEST_SHA256,
            "digest alias \"%s\" should resolve to SHA-256", aliases[i]);
      EVP_MD_free(md);
    }
    {
      EVP_MD *md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
      if (md != NULL) {
        CHECK(awskms_digest_of(md) == AWSKMS_DIGEST_OTHER,
              "SHA3-256 is a real digest KMS does not sign with");
        EVP_MD_free(md);
      }
    }
  }
}
