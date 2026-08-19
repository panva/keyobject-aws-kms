#include <openssl/err.h>

#include "unit.h"
#include "uri.h"

/* Errors are raised through the provider core upcalls, which are absent in a
 * unit test, so awskms_err_raise() is a no-op here and only return codes are
 * asserted. That is the interesting part anyway. */

static void ok(const char *uri, const char *key_id, const char *region,
               const char *profile, const char *endpoint) {
  AWSKMS_URI u;
  memset(&u, 0, sizeof(u));

  if (!awskms_uri_parse(uri, &u, NULL)) {
    awskms_test_checks++;
    awskms_test_failures++;
    fprintf(stderr, "  FAIL %s: expected to parse, was rejected\n", uri);
    return;
  }
  CHECK_STR(u.key_id, key_id, uri);
  CHECK_STR(u.region, region, uri);
  CHECK_STR(u.profile, profile, uri);
  CHECK_STR(u.endpoint, endpoint, uri);
  awskms_uri_cleanup(&u);
  /* Cleanup must be idempotent: the parse error path calls it too. */
  awskms_uri_cleanup(&u);
}

static void rejected(const char *uri, const char *why) {
  AWSKMS_URI u;
  memset(&u, 0, sizeof(u));
  CHECK(!awskms_uri_parse(uri, &u, NULL), "expected rejection (%s): %s", why,
        uri);
  /* On failure the parser must leave nothing allocated and nothing set. */
  CHECK(u.key_id == NULL && u.region == NULL && u.profile == NULL &&
            u.endpoint == NULL,
        "fields left set after a failed parse: %s", uri);
  awskms_uri_cleanup(&u);
}

void test_uri(void) {
  /* --- the shapes from the README ------------------------------------- */
  ok("aws-kms:key-id=alias/my-signer", "alias/my-signer", NULL, NULL, NULL);
  ok("aws-kms:key-id=alias/my-signer;region=eu-central-1", "alias/my-signer",
     "eu-central-1", NULL, NULL);
  ok("aws-kms:key-id=1234abcd-12ab-34cd-56ef-1234567890ab;region=us-east-1",
     "1234abcd-12ab-34cd-56ef-1234567890ab", "us-east-1", NULL, NULL);
  ok("aws-kms:key-id=alias/s;region=eu-central-1?profile=prod", "alias/s",
     "eu-central-1", "prod", NULL);
  ok("aws-kms:key-id=alias/s?profile=p&endpoint=http://127.0.0.1:4566",
     "alias/s", NULL, "p", "http://127.0.0.1:4566");

  /* --- region inferred from an ARN, which the AWS SDKs do not do ------- */
  ok("aws-kms:key-id=arn:aws:kms:eu-central-1:111122223333:key/"
     "1234abcd-12ab-34cd-56ef-1234567890ab",
     "arn:aws:kms:eu-central-1:111122223333:key/"
     "1234abcd-12ab-34cd-56ef-1234567890ab",
     "eu-central-1", NULL, NULL);
  ok("aws-kms:key-id=arn:aws:kms:us-west-2:111122223333:alias/my-signer",
     "arn:aws:kms:us-west-2:111122223333:alias/my-signer", "us-west-2", NULL,
     NULL);
  /* Non-commercial partitions carry the region in the same field. */
  ok("aws-kms:key-id=arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/abcd",
     "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/abcd", "us-gov-west-1",
     NULL, NULL);
  /* An explicit region that agrees with the ARN is fine. */
  ok("aws-kms:key-id=arn:aws:kms:eu-central-1:1:key/a;region=eu-central-1",
     "arn:aws:kms:eu-central-1:1:key/a", "eu-central-1", NULL, NULL);
  /* A multi-Region key id is not an ARN and infers nothing. */
  ok("aws-kms:key-id=mrk-1234abcd12ab34cd56ef1234567890ab;region=eu-west-1",
     "mrk-1234abcd12ab34cd56ef1234567890ab", "eu-west-1", NULL, NULL);
  /* An ARN for some other service must not be mined for a region. */
  ok("aws-kms:key-id=arn:aws:iam:eu-central-1:111122223333:role/r",
     "arn:aws:iam:eu-central-1:111122223333:role/r", NULL, NULL, NULL);

  /* --- percent decoding ------------------------------------------------ */
  ok("aws-kms:key-id=alias/with%20space", "alias/with space", NULL, NULL, NULL);
  ok("aws-kms:key-id=alias/a%3Bb", "alias/a;b", NULL, NULL, NULL);
  ok("aws-kms:key-id=alias/a%3Db", "alias/a=b", NULL, NULL, NULL);

  /* --- attribute order and separators --------------------------------- */
  ok("aws-kms:region=eu-central-1;key-id=alias/s", "alias/s", "eu-central-1",
     NULL, NULL);
  ok("aws-kms:key-id=alias/s;", "alias/s", NULL, NULL, NULL);
  ok("aws-kms:key-id=alias/s;;region=eu-west-1", "alias/s", "eu-west-1", NULL,
     NULL);

  /* --- rejections ------------------------------------------------------ */
  rejected("aws-kms:", "no attributes at all");
  rejected("aws-kms:region=eu-central-1", "no key-id");
  rejected("aws-kms:key-id=", "empty key-id");
  rejected("aws-kms:key-id=a;key-id=b", "repeated key-id");
  rejected("aws-kms:key-id=a;object=b", "unknown path attribute");
  rejected("aws-kms:key-id=a;type=private", "a pkcs11 attribute, not ours");
  rejected("aws-kms:key-id=a?region=eu-central-1",
           "region belongs in the path, not the query");
  rejected("aws-kms:key-id=a?nope=1", "unknown query attribute");
  rejected("aws-kms:key-id=a?profile=first&profile=second", "repeated profile");
  rejected("aws-kms:key-id=a?endpoint=http://one&endpoint=http://two",
           "repeated endpoint");
  rejected("aws-kms:key-id=a?profile=first&%70rofile=second",
           "percent-encoded repeated profile");
  rejected("aws-kms:key-id=a;region", "path attribute without a value");
  rejected("aws-kms:key-id=a#frag", "fragment");
  rejected("aws-kms:key-id=alias/%zz", "malformed percent escape");
  rejected("aws-kms:key-id=alias/%2", "truncated percent escape");
  rejected("aws-kms:key-id=alias/a%00b", "percent-encoded NUL");
  rejected("pkcs11:object=a", "wrong scheme");
  rejected("aws-kms:key-id=arn:aws:kms:eu-central-1:1:key/a;region=us-east-1",
           "region contradicts the ARN");

  /* --- an uppercase scheme is normalised by the WHATWG parser, so it must
   * still be accepted; this is exactly what ada buys us ---------------- */
  ok("AWS-KMS:key-id=alias/s", "alias/s", NULL, NULL, NULL);

  CHECK(!awskms_uri_parse(NULL, NULL, NULL), "NULL uri must be rejected");
}
