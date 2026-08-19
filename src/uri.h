/*
 * The `aws-kms:` URI.
 *
 * RFC 7512-flavoured, deliberately chosen so that it survives a round trip
 * through the WHATWG URL parser unchanged -- which matters because Node.js hands
 * the loader `new URL(x).href`, not the string the caller wrote:
 *
 *   aws-kms:key-id=<id>[;region=<region>][?profile=<p>&endpoint=<url>]
 *
 * Path attributes describe the key's identity; query attributes describe how to
 * reach it. `region` is a path attribute because for a bare key id or alias the
 * region is genuinely part of the key's identity -- a key id is only unique
 * within one account and region.
 *
 * Colons, slashes, `;`, `=`, `?` and `&` all survive WHATWG URL normalisation in
 * an opaque path, so key ARNs and aliases need no escaping. Values are still
 * percent-decoded, so a value may contain a literal delimiter if it needs to.
 *
 * The WHATWG layer is parsed by ada, the library Node.js also uses, though not
 * necessarily at the host's version -- see third_party/ada/README.awskms.md.
 * Node hands the loader `new URL(x).href`, which is already normalised, so
 * re-parsing it with a conformant WHATWG parser is idempotent.
 */
#ifndef AWSKMS_URI_H
#define AWSKMS_URI_H

#include <openssl/core.h>

typedef struct awskms_uri_st {
  char *key_id;   /* required: key id, key ARN, alias name, or alias ARN */
  char *region;   /* NULL -> fall through to the ordinary AWS region chain */
  char *profile;  /* NULL -> ordinary AWS profile resolution */
  char *endpoint; /* NULL -> the SDK's resolved KMS endpoint */
} AWSKMS_URI;

/*
 * Parses `uri` into `out`, which must be zeroed by the caller.
 *
 * Raises an error and returns 0 on: a missing or empty key-id, an unknown
 * attribute (typos should be loud, not silently ignored), a repeated attribute,
 * a URI fragment, a bad percent escape, or a `region` attribute that contradicts
 * the region embedded in a key ARN.
 *
 * On success `out->region` is the explicit `region` attribute if given, else the
 * region parsed out of a key/alias ARN, else NULL. Resolving it from an ARN is a
 * convenience this provider adds: the AWS SDKs do not do it, because the KMS
 * endpoint ruleset has no ARN-based region resolution, so a Frankfurt ARN on a
 * us-east-1 client simply fails to find the key.
 */
int awskms_uri_parse(const char *uri, AWSKMS_URI *out,
                     const OSSL_CORE_HANDLE *handle);

/* Frees the members; does not free `u` itself. Safe on a zeroed struct. */
void awskms_uri_cleanup(AWSKMS_URI *u);

#endif /* AWSKMS_URI_H */
