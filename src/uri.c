/*
 * Two layers, parsed by whoever owns them.
 *
 *  - The WHATWG URL layer (scheme, opaque path, query, fragment) is parsed by
 *    ada, the library Node.js also uses, at a pinned version rather than the
 *    host's. Node hands the loader `new URL(x).href`, which is already
 *    normalised, so re-parsing it is idempotent for any conformant parser.
 *
 *  - The `;`-separated attribute layer *inside* the opaque path is ours. WHATWG
 *    gives an opaque path no structure at all -- it is one string -- so this is
 *    RFC 7512's convention rather than the URL standard's, and is parsed here
 *    exactly as RFC 7512 describes: percent-decoding, and no `+`-means-space.
 *    Query attributes go through ada's URLSearchParams, which is what a Node
 *    user reading `url.searchParams` would expect.
 */
#include "uri.h"

#include <openssl/crypto.h>
#include <string.h>

#include "ada_c.h"
#include "compat.h"
#include "err.h"

#define SCHEME "awskms:"

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Percent-decodes [begin, end) into a fresh NUL-terminated string. Returns NULL
 * on a malformed escape, or on one that would introduce a NUL: the value ends up
 * as a C string in an AWS API call, and a truncating embedded NUL is how a typo
 * turns into a request against the wrong key. */
static char *decode(const char *begin, const char *end) {
  size_t n = (size_t)(end - begin);
  char *out = OPENSSL_malloc(n + 1);
  size_t w = 0;

  if (out == NULL) return NULL;
  for (const char *p = begin; p < end;) {
    if (*p == '%') {
      int hi, lo;
      if (end - p < 3 || (hi = hexval(p[1])) < 0 || (lo = hexval(p[2])) < 0) {
        OPENSSL_free(out);
        return NULL;
      }
      if ((hi << 4 | lo) == 0) {
        OPENSSL_free(out);
        return NULL;
      }
      out[w++] = (char)(hi << 4 | lo);
      p += 3;
    } else {
      out[w++] = *p++;
    }
  }
  out[w] = '\0';
  return out;
}

/* Parses the `;`-separated `name=value` attributes of the opaque path. */
static int parse_path_attrs(const char *begin, const char *end, AWSKMS_URI *out,
                            const OSSL_CORE_HANDLE *handle) {
  const char *p = begin;

  while (p < end) {
    const char *item_end = memchr(p, ';', (size_t)(end - p));
    const char *eq;
    char **slot;
    size_t namelen;

    if (item_end == NULL) item_end = end;
    if (item_end == p) { /* ";;" or a trailing ";" */
      p = item_end + 1;
      continue;
    }

    if ((eq = memchr(p, '=', (size_t)(item_end - p))) == NULL) {
      AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                   "path attribute \"%.*s\" is not name=value",
                   (int)(item_end - p), p);
      return 0;
    }

    namelen = (size_t)(eq - p);
    if (namelen == 6 && memcmp(p, "key-id", 6) == 0)
      slot = &out->key_id;
    else if (namelen == 6 && memcmp(p, "region", 6) == 0)
      slot = &out->region;
    else {
      /* Loud rather than silently ignored: a mistyped attribute that changes
       * which key is used is worse than a failed load. */
      AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                   "unknown path attribute \"%.*s\"", (int)namelen, p);
      return 0;
    }

    if (*slot != NULL) {
      AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                   "path attribute \"%.*s\" given more than once", (int)namelen,
                   p);
      return 0;
    }
    if ((*slot = decode(eq + 1, item_end)) == NULL) {
      AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                   "malformed percent escape in path attribute \"%.*s\"",
                   (int)namelen, p);
      return 0;
    }

    p = item_end + 1;
  }
  return 1;
}

/* Copies one query attribute out of ada's URLSearchParams. */
static int take_query_attr(ada_url_search_params params, const char *name,
                           char **slot, const OSSL_CORE_HANDLE *handle) {
  ada_string v;

  if (!ada_search_params_has(params, name, strlen(name))) return 1;
  v = ada_search_params_get(params, name, strlen(name));
  if (v.data == NULL) return 1;
  if (memchr(v.data, '\0', v.length) != NULL) {
    AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                 "query attribute \"%s\" contains a NUL byte", name);
    return 0;
  }
  /* ada has already percent-decoded these. */
  if ((*slot = OPENSSL_strndup(v.data, v.length)) == NULL) return 0;
  return 1;
}

/*
 * Extracts the region from a KMS ARN:
 *   arn:<partition>:kms:<region>:<account>:key/<id>
 *   arn:<partition>:kms:<region>:<account>:alias/<name>
 * Returns NULL when `id` is not a KMS ARN, which is not an error.
 */
static const char *arn_region(const char *id, size_t *len) {
  const char *p = id;
  const char *field[4];

  if (strncmp(p, "arn:", 4) != 0) return NULL;
  p += 4;
  for (int i = 0; i < 4; i++) {
    const char *colon;
    field[i] = p;
    if ((colon = strchr(p, ':')) == NULL) return NULL;
    p = colon + 1;
  }
  if (strncmp(field[1], "kms:", 4) != 0) return NULL;
  *len = (size_t)(field[3] - field[2] - 1);
  return *len > 0 ? field[2] : NULL;
}

int awskms_uri_parse(const char *uri, AWSKMS_URI *out,
                     const OSSL_CORE_HANDLE *handle) {
  ada_url url = NULL;
  ada_url_search_params params = NULL;
  ada_string protocol, pathname, hash;
  const char *arn;
  size_t arnlen = 0;
  int ret = 0;

  if (uri == NULL) {
    AWSKMS_raise(handle, AWSKMS_R_INVALID_URI, "no URI");
    return 0;
  }

  if ((url = ada_parse(uri, strlen(uri))) == NULL) return 0;
  if (!ada_is_valid(url)) {
    AWSKMS_raise(handle, AWSKMS_R_INVALID_URI, "not a valid URL");
    goto out;
  }

  /* OpenSSL picks the loader by scheme, so this should always hold; checking
   * means we cannot mis-parse something handed to us directly. ada normalises
   * the scheme to lower case and includes the colon. */
  protocol = ada_get_protocol(url);
  if (protocol.length != sizeof(SCHEME) - 1 ||
      memcmp(protocol.data, SCHEME, sizeof(SCHEME) - 1) != 0) {
    AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                 "expected scheme \"%s\", got \"%.*s\"", SCHEME,
                 (int)protocol.length, protocol.data);
    goto out;
  }

  hash = ada_get_hash(url);
  if (hash.length != 0) {
    AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                 "URI fragments are not meaningful here");
    goto out;
  }

  pathname = ada_get_pathname(url);
  if (!parse_path_attrs(pathname.data, pathname.data + pathname.length, out,
                        handle))
    goto out;

  {
    ada_string search = ada_get_search(url);
    if (search.length > 0) {
      /* ada_get_search includes the leading '?'. */
      params = ada_parse_search_params(search.data + 1, search.length - 1);
      if (params == NULL) {
        AWSKMS_raise(handle, AWSKMS_R_INVALID_URI, "malformed query");
        goto out;
      }
      if (!take_query_attr(params, "profile", &out->profile, handle)) goto out;
      if (!take_query_attr(params, "endpoint", &out->endpoint, handle))
        goto out;

      /* Reject unknown query attributes for the same reason as path ones. */
      {
        ada_url_search_params_keys_iter it = ada_search_params_get_keys(params);
        while (it != NULL && ada_search_params_keys_iter_has_next(it)) {
          ada_string k = ada_search_params_keys_iter_next(it);
          if ((k.length != 7 || memcmp(k.data, "profile", 7) != 0) &&
              (k.length != 8 || memcmp(k.data, "endpoint", 8) != 0)) {
            AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                         "unknown query attribute \"%.*s\"", (int)k.length,
                         k.data);
            ada_free_search_params_keys_iter(it);
            goto out;
          }
        }
        if (it != NULL) ada_free_search_params_keys_iter(it);
      }
    }
  }

  if (out->key_id == NULL || out->key_id[0] == '\0') {
    AWSKMS_raise(handle, AWSKMS_R_INVALID_URI,
                 "missing required attribute \"key-id\"");
    goto out;
  }

  /* An explicit region wins, but if the key id is an ARN the two must agree.
   * KMS's endpoint ruleset has no ARN-based region resolution, so a mismatch
   * would silently send a Frankfurt key to us-east-1 and come back as a
   * NotFoundException that tells the user nothing. */
  arn = arn_region(out->key_id, &arnlen);
  if (arn != NULL) {
    if (out->region != NULL) {
      if (strlen(out->region) != arnlen ||
          strncmp(out->region, arn, arnlen) != 0) {
        AWSKMS_raise(handle, AWSKMS_R_REGION_CONFLICT,
                     "region \"%s\" contradicts the region \"%.*s\" in the key "
                     "ARN",
                     out->region, (int)arnlen, arn);
        goto out;
      }
    } else if ((out->region = OPENSSL_strndup(arn, arnlen)) == NULL) {
      goto out;
    }
  }

  ret = 1;

out:
  if (params != NULL) ada_free_search_params(params);
  if (url != NULL) ada_free(url);
  if (!ret) awskms_uri_cleanup(out);
  return ret;
}

void awskms_uri_cleanup(AWSKMS_URI *u) {
  if (u == NULL) return;
  OPENSSL_free(u->key_id);
  OPENSSL_free(u->region);
  OPENSSL_free(u->profile);
  OPENSSL_free(u->endpoint);
  memset(u, 0, sizeof(*u));
}
