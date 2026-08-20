#!/usr/bin/env bash
#
# Keep vendored s2n's empty KDF inputs compatible with OpenSSL providers.
#
#   scripts/patch-s2n-empty-kdf.sh <aws-sdk-source-dir>
#
# An empty s2n_blob is valid as { data = NULL, size = 0 }. OpenSSL's KDF setters
# reject that representation even for an empty octet-string parameter, while
# accepting a non-NULL pointer with the same zero length. During a TLS 1.3
# handshake this breaks HKDF-Expand when s2n supplies its unused empty salt.
#
# Normalize only the valid empty representation at s2n's shared OSSL_PARAM
# boundary. A malformed { NULL, nonzero } blob remains NULL and still fails.
# This also covers optional empty TLS1-PRF inputs without changing any bytes or
# lengths passed to libcrypto.
#
# SELF-INVALIDATING BY DESIGN. The pinned source has one exact two-line macro.
# If upstream fixes or reshapes it, configuration fails and requires review
# instead of silently retaining a dead compatibility patch.
set -euo pipefail

SDK=${1:?usage: patch-s2n-empty-kdf.sh <aws-sdk-source-dir>}
S2N="$SDK/crt/aws-crt-cpp/crt/s2n"
SOURCE="$S2N/crypto/s2n_kdf.h"
MARKER="$S2N/.awskms-empty-kdf-patched"
DEFINE="    #define S2N_OSSL_PARAM_BLOB(id, blob) \\"
BODY='        OSSL_PARAM_octet_string(id, blob->data, blob->size)'
PATCHED='s2n_ossl_empty_param_data'

[ -f "$SOURCE" ] || { echo "no vendored s2n KDF header at $SOURCE" >&2; exit 1; }

if [ -f "$MARKER" ]; then
  grep -Fq "$PATCHED" "$SOURCE" || {
    echo "::error::s2n empty-KDF patch marker exists but the patch is absent" >&2
    exit 1
  }
  if grep -Fq "$BODY" "$SOURCE"; then
    echo "::error::s2n empty-KDF patch marker exists but the original macro remains" >&2
    exit 1
  fi
  echo "s2n already patched for empty KDF parameters"
  exit 0
fi

define_count=$(grep -Fxc "$DEFINE" "$SOURCE" || true)
body_count=$(grep -Fxc "$BODY" "$SOURCE" || true)
if [ "$define_count" = 0 ] && [ "$body_count" = 0 ]; then
  echo "::error::vendored s2n no longer has the affected OSSL_PARAM macro. Delete" \
       "scripts/patch-s2n-empty-kdf.sh and its call in" \
       "cmake/FetchAwsSdkKms.cmake rather than retaining a dead patch."
  exit 1
fi
if [ "$define_count" != 1 ] || [ "$body_count" != 1 ]; then
  echo "::error::expected one exact vendored s2n OSSL_PARAM blob macro, found" \
       "$define_count definitions and $body_count bodies. The SDK tag has moved;" \
       "re-read the KDF parameter boundary before updating this patch."
  exit 1
fi

temporary=$(mktemp "${TMPDIR:-/tmp}/awskms-s2n-kdf.XXXXXX")
trap 'rm -f "$temporary"' EXIT
AWSKMS_S2N_KDF_DEFINE=$DEFINE AWSKMS_S2N_KDF_BODY=$BODY awk '
  BEGIN {
    define = ENVIRON["AWSKMS_S2N_KDF_DEFINE"]
    body = ENVIRON["AWSKMS_S2N_KDF_BODY"]
  }
  $0 == define {
    if ((getline next_line) <= 0 || next_line != body) {
      failed = 42
      exit failed
    }
    print "    /* OpenSSL rejects NULL data for an empty input OSSL_PARAM. */"
    print "    static uint8_t s2n_ossl_empty_param_data = 0;"
    print ""
    print define
    print "        OSSL_PARAM_octet_string(id, \\"
    print "                (blob->data != NULL || blob->size != 0) ? blob->data : &s2n_ossl_empty_param_data, \\"
    print "                blob->size)"
    patched++
    next
  }
  { print }
  END {
    if (failed) exit failed
    if (patched != 1) exit 43
  }
' "$SOURCE" > "$temporary" || {
  echo "::error::affected s2n OSSL_PARAM macro is no longer in the expected shape" >&2
  exit 1
}
cp "$temporary" "$SOURCE"

grep -Fq "$PATCHED" "$SOURCE"
if grep -Fq "$BODY" "$SOURCE"; then
  echo "::error::the original unsafe s2n OSSL_PARAM macro remains after patching" >&2
  exit 1
fi

: > "$MARKER"
echo "s2n patched for empty KDF parameters"
