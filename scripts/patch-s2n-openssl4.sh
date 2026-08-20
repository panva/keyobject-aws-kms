#!/usr/bin/env bash
#
# Make vendored s2n loadable against OpenSSL 4.0.
#
#   scripts/patch-s2n-openssl4.sh <aws-sdk-source-dir>
#
# The pinned s2n calls ASN1_STRING_data(), an API deprecated since
# 1.1.0 in favour of ASN1_STRING_get0_data() and REMOVED OUTRIGHT in OpenSSL 4.0.
# Because this module links no libcrypto, that call stays an undefined symbol and
# binds at dlopen. OpenSSL 4.0 cannot load the provider while that symbol remains.
# The compatibility patch changes only the four read-only call sites to the
# replacement API, which has existed since OpenSSL 1.1.0.
#
# THE SUBSTITUTION IS SAFE. ASN1_STRING_get0_data() returns a const pointer where
# ASN1_STRING_data() returned non-const, so the cast is restored explicitly.
# Every one of these call sites only READS -- s2n's own comments say the pointer
# "should not be freed or modified in any way" -- so nothing relied on the
# writability the old signature implied.
#
# SELF-INVALIDATING BY DESIGN. It asserts the exact number of call sites it
# expects. When s2n upstream fixes this, or adds another use, the count changes
# and this FAILS LOUDLY rather than silently patching nothing -- which is how a
# temporary workaround becomes permanent without anyone deciding it should.
set -euo pipefail

SDK=${1:?usage: patch-s2n-openssl4.sh <aws-sdk-source-dir>}
S2N="$SDK/crt/aws-crt-cpp/crt/s2n"
MARKER="$S2N/.awskms-openssl4-patched"

# Number of real call sites at the pinned SDK tag. Comment mentions are written
# `ASN1_STRING_data()` with empty parens and are matched separately, so they do
# not inflate this.
EXPECTED=4

[ -d "$S2N" ] || { echo "no vendored s2n at $S2N" >&2; exit 1; }

if [ -f "$MARKER" ]; then
  echo "s2n already patched for OpenSSL 4.0"
  exit 0
fi

# Use `find | xargs grep` because BusyBox grep does not implement GNU's
# `--include` option. Leave stderr visible so unsupported invocations are loud.
sources=$(find "$S2N" \( -name '*.c' -o -name '*.h' \) -type f)
files=$(printf '%s\n' "$sources" | xargs grep -l 'ASN1_STRING_data([^)]' || true)
# A zero-match grep is a supported state that the explicit count check handles.
count=$( { printf '%s\n' "$sources" | xargs grep -ho 'ASN1_STRING_data([^)]' || true; } | wc -l | tr -d ' ')

if [ "$count" = 0 ]; then
  echo "::error::vendored s2n no longer calls ASN1_STRING_data. Delete" \
       "scripts/patch-s2n-openssl4.sh and its call in" \
       "cmake/FetchAwsSdkKms.cmake rather than retaining a dead patch."
  exit 1
fi

if [ "$count" != "$EXPECTED" ]; then
  echo "::error::expected $EXPECTED ASN1_STRING_data call sites in vendored s2n," \
       "found $count. The SDK tag has moved; re-read the call sites and confirm" \
       "they are still read-only before bumping EXPECTED."
  exit 1
fi

for f in $files; do
  # Only real calls: a comment reference is `ASN1_STRING_data()`, whose next
  # character is `)`, and the negated class below will not match it.
  sed -i.awskms-bak \
    's/ASN1_STRING_data(\([^)]\)/(unsigned char *) ASN1_STRING_get0_data(\1/g' "$f"
  rm -f "$f.awskms-bak"
  echo "  patched $(basename "$f")"
done

: > "$MARKER"
echo "s2n patched for OpenSSL 4.0 ($count call sites, ASN1_STRING_data -> ASN1_STRING_get0_data)"
