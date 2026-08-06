#!/usr/bin/env bash
#
# Make vendored s2n loadable against OpenSSL 4.0.  (B5)
#
#   scripts/patch-s2n-openssl4.sh <aws-sdk-source-dir>
#
# THE DEFECT. s2n calls ASN1_STRING_data(), a 1.0.2-era API deprecated since
# 1.1.0 in favour of ASN1_STRING_get0_data() and REMOVED OUTRIGHT in OpenSSL 4.0.
# Because this module links no libcrypto, that call stays an undefined symbol and
# binds at dlopen -- so on a 4.0 host the provider does not load at all:
#
#   openssl 4.0.1 runtime / aws -> FAIL  ASN1_STRING_data
#
# THIS IS NOT B4 AND THE B4 FIX CANNOT HELP. B4 was "built too new to run on
# old", cured by compiling against the oldest supported headers. This is the
# reverse: a dependency calls something the NEW version deleted. No choice of
# build headers produces a symbol that does not exist in a 4.0 libcrypto.
#
# WHY PATCH RATHER THAN WAIT. Waiting on s2n upstream is the right long-term
# answer and OpenSSL 4.0 will force it, but it leaves the artifact unloadable on
# 4.0 in the meantime. This is deliberately the narrowest possible change: four
# call sites, all read-only, swapped for the modern spelling that has existed
# since 1.1.0 -- comfortably below this project's 3.0 floor.
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

files=$(grep -rl 'ASN1_STRING_data([^)]' "$S2N" --include='*.c' --include='*.h' 2>/dev/null || true)
count=$(grep -rho 'ASN1_STRING_data([^)]' "$S2N" --include='*.c' --include='*.h' 2>/dev/null | wc -l | tr -d ' ')

if [ "$count" = 0 ]; then
  echo "::error::vendored s2n no longer calls ASN1_STRING_data -- upstream has" \
       "likely fixed this (B5). DELETE scripts/patch-s2n-openssl4.sh and its" \
       "call in cmake/FetchAwsSdkKms.cmake rather than leaving a dead patch."
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
