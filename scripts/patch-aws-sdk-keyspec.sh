#!/usr/bin/env bash
#
# Remove the out-of-scope curve from the generated AWS KMS KeySpec mappers.
#
# The SDK otherwise embeds the service identifier in every AWS-backend module,
# even though this provider rejects that KeySpec. Unity compilation means both
# the GetPublicKey and data-key-pair mappers land in the same linked object, so
# both must be restricted. Leaving enum declarations in generated headers is
# harmless: they have no runtime bytes. Removing each mapper's hash/parser and
# serializer cases has the useful additional property that a response carrying
# this KeySpec follows the SDK's unknown-enum path; our own KeySpec allow-list
# then rejects it while loading the public key, before a Sign request can occur.
#
# SELF-INVALIDATING BY DESIGN.  The generated source at the pinned SDK tag has
# exactly three affected constructs and six identifier occurrences per mapper.
# The awk rewrite validates every complete construct before emitting a
# replacement. A changed generator shape or count fails configuration and
# requires review.
set -euo pipefail

SDK=${1:?usage: patch-aws-sdk-keyspec.sh <aws-sdk-source-dir>}
MODEL_DIR="$SDK/generated/src/aws-cpp-sdk-kms/source/model"
MARKER="$SDK/.awskms-keyspec-policy-patched-v2"

# Keep the identifier split so project-owned source remains free of it too.
identifier='ECC_SECG_''P256K1'
expected_occurrences=6

sources=("$MODEL_DIR/KeySpec.cpp" "$MODEL_DIR/DataKeyPairSpec.cpp")

if [ -f "$MARKER" ]; then
  for source in "${sources[@]}"; do
    [ -f "$source" ] || { echo "generated KMS KeySpec mapper not found: $source" >&2; exit 1; }
    if grep -F "$identifier" "$source" >/dev/null; then
      echo "::error::AWS KMS KeySpec patch marker exists, but the removed identifier is present in $source" >&2
      exit 1
    fi
  done
  echo "AWS KMS KeySpec mappers already restricted to supported curves"
  exit 0
fi

temporary_files=()
cleanup() {
  local temporary
  for temporary in "${temporary_files[@]}"; do rm -f "$temporary"; done
}
trap cleanup EXIT

prepare_mapper() {
  local source=$1 enum_type occurrences temporary
  [ -f "$source" ] || { echo "generated KMS KeySpec mapper not found: $source" >&2; exit 1; }
  case ${source##*/} in
    KeySpec.cpp) enum_type=KeySpec ;;
    DataKeyPairSpec.cpp) enum_type=DataKeyPairSpec ;;
    *) echo "unexpected generated KMS mapper: $source" >&2; exit 1 ;;
  esac

  occurrences=$( { grep -Fo "$identifier" "$source" || true; } | wc -l | tr -d ' ')
  if [ "$occurrences" = 0 ]; then
    echo "::error::the generated AWS KMS mapper no longer contains the out-of-scope KeySpec: $source" >&2
    echo "Delete this patch and its CMake call after confirming the SDK now omits it." >&2
    exit 1
  fi
  if [ "$occurrences" != "$expected_occurrences" ]; then
    echo "::error::expected $expected_occurrences identifier occurrences in $source, found $occurrences" >&2
    echo "The pinned AWS SDK changed; review the generated mapper before updating this patch." >&2
    exit 1
  fi

  temporary="$source.awskms-new"
  temporary_files+=("$temporary")

  awk -v identifier="$identifier" -v enum_type="$enum_type" '
  $0 == "static const int " identifier "_HASH = HashingUtils::HashString(\"" identifier "\");" {
    hashes++
    next
  }

  $0 == "  } else if (hashCode == " identifier "_HASH) {" {
    parsers++
    if ((getline following) <= 0 || following != "    return " enum_type "::" identifier ";") {
      print "unexpected generated parser branch for the out-of-scope KeySpec" > "/dev/stderr"
      exit 41
    }
    next
  }

  $0 == "    case " enum_type "::" identifier ":" {
    serializers++
    if ((getline following) <= 0 || following != "      return \"" identifier "\";") {
      print "unexpected generated serializer branch for the out-of-scope KeySpec" > "/dev/stderr"
      exit 42
    }
    next
  }

  { print }

  END {
    if (hashes != 1 || parsers != 1 || serializers != 1) {
      print "expected one hash, parser, and serializer construct; found " hashes ", " parsers ", " serializers > "/dev/stderr"
      exit 43
    }
  }
' "$source" > "$temporary"

  if grep -F "$identifier" "$temporary" >/dev/null; then
    echo "::error::the patched KMS KeySpec mapper still contains the removed identifier: $source" >&2
    exit 1
  fi
}

for source in "${sources[@]}"; do prepare_mapper "$source"; done
for source in "${sources[@]}"; do
  if [ -f "$source.awskms-new" ]; then mv "$source.awskms-new" "$source"; fi
done
: > "$MARKER"
trap - EXIT
echo "AWS KMS KeySpec mappers restricted to supported curves (6 constructs removed)"
