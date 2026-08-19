#!/usr/bin/env bash
# Verify the complete six-platform GitHub release payload before attestation.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
dist=${1:?usage: ci-verify-release.sh <directory> <version>}
version=${2:?usage: ci-verify-release.sh <directory> <version>}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ $version != 0.0.0 && $version != current ]] || die "refusing placeholder version $version"
[[ -d $dist ]] || die "release directory not found: $dist"
node scripts/check-licenses.mjs

targets=(
  darwin-arm64
  darwin-x64
  linux-arm64
  linux-x64
  linuxmusl-arm64
  linuxmusl-x64
)

mapfile -t archives < <(find "$dist" -maxdepth 1 -type f -name 'awskms-*.tar.gz' -print | sort)
[[ ${#archives[@]} -eq ${#targets[@]} ]] \
  || die "expected ${#targets[@]} archives, found ${#archives[@]}"

for target in "${targets[@]}"; do
  name="awskms-$version-$target"
  archive="$dist/$name.tar.gz"
  [[ -f $archive ]] || die "missing $archive"
  case "$target" in
    darwin-*) module=aws-kms.dylib ;;
    *) module=aws-kms.so ;;
  esac

  listing=$(tar tzf "$archive" | sort)
  expected=$(
    printf '%s\n' \
      "$name/" \
      "$name/LICENSE" \
      "$name/THIRD_PARTY_NOTICES.md" \
      "$name/$module" \
      "$name/awskms.cnf" \
      "$name/check.mjs" \
      "$name/docs/" \
      "$name/docs/INSTALL.md" \
      "$name/third_party/" \
      "$name/third_party/components.json" \
      "$name/third_party/licenses/"
    for legal in third_party/licenses/*; do
      printf '%s/third_party/licenses/%s\n' "$name" "$(basename "$legal")"
    done
  )
  expected=$(sort <<<"$expected")
  [[ $listing == "$expected" ]] || {
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$listing") || true
    die "$archive has an unexpected public inventory"
  }

  unpack=$(mktemp -d)
  tar xzf "$archive" -C "$unpack"
  cmp LICENSE "$unpack/$name/LICENSE"
  cmp THIRD_PARTY_NOTICES.md "$unpack/$name/THIRD_PARTY_NOTICES.md"
  cmp docs/INSTALL.md "$unpack/$name/docs/INSTALL.md"
  cmp third_party/components.json "$unpack/$name/third_party/components.json"
  for legal in third_party/licenses/*; do
    cmp "$legal" "$unpack/$name/third_party/licenses/$(basename "$legal")"
  done
  rm -rf "$unpack"
  scripts/ci-policy-gate.sh archive "$archive"
done

echo "ok: exact, licensed six-platform release payload for $version"
