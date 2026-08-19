#!/usr/bin/env bash
# Stage one native binary archive from an AWS-backend build tree.
#
#   scripts/package-archive.sh <build-dir> <target> [output-dir]
#
# The archive and its sole top-level directory are both named
# awskms-<version>-<target>. The version comes from the npm core manifest so the
# npm and GitHub distributions cannot acquire independent versions.
set -euo pipefail

# Apple copyfile metadata (Finder provenance, resource forks, quarantine) is
# host-local state, not part of a public artifact. macOS cp/tar honor this;
# other platforms harmlessly ignore it.
export COPYFILE_DISABLE=1

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

build_dir=${1:?usage: package-archive.sh <build-dir> <target> [output-dir]}
target=${2:?usage: package-archive.sh <build-dir> <target> [output-dir]}
output_dir=${3:-.}

die() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

case "$target" in
  darwin-arm64|darwin-x64) module=aws-kms.dylib ;;
  linux-arm64|linux-x64|linuxmusl-arm64|linuxmusl-x64) module=aws-kms.so ;;
  *) die "unsupported archive target: $target" ;;
esac

[[ -f $build_dir/$module ]] || die "no $module in $build_dir"
[[ -f $build_dir/awskms.relocatable.cnf ]] \
  || die "no awskms.relocatable.cnf in $build_dir"
[[ -f $build_dir/awskms-backend ]] \
  || die "no awskms-backend marker in $build_dir"
backend=$(cat "$build_dir/awskms-backend")
backend_bytes=$(wc -c < "$build_dir/awskms-backend")
[[ $backend == aws && $backend_bytes -eq 4 ]] \
  || die "refusing to archive AWSKMS_BACKEND=$backend; releases require the aws backend"
[[ -f $build_dir/awskms-dependencies ]] \
  || die "no awskms-dependencies marker in $build_dir"
sdk_tag=$(node -p "require('./third_party/components.json').awsSdkTag")
[[ $(cat "$build_dir/awskms-dependencies") == "aws-sdk-cpp=$sdk_tag" ]] \
  || die "refusing to archive an AWS SDK dependency graph not covered by third_party/components.json"

for required in scripts/check.mjs docs/INSTALL.md LICENSE \
  THIRD_PARTY_NOTICES.md third_party/components.json; do
  [[ -f $required ]] || die "required archive payload is missing: $required"
done
[[ -d third_party/licenses ]] || die "required archive payload is missing: third_party/licenses"

# Validate component-to-license coverage before copying a byte. The same
# authoritative source tree is staged into npm satellites.
node scripts/check-licenses.mjs \
  || die "authoritative third-party license inventory failed"

version=$(node -p "require('./npm/core/package.json').version")
name="awskms-$version-$target"
mkdir -p "$output_dir"
archive="$output_dir/$name.tar.gz"
[[ ! -e $archive ]] || die "refusing to overwrite existing archive: $archive"

stage=$(mktemp -d "${TMPDIR:-/tmp}/awskms-archive.XXXXXX")
temporary_archive=$(mktemp "$output_dir/.$name.XXXXXX")
cleanup() {
  rm -rf -- "$stage"
  rm -f -- "$temporary_archive"
}
trap cleanup EXIT

destination="$stage/$name"
mkdir -p "$destination/docs" "$destination/third_party"
cp "$build_dir/$module" "$destination/"
cp "$build_dir/awskms.relocatable.cnf" "$destination/awskms.cnf"
cp scripts/check.mjs LICENSE THIRD_PARTY_NOTICES.md "$destination/"
cp docs/INSTALL.md "$destination/docs/"
cp third_party/components.json "$destination/third_party/"
cp -R third_party/licenses "$destination/third_party/"

cmp -s THIRD_PARTY_NOTICES.md "$destination/THIRD_PARTY_NOTICES.md" \
  || die "staged third-party notice differs from the authoritative file"
cmp -s third_party/components.json "$destination/third_party/components.json" \
  || die "staged component manifest differs from the authoritative file"
for legal in third_party/licenses/*; do
  cmp -s "$legal" "$destination/$legal" \
    || die "staged $(basename "$legal") differs from the authoritative file"
done

tar czf "$temporary_archive" -C "$stage" "$name"

# Compare every tar entry, including directories. This simultaneously enforces
# the single matching top-level directory and prevents accidental build files,
# caches, or incomplete legal payloads from becoming public artifacts.
listing=$(tar tzf "$temporary_archive" | sort)
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
expected=$(printf '%s\n' "$expected" | sort)
if [[ $listing != "$expected" ]]; then
  diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$listing") || true
  die "archive inventory differs from the exact public payload"
fi

mv "$temporary_archive" "$archive"
printf '%s\n' "$archive"
