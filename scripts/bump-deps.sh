#!/usr/bin/env bash
#
# Bring every pinned dependency to its latest release, one commit each.
#
#   scripts/bump-deps.sh          # commit each bump, print a summary
#   scripts/bump-deps.sh --dry-run
#
# TWO KINDS OF DEPENDENCY, and they are updated differently:
#
#   VENDORED   files copied into third_party/, listed in vendored.manifest and
#              handled by update-vendored.sh, which re-downloads and re-checks
#              the API surface before writing anything.
#   PINNED     fetched at BUILD time from a tag in a cmake file, so there is
#              nothing in the tree to refresh -- only a version string to move.
#              aws-sdk-cpp is the whole of this category today.
#
# Dependabot covers neither: it reads package manifests, and a CMake
# FetchContent tag is invisible to it. That is why aws-sdk-cpp sat unwatched --
# nothing anywhere would have told us the pin was stale.
#
# ONE COMMIT PER DEPENDENCY, deliberately. The branch this runs on is reset off
# main every week, so the PR is always exactly `main + N bump commits` and never
# accumulates history. Separate commits mean a reviewer can drop one bump and
# keep another, and `git revert` names a single dependency.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

DRY=0
[[ ${1:-} == --dry-run ]] && DRY=1

bumped=0

commit() { # <message>
  if (( DRY )); then echo "  would commit: $1"; return; fi
  git commit -q -m "$1"
  bumped=$((bumped + 1))
}

# --- pinned: aws-sdk-cpp ------------------------------------------------------
# The tag lives in one place and is read back with the same expression that sets
# it, so a reformat of that line breaks this loudly rather than silently
# matching nothing and reporting "up to date" forever.
PIN_FILE=cmake/FetchAwsSdkKms.cmake
cur=$(sed -n 's/^set(AWSKMS_AWS_SDK_TAG "\([^"]*\)".*/\1/p' "$PIN_FILE")
[[ -n $cur ]] || { echo "could not read AWSKMS_AWS_SDK_TAG from $PIN_FILE" >&2; exit 1; }

# TAGS, not releases: aws-sdk-cpp publishes NO GitHub Releases at all -- both
# /releases/latest and /releases come back empty -- so the endpoint ada uses
# 404s here. This is why the manifest notes that tag schemes differ per project.
#
# sort -V rather than trusting the API's order: /tags is not documented to be
# version-sorted, and silently taking .[0] would pin whatever happened to be
# first the day the ordering changed.
latest=$(gh api 'repos/aws/aws-sdk-cpp/tags?per_page=100' --jq '.[].name' 2>/dev/null \
         | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
# Validated, not merely non-empty. `gh api` prints its error body to STDOUT, so
# a failed call assigns a blob of JSON that would otherwise sail straight into a
# commit message and a sed replacement.
[[ $latest =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || { echo "could not resolve the latest aws-sdk-cpp tag (got: ${latest:-<empty>})" >&2; exit 1; }

echo "aws-sdk-cpp: pinned $cur, latest $latest"
if [[ $cur != "$latest" ]]; then
  if (( ! DRY )); then
    sed -i.bak "s/^set(AWSKMS_AWS_SDK_TAG \"$cur\"/set(AWSKMS_AWS_SDK_TAG \"$latest\"/" "$PIN_FILE"
    rm -f "$PIN_FILE.bak"
    git add "$PIN_FILE"
  fi
  # The body is not decoration. A bump moves vendored s2n and regenerates the
  # KMS model mappers. Both configure-time patches validate exact source shapes.
  # In particular, the two s2n patches assert exact KDF macro and
  # ASN1_STRING_data source shapes, so they require review if upstream fixes
  # either issue or moves the code.
  # Whoever reviews this needs to know that before they see a red build.
  commit "$(printf 'build: bump aws-sdk-cpp to %s\n\n%s' "$latest" \
"Was $cur.

This moves vendored s2n. scripts/patch-s2n-empty-kdf.sh and
scripts/patch-s2n-openssl4.sh assert exact source shapes and fail loudly when
they change, so a red build here is expected to mean one of:

  * upstream fixed an OpenSSL compatibility issue -- delete that patch and its
    call in cmake/FetchAwsSdkKms.cmake
  * an affected source shape moved -- re-read the KDF boundary or ASN1 call
    sites and update that patch's assertions only after confirming its semantics

The SDK bump also regenerates its KMS KeySpec mappers.
scripts/patch-aws-sdk-keyspec.sh validates their exact shape and occurrence
counts. If it fails, confirm the out-of-scope curve is still excluded from the
linked artifact before updating or deleting that patch.")"
fi

# --- vendored: everything in third_party/vendored.manifest --------------------
# update-vendored.sh already re-downloads, re-checks the API surface against
# src/, and refuses to write when a release drops something we use. This only
# drives it and turns each result into a commit.
while IFS='|' read -r name repo tag _assets _repofiles; do
  name=$(echo "$name" | tr -d ' '); repo=$(echo "$repo" | tr -d ' '); tag=$(echo "$tag" | tr -d ' ')
  [[ -n $name && $name != \#* ]] || continue

  newtag=$(gh api "repos/$repo/releases/latest" --jq .tag_name 2>/dev/null || true)
  # Same reasoning as above: gh prints errors to stdout, so test the SHAPE.
  [[ $newtag =~ ^[A-Za-z0-9._-]+$ ]] \
    || { echo "$name: could not resolve latest release (got: ${newtag:-<empty>}), skipping" >&2; continue; }
  echo "$name: vendored $tag, latest $newtag"
  [[ $tag != "$newtag" ]] || continue

  if (( DRY )); then echo "  would update $name $tag -> $newtag"; continue; fi
  # Not `|| true`: a refusal here means the new release drops something src/
  # uses, which is a fact worth failing on rather than skipping past.
  scripts/update-vendored.sh update "$name" "$newtag"
  git add third_party
  commit "build: bump $name to $newtag

Was $tag. Refreshed by scripts/update-vendored.sh, which re-downloads the
release assets and verifies the API surface src/ depends on still exists."
done < <(grep -v '^[[:space:]]*#' third_party/vendored.manifest | grep '|')

echo
if (( DRY )); then echo "dry run; nothing committed"; exit 0; fi
echo "bumped $bumped dependency(ies)"
# Exit 3, NOT 1, for "nothing to bump". 1 is what every real failure above
# already exits with -- a failed gh call, an unreadable pin, update-vendored.sh
# refusing a release that drops an API we use. Sharing a code meant the caller
# could not tell "all up to date" from "the bump is broken", and vendored.yml
# reported the second as the first: silently no PR, week after week, with a
# green tick. A distinct code makes the two distinguishable.
(( bumped > 0 )) || exit 3
