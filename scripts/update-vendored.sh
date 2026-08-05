#!/usr/bin/env bash
#
# Refreshes third_party/ from upstream releases, and verifies that what is
# checked in really is what upstream published.
#
#   scripts/update-vendored.sh verify [name...]      bytes match the recorded release
#   scripts/update-vendored.sh check  [name...]      recorded release vs latest upstream
#   scripts/update-vendored.sh update <name> [tag]   fetch and install
#
# Dependabot cannot do any of this. Its ecosystems key off a manifest or a git
# submodule, and a vendored amalgamation is neither: ada's ada.cpp/ada.h/ada_c.h
# exist only as release assets, since upstream's singleheader/ directory holds
# the generator rather than the generated files. Making it a submodule would mean
# running amalgamate.py at build time -- a python dependency and codegen in the
# build -- which trades away the hermetic offline build the vendoring exists for.
#
# `verify` is what makes a version bump honest. A tool that rewrites the recorded
# version without replacing the source produces a green PR that ships different
# code than it claims; here that PR fails until `update` has actually run.
#
# `update` deliberately does not build or test. CI does both on the resulting
# commit, against every OpenSSL in the matrix rather than the one on this
# machine, so duplicating it here would be the weaker check of the two.
#
# Needs `gh`, which is what the Actions-pin notes in TODO.txt already assume and
# what shells out to the official tool rather than reimplementing it -- the same
# stance scripts/aws-cli.mjs takes with `aws`. The one cost is that gh requires
# authentication even to read public data, where a plain curl would not; in
# Actions that is `GH_TOKEN: ${{ github.token }}`. Worth it to avoid hand-parsing
# API JSON and hand-building release-asset URLs.
#
# Kept to bash 3.2 features, since that is what macOS ships.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
MANIFEST=third_party/vendored.manifest

TMP=$(mktemp -d -t awskms-vendored.XXXXXX) || { echo "mktemp failed" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT

fail=0
drifted=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
die()  { printf '\033[31merror\033[0m %s\n' "$1" >&2; exit 1; }

trim() { local s=$1; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }

command -v gh >/dev/null || die "gh is required (https://cli.github.com); it also needs to be authenticated"

latest_tag() { gh api "repos/$1/releases/latest" --jq .tag_name 2>/dev/null; }

# Tag schemes differ between projects, so the manifest stores the tag verbatim
# and the human-facing version is that minus a leading v.
version_of() { printf '%s' "${1#v}"; }

# Emits: name|repo|tag|assets|repofiles for each requested dep (all, if none).
select_deps() {
  local name repo tag assets repofiles w found
  while IFS='|' read -r name repo tag assets repofiles; do
    name=$(trim "$name")
    [[ -z $name || $name == \#* ]] && continue
    if (( $# )); then
      found=0
      for w in "$@"; do [[ $w == "$name" ]] && found=1; done
      (( found )) || continue
    fi
    printf '%s|%s|%s|%s|%s\n' "$name" "$(trim "$repo")" "$(trim "$tag")" "$(trim "$assets")" "$(trim "$repofiles")"
  done < "$MANIFEST"
}

# Release assets and repo-tree files come from two different places, which is why
# the manifest lists them in separate columns.
fetch_file() {
  local repo=$1 tag=$2 file=$3 assets=$4 dest=$5
  case " $assets " in
    *" $file "*) gh release download "$tag" -R "$repo" -p "$file" -O "$dest" --clobber 2>/dev/null ;;
    *)           gh api -H "Accept: application/vnd.github.raw" "repos/$repo/contents/$file?ref=$tag" >"$dest" 2>/dev/null ;;
  esac
}

# The API surface check is ada-specific on purpose. What "the API we depend on"
# means is a property of the dependency, not something to guess for a second one
# that does not exist yet; add a branch here when it does.
check_api() {
  local name=$1 dir=$2 header used sym missing=""
  [[ $name == ada ]] || return 0
  header="$dir/ada_c.h"
  [[ -f $header ]] || { bad "$name: $header missing"; return 1; }
  # Drop #include lines first, or "ada_c.h" harvests a bogus ada_c identifier.
  used=$(grep -hv '#include' src/*.c src/*.h 2>/dev/null | grep -ohE '\bada_[a-z0-9_]+' | sort -u)
  while read -r sym; do
    [[ -z $sym ]] && continue
    grep -q "\\b$sym\\b" "$header" || missing="$missing $sym"
  done <<<"$used"
  if [[ -n $missing ]]; then
    bad "$name: used by src/ but absent from the vendored header:$missing"
    return 1
  fi
  pass "$name: all $(grep -c . <<<"$used" | tr -d ' ') ada_* identifiers used by src/ exist in the header"
}

readme_of() { printf 'third_party/%s/README.awskms.md' "$1"; }

cmd_verify() {
  local name repo tag assets repofiles f want readme
  while IFS='|' read -r name repo tag assets repofiles; do
    echo
    echo "$name $(version_of "$tag")  ($repo $tag)"
    # shellcheck disable=SC2086 # both columns are deliberately space-separated lists
    for f in $assets $repofiles; do
      want="third_party/$name/$f"
      if [[ ! -f $want ]]; then bad "$f: not vendored"; continue; fi
      if ! fetch_file "$repo" "$tag" "$f" "$assets" "$TMP/$f"; then
        bad "$f: could not fetch from upstream"; continue
      fi
      if cmp -s "$TMP/$f" "$want"; then
        pass "$f: byte-identical to upstream ($(wc -c <"$want" | tr -d ' ') bytes)"
      else
        bad "$f: DIFFERS from upstream $tag -- the tree is not what the manifest claims"
      fi
    done
    check_api "$name" "third_party/$name"
    # A stale README is the same silent lie as stale bytes, one layer up.
    readme=$(readme_of "$name")
    if [[ -f $readme ]]; then
      if head -1 "$readme" | grep -q "^$name $(version_of "$tag")[^0-9]"; then
        pass "$(basename "$readme") records $(version_of "$tag")"
      else
        bad "$(basename "$readme") disagrees with the manifest: $(head -1 "$readme")"
      fi
    fi
  done < <(select_deps "$@")
}

cmd_check() {
  local name repo tag assets repofiles latest
  while IFS='|' read -r name repo tag assets repofiles; do
    latest=$(latest_tag "$repo")
    if [[ -z $latest ]]; then bad "$name: could not read the latest release of $repo"; continue; fi
    if [[ $latest == "$tag" ]]; then
      pass "$name $(version_of "$tag") is the latest release of $repo"
    else
      # Parseable on purpose: the scheduled workflow turns these lines into
      # issues. Format is "drift: <name> <recorded> <latest>".
      printf '  \033[33mdrift\033[0m %s %s -> %s available (%s)\n' \
        "$name" "$(version_of "$tag")" "$(version_of "$latest")" "$repo"
      printf 'drift: %s %s %s\n' "$name" "$(version_of "$tag")" "$(version_of "$latest")"
      drifted=1
    fi
  done < <(select_deps "$@")
}

cmd_update() {
  local want=${1:-} newtag=${2:-} line name repo tag assets repofiles f ver readme
  [[ -n $want ]] || die "usage: update-vendored.sh update <name> [tag]"
  line=$(select_deps "$want")
  [[ -n $line ]] || die "no dependency named '$want' in $MANIFEST"
  IFS='|' read -r name repo tag assets repofiles <<<"$line"

  [[ -n $newtag ]] || newtag=$(latest_tag "$repo")
  [[ -n $newtag ]] || die "could not resolve the latest release of $repo"
  echo "$name: $tag -> $newtag"
  [[ $newtag == "$tag" ]] && echo "  (already recorded; refetching to confirm the tree matches)"

  # shellcheck disable=SC2086
  for f in $assets $repofiles; do
    fetch_file "$repo" "$newtag" "$f" "$assets" "$TMP/$f" || die "could not fetch $f at $newtag"
    printf '  fetched %s (%s bytes)\n' "$f" "$(wc -c <"$TMP/$f" | tr -d ' ')"
  done

  # Check the API against the NEW header before overwriting anything, so a
  # breaking release leaves the tree untouched rather than half-updated.
  echo
  check_api "$name" "$TMP" || die "aborted: $newtag drops something src/ uses. Nothing was written."

  echo
  # shellcheck disable=SC2086
  for f in $assets $repofiles; do
    if cmp -s "$TMP/$f" "third_party/$name/$f"; then
      pass "$f unchanged"
    else
      cp "$TMP/$f" "third_party/$name/$f" && pass "$f updated"
    fi
  done

  ver=$(version_of "$newtag")
  readme=$(readme_of "$name")
  if [[ -f $readme ]]; then
    sed "1s/^$name [0-9][^,]*,/$name $ver,/" "$readme" > "$TMP/readme" && cp "$TMP/readme" "$readme"
  fi
  # ${name} braced, or the following [ reads as an array subscript.
  sed "s#^\\([[:space:]]*${name}[[:space:]]*|[^|]*|\\)[^|]*#\\1 $newtag #" "$MANIFEST" > "$TMP/manifest" \
    && cp "$TMP/manifest" "$MANIFEST"
  pass "recorded $ver in $MANIFEST and $(basename "$readme")"

  echo
  echo "next: rebuild, run the suites, and commit third_party/ together with the manifest."
}

case "${1:-verify}" in
  verify) shift || true; cmd_verify "$@" ;;
  check)  shift || true; cmd_check  "$@" ;;
  update) shift || true; cmd_update "$@" ;;
  *) die "usage: update-vendored.sh [verify|check|update] ..." ;;
esac

echo
# 0 current / 1 something is wrong / 2 an upstream release is newer. `check`
# separates the last two so a scheduled drift notification is not reported as a
# broken build.
if (( fail )); then echo "FAILED"; exit 1; fi
if (( drifted )); then echo "drift found"; exit 2; fi
echo "all checks passed"
