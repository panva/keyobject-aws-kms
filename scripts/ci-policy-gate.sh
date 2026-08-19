#!/usr/bin/env bash
# Reject stale project residue and non-relocatable distribution artifacts.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

removed_curve='secp256''k1'
removed_enum='ECC_SECG_''P256K1'
removed_oid='1.3.132.''0.10'
escaped_removed_oid=${removed_oid//./\\.}
stale_marker='(^|[^[:alnum:]_])(todo|wip|journal|work[ -]?in[ -]?progress)([^[:alnum:]_]|$)'
forbidden_source="$removed_curve|$removed_enum|$escaped_removed_oid|/Users/[^/]+/|/home/[^/]+/|/private/var/folders/"
forbidden_artifact="$removed_curve|$removed_enum|$escaped_removed_oid|/Users/[^/]+/|/home/runner/|/private/var/folders/"
absolute_repository_path='(^|[^[:alnum:]_./~-])/src/'

scan_contains_absolute_path() {
  local scan=$1
  local path=$2
  local line prefix rest

  while IFS= read -r line || [[ -n $line ]]; do
    rest=$line
    while [[ $rest == *"$path"* ]]; do
      prefix=${rest%%"$path"*}
      if [[ -z $prefix || ${prefix: -1} != [[:alnum:]_./~-] ]]; then
        return 0
      fi
      rest=${rest#*"$path"}
    done
  done < <(grep -F "$path" "$scan" || true)
  return 1
}

check_artifact_scan() {
  local subject=$1
  local scan=$2
  local matches

  if scan_contains_absolute_path "$scan" "$PWD/"; then
    die "$subject embeds repository path $PWD"
  fi
  if [[ -n ${HOME:-} ]] && scan_contains_absolute_path "$scan" "$HOME/"; then
    die "$subject embeds home path $HOME"
  fi
  matches=$(grep -E "$forbidden_artifact|$absolute_repository_path" "$scan" || true)
  [[ -z $matches ]] || die "$subject embeds forbidden residue:\n$matches"
}

case ${1:-} in
  source)
    stale=$(
      find . -maxdepth 1 -type f -iname '*[Tt][Oo][Dd][Oo]*' -print
      find docs -maxdepth 1 -type f \
        \( -iname '*[Jj][Oo][Uu][Rr][Nn][Aa][Ll]*' \
        -o -iname '*[Dd][Ii][Ss][Tt][Rr][Ii][Bb][Uu][Tt][Ii][Oo][Nn]*' \) \
        -print
    )
    [[ -z $stale ]] || die "stale project-history file remains:\n$stale"

    matches=$(
      git ls-files --cached --others --exclude-standard -z |
        while IFS= read -r -d '' file; do
          [[ -f $file ]] || continue
          [[ $file == scripts/ci-policy-gate.sh ]] && continue
          [[ $file == third_party/* ]] && continue
          if [[ $file == README.md ]]; then
            # The repository status note is intentional; every other stale
            # marker in README still fails this gate.
            grep -IHniE "$forbidden_source|$stale_marker" "$file" |
              grep -Fv 'README.md:2:> **Work in progress.** This package is not yet ready for production use.' || true
          else
            grep -IHniE "$forbidden_source|$stale_marker" "$file" || true
          fi
        done
    )
    [[ -z $matches ]] || die "forbidden source residue found:\n$matches"
    echo 'ok: no stale files or markers, private workspace paths, or removed-curve residue'
    ;;

  archive)
    archive=${2:?usage: ci-policy-gate.sh archive <archive>}
    [[ -f $archive ]] || die "archive not found: $archive"
    listing=$(tar tzf "$archive")
    if grep -Eq '(^|/)\.\.(/|$)|^/' <<<"$listing"; then
      die "archive contains an unsafe path"
    fi
    unpack=$(mktemp -d)
    scan=$(mktemp)
    trap 'rm -rf "$unpack"; rm -f "$scan"' EXIT
    tar xzf "$archive" -C "$unpack"
    while IFS= read -r -d '' file; do
      strings "$file" >> "$scan"
    done < <(find "$unpack" -type f -print0)
    check_artifact_scan archive "$scan"
    echo 'ok: archive contains no private path or removed-curve residue'
    ;;

  artifact)
    module=${2:?usage: ci-policy-gate.sh artifact <module> [archive]}
    archive=${3:-}
    [[ -f $module ]] || die "module not found: $module"
    directory=$(dirname "$module")
    for required in awskms.relocatable.cnf awskms-backend awskms-dependencies; do
      [[ -s $directory/$required ]] || die "$directory/$required is missing or empty"
    done

    scan=$(mktemp)
    trap 'rm -f "$scan"; [[ -z ${unpack:-} ]] || rm -rf "$unpack"' EXIT
    strings "$module" > "$scan"
    cat "$directory/awskms.relocatable.cnf" "$directory/awskms-dependencies" >> "$scan"
    check_artifact_scan artifact "$scan"

    if [[ -n $archive ]]; then
      [[ -f $archive ]] || die "archive not found: $archive"
      listing=$(tar tzf "$archive")
      if grep -Eq '(^|/)\.\.(/|$)|^/' <<<"$listing"; then
        die "archive contains an unsafe path"
      fi
      unpack=$(mktemp -d)
      tar xzf "$archive" -C "$unpack"
      while IFS= read -r -d '' file; do
        strings "$file" >> "$scan"
      done < <(find "$unpack" -type f -print0)
      check_artifact_scan archive "$scan"
    fi
    echo 'ok: artifact is relocatable and contains no private path or removed-curve residue'
    ;;

  *)
    die 'usage: ci-policy-gate.sh source | archive <archive> | artifact <module> [archive]'
    ;;
esac
