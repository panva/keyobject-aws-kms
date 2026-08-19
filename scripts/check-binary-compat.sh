#!/usr/bin/env bash
# CI assertion for the platform contract of a distributable module.
set -euo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

mode=${1:?usage: check-binary-compat.sh linux|musl|macos <module> <arch> [floor]}
module=${2:?usage: check-binary-compat.sh linux|musl|macos <module> <arch> [floor]}
arch=${3:?usage: check-binary-compat.sh linux|musl|macos <module> <arch> [floor]}
floor=${4:-}
[[ -f $module ]] || die "module not found: $module"

case "$mode" in
  linux|musl)
    machine=$(readelf -h "$module" | awk -F: '/Machine:/{sub(/^[[:space:]]+/, "", $2); print $2}')
    case "$arch:$machine" in
      x64:*X86-64*|arm64:AArch64) ;;
      *) die "expected $arch ELF, readelf reports '$machine'" ;;
    esac

    needed=$(readelf -d "$module" | awk '/NEEDED/{print $0}')
    if grep -Eq 'libstdc\+\+|libgcc_s' <<<"$needed"; then
      die "C++/GCC runtime is dynamically linked: $needed"
    fi

    versions=$(readelf --version-info "$module")
    runtime_versions=$(grep -Eo '(GLIBCXX|CXXABI|GCC)_[0-9][0-9.]*' <<<"$versions" | sort -u || true)
    [[ -z $runtime_versions ]] || die "dynamic compiler ABI requirements found: $runtime_versions"

    if [[ $mode == musl ]]; then
      glibc_versions=$(grep -Eo 'GLIBC_[A-Za-z0-9_.]+' <<<"$versions" | sort -u || true)
      [[ -z $glibc_versions ]] || die "glibc ABI requirement found in musl artifact: $glibc_versions"
      printf 'ok: %s musl ELF, compiler runtimes static, no glibc ABI\n' "$machine"
      exit 0
    fi

    [[ -n $floor ]] || die "linux mode requires a glibc floor"
    if grep -q 'GLIBC_PRIVATE' <<<"$versions"; then
      die "private glibc ABI requirement found"
    fi
    glibc_versions=$(grep -Eo 'GLIBC_[0-9]+(\.[0-9]+)*' <<<"$versions" | sort -Vu || true)
    [[ -n $glibc_versions ]] || die "no GLIBC symbol versions found; the floor check was vacuous"
    highest=$(sed 's/^GLIBC_//' <<<"$glibc_versions" | sort -V | tail -1)
    if [[ $(printf '%s\n%s\n' "$floor" "$highest" | sort -V | tail -1) != "$floor" ]]; then
      die "module requires GLIBC_$highest, newer than GLIBC_$floor"
    fi
    printf 'ok: %s, GLIBC <= %s, compiler runtimes static\n' "$machine" "$floor"
    ;;

  macos)
    [[ -n $floor ]] || die "macos mode requires a deployment floor"
    actual=$(lipo -archs "$module")
    [[ $actual == "$arch" ]] || die "expected a single $arch slice, found '$actual'"

    minos=$(otool -l "$module" | awk '
      $1 == "cmd" { command = $2 }
      command == "LC_BUILD_VERSION" && $1 == "minos" { print $2; exit }
      command == "LC_VERSION_MIN_MACOSX" && $1 == "version" { print $2; exit }
    ')
    [[ -n $minos ]] || die "no macOS minimum-version load command found"
    [[ $minos == "$floor" ]] || die "expected macOS minimum $floor, found $minos"
    printf 'ok: %s, macOS minimum %s\n' "$actual" "$minos"
    ;;

  *)
    die "unknown mode '$mode'"
    ;;
esac
