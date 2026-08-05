#!/usr/bin/env bash
#
# Compiles the module against several OpenSSL header trees.
#
# The module is built against one header tree but must run against whatever
# OpenSSL the host has -- 3.0 at the oldest, with no upper bound. Nothing
# deprecated in 3.0 is used, so 4.x hosts work too; this script is what keeps
# that honest.
#
#   scripts/check-openssl-matrix.sh                    # discover via nix
#   scripts/check-openssl-matrix.sh /a/include /b/include
#
# Discovery expects the nodejs checkout's OpenSSL matrix. Override with
# NODE_REPO=/path/to/node.
set -uo pipefail

# The main checkout, not a worktree: worktrees come and go, and this only needs
# tools/nix/, which any checkout has.
NODE_REPO=${NODE_REPO:-$HOME/repo/node}
includes=("$@")

if (( ${#includes[@]} == 0 )); then
  # Homebrew first: no nix required, and an openssl@N keg is the likeliest thing
  # a contributor already has. Deduplicated below, so overlapping sources are
  # harmless.
  for keg in /opt/homebrew/opt/openssl@* /usr/local/opt/openssl@*; do
    [[ -d $keg/include/openssl ]] && includes+=("$keg/include")
  done

  if command -v nix-build >/dev/null && [[ -f ${NODE_REPO:-}/tools/nix/openssl-matrix.nix ]]; then
    echo "discovering more OpenSSL header trees via nix (${NODE_REPO})..."
    # `openssl` is the matrix's "default" attr, deliberately kept in sync with the
    # version Node bundles -- so it is the single most relevant tree here, and it
    # is NOT named openssl_3_5. Naming it that way silently tested one fewer
    # version than the output implied.
    for attr in openssl openssl_3 openssl_3_6 openssl_4_0; do
      p=$(cd "$NODE_REPO" && nix-build --no-out-link -E \
        "let pkgs = import ./tools/nix/pkgs.nix {}; in (import ./tools/nix/openssl-matrix.nix { inherit pkgs; }).$attr.dev" \
        2>/dev/null | tail -1)
      [[ -d ${p:-}/include ]] && includes+=("$p/include")
    done
  fi

  if (( ${#includes[@]} == 0 )); then
    echo "no OpenSSL header trees found (no homebrew keg, no nix)" >&2
    echo "usage: $0 /path/to/openssl/include ..." >&2
    exit 2
  fi
fi

# Same version from two sources builds the same thing, so keep one per version.
# A newline-delimited string rather than an associative array: macOS ships bash
# 3.2, where `declare -A` does not exist and a version like 3.6.3 used as a
# subscript is evaluated as arithmetic.
uniq=()
seen=$'\n'
for inc in "${includes[@]}"; do
  v=$(sed -n 's/.*OPENSSL_FULL_VERSION_STR *"\([^"]*\)".*/\1/p' "$inc/openssl/opensslv.h" 2>/dev/null | head -1)
  [[ -z $v ]] && v=$inc
  case $seen in *$'\n'"$v"$'\n'*) continue ;; esac
  seen="$seen$v"$'\n'
  uniq+=("$inc")
done
includes=("${uniq[@]}")

fail=0
for inc in "${includes[@]}"; do
  ver=$(sed -n 's/.*OPENSSL_FULL_VERSION_STR *"\([^"]*\)".*/\1/p' "$inc/openssl/opensslv.h" 2>/dev/null | head -1)
  [[ -z $ver ]] && ver=$(basename "$(dirname "$inc")")
  bd="build-ossl-$ver"
  out=$(cmake -S . -B "$bd" -DCMAKE_BUILD_TYPE=Release \
          -DAWSKMS_OPENSSL_INCLUDE_DIR="$inc" 2>&1 &&
        cmake --build "$bd" --parallel 2>&1)
  rc=$?
  warns=$(grep -c 'warning:' <<<"$out")
  if (( rc == 0 )) && grep -q 'Built target awskms' <<<"$out"; then
    if (( warns )); then
      printf '  \033[33mwarn\033[0m %-10s %s warning(s)\n' "$ver" "$warns"
      grep 'warning:' <<<"$out" | head -5 | sed 's/^/       /'
      fail=1
    else
      printf '  \033[32mok\033[0m   %-10s clean\n' "$ver"
    fi
  else
    printf '  \033[31mFAIL\033[0m %-10s\n' "$ver"
    grep -E 'error:' <<<"$out" | head -8 | sed 's/^/       /'
    fail=1
  fi
done

(( fail )) && { echo "FAILED"; exit 1; }
echo "all header trees build clean"
