#!/usr/bin/env bash
#
# Does this module load on the OLDEST OpenSSL we claim to support?
#
#   scripts/check-symbol-floor.sh <module> <libcrypto-or-prefix>...
#
# WHY THIS EXISTS. The module links no libcrypto by design -- every OpenSSL call
# stays an undefined symbol and binds at dlopen to whatever the host provides.
# That makes the required symbol set a function of the HEADERS present on the
# build machine, and nothing else notices when it changes:
#
#   * no compiler warning -- the headers are doing exactly what they mean to
#   * no linker error -- we deliberately link nothing, so there is no link step
#     that could catch a missing symbol. The property that makes the design work
#     is the property that hides this.
#   * source review finds nothing -- the version dependency is in OpenSSL's
#     headers, not in our code, and often not even in code we wrote
#   * check-openssl-matrix.sh passes -- it compiles against each header tree and
#     each build is correct FOR THAT HEADER. The defect only exists when the axes
#     are CROSSED: built against headers A, loaded against libcrypto B, B < A.
#
# MEASURED INSTANCE (B4, 2026-08-06). Vendored s2n calls EVP_MD_CTX_size, which
# is a MACRO. Under 3.0 headers it expands to
# EVP_MD_get_size(EVP_MD_CTX_get0_md(e)); from 3.4 it expands to the function
# EVP_MD_CTX_get_size_ex, which does not exist before 3.4. Identical pinned
# source, different undefined symbol, decided entirely by the build host. The
# shipped artifact therefore could not dlopen on an OpenSSL 3.0 host at all --
# "symbol not found in flat namespace", before any of our code runs.
#
# This costs no node and no runtime host: it is symbol arithmetic against a
# libcrypto that is already on disk.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
# shellcheck source=scripts/lib-symbols.sh
. scripts/lib-symbols.sh

die() { printf '\033[31merror\033[0m %s\n' "$1" >&2; exit 2; }

[[ $# -ge 2 ]] || die "usage: check-symbol-floor.sh <module> <libcrypto-or-prefix>..."

MODULE=$1; shift
[[ -f $MODULE ]] || die "no such module: $MODULE"

# Accept either a libcrypto directly or an OpenSSL prefix, because CI has the
# prefix and a developer usually has the library.
refs=()
for a in "$@"; do
  if [[ -d $a ]]; then
    # -L because a prefix is routinely a symlink -- homebrew's opt/openssl@3
    # points into Cellar, and find would not descend into it otherwise.
    found=$(find -L "$a" -maxdepth 2 \( -name 'libcrypto.so*' -o -name 'libcrypto*.dylib' \) 2>/dev/null | sort | head -1)
    [[ -n $found ]] || die "no libcrypto under prefix $a"
    refs+=("$found")
  elif [[ -f $a ]]; then
    refs+=("$a")
  else
    die "no such libcrypto or prefix: $a"
  fi
done

need=$(awskms_needed_symbols "$MODULE")
have=$(awskms_provided_symbols "${refs[@]}")

n_need=$(printf '%s\n' "$need" | grep -c . || true)
n_have=$(printf '%s\n' "$have" | grep -c . || true)

echo "module:    $MODULE"
for r in "${refs[@]}"; do echo "reference: $r"; done
echo "           $n_need OpenSSL symbols needed, $n_have exported by the reference"

missing=$(comm -23 <(printf '%s\n' "$need") <(printf '%s\n' "$have") || true)

if [[ -z $missing ]]; then
  printf '  \033[32mok\033[0m   every OpenSSL symbol the module needs exists in the reference\n'
  exit 0
fi

printf '  \033[31mFAIL\033[0m the module needs symbols the reference does not export.\n'
printf '       On such a host dlopen fails OUTRIGHT -- the provider never loads,\n'
printf '       and nothing reports why. Build against the oldest supported\n'
printf '       headers so the required set stays within that floor.\n\n'
printf '%s\n' "$missing" | sed 's/^/       /'
exit 1
