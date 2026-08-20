#!/usr/bin/env bash
#
# Does this module load on the OLDEST OpenSSL we claim to support?
#
#   scripts/check-symbol-floor.sh <module> <libcrypto-or-prefix>...
#
# The module links no libcrypto by design: every OpenSSL call stays undefined
# and binds at dlopen to the host. The required symbol set is therefore a
# function of the headers present on the build machine:
#
#   * no compiler warning -- the headers are doing exactly what they mean to
#   * no linker error -- we deliberately link nothing, so there is no link step
#     that could catch a missing symbol. The property that makes the design work
#     is the property that hides this.
#   * source review may not reveal a dependency introduced by OpenSSL headers
#   * check-openssl-matrix.sh passes -- it compiles against each header tree and
#     each build is correct FOR THAT HEADER. The defect only exists when the axes
#     are CROSSED: built against headers A, loaded against libcrypto B, B < A.
#
# For example, vendored s2n calls the EVP_MD_CTX_size macro. Under 3.0 headers it
# expands to
# EVP_MD_get_size(EVP_MD_CTX_get0_md(e)); from 3.4 it expands to the function
# EVP_MD_CTX_get_size_ex, which does not exist before 3.4. Identical pinned
# source can thus acquire a different undefined symbol solely from its build
# headers and become unloadable below that symbol's introduction version.
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

# A VACUOUS PASS IS A FAILURE. If extraction yields nothing -- wrong nm flags, a
# stripped or unreadable module, a platform branch that silently matched nothing
# -- then `comm` finds no missing symbols and this reports ok having checked
# NOTHING. That is the exact shape of defect this script exists to catch, so it
# must not be able to commit it itself.
if [ "$n_need" -eq 0 ]; then
  printf '  \033[31mFAIL\033[0m extracted ZERO OpenSSL symbols from the module.\n'
  printf '       This check verified nothing. Either the module is not what we\n'
  printf '       think it is, or symbol extraction is broken -- both are bugs.\n'
  exit 1
fi
if [ "$n_have" -eq 0 ]; then
  printf '  \033[31mFAIL\033[0m the reference libcrypto exported ZERO symbols.\n'
  printf '       Nothing was actually compared. Check the reference path.\n'
  exit 1
fi

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
