#!/usr/bin/env bash
#
# Verifies a built awskms module is loadable and hygienic. Run after every build:
# a provider that fails to load from openssl.cnf produces NO diagnostic at all --
# the process starts fine and then fails at the first createPrivateKey() -- so
# this script is the only thing standing between you and that.
#
#   scripts/check-load.sh [build-dir] [node-binary ...]
#
# With no node binaries it checks the openssl CLI only. Pass the OLDEST node you
# intend to support first: the undefined-symbol audit is only as good as the
# oldest host it is run against.
set -uo pipefail

# The symbol-extraction rules are shared with check-symbol-floor.sh, which asks
# the same "needed minus provided" question against the oldest supported
# libcrypto rather than against a node. They are subtle enough -- which prefixes
# count as OpenSSL, and why weak undefined symbols must NOT count as
# requirements -- that keeping two copies would guarantee they drift.
# shellcheck source=scripts/lib-symbols.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib-symbols.sh"

BUILD_DIR=${1:-build}
shift || true
# ${NODES[@]+...} so the documented "no node binaries" mode does not die with
# "unbound variable" under set -u on macOS bash 3.2, where an empty array is unset.
NODES=("$@")

if [[ $(uname -s) == Darwin ]]; then MODULE="$BUILD_DIR/aws-kms.dylib"; else MODULE="$BUILD_DIR/aws-kms.so"; fi

fail=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }

echo "module: $MODULE"
[[ -f $MODULE ]] || { bad "not built"; exit 1; }

# --- 1. exactly these two exported symbols ---------------------------------
#
# EXACTLY, not at-most: an export list that quietly grows is how a module starts
# interposing on its host. Two, because one artifact is both the OpenSSL provider
# and its own N-API addon.
echo
echo "exported symbols"
if [[ $(uname -s) == Darwin ]]; then
  exported=$(nm -gU "$MODULE" 2>/dev/null | awk '$2=="T"{print $3}' | sed 's/^_//' | sort)
else
  exported=$(nm -D --defined-only "$MODULE" 2>/dev/null | awk '$2=="T"{print $3}' | sort)
fi
expected=$(printf 'OSSL_provider_init\nnapi_register_module_v1\n' | sort)
if [[ $exported == "$expected" ]]; then
  pass "exports exactly OSSL_provider_init and napi_register_module_v1"
else
  bad "unexpected export set: $(echo "$exported" | tr '\n' ' ')"
fi

# --- 1b. every napi reference must be WEAK ---------------------------------
#
# A strong napi reference is fatal in any host without node's symbols -- the
# `openssl` CLI, or any other application loading the provider -- because
# OpenSSL's DSO layer uses RTLD_NOW and resolves everything eagerly. A weak one
# resolves to 0 there and the code tests for it.
echo
echo "napi references"
if [[ $(uname -s) == Darwin ]]; then
  strong=$(nm -m -u "$MODULE" 2>/dev/null | grep '_napi_' | grep -v 'weak external' || true)
else
  strong=$(nm -D --undefined-only "$MODULE" 2>/dev/null | awk '$1=="U" && $2 ~ /^napi_/' || true)
fi
if [[ -z $strong ]]; then
  pass "all napi references are weak (module still loads in non-node hosts)"
else
  bad "STRONG napi reference(s) -- the module will not load outside node:"
  sed 's/^/       /' <<<"$strong"
fi

# --- 2. no second OpenSSL (or TLS stack) dragged in ------------------------
echo
echo "shared library dependencies"
if [[ $(uname -s) == Darwin ]]; then deps=$(otool -L "$MODULE" | tail -n +2); else deps=$(readelf -d "$MODULE" | grep NEEDED || true); fi
if grep -qiE 'libcrypto|libssl|libcurl' <<<"$deps"; then
  bad "links a second crypto/TLS stack:"; grep -iE 'libcrypto|libssl|libcurl' <<<"$deps" | sed 's/^/       /'
else
  pass "no libcrypto / libssl / libcurl"
fi

# --- 3. the openssl CLI can load it ---------------------------------------
# This works because the CLI already has libcrypto loaded before it dlopen()s
# the module, so the module's undefined symbols resolve. Fastest smoke test.
echo
echo "openssl CLI"
if command -v openssl >/dev/null; then
  out=$(openssl list -providers -provider-path "$BUILD_DIR" -provider aws-kms 2>&1)
  if grep -q 'aws-kms' <<<"$out" && grep -q 'active' <<<"$out"; then
    pass "loads and reports active ($(openssl version | cut -d' ' -f1-2))"
  else
    bad "did not load:"; sed 's/^/       /' <<<"$out"
  fi
else
  echo "  skip (no openssl in PATH)"
fi

# --- 4. per-node: undefined symbols must all exist, and it must load -------
CNF=$(mktemp -t awskms-check.XXXXXX)
cat >"$CNF" <<EOF
openssl_conf = init
nodejs_conf  = init
[init]
providers   = provider_sect
alg_section = algs_sect
[algs_sect]
default_properties = ?keyobject.aws_kms!=yes
[provider_sect]
default = default_sect
aws-kms = awskms_sect
[default_sect]
activate = 1
[awskms_sect]
module   = $(cd "$(dirname "$MODULE")" && pwd)/$(basename "$MODULE")
activate = 1
EOF
trap 'rm -f "$CNF"' EXIT

for node in ${NODES[@]+"${NODES[@]}"}; do
  echo
  echo "node: $node"
  if [[ ! -x $node ]]; then bad "not executable"; continue; fi
  ver=$("$node" -p 'process.version + " openssl=" + process.versions.openssl + " shared=" + !!process.config.variables.node_shared_openssl' 2>/dev/null)
  echo "  $ver"

  # Symbol skew, not version numbers, is the real portability limit: two node
  # builds reporting the same OpenSSL version can export different symbol sets,
  # and a missing one is an all-or-nothing load failure that node hides.
  #
  # Where the symbols live depends on how node was built. With a statically
  # bundled OpenSSL they are re-exported by the executable itself; with
  # --shared-openssl they are in the libcrypto/libssl it links, so those have to
  # be included or every shared-openssl host looks broken.
  # Only OpenSSL symbols are audited. Everything else the module needs (libc,
  # libc++) is satisfied through its own declared dependencies in the normal way;
  # it is specifically the OpenSSL ABI that has to come from the host process.
  need=$(awskms_needed_symbols "$MODULE")
  libs=$(awskms_linked_ssl_libs "$node")
  # A node with BUNDLED OpenSSL reports no libs, which is correct -- its OpenSSL
  # symbols are exported by the executable itself. Unquoted on purpose: $libs is
  # a newline-separated list to be split into separate arguments.
  # shellcheck disable=SC2086
  have=$(awskms_provided_symbols "$node" $libs)
  if [[ -n $libs ]]; then
    echo "  (shared OpenSSL: $(echo "$libs" | tr '\n' ' '))"
  fi
  echo "  ($(wc -l <<<"$need" | tr -d ' ') OpenSSL symbols needed)"
  missing=$(comm -23 <(echo "$need") <(echo "$have") || true)
  if [[ -z $missing ]]; then
    pass "every OpenSSL symbol the module needs is exported by this node"
  else
    bad "symbols this node does not export (module will fail to load, silently):"
    sed 's/^/       /' <<<"$missing" | head -20
  fi

  # Actually load it, and prove the provider is REACHABLE rather than merely that
  # node survived startup.
  #
  # The discriminator is a bare "aws-kms:" URI, which src/store.c rejects while
  # parsing -- before awskms_kms_get_public_key -- so it costs no network call, no
  # credentials and no IAM. What comes back says exactly who handled it:
  #
  #   ERR_OSSL_AWSKMS_INVALID_URI     our loader ran. The provider is live.
  #   ERR_OSSL_OSSL_STORE_UNSUPPORTED node accepts URL keys but nothing claims the
  #                                   awskms scheme -- i.e. the module did not load.
  #                                   This identifies a silent provider-load failure.
  #   ERR_INVALID_ARG_TYPE            this node lacks the OSSL_STORE URL-key
  #                                   capability, so activation is not observable.
  #
  # Delegate to check.mjs so the reachability probe has one implementation.
  # 0 working / 1 broken / 2 this node lacks the capability, so skip.
  out=$("$node" --openssl-config="$CNF" "$(dirname "${BASH_SOURCE[0]}")/check.mjs" 2>&1)
  case $? in
    0) pass "provider is loaded and reachable (aws-kms: URI reached our store loader)" ;;
    2) echo "  skip (this node has no OSSL_STORE loader; activation not observable)" ;;
    *) bad "node boots but the provider is not reachable:"
       sed 's/^/       /' <<<"$out" | tail -12 ;;
  esac
done

echo
if (( fail )); then echo "FAILED"; exit 1; fi
echo "all checks passed"
