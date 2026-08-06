# Shared symbol extraction. Sourced, never executed.
#
# Two questions are asked of this module in two different places, and they must
# be asked the SAME way or one of them lies:
#
#   check-load.sh          does this NODE export everything the module needs?
#   check-symbol-floor.sh  does the OLDEST SUPPORTED libcrypto export it?
#
# Both reduce to "needed minus provided", and both depend on two rules that are
# easy to get subtly wrong. They live here so a fix lands in both.
#
# shellcheck shell=bash

# Symbols that belong to OpenSSL rather than to libc, libc++ or the CRT. Matching
# by prefix rather than by "everything undefined" is deliberate: the module also
# imports malloc, memcpy and friends, which no libcrypto exports and which are
# not a version-skew question.
AWSKMS_OSSL_RE='^(OSSL_|OPENSSL_|EVP_|BN_|ERR_|CRYPTO_|ASN1_|EC_|ECDSA_|ECDH_|RSA_|DSA_|DH_|X509_|X509V3_|d2i_|i2d_|PEM_|HMAC_|OBJ_|BIO_|RAND_|SHA[0-9]|MD5_|CONF_|NCONF_|UI_|SSL_|TLS_|CMS_|OCSP_|PKCS[0-9]|EVP)'

# The OpenSSL symbols a module REQUIRES, one per line, sorted, no leading _.
#
# WEAK undefined symbols are excluded, and that exclusion is load-bearing rather
# than tidiness. A weak undefined resolves to 0 when the host does not provide
# it, and the referencing code tests for it at runtime. aws-c-cal does exactly
# that to support several libcrypto vintages at once: on Linux the module carries
# weak references to the OpenSSL 1.0.2-era EVP_MD_CTX_create / EVP_MD_CTX_destroy
# / HMAC_CTX_init / HMAC_CTX_cleanup, none of which any modern libcrypto exports
# and none of which it needs to. Counted as requirements they fail the audit on a
# module that loads perfectly -- measured: 186 strong against 9 weak, with the
# module reported `status: active` by the openssl CLI, which uses RTLD_NOW.
awskms_needed_symbols() {
  local module=$1
  if [[ $(uname -s) == Darwin ]]; then
    # `nm -m` lines end with " (dynamically looked up)", so strip that before
    # taking the symbol as the last field.
    nm -m -u "$module" | grep -v 'weak external' \
      | sed 's/ (dynamically looked up)$//' | awk '{print $NF}' \
      | sed 's/^_//' | grep -E "$AWSKMS_OSSL_RE" | sort -u
  else
    # $1=="U" keeps strong undefined only; a weak undefined shows as 'w'.
    # @VERSION is stripped for the same reason as in awskms_provided_symbols.
    nm -D --undefined-only "$module" | awk '$1=="U"{print $NF}' \
      | sed 's/@.*//' | grep -E "$AWSKMS_OSSL_RE" | sort -u
  fi
}

# The symbols one or more binaries PROVIDE, one per line, sorted, no leading _.
# Accepts executables and shared libraries alike, so the same function serves a
# node binary and a bare libcrypto.
#
# ELF SYMBOL VERSIONING is stripped. A real libcrypto.so exports
# `CRYPTO_free@@OPENSSL_3.0.0`, while the module's undefined reference is the
# bare `CRYPTO_free`, so an exact-match comparison reports every single core
# symbol as missing. Measured: against a from-source OpenSSL 3.0.21 on musl this
# produced a 68-symbol "failure" listing CRYPTO_malloc and CRYPTO_free.
#
# This path was previously unreachable, which is why it survived: check-load.sh
# only ever audits against node, and node bundles OpenSSL statically, so its
# shared-library branch never ran on a versioned library. It became reachable
# the moment check-symbol-floor.sh started pointing at a bare libcrypto.
awskms_provided_symbols() {
  local f
  {
    for f in "$@"; do
      [[ -f $f ]] || continue
      if [[ $(uname -s) == Darwin ]]; then
        nm -gU "$f" 2>/dev/null | awk '{print $3}' | sed 's/^_//'
      else
        nm -D --defined-only "$f" 2>/dev/null | awk '{print $NF}' | sed 's/@.*//'
      fi
    done
  } | sort -u
}

# Any shared libcrypto/libssl a binary pulls in. A node with bundled OpenSSL
# returns nothing, which is correct -- its symbols come from the executable.
awskms_linked_ssl_libs() {
  local bin=$1
  if [[ $(uname -s) == Darwin ]]; then
    otool -L "$bin" 2>/dev/null | awk '/lib(crypto|ssl)/{print $1}'
  else
    ldd "$bin" 2>/dev/null | awk '/lib(crypto|ssl)/{print $3}'
  fi
}
