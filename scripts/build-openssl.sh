#!/usr/bin/env bash
#
# Build an OpenSSL into a prefix, idempotently.
#
#   scripts/build-openssl.sh <version> [prefix]
#
# Default prefix is ~/.cache/awskms-openssl/<version>, which is what CI caches.
# If the prefix already looks complete this exits 0 without doing anything, so it
# is safe to call unconditionally after a cache restore.
#
# THREE CALLERS, one recipe: the openssl-headers matrix (API conformance across
# 3.0 / 3.5 / 4.0), the build job (which compiles the shipped artifact against
# the OLDEST supported headers -- see B4), and the musl legs via ci-alpine.sh.
# They had drifted into two copies already.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

V=${1:?usage: build-openssl.sh <version> [prefix]}
PREFIX=${2:-$HOME/.cache/awskms-openssl/$V}

# All three of these, because each catches a different partial tree:
#
#   configuration.h  core_dispatch.h is SHIPPED, so its presence proves nothing;
#                    configuration.h and opensslconf.h are GENERATED from .h.in
#                    templates, so a bare source tarball fails here as it should.
#   lib/             headers without libraries link nothing.
#   bin/openssl      the CLI is what the runtime lane loads the module into, and
#                    an `install_dev` tree has headers and libs but NO CLI. That
#                    is not hypothetical: a prefix built that way silently
#                    satisfied a PATH prepend, so a "3.0 host" check ran against
#                    the machine's own 3.6 openssl and reported a pass.
if [ -f "$PREFIX/include/openssl/configuration.h" ] &&
   [ -d "$PREFIX/lib" ] && [ -x "$PREFIX/bin/openssl" ]; then
  echo "openssl $V already present at $PREFIX"
  exit 0
fi

jobs=$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu || echo 2 )
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "building openssl $V -> $PREFIX"
curl -fsSL --retry 3 -o "$work/openssl-$V.tar.gz" \
  "https://github.com/openssl/openssl/releases/download/openssl-$V/openssl-$V.tar.gz"
tar xzf "$work/openssl-$V.tar.gz" -C "$work"
cd "$work/openssl-$V"

# --libdir=lib because some Linux configurations install to lib64, which would
# make the cache path and find_package platform-dependent for no reason.
# --openssldir keeps the built CLI from reading /etc/ssl and picking up a system
# config that activates providers.
#
# Docs are skipped by building the `build_sw` target rather than by passing
# `no-docs`, which 3.0 does not accept -- measured: "***** Unsupported options:
# no-docs", since it arrived after 3.0. build_sw exists in every version in the
# matrix, so one recipe covers them all with no version-conditional flags.
./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib no-tests
make -j"$jobs" build_sw
# install_sw rather than install_dev: the CLI comes with it, and check-load.sh
# and the HTTP KMS stub both need a real `openssl` of a known version.
make install_sw

echo "openssl $V installed at $PREFIX"
