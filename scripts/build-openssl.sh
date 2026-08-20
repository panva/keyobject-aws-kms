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
# The header, artifact, runtime, and musl CI lanes share this recipe.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

V=${1:?usage: build-openssl.sh <version> [prefix]}
PREFIX=${2:-$HOME/.cache/awskms-openssl/$V}
FIPS=${AWSKMS_OPENSSL_FIPS:-0}
PLATFORM=$(uname -s)
MACOS_DEPLOYMENT_MARKER=
case $PLATFORM in
  Darwin)
    FIPS_MODULE="$PREFIX/lib/ossl-modules/fips.dylib"
    # Clang otherwise targets the runner's host release. Keep standalone builds
    # on the supported floor while allowing callers to request another target.
    MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-${AWSKMS_MACOS_FLOOR:-13.5}}
    export MACOSX_DEPLOYMENT_TARGET
    MACOS_DEPLOYMENT_MARKER="$PREFIX/.awskms-macos-deployment-target"
    ;;
  *) FIPS_MODULE="$PREFIX/lib/ossl-modules/fips.so" ;;
esac

# Require generated headers, libraries, the CLI, and the exact macOS deployment
# target before accepting a cache or an existing local prefix.
if [ -f "$PREFIX/include/openssl/configuration.h" ] &&
   [ -d "$PREFIX/lib" ] && [ -x "$PREFIX/bin/openssl" ] &&
   { [ "$PLATFORM" != Darwin ] || {
     [ -f "$MACOS_DEPLOYMENT_MARKER" ] &&
       [ "$(cat "$MACOS_DEPLOYMENT_MARKER")" = "$MACOSX_DEPLOYMENT_TARGET" ];
   }; } &&
   { [ "$FIPS" != 1 ] || {
     [ -f "$PREFIX/.awskms-fips-enabled" ] &&
       [ -f "$FIPS_MODULE" ] &&
       [ -f "$PREFIX/ssl/fipsmodule.cnf" ];
   }; }; then
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

# Keep libraries in one cross-platform cache path and isolate the CLI config.
# `build_sw` skips documentation and is available throughout the version matrix.
configure_extra=()
if [ "$FIPS" = 1 ]; then configure_extra+=(enable-fips); fi
./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib \
  no-tests ${configure_extra[@]+"${configure_extra[@]}"}
make -j"$jobs" build_sw
# install_sw rather than install_dev: the CLI comes with it, and check-load.sh
# and the HTTP KMS stub both need a real `openssl` of a known version.
make install_sw
if [ "$FIPS" = 1 ]; then
  make install_fips
  [ -f "$FIPS_MODULE" ]
  [ -f "$PREFIX/ssl/fipsmodule.cnf" ]
  touch "$PREFIX/.awskms-fips-enabled"
fi
if [ "$PLATFORM" = Darwin ]; then
  printf '%s\n' "$MACOSX_DEPLOYMENT_TARGET" > "$MACOS_DEPLOYMENT_MARKER"
fi

echo "openssl $V installed at $PREFIX"
