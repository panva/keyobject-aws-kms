#!/bin/sh
#
# Everything the musl legs of CI do, run INSIDE an Alpine container.
#
#   scripts/ci-alpine.sh <backend> <arch>        # arch is x64 | arm64
#
# WHY A SCRIPT RATHER THAN `container:` ON THE JOB.
#
# GitHub's runner refuses to run JavaScript actions in an Alpine container on
# anything but x64:
#
#   JavaScript Actions in Alpine containers are only supported on x64 Linux
#   runners. Detected Linux Arm64
#
# It injects its own glibc node to run actions/checkout and friends, and that
# binary cannot execute under musl; on x64 it ships a musl build of the action
# runtime, on arm64 it does not. So `container: node:26-alpine` fails at
# checkout on ubuntu-24.04-arm before any step of ours runs.
#
# Driving the container with `docker run` from an ordinary glibc runner sidesteps
# it entirely: checkout, cache and upload-artifact stay on the HOST, where the
# runner's own node is fine, and only the build and the tests -- which is all
# that actually needs musl -- happen inside. Identical on both architectures.
#
# This is POSIX sh on purpose. It is the entry point, so it runs before `apk add
# bash`; the bash scripts it calls are invoked after that.
set -eu

BACKEND=${1:?usage: ci-alpine.sh <backend> <arch>}
ARCH=${2:?usage: ci-alpine.sh <backend> <arch>}

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

say "prerequisites"
# No sudo, no apt, no toolchain in the base image. linux-headers and perl are
# not optional: the CRT needs the headers, and OpenSSL's own build needs perl.
apk add --no-cache build-base cmake git openssl-dev openssl linux-headers \
  perl bash tar xz curl

# The workspace was checked out on the host by a different uid, and the aws
# backend runs git to fetch the SDK. Without this every git command dies on
# "detected dubious ownership in repository".
git config --global --add safe.directory '*'

say "node"
# nodejs.org/dist publishes no musl builds at all -- that is what
# nodejs/unofficial-builds exists for -- so setup-node cannot serve this leg.
# Taking the floor from there rather than using an image's bundled node pins
# musl to the SAME .node-version as every other target, instead of whatever a
# node:*-alpine tag happens to carry (26.6.0 at the time of writing, which is
# below the floor and has no OSSL_STORE loader).
#
# "Unofficial" is about who builds it, not what it is: the OpenSSL surface these
# expose was compared symbol for symbol against the node:26-alpine image's own
# node and is IDENTICAL (4648 exported OpenSSL symbols, no difference in either
# direction, across two different node versions). Since binding those undefined
# symbols to the host is the entire mechanism this provider rests on, the two
# are interchangeable for building and testing.
v=$(cat .node-version)
url="https://unofficial-builds.nodejs.org/download/release/v$v/node-v$v-linux-$ARCH-musl.tar.xz"
curl -fsSL --retry 3 -o /tmp/node.tar.xz "$url"
mkdir -p /tmp/node
tar xJf /tmp/node.tar.xz -C /tmp/node --strip-components=1
PATH=/tmp/node/bin:$PATH
export PATH
node -p "'musl node ' + process.version + ' on ' + process.arch"

# One node, filling both roles. The glibc legs install the floor AND the matrix
# node so the symbol audit runs against the oldest supported host; here the
# matrix value is a setup-node spec ("current") rather than a version number, so
# there is nothing to turn into a download URL. The floor is the more valuable
# of the two to audit against, so it is the one used.

say "configure ($BACKEND)"
if [ "$BACKEND" = aws ]; then
  # Matches the glibc release legs: static libstdc++/libgcc so the artifact does
  # not additionally require the builder's GCC runtime.
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAWSKMS_BACKEND="$BACKEND" \
    -DCMAKE_MODULE_LINKER_FLAGS="-static-libstdc++ -static-libgcc"
else
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAWSKMS_BACKEND="$BACKEND"
fi

say "build"
cmake --build build --parallel

say "unit tests"
ctest --test-dir build -R '^unit$' --no-tests=error --output-on-failure

say "check-load"
scripts/check-load.sh build "$(command -v node)"

say "the provider is reachable"
node --openssl-config="$PWD/build/awskms.cnf" scripts/awskms-doctor.mjs

say "end-to-end suites"
# Same guard as the glibc legs: run.mjs exits 0 with an explanation when the
# node cannot pass a URL to createPrivateKey, which would make this a green
# no-op rather than a failure.
#
# Redirect-then-cat rather than `| tee`, because this is POSIX sh and `set -eu`
# carries NO pipefail: in a `node ... | tee` pipeline the status is tee's, so a
# suite that failed outright would be reported as a pass. The glibc legs get
# this right only because they run under bash with `set -o pipefail`.
if ! node test/run.mjs > /tmp/suite.log 2>&1; then
  cat /tmp/suite.log
  echo "::error::the end-to-end suites failed"
  exit 1
fi
cat /tmp/suite.log
if grep -q 'Skipping the end-to-end suites' /tmp/suite.log; then
  echo "::error::the suites silently skipped -- $(node -p process.version) lacks the OSSL_STORE loader (needs >= $v)"
  exit 1
fi
grep -qE '^. pass [1-9]' /tmp/suite.log || {
  echo "::error::the suites reported no passing tests"
  exit 1
}

if [ "$BACKEND" = aws ]; then
  say "stage the archive"
  # linuxmusl-<arch>, hardcoded, because this script only ever runs on musl.
  # NOT `process.platform + '-' + process.arch` as the glibc legs use: node
  # reports plain "linux" under musl too, so that would produce linux-x64 --
  # colliding with the glibc artifact of the same name and shipping musl bytes
  # under a glibc key. The npm satellite is looked up by this exact string.
  target="linuxmusl-$ARCH"
  dir="awskms-$target"
  mkdir -p "stage/$dir"
  cp build/awskms.so "stage/$dir/"
  cp build/awskms.relocatable.cnf "stage/$dir/awskms.cnf"
  cp scripts/awskms-doctor.mjs LICENSE "stage/$dir/"
  tar czf "$dir.tar.gz" -C stage "$dir"
  ls -la "$dir.tar.gz"

  say "the unpacked archive works"
  # Has to happen in here: the host is glibc and cannot load a musl .so at all.
  d=/tmp/unpack
  mkdir -p "$d"
  tar xzf "$dir.tar.gz" -C "$d"
  AWSKMS_MODULE="$d/$dir/awskms.so" \
    node --openssl-config="$d/$dir/awskms.cnf" "$d/$dir/awskms-doctor.mjs"
fi

say "npm packages"
scripts/npm-pack.sh build

# Everything above ran as root against a bind mount, so the tree is now full of
# root-owned files the host's own steps -- upload-artifact, and checkout's post
# cleanup -- would trip over.
if [ -n "${AWSKMS_HOST_UID:-}" ]; then
  chown -R "$AWSKMS_HOST_UID:${AWSKMS_HOST_GID:-$AWSKMS_HOST_UID}" .
fi
