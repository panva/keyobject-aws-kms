#!/bin/sh
#
# The musl legs of CI, run INSIDE an Alpine container.
#
#   scripts/ci-alpine.sh build <backend> <arch> <openssl-floor>
#   scripts/ci-alpine.sh test  <backend> <arch> <node-spec>
#   scripts/ci-alpine.sh ossl  <backend> <arch> <openssl-version>
#
# Two phases, for the same reason the glibc legs are two jobs: compiling does not
# depend on the node version, so building once per node version would produce N
# identical binaries. `build` produces the artifact; `test` consumes one and is
# the phase that carries the node matrix.
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
# runtime, on arm64 it does not. So `container: node:26-alpine` fails at checkout
# on ubuntu-24.04-arm before any step of ours runs.
#
# Driving the container with `docker run` from an ordinary glibc runner sidesteps
# it entirely: checkout, cache, download-artifact and upload-artifact stay on the
# HOST, where the runner's own node is fine, and only the parts that genuinely
# need musl happen inside.
#
# This is POSIX sh on purpose. It is the entry point, so it runs before `apk add
# bash`; the bash scripts it calls are invoked after that.
set -eu

PHASE=${1:?usage: ci-alpine.sh build|test <backend> <arch> <arg>}
BACKEND=${2:?usage: ci-alpine.sh build|test <backend> <arch> <arg>}
ARCH=${3:?usage: ci-alpine.sh build|test <backend> <arch> <arg>}
ARG=${4:?usage: ci-alpine.sh build|test <backend> <arch> <arg>}

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

say "prerequisites"
# No sudo, no apt, no toolchain in the base image. linux-headers and perl are not
# optional in the build phase: the CRT needs the headers and OpenSSL's own build
# needs perl. jq resolves a node spec in the test phase.
apk add --no-cache build-base cmake git openssl-dev openssl linux-headers \
  perl bash tar xz curl jq

# The workspace was checked out on the host by a different uid, and the aws
# backend runs git to fetch the SDK. Without this every git command dies on
# "detected dubious ownership in repository".
git config --global --add safe.directory '*'

# Ownership is repaired on EVERY exit path, not only the happy one. The container
# runs as root against a bind mount, so a failed run would otherwise leave a tree
# of root-owned files that the host's own upload-artifact and checkout-cleanup
# steps trip over -- turning one red job into two.
finish() {
  if [ -n "${AWSKMS_HOST_UID:-}" ]; then
    chown -R "$AWSKMS_HOST_UID:${AWSKMS_HOST_GID:-$AWSKMS_HOST_UID}" . 2>/dev/null || true
  fi
}
trap finish EXIT

UB=https://unofficial-builds.nodejs.org/download/release

# Install node, from either a concrete version or a setup-node-style spec.
#
# Resolve against the unofficial-builds index because it only selects musl
# artifacts that exist. Filter files by architecture before selecting a version.
install_node() {
  want=$1
  case "$want" in
    [0-9]*.[0-9]*.[0-9]*)
      v=$want
      ;;
    *)
      curl -fsSL --retry 3 -o /tmp/ub.json "$UB/index.json"
      v=$(jq -r --arg a "linux-$ARCH-musl" --arg s "$want" '
            [ .[] | select(.files | index($a)) ] as $all
            | ( if   $s == "current" or $s == "latest" or $s == "node" then $all
                elif $s == "lts/*"            then [ $all[] | select(.lts) ]
                elif ($s | startswith("lts/")) then
                  [ $all[] | select((.lts | strings | ascii_downcase) == ($s[4:] | ascii_downcase)) ]
                else
                  [ $all[] | select(.version | startswith("v" + ($s | ltrimstr("v")) + ".")) ]
                end )
            | if length == 0 then "" else (.[0].version | ltrimstr("v")) end' /tmp/ub.json)
      [ -n "$v" ] || { echo "::error::no musl build for node spec '$want' on $ARCH"; exit 1; }
      echo "resolved node spec '$want' -> v$v (via unofficial-builds index)"
      ;;
  esac
  curl -fsSL --retry 3 -o /tmp/node.tar.xz \
    "$UB/v$v/node-v$v-linux-$ARCH-musl.tar.xz"
  mkdir -p /tmp/node
  tar xJf /tmp/node.tar.xz -C /tmp/node --strip-components=1
  PATH=/tmp/node/bin:$PATH
  export PATH
  node -p "'musl node ' + process.version + ' on ' + process.arch"
}

case "$PHASE" in
build)
  OSSL=$ARG

  say "node"
  # The floor. nodejs.org/dist publishes no musl builds at all -- that is what
  # nodejs/unofficial-builds exists for -- so setup-node cannot serve this leg.
  # Pinning to .node-version keeps musl on the SAME floor as every other target.
  #
  # "Unofficial" is about who builds it, not what it is: the OpenSSL surface
  # these expose was compared symbol for symbol against the node:26-alpine
  # image's own node and is IDENTICAL (4648 exported OpenSSL symbols, zero
  # difference in either direction, across two different node versions). Since
  # binding those undefined symbols to the host is the entire mechanism this
  # provider rests on, the two are interchangeable.
  install_node "$(cat .node-version)"

  say "openssl $OSSL"
  # Build against the common OpenSSL floor rather than Alpine's newer headers.
  # Installed under the bind-mounted workspace rather than into the container, so
  # the host can cache it between runs -- the container itself is ephemeral.
  OSSL_PREFIX="$PWD/.ossl/$OSSL"
  scripts/build-openssl.sh "$OSSL" "$OSSL_PREFIX"

  say "configure ($BACKEND)"
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAWSKMS_BACKEND="$BACKEND" \
    -DOPENSSL_ROOT_DIR="$OSSL_PREFIX" -DCMAKE_PREFIX_PATH="$OSSL_PREFIX" \
    -DCMAKE_MODULE_LINKER_FLAGS="-static-libstdc++ -static-libgcc"

  say "build"
  cmake --build build --parallel

  say "unit tests"
  # Node-independent -- awskms_unit is a pure C executable linking only
  # libcrypto/libc -- so it belongs here rather than being re-run once per node.
  ctest --test-dir build -R '^unit$' --no-tests=error --output-on-failure

  say "openssl floor"
  scripts/check-symbol-floor.sh build/aws-kms.so "$OSSL_PREFIX"

  say "musl binary contract"
  scripts/check-binary-compat.sh musl build/aws-kms.so "$ARCH"
  [ -s build/awskms-dependencies ] || {
    echo "::error::build/awskms-dependencies is missing"
    exit 1
  }
  scripts/ci-policy-gate.sh artifact build/aws-kms.so

  if [ "$BACKEND" = aws ]; then
    say "stage the archive"
    # linuxmusl-<arch>, hardcoded, because this script only ever runs on musl.
    # NOT `process.platform + '-' + process.arch` as the glibc legs use: node
    # reports plain "linux" under musl too, so that would produce linux-x64 --
    # colliding with the glibc artifact of the same name and shipping musl bytes
    # under a glibc key. The npm satellite is looked up by this exact string.
    target="linuxmusl-$ARCH"
    version=$(node -p "require('./npm/core/package.json').version")
    dir="awskms-$version-$target"
    archive="$dir.tar.gz"
    scripts/package-archive.sh build "$target" .
    scripts/ci-policy-gate.sh artifact build/aws-kms.so "$archive"
    ls -la "$archive"

    say "the unpacked archive works"
    # Has to happen in here: the host is glibc and cannot load a musl .so at all.
    d=/tmp/unpack
    mkdir -p "$d"
    tar xzf "$archive" -C "$d"
    AWSKMS_MODULE="$d/$dir/aws-kms.so" \
      node --openssl-config="$d/$dir/awskms.cnf" "$d/$dir/check.mjs"
  fi
  ;;

test)
  SPEC=$ARG

  # The module arrives from the build phase as an artifact the HOST downloaded
  # into build/. Nothing is compiled here.
  [ -f build/aws-kms.so ] || {
    echo "::error::no build/aws-kms.so -- the build artifact did not arrive"
    exit 1
  }
  [ -s build/awskms_provider_unload ] || {
    echo "::error::downloaded build is missing awskms_provider_unload"
    exit 1
  }
  chmod 755 build/awskms_provider_unload
  AWSKMS_UNLOAD_HARNESS="$PWD/build/awskms_provider_unload"
  export AWSKMS_UNLOAD_HARNESS

  say "node ($SPEC)"
  install_node "$SPEC"

  say "check-load"
  # One node fills both roles. The glibc legs pass the floor AND the matrix node
  # so the symbol audit runs against the oldest supported host; on musl the floor
  # is a matrix entry in its own right rather than a second install.
  scripts/check-load.sh build "$(command -v node)"

  set +e
  node -e '
    const { createPrivateKey } = require("node:crypto");
    try { createPrivateKey({ key: new URL("aws-kms:") }); process.exit(0); }
    catch (error) { process.exit(error.code === "ERR_INVALID_ARG_TYPE" ? 2 : 0); }
  '
  capability=$?
  set -e
  if [ "$capability" -eq 2 ]; then
    echo "::error::Node $(node -p 'process.version') must support URL-backed OpenSSL STORE keys"
    exit 1
  fi

  say "the provider is reachable"
  # The RELOCATABLE cnf plus AWSKMS_MODULE, never build/awskms.cnf: that one
  # baked in the absolute path of the machine that COMPILED it, which is a
  # different job now, and it would fail silently rather than loudly.
  AWSKMS_MODULE="$PWD/build/aws-kms.so" \
    node --openssl-config="$PWD/build/awskms.relocatable.cnf" scripts/check.mjs

  say "end-to-end suites"
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
    echo "::error::the suites silently skipped -- $(node -p process.version) lacks the OSSL_STORE loader (needs >= $(cat .node-version))"
    exit 1
  fi
  grep -qE ' pass [1-9][0-9]*$' /tmp/suite.log || {
    echo "::error::the suites reported no passing tests"
    exit 1
  }
  grep -F '✔ explicit provider unload leaves the host process usable' /tmp/suite.log

  if [ "$BACKEND" = aws ]; then
    say "npm packages"
    scripts/npm-pack.sh build
  fi
  ;;

ossl)
  # The musl binary has its own runtime matrix because its toolchain and symbol
  # requirements differ from the glibc artifact.
  V=$ARG
  [ -f build/aws-kms.so ] || {
    echo "::error::no build/aws-kms.so -- the build artifact did not arrive"
    exit 1
  }

  say "node"
  install_node "$(cat .node-version)"

  say "openssl $V"
  PREFIX="$PWD/.ossl/$V"
  scripts/build-openssl.sh "$V" "$PREFIX"

  say "does it load against openssl $V"
  # Static first, so a failure names the missing symbols rather than only
  # reporting that dlopen failed.
  scripts/check-symbol-floor.sh build/aws-kms.so "$PREFIX"

  PATH="$PREFIX/bin:$PATH"
  LD_LIBRARY_PATH="$PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export PATH LD_LIBRARY_PATH
  # Assert the loaded library version because the system libcrypto has the same
  # SONAME as several matrix versions.
  out=$(openssl version)
  lib=$(printf '%s' "$out" | sed -n 's/.*(Library: OpenSSL \([0-9][0-9.]*\).*/\1/p')
  got=${lib:-$(printf '%s' "$out" | awk '{print $2}')}
  echo "openssl: $out"
  [ "$got" = "$V" ] || {
    echo "::error::the libcrypto in use is $got, not $V -- this leg would have graded the wrong OpenSSL"
    exit 1
  }
  scripts/check-load.sh build "$(command -v node)"
  ;;

*)
  echo "unknown phase '$PHASE' -- expected build, test or ossl" >&2
  exit 2
  ;;
esac
