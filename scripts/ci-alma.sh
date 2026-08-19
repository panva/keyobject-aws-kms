#!/usr/bin/env bash
# Build and test distributable glibc artifacts in the pinned AlmaLinux 8 image.
set -euo pipefail

phase=${1:?usage: ci-alma.sh build|test|sanitize <backend> <arch> <argument> [floor]}
backend=${2:?missing backend}
arch=${3:?missing architecture}
argument=${4:?missing OpenSSL floor or Node version}
floor=${5:-$argument}

finish() {
  if [[ -n ${AWSKMS_HOST_UID:-} ]]; then
    chown -R "$AWSKMS_HOST_UID:${AWSKMS_HOST_GID:-$AWSKMS_HOST_UID}" . 2>/dev/null || true
  fi
}
trap finish EXIT

grep -q '^AlmaLinux release 8\.10 ' /etc/almalinux-release || {
  echo "error: expected AlmaLinux 8.10 container" >&2
  cat /etc/almalinux-release >&2
  exit 1
}

dnf -q -y install dnf-plugins-core
dnf config-manager --set-enabled powertools >/dev/null
dnf -q -y install \
  ca-certificates curl diffutils file findutils git jq libatomic make openssl perl-core \
  tar xz binutils \
  gcc-toolset-13-gcc-13.3.1-2.2.el8_10 \
  gcc-toolset-13-gcc-c++-13.3.1-2.2.el8_10 \
  gcc-toolset-13-libstdc++-devel-13.3.1-2.2.el8_10
if [[ $phase == sanitize ]]; then
  dnf -q -y install \
    gcc-toolset-13-libasan-devel-13.3.1-2.2.el8_10 \
    gcc-toolset-13-libubsan-devel-13.3.1-2.2.el8_10
fi

# shellcheck disable=SC1091
source /opt/rh/gcc-toolset-13/enable
[[ $(gcc -dumpfullversion) == 13.3.1 ]] || {
  echo "error: expected GCC 13.3.1, found $(gcc -dumpfullversion)" >&2
  exit 1
}
export CC=gcc CXX=g++

cmake_version=3.31.8
case "$arch" in
  x64)
    machine=x86_64
    node_arch=x64
    cmake_sha=630615d8e98ac33eba7fbe472626dff5c899c85af3c024585ae109166a6909d0
    ;;
  arm64)
    machine=aarch64
    node_arch=arm64
    cmake_sha=609735983e3bdf24b6ab379d918458d64196fe72b98226f62dd5e9fe7b2997cc
    ;;
  *)
    echo "error: unsupported architecture $arch" >&2
    exit 2
    ;;
esac
[[ $(uname -m) == "$machine" ]] || {
  echo "error: expected $machine container, found $(uname -m)" >&2
  exit 1
}
cmake_archive="cmake-$cmake_version-linux-$machine.tar.gz"
curl -fsSL --retry 3 -o "/tmp/$cmake_archive" \
  "https://github.com/Kitware/CMake/releases/download/v$cmake_version/$cmake_archive"
printf '%s  %s\n' "$cmake_sha" "/tmp/$cmake_archive" | sha256sum -c -
rm -rf /opt/cmake
mkdir -p /opt/cmake
tar xzf "/tmp/$cmake_archive" -C /opt/cmake --strip-components=1
export PATH="/opt/cmake/bin:$PATH"
[[ $(cmake --version | awk 'NR == 1 { print $3 }') == "$cmake_version" ]]

glibc=$(ldd --version | awk 'NR == 1 { print $NF }')
[[ $glibc == 2.28 ]] || {
  echo "error: pinned build container must provide glibc 2.28, found $glibc" >&2
  exit 1
}

git config --global --add safe.directory '*'

install_node() {
  local spec=$1 destination=$2 version archive checksum
  curl -fsSL --retry 3 -o /tmp/node-index.json https://nodejs.org/dist/index.json
  case "$spec" in
    [0-9]*.[0-9]*.[0-9]*) version=$spec ;;
    *)
      version=$(jq -r --arg spec "$spec" '
        (if $spec == "current" or $spec == "latest" or $spec == "node" then .
         elif $spec == "lts/*" then [ .[] | select(.lts) ]
         elif ($spec | startswith("lts/")) then
           [ .[] | select((.lts | strings | ascii_downcase) == ($spec[4:] | ascii_downcase)) ]
         else [ .[] | select(.version | startswith("v" + ($spec | ltrimstr("v")) + ".")) ]
         end) | if length == 0 then "" else .[0].version[1:] end
      ' /tmp/node-index.json)
      ;;
  esac
  [[ -n $version ]] || { echo "error: no Node release for '$spec'" >&2; exit 1; }
  archive="node-v$version-linux-$node_arch.tar.xz"
  curl -fsSL --retry 3 -o "/tmp/$archive" "https://nodejs.org/dist/v$version/$archive"
  checksum=$(curl -fsSL --retry 3 "https://nodejs.org/dist/v$version/SHASUMS256.txt" \
    | awk -v file="$archive" '$2 == file { print $1 }')
  [[ -n $checksum ]] || { echo "error: no checksum for $archive" >&2; exit 1; }
  printf '%s  %s\n' "$checksum" "/tmp/$archive" | sha256sum -c -
  rm -rf "$destination"
  mkdir -p "$destination"
  tar xJf "/tmp/$archive" -C "$destination" --strip-components=1
  "$destination/bin/node" -p "process.version + ' ' + process.arch"
}

case "$phase" in
  build)
    openssl_prefix="$PWD/.ossl-glibc/$argument"
    scripts/build-openssl.sh "$argument" "$openssl_prefix"
    install_node "$(cat .node-version)" /tmp/node
    export PATH="/tmp/node/bin:$PATH"

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
      -DAWSKMS_BACKEND="$backend" \
      -DOPENSSL_ROOT_DIR="$openssl_prefix" \
      -DCMAKE_PREFIX_PATH="$openssl_prefix" \
      -DCMAKE_MODULE_LINKER_FLAGS="-static-libstdc++ -static-libgcc"
    cmake --build build --parallel
    ctest --test-dir build -R '^unit$' --no-tests=error --output-on-failure
    scripts/check-symbol-floor.sh build/aws-kms.so "$openssl_prefix"
    scripts/check-binary-compat.sh linux build/aws-kms.so "$arch" 2.28
    scripts/ci-policy-gate.sh artifact build/aws-kms.so

    if [[ $backend == aws ]]; then
      target="linux-$arch"
      version=$(node -p "require('./npm/core/package.json').version")
      directory="awskms-$version-$target"
      archive="$directory.tar.gz"
      scripts/package-archive.sh build "$target" .
      scripts/ci-policy-gate.sh artifact build/aws-kms.so "$archive"

      unpack=/tmp/awskms-unpack
      rm -rf "$unpack"
      mkdir -p "$unpack"
      tar xzf "$archive" -C "$unpack"
      AWSKMS_MODULE="$unpack/$directory/aws-kms.so" \
        node --openssl-config="$unpack/$directory/awskms.cnf" \
        "$unpack/$directory/check.mjs"
    fi
    ;;

  test)
    openssl_prefix="$PWD/.ossl-glibc/$floor"
    [[ -x $openssl_prefix/bin/openssl ]] || {
      echo "error: cached OpenSSL floor is missing: $openssl_prefix" >&2
      exit 1
    }
    [[ -s build/awskms_provider_unload ]] || {
      echo "error: downloaded build is missing awskms_provider_unload" >&2
      exit 1
    }
    chmod 755 build/awskms_provider_unload
    export AWSKMS_UNLOAD_HARNESS="$PWD/build/awskms_provider_unload"
    install_node "$(cat .node-version)" /tmp/node-floor
    install_node "$argument" /tmp/node-test
    export PATH="/tmp/node-test/bin:$openssl_prefix/bin:$PATH"
    export LD_LIBRARY_PATH="$openssl_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    scripts/check-load.sh build /tmp/node-floor/bin/node /tmp/node-test/bin/node

    set +e
    /tmp/node-test/bin/node -e '
      const { createPrivateKey } = require("node:crypto");
      try { createPrivateKey({ key: new URL("aws-kms:") }); process.exit(0); }
      catch (error) { process.exit(error.code === "ERR_INVALID_ARG_TYPE" ? 2 : 0); }
    '
    capability=$?
    set -e
    if (( capability == 2 )); then
      version=$(/tmp/node-test/bin/node -p 'process.version')
      echo "error: Node $version must support URL-backed OpenSSL STORE keys" >&2
      exit 1
    fi

    AWSKMS_MODULE="$PWD/build/aws-kms.so" \
      /tmp/node-test/bin/node --openssl-config="$PWD/build/awskms.relocatable.cnf" \
      scripts/check.mjs

    /tmp/node-test/bin/node test/run.mjs 2>&1 | tee /tmp/suite.log
    ! grep -q 'Skipping the end-to-end suites' /tmp/suite.log
    grep -qE ' pass [1-9][0-9]*$' /tmp/suite.log
    grep -F '✔ explicit provider unload leaves the host process usable' /tmp/suite.log
    if [[ $backend == aws ]]; then scripts/npm-pack.sh build; fi
    ;;

  sanitize)
    openssl_prefix="$PWD/.ossl-glibc/$floor"
    scripts/build-openssl.sh "$floor" "$openssl_prefix"
    install_node "$argument" /tmp/node-sanitize
    export PATH="/tmp/node-sanitize/bin:$openssl_prefix/bin:$PATH"
    export LD_LIBRARY_PATH="$openssl_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    for runtime in libasan_preinit.o libasan.so libubsan.so; do
      runtime_path=$(gcc -print-file-name="$runtime")
      [[ $runtime_path != "$runtime" && -f $runtime_path ]] || {
        echo "error: GCC sanitizer runtime is missing: $runtime" >&2
        exit 1
      }
    done

    sanitizer_flags='-fsanitize=address,undefined -fno-omit-frame-pointer'
    cmake -S . -B build-sanitized -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DAWSKMS_BACKEND=stub \
      -DOPENSSL_ROOT_DIR="$openssl_prefix" \
      -DCMAKE_PREFIX_PATH="$openssl_prefix" \
      -DCMAKE_C_FLAGS="$sanitizer_flags" \
      -DCMAKE_CXX_FLAGS="$sanitizer_flags" \
      -DCMAKE_EXE_LINKER_FLAGS="$sanitizer_flags" \
      -DCMAKE_MODULE_LINKER_FLAGS="$sanitizer_flags"
    cmake --build build-sanitized --parallel

    export ASAN_OPTIONS='abort_on_error=1:detect_leaks=0:strict_string_checks=1'
    export UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'
    ctest --test-dir build-sanitized -R '^unit$' --no-tests=error --output-on-failure

    asan=$(gcc -print-file-name=libasan.so)
    ubsan=$(gcc -print-file-name=libubsan.so)
    [[ -f $asan && -f $ubsan ]] || {
      echo "error: sanitizer runtimes were not found" >&2
      exit 1
    }
    export LD_PRELOAD="$asan:$ubsan${LD_PRELOAD:+:$LD_PRELOAD}"
    AWSKMS_MODULE="$PWD/build-sanitized/aws-kms.so" \
      /tmp/node-sanitize/bin/node test/run.mjs 2>&1 | tee /tmp/sanitizer-suite.log
    ! grep -q 'Skipping the end-to-end suites' /tmp/sanitizer-suite.log
    grep -qE ' pass [1-9][0-9]*$' /tmp/sanitizer-suite.log
    ;;

  *)
    echo "error: unknown phase '$phase'" >&2
    exit 2
    ;;
esac
