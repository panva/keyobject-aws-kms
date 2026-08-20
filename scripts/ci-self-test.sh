#!/usr/bin/env bash
# Fast regressions for CI helpers that otherwise fail only after container setup.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

fail() {
  echo "error: $*" >&2
  exit 1
}

# AlmaLinux uses uname/CMake architecture names and Node distribution names for
# different purposes. Keep both mappings explicit and keep Node archive names
# independent from the machine spelling.
grep -Fq 'machine=x86_64' "$repo/scripts/ci-alma.sh"
grep -Fq 'node_arch=x64' "$repo/scripts/ci-alma.sh"
grep -Fq 'machine=aarch64' "$repo/scripts/ci-alma.sh"
grep -Fq 'node_arch=arm64' "$repo/scripts/ci-alma.sh"
grep -Fq 'archive="node-v$version-linux-$node_arch.tar.xz"' \
  "$repo/scripts/ci-alma.sh"
assert_dnf_package() {
  local package=$1

  awk -v package="$package" '
    /^[[:space:]]*dnf -q -y install \\$/ { packages = 1; next }
    packages {
      for (field = 1; field <= NF; field++) {
        if ($field == package) found = 1
      }
      if ($0 !~ /\\$/) packages = 0
    }
    END { exit(found ? 0 : 1) }
  ' "$repo/scripts/ci-alma.sh" || fail "AlmaLinux does not install $package"
}

assert_dnf_package libatomic
assert_dnf_package gcc-toolset-13-libasan-devel-13.3.1-2.2.el8_10
assert_dnf_package gcc-toolset-13-libubsan-devel-13.3.1-2.2.el8_10
grep -Fq 'gcc -print-file-name=libasan.so.8' "$repo/scripts/ci-alma.sh"
grep -Fq 'gcc -print-file-name=libubsan.so.1' "$repo/scripts/ci-alma.sh"

extract_function() {
  local function_name=$1 source=$2

  awk -v signature="$function_name() {" '
    $0 == signature { inside = 1 }
    inside { print }
    inside && $0 == "}" { exit }
  ' "$source"
}

extract_yaml_job() {
  local job_name=$1 workflow=$2

  awk -v header="  $job_name:" '
    $0 == header { inside = 1 }
    inside && $0 != header && $0 ~ /^  [[:alnum:]_-]+:$/ { exit }
    inside { print }
  ' "$workflow"
}

alma_test_prerequisites=$(extract_function install_test_prerequisites \
  "$repo/scripts/ci-alma.sh")
[[ -n $alma_test_prerequisites ]] || fail 'missing AlmaLinux test prerequisites'
if grep -Eq '(ccache|gcc|g\+\+|cmake|make|headers|-devel)' \
  <<<"$alma_test_prerequisites"; then
  fail 'AlmaLinux test phase installs a compiler, CMake, make, or headers'
fi
grep -Fq 'if [[ $test_version == "$floor_version" ]]' \
  "$repo/scripts/ci-alma.sh" ||
  fail 'AlmaLinux does not reuse an identical floor and matrix Node runtime'
awk '
  /^  build\)$/ { build = 1 }
  build && /if \[\[ \$backend == aws \]\]; then/ { aws = 1 }
  build && aws && /install_node .*\.node-version/ { found = 1 }
  build && /^  test\)$/ { exit(found ? 0 : 1) }
  END { if (build) exit(found ? 0 : 1) }
' "$repo/scripts/ci-alma.sh" ||
  fail 'AlmaLinux must install the build-time Node runtime only for AWS packaging'

alpine_test_prerequisites=$(awk '
  /^test\)$/ { occurrences++; if (occurrences == 1) inside = 1 }
  inside && /^[[:space:]]*apk add / { packages = 1 }
  packages { print }
  packages && $0 !~ /\\$/ { exit }
' "$repo/scripts/ci-alpine.sh")
[[ -n $alpine_test_prerequisites ]] || fail 'missing Alpine test prerequisites'
if grep -Eq '(^|[[:space:]])(build-base|ccache|gcc|g\+\+|cmake|make|linux-headers|[[:alnum:]+._-]+-dev)([[:space:]\\]|$)' \
  <<<"$alpine_test_prerequisites"; then
  fail 'Alpine test phase installs a compiler, CMake, make, or headers'
fi
awk '
  /^build\)$/ { build = 1 }
  build && /if \[ "\$BACKEND" = aws \]; then/ { aws = 1 }
  build && aws && /install_node .*\.node-version/ { found = 1 }
  build && /^test\)$/ { exit(found ? 0 : 1) }
  END { if (build) exit(found ? 0 : 1) }
' "$repo/scripts/ci-alpine.sh" ||
  fail 'Alpine must install the build-time Node runtime only for AWS packaging'

grep -Fq "    - if: inputs.phase == 'build' && inputs.backend == 'aws'" \
  "$repo/.github/actions/ci-macos/action.yml" ||
  fail 'macOS must install the build-time Node runtime only for AWS packaging'

macos_action="$repo/.github/actions/ci-macos/action.yml"
grep -Fq "key: openssl-v2-\${{ runner.os }}-\${{ runner.arch }}-\${{ env.AWSKMS_OPENSSL_FLOOR }}-osx\${{ env.AWSKMS_MACOS_FLOOR }}-\${{ hashFiles('scripts/build-openssl.sh') }}" \
  "$macos_action" ||
  fail 'macOS OpenSSL cache identity must include the deployment floor and builder'
[[ $(grep -Fc 'MACOSX_DEPLOYMENT_TARGET: ${{ env.AWSKMS_MACOS_FLOOR }}' \
  "$macos_action") -eq 2 ]] ||
  fail 'macOS OpenSSL build and restore must use the declared deployment floor'

# A cached prefix is valid only for the target requested by this invocation.
# Fake Darwin and a complete prefix so these checks remain fast on Linux hosts.
macos_openssl_fakebin="$temporary/macos-openssl-bin"
mkdir -p "$macos_openssl_fakebin"
printf '#!/bin/sh\nprintf "Darwin\\n"\n' > "$macos_openssl_fakebin/uname"
printf '#!/bin/sh\nexit 97\n' > "$macos_openssl_fakebin/curl"
chmod 755 "$macos_openssl_fakebin/uname" "$macos_openssl_fakebin/curl"
make_cached_macos_openssl() {
  local name=$1 target=$2
  local prefix="$temporary/macos-openssl-$name"

  mkdir -p "$prefix/include/openssl" "$prefix/lib" "$prefix/bin"
  : > "$prefix/include/openssl/configuration.h"
  printf '#!/bin/sh\nexit 0\n' > "$prefix/bin/openssl"
  chmod 755 "$prefix/bin/openssl"
  printf '%s\n' "$target" > "$prefix/.awskms-macos-deployment-target"
  printf '%s\n' "$prefix"
}

explicit_macos_prefix=$(make_cached_macos_openssl explicit 14.2)
PATH="$macos_openssl_fakebin:$PATH" MACOSX_DEPLOYMENT_TARGET=14.2 \
  AWSKMS_MACOS_FLOOR=13.5 \
  "$repo/scripts/build-openssl.sh" 3.0.21 "$explicit_macos_prefix" >/dev/null ||
  fail 'an explicit macOS deployment target must take precedence'

configured_macos_prefix=$(make_cached_macos_openssl configured 12.3)
(
  unset MACOSX_DEPLOYMENT_TARGET
  PATH="$macos_openssl_fakebin:$PATH" AWSKMS_MACOS_FLOOR=12.3 \
    "$repo/scripts/build-openssl.sh" 3.0.21 "$configured_macos_prefix" >/dev/null
) || fail 'the configured macOS floor must be used when no explicit target exists'

default_macos_prefix=$(make_cached_macos_openssl default 13.5)
(
  unset MACOSX_DEPLOYMENT_TARGET AWSKMS_MACOS_FLOOR
  PATH="$macos_openssl_fakebin:$PATH" \
    "$repo/scripts/build-openssl.sh" 3.0.21 "$default_macos_prefix" >/dev/null
) || fail 'standalone Darwin OpenSSL builds must default to macOS 13.5'

for source in "$repo/scripts/ci-alma.sh" "$repo/scripts/ci-alpine.sh"; do
  grep -Fq -- '-DCMAKE_C_COMPILER_LAUNCHER=ccache' "$source" ||
    fail "$(basename "$source") does not cache C compilations"
  grep -Fq -- '-DCMAKE_CXX_COMPILER_LAUNCHER=ccache' "$source" ||
    fail "$(basename "$source") does not cache C++ compilations"
done
grep -Fq 'epel-release-8-21.el8' "$repo/scripts/ci-alma.sh" ||
  fail 'AlmaLinux must bootstrap EPEL from the release available in Extras'
grep -Fq 'ccache-3.7.7-1.el8' "$repo/scripts/ci-alma.sh" ||
  fail 'AlmaLinux must pin the compiler cache after enabling EPEL'
ci_cache_actions=(
  "$repo/.github/actions/ci-glibc/action.yml"
  "$repo/.github/actions/ci-macos/action.yml"
  "$repo/.github/actions/ci-musl/action.yml"
)
for action_file in "${ci_cache_actions[@]}"; do
  [[ $(grep -Fc 'name: cache compiled AWS dependencies' "$action_file") -eq 1 ]] ||
    fail "$(basename "$(dirname "$action_file")") must cache compiled AWS dependencies"
  [[ $(grep -Fc 'name: cache AWS SDK source' "$action_file") -eq 1 ]] ||
    fail "$(basename "$(dirname "$action_file")") must restore AWS SDK sources"
done

workflow="$repo/.github/workflows/ci.yml"
[[ $(grep -Ec '^  build-(glibc|macos|musl-experimental)-(x64|arm64)-(stub|aws):$' \
  "$workflow") -eq 12 ]] || fail 'CI must define exactly 12 coordinate producers'
[[ $(grep -Ec '^  test-(glibc|macos|musl-experimental)-(x64|arm64)-(stub|aws):$' \
  "$workflow") -eq 12 ]] || fail 'CI must define exactly 12 coordinate consumers'
for legacy_job in build-glibc build-macos build-musl-experimental \
  test-glibc test-macos test-musl-experimental openssl-runtime; do
  [[ -z $(extract_yaml_job "$legacy_job" "$workflow") ]] ||
    fail "legacy aggregate CI job remains: $legacy_job"
done
for family in glibc macos musl-experimental; do
  case $family in
    glibc) action=ci-glibc ;;
    macos) action=ci-macos ;;
    musl-experimental) action=ci-musl ;;
  esac
  for arch in x64 arm64; do
    for backend in stub aws; do
      producer="build-$family-$arch-$backend"
      consumer="test-$family-$arch-$backend"
      producer_job=$(extract_yaml_job "$producer" "$workflow")
      consumer_job=$(extract_yaml_job "$consumer" "$workflow")
      [[ -n $producer_job ]] || fail "missing exact CI producer $producer"
      [[ -n $consumer_job ]] || fail "missing exact CI consumer $consumer"
      grep -Fq "uses: ./.github/actions/$action" <<<"$producer_job" ||
        fail "$producer does not use $action"
      grep -Fq '          phase: build' <<<"$producer_job" ||
        fail "$producer does not select the build phase"
      grep -Fq "          arch: $arch" <<<"$producer_job" ||
        fail "$producer has the wrong architecture input"
      grep -Fq "          backend: $backend" <<<"$producer_job" ||
        fail "$producer has the wrong backend input"
      grep -Fq "uses: ./.github/actions/$action" <<<"$consumer_job" ||
        fail "$consumer does not use $action"
      grep -Fq '          phase: test' <<<"$consumer_job" ||
        fail "$consumer does not select the test phase"
      grep -Fq "          arch: $arch" <<<"$consumer_job" ||
        fail "$consumer has the wrong architecture input"
      grep -Fq "          backend: $backend" <<<"$consumer_job" ||
        fail "$consumer has the wrong backend input"
      grep -Fq '          node-version: ${{ matrix.node-version }}' \
        <<<"$consumer_job" || fail "$consumer does not pass its Node version"
      grep -Fq "needs: [node-versions, $producer]" <<<"$consumer_job" ||
        fail "$consumer waits on more than its exact producer"
      if [[ $family != macos ]]; then
        grep -Eq '^          image: [^[:space:]]+$' <<<"$producer_job" ||
          fail "$producer does not pass its pinned container image"
        grep -Eq '^          image: [^[:space:]]+$' <<<"$consumer_job" ||
          fail "$consumer does not pass its pinned container image"
      elif ! grep -Eq '^          binary-arch: (x86_64|arm64)$' \
        <<<"$producer_job"; then
        fail "$producer does not pass its Mach-O architecture"
      fi
      if [[ $family == musl-experimental ]]; then
        grep -Fq "if: always() && needs.node-versions.result == 'success' && needs.$producer.result == 'success'" \
          <<<"$consumer_job" ||
          fail "$consumer lost the experimental musl result guard"
      fi
    done
  done
done

if grep -Eq 'matrix\.(platform|backend)' "$workflow"; then
  fail 'CI must not retain platform/backend matrix-wide build barriers'
fi
for backend in stub aws; do
  runtime_job=$(extract_yaml_job "openssl-runtime-$backend" "$workflow")
  grep -Fq "needs: build-glibc-x64-$backend" <<<"$runtime_job" ||
    fail "OpenSSL $backend runtime does not wait on its exact producer"
  grep -Fq 'uses: ./.github/actions/ci-openssl-runtime' <<<"$runtime_job" ||
    fail "OpenSSL $backend runtime does not use the runtime action"
  grep -Fq '          version: ${{ matrix.version }}' <<<"$runtime_job" ||
    fail "OpenSSL $backend runtime does not pass its version"
  grep -Fq "          backend: $backend" <<<"$runtime_job" ||
    fail "OpenSSL $backend runtime has the wrong backend input"
done
required_job=$(extract_yaml_job required-capable "$workflow")
grep -Fq 'needs: build-glibc-x64-stub' <<<"$required_job" ||
  fail 'mandatory-capable lane does not wait on the x64 stub producer'
real_kms_job=$(extract_yaml_job real-kms "$workflow")
grep -Fq 'needs: build-glibc-x64-aws' <<<"$real_kms_job" ||
  fail 'real-KMS lane does not wait on the x64 AWS producer'
if grep -Eq 'gcc -print-file-name=lib(asan|ubsan)\.so([")])' \
  "$repo/scripts/ci-alma.sh"; then
  fail 'LD_PRELOAD must use sanitizer runtime DSOs, not linker scripts'
fi
if grep -Fq 'kms:CancelKeyDeletion' "$repo/scripts/real-kms-bootstrap.mjs"; then
  fail 'the test harness must not receive permission to recover keys pending deletion'
fi
if grep -Fq 'cancel-key-deletion' "$repo/scripts/real-kms-keys.mjs"; then
  fail 'the test harness must not recover or reuse keys pending deletion'
fi
grep -Fq "Sid: 'DeleteAliasesOnlyForOwnedKeys'" \
  "$repo/scripts/real-kms-bootstrap.mjs" ||
  fail 'DeleteAlias must be authorised against owned target keys'
if grep -Fq 'archive="node-v$version-linux-$machine.tar.xz"' \
  "$repo/scripts/ci-alma.sh"; then
  fail 'Node archive names must not use uname architecture names'
fi

# TAP's informational prefix is multibyte. Match the ASCII summary suffix so
# the assertion remains valid under the C locale used by AlmaLinux containers.
printf 'ℹ pass 300\n' > "$temporary/suite.log"
LC_ALL=C grep -qE ' pass [1-9][0-9]*$' "$temporary/suite.log"
for source in "$repo/scripts/ci-alma.sh" "$repo/scripts/ci-alpine.sh" \
  "$repo/.github/workflows/ci.yml"; do
  if grep -Fq "'^. pass [1-9]'" "$source"; then
    fail "locale-sensitive TAP summary check remains in $source"
  fi
done

make_artifact() {
  local name=$1
  local contents=$2
  local directory="$temporary/artifact-$name"

  mkdir -p "$directory"
  printf '%s\n' "$contents" > "$directory/aws-kms.so"
  printf 'provider configuration\n' > "$directory/awskms.relocatable.cnf"
  printf 'stub\n' > "$directory/awskms-backend"
  printf 'backend=stub\n' > "$directory/awskms-dependencies"
  printf '%s\n' "$directory/aws-kms.so"
}

# Relative compiler paths produced by -ffile-prefix-map are safe. Absolute
# container-root paths, including paths embedded in diagnostics, are not.
safe_artifact=$(make_artifact safe \
  $'./src/provider.c\n../src/provider.c\nfoo/src/provider.c\n~/src/provider.c')
"$repo/scripts/ci-policy-gate.sh" artifact "$safe_artifact" >/dev/null

for unsafe in '/src/provider.c' 'diagnostic: /src/provider.c' \
  '(/src/provider.c)'; do
  unsafe_artifact=$(make_artifact "unsafe-${unsafe//[^[:alnum:]]/_}" "$unsafe")
  if "$repo/scripts/ci-policy-gate.sh" artifact "$unsafe_artifact" \
    > "$temporary/policy-error" 2>&1; then
    fail "artifact policy accepted $unsafe"
  fi
  grep -Fq 'embeds forbidden residue' "$temporary/policy-error"
done

identifier='ECC_SECG_''P256K1'

write_mapper() {
  local source=$1
  local enum_type=$2
  local variant=${3:-valid}
  local hash_string=$identifier
  local return_indent='    '

  case "$variant" in
    valid) ;;
    five) hash_string=OTHER_KEY_SPEC ;;
    seven) ;;
    malformed) return_indent='   ' ;;
    *) fail "unknown mapper fixture variant: $variant" ;;
  esac

  {
    printf 'static const int %s_HASH = HashingUtils::HashString("%s");\n' \
      "$identifier" "$hash_string"
    printf '  } else if (hashCode == %s_HASH) {\n' "$identifier"
    printf '%sreturn %s::%s;\n' "$return_indent" "$enum_type" "$identifier"
    printf '    case %s::%s:\n' "$enum_type" "$identifier"
    printf '      return "%s";\n' "$identifier"
    if [[ $variant == seven ]]; then printf '// %s\n' "$identifier"; fi
  } > "$source"
}

make_sdk() {
  local name=$1
  local variant=${2:-valid}
  local sdk="$temporary/sdk-$name"
  local model="$sdk/generated/src/aws-cpp-sdk-kms/source/model"

  mkdir -p "$model"
  write_mapper "$model/KeySpec.cpp" KeySpec "$variant"
  write_mapper "$model/DataKeyPairSpec.cpp" DataKeyPairSpec valid
  printf '%s\n' "$sdk"
}

valid_sdk=$(make_sdk valid)
"$repo/scripts/patch-aws-sdk-keyspec.sh" "$valid_sdk" >/dev/null
if grep -FRq "$identifier" "$valid_sdk"; then
  fail 'the mapper sanitizer left the removed identifier behind'
fi
"$repo/scripts/patch-aws-sdk-keyspec.sh" "$valid_sdk" \
  | grep -Fq 'already restricted'

for variant in five seven malformed; do
  invalid_sdk=$(make_sdk "$variant" "$variant")
  if "$repo/scripts/patch-aws-sdk-keyspec.sh" "$invalid_sdk" \
    > "$temporary/mapper-error" 2>&1; then
    fail "the mapper sanitizer accepted the $variant fixture"
  fi
done

make_s2n_kdf_sdk() {
  local name=$1
  local variant=${2:-valid}
  local sdk="$temporary/s2n-sdk-$name"
  local crypto="$sdk/crt/aws-crt-cpp/crt/s2n/crypto"

  mkdir -p "$crypto"
  {
    printf '#pragma once\n'
    printf '#if S2N_OPENSSL_VERSION_AT_LEAST(3, 0, 0)\n'
    printf '    #define S2N_OSSL_PARAM_BLOB(id, blob) \\\n'
    if [[ $variant == valid ]]; then
      printf '        OSSL_PARAM_octet_string(id, blob->data, blob->size)\n'
    else
      printf '        OSSL_PARAM_octet_string(id, blob->data, (blob)->size)\n'
    fi
    printf '#endif\n'
  } > "$crypto/s2n_kdf.h"
  printf '%s\n' "$sdk"
}

valid_s2n_sdk=$(make_s2n_kdf_sdk valid)
"$repo/scripts/patch-s2n-empty-kdf.sh" "$valid_s2n_sdk" >/dev/null
grep -Fq 's2n_ossl_empty_param_data' \
  "$valid_s2n_sdk/crt/aws-crt-cpp/crt/s2n/crypto/s2n_kdf.h"
if grep -Fq 'OSSL_PARAM_octet_string(id, blob->data, blob->size)' \
  "$valid_s2n_sdk/crt/aws-crt-cpp/crt/s2n/crypto/s2n_kdf.h"; then
  fail 'the s2n empty-KDF patch left the unsafe macro behind'
fi
"$repo/scripts/patch-s2n-empty-kdf.sh" "$valid_s2n_sdk" \
  | grep -Fq 'already patched'

invalid_s2n_sdk=$(make_s2n_kdf_sdk malformed malformed)
if "$repo/scripts/patch-s2n-empty-kdf.sh" "$invalid_s2n_sdk" \
  > "$temporary/s2n-kdf-error" 2>&1; then
  fail 'the s2n empty-KDF patch accepted an unexpected macro shape'
fi

echo 'ok: CI helper regressions pass'
