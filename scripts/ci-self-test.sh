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

for source in "$repo/scripts/ci-alma.sh" "$repo/scripts/ci-alpine.sh"; do
  grep -Fq -- '-DCMAKE_C_COMPILER_LAUNCHER=ccache' "$source" ||
    fail "$(basename "$source") does not cache C compilations"
  grep -Fq -- '-DCMAKE_CXX_COMPILER_LAUNCHER=ccache' "$source" ||
    fail "$(basename "$source") does not cache C++ compilations"
done
[[ $(grep -Fc 'name: cache compiled AWS dependencies' \
  "$repo/.github/workflows/ci.yml") == 3 ]] ||
  fail 'CI must cache compiled AWS dependencies for glibc, macOS and musl'
[[ $(grep -Fc 'name: cache AWS SDK source' \
  "$repo/.github/workflows/ci.yml") == 3 ]] ||
  fail 'CI must restore AWS SDK sources for glibc, macOS and musl'
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
