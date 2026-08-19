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
awk '
  $0 == "dnf -q -y install \\" { packages = 1; next }
  packages {
    for (field = 1; field <= NF; field++) {
      if ($field == "libatomic") found = 1
    }
    if ($0 !~ /\\$/) exit(found ? 0 : 1)
  }
  END { if (!found) exit 1 }
' "$repo/scripts/ci-alma.sh"
if grep -Fq 'archive="node-v$version-linux-$machine.tar.xz"' \
  "$repo/scripts/ci-alma.sh"; then
  fail 'Node archive names must not use uname architecture names'
fi

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

echo 'ok: CI helper regressions pass'
