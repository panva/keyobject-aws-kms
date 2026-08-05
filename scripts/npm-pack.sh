#!/usr/bin/env bash
#
# Builds the npm packages from a build tree and, by default, installs them into a
# throwaway project and exercises them.
#
#   scripts/npm-pack.sh [build-dir] [out-dir]
#
# NOTHING here talks to a registry. `npm pack` produces the exact tarball a
# publish would upload, and installing from that tarball exercises the whole
# resolution path -- optionalDependencies, os/cpu gating, exports subpaths,
# require.resolve -- which is the part that actually breaks. Publishing adds
# nothing to the test and cannot be undone.
#
# The package NAMES are placeholders (see TODO.txt Q1). They appear in exactly
# three files and are a rename away from real.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

BUILD_DIR=${1:-build}
OUT=${2:-$(mktemp -d -t awskms-npm.XXXXXX)}

fail=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
die()  { printf '\033[31merror\033[0m %s\n' "$1" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) MODULE=awskms.dylib; OS=darwin ;;
  *)      MODULE=awskms.so;    OS=linux  ;;
esac
case "$(uname -m)" in
  arm64|aarch64) CPU=arm64 ;;
  *)             CPU=x64   ;;
esac
TARGET="$OS-$CPU"

[[ -f $BUILD_DIR/$MODULE ]] || die "no $MODULE in $BUILD_DIR -- build it first"
# The RELOCATABLE cnf, not the build-tree one: the satellite ships a file whose
# module path is a token, and core substitutes it. Shipping the build-tree copy
# would bake in a path from the machine that built it.
[[ -f $BUILD_DIR/awskms.relocatable.cnf ]] \
  || die "no awskms.relocatable.cnf in $BUILD_DIR -- reconfigure with a current CMakeLists"

VERSION=$(node -p "require('./npm/core/package.json').version")

echo "packing $TARGET $VERSION into $OUT"

# --- the platform package ---------------------------------------------------
sat="$OUT/platform"
mkdir -p "$sat"
sed -e "s|@TARGET@|$TARGET|g" -e "s|@VERSION@|$VERSION|g" \
    -e "s|@OS@|$OS|g" -e "s|@CPU@|$CPU|g" -e "s|@MODULE@|$MODULE|g" \
    npm/platform/package.json.in > "$sat/package.json"
cp "$BUILD_DIR/$MODULE" "$sat/"
cp "$BUILD_DIR/awskms.relocatable.cnf" "$sat/awskms.cnf"
cp LICENSE "$sat/"
(cd "$sat" && npm pack --silent >/dev/null 2>&1) || die "npm pack failed for the platform package"
pass "platform package packed ($(basename "$sat"/*.tgz))"

# --- the core package -------------------------------------------------------
core="$OUT/core"
mkdir -p "$core/bin"
cp npm/core/package.json npm/core/index.js npm/core/register.js LICENSE "$core/"
cp npm/core/bin/awskms.js "$core/bin/"
# The doctor is shipped rather than re-implemented, so all three distribution
# tiers run the same health check.
cp scripts/awskms-doctor.mjs "$core/"
(cd "$core" && npm pack --silent >/dev/null 2>&1) || die "npm pack failed for the core package"
pass "core package packed ($(basename "$core"/*.tgz))"

if [[ ${AWSKMS_NPM_PACK_ONLY:-} == 1 ]]; then
  echo; echo "$OUT"
  exit 0
fi

# --- install both into a throwaway project and use them ---------------------
app="$OUT/app"
mkdir -p "$app"
cat > "$app/package.json" <<EOF
{ "name": "awskms-npm-smoke", "private": true, "type": "module", "version": "0.0.0" }
EOF
# The satellite is installed by path so npm does not go to the registry looking
# for a name that does not exist yet. That is the ONLY difference from a real
# install; resolution, os/cpu and exports all behave identically.
(cd "$app" && npm install --silent --no-audit --no-fund \
   "$sat"/*.tgz "$core"/*.tgz >/dev/null 2>&1) \
  || die "npm install of the packed tarballs failed"
pass "both packages install into a clean project"

run() { (cd "$app" && node -e "$1" 2>&1); }

out=$(run 'import("awskms-openssl-provider").then(m=>console.log(m.modulePath()))')
if [[ -f $out ]]; then pass "modulePath() resolves to a real file"; else bad "modulePath() -> $out"; fi

out=$(run 'import("awskms-openssl-provider").then(m=>console.log(JSON.stringify(m.isSupported())))')
if [[ $out == *'"ok":true'* ]]; then pass "isSupported() -> ok"; else bad "isSupported() -> $out"; fi

cnf=$(run 'import("awskms-openssl-provider").then(m=>console.log(m.opensslConfigPath()))')
# shellcheck disable=SC2016 # the literal $ENV:: is the point
if [[ -f $cnf ]] && ! grep -q '\$ENV::' "$cnf"; then
  pass "opensslConfigPath() writes a cnf with the module path substituted"
else
  bad "opensslConfigPath() -> $cnf"
fi

# Idempotent: a second call must return the same path and not rewrite.
cnf2=$(run 'import("awskms-openssl-provider").then(m=>console.log(m.opensslConfigPath()))')
if [[ $cnf == "$cnf2" ]]; then pass "opensslConfigPath() is stable across calls"; else bad "cnf path changed between calls: $cnf vs $cnf2"; fi

# CJS consumers: require(ESM) is unflagged well below our floor, so the
# ESM-only package must still be require()-able.
out=$(cd "$app" && node -e 'console.log(typeof require("awskms-openssl-provider").modulePath)' 2>&1)
if [[ $out == function ]]; then pass "require() works from CJS (require(ESM))"; else bad "require() from CJS -> $out"; fi

# The end that matters: does the provider actually load with that cnf?
out=$(cd "$app" && node --openssl-config="$cnf" \
        ./node_modules/awskms-openssl-provider/awskms-doctor.mjs 2>&1 | tail -1)
if [[ $out == *"awskms is working"* ]]; then pass "the provider loads and is reachable"; else bad "doctor said: $out"; fi

# And through the bin, which is how most people will reach it.
out=$(cd "$app" && ./node_modules/.bin/awskms-openssl-provider doctor 2>&1 | tail -1)
if [[ $out == *"awskms is working"* ]]; then pass "bin: doctor"; else bad "bin doctor -> $out"; fi

out=$(cd "$app" && ./node_modules/.bin/awskms-openssl-provider exec -- \
        node -e 'const{createPrivateKey}=require("crypto");
                 try{createPrivateKey({key:new URL("awskms:")})}catch(e){console.log(e.code)}' 2>&1 | tail -1)
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then pass "bin: exec activates the provider for a child process"; else bad "bin exec -> $out"; fi

# NEGATIVE CONTROL FIRST. Without register(), and with no cnf, the provider must
# NOT be reachable -- otherwise every check below could be passing because of a
# stray OPENSSL_CONF in the environment rather than anything this package does.
out=$(run 'const {createPrivateKey}=require("crypto");
  try { createPrivateKey({key:new URL("awskms:")}) } catch(e){ console.log(e.code) }')
if [[ $out == ERR_OSSL_OSSL_STORE_UNSUPPORTED ]]; then
  pass "negative control: the provider is absent until something registers it"
else
  bad "expected the provider to be ABSENT without register(), got: $out"
fi

# The in-process route: no cnf, no CLI flag. This is what `register()` buys, and
# the only way to know it works is to do it.
out=$(run 'import("awskms-openssl-provider/register").then(()=>{
  const {createPrivateKey}=require("crypto");
  try { createPrivateKey({key:new URL("awskms:")}) } catch(e){ console.log(e.code) }
})')
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then
  pass "import 'pkg/register' activates the provider -- no cnf, no flag"
else
  bad "register subpath -> $out"
fi

# Idempotent, and STILL WORKING afterwards. Asserting only "did not throw" would
# pass just as happily if register() had quietly done nothing at all.
out=$(run 'import("awskms-openssl-provider").then(m=>{
  m.register(); m.register();
  const {createPrivateKey}=require("crypto");
  try { createPrivateKey({key:new URL("awskms:")}) } catch(e){ console.log(e.code) }
})')
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then
  pass "register() twice is safe AND the provider still works"
else
  bad "double register() -> $out"
fi

# The claimed advantage over the cnf route is that failure is LOUD. A cnf that
# names a bad module produces no diagnostic whatsoever; this must throw.
out=$(run 'import("awskms-openssl-provider").then(m=>{
  const orig = m.modulePath();
  try { process.dlopen({exports:{}}, orig + ".nonexistent"); console.log("SILENT") }
  catch (e) { console.log("threw:", e.code ?? "Error") }
})')
if [[ $out == threw:* ]]; then
  pass "a failed registration THROWS rather than failing silently ($out)"
else
  bad "expected a throw on a bad module, got: $out"
fi

# And crucially: registering must not break unrelated crypto in the process.
out=$(run 'import("awskms-openssl-provider/register").then(()=>{
  const {generateKeyPairSync}=require("crypto");
  console.log(!!generateKeyPairSync("ec",{namedCurve:"P-256"}).publicKey);
})')
if [[ $out == true ]]; then
  pass "generateKeyPair still works after register() (the property guard holds)"
else
  bad "generateKeyPair after register() -> $out"
fi

echo
echo "project: $app"
if (( fail )); then echo "FAILED"; exit 1; fi
echo "all checks passed"
