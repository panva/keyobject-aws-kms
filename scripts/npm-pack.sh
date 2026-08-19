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
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

BUILD_DIR=${1:-build}
OUT=${2:-$(mktemp -d -t awskms-npm.XXXXXX)}
mkdir -p "$OUT/npm-cache"
# Never depend on or mutate the caller's npm cache. Besides making the smoke
# hermetic, this avoids permission failures from a cache created by another uid.
export npm_config_cache="$OUT/npm-cache"

fail=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
die()  { printf '\033[31merror\033[0m %s\n' "$1" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) MODULE=aws-kms.dylib; OS=darwin ;;
  *)      MODULE=aws-kms.so;    OS=linux  ;;
esac
case "$(uname -m)" in
  arm64|aarch64) CPU=arm64 ;;
  *)             CPU=x64   ;;
esac

# glibc and musl are different C libraries, not versions of one, so a Linux
# artifact needs a third term. Asked of node rather than sniffed from the
# filesystem, because this must agree EXACTLY with what npm/core/index.js
# computes at runtime -- if the packer and the resolver disagree, a correctly
# installed package fails to find itself. glibcVersionRuntime is present on
# glibc and absent on musl.
if [[ $OS == linux ]]; then
  if node -p "process.report.getReport().header.glibcVersionRuntime ?? ''" | grep -q .; then
    LIBC=glibc; TARGET="linux-$CPU"
  else
    LIBC=musl;  TARGET="linuxmusl-$CPU"
  fi
else
  LIBC=; TARGET="$OS-$CPU"
fi

[[ -f $BUILD_DIR/$MODULE ]] || die "no $MODULE in $BUILD_DIR -- build it first"
[[ -f $BUILD_DIR/awskms-backend ]] \
  || die "no awskms-backend marker in $BUILD_DIR -- reconfigure with a current CMakeLists"
BACKEND=$(cat "$BUILD_DIR/awskms-backend")
BACKEND_BYTES=$(wc -c < "$BUILD_DIR/awskms-backend")
[[ $BACKEND == aws && $BACKEND_BYTES -eq 4 ]] \
  || die "refusing to package AWSKMS_BACKEND=$BACKEND; distributed packages must use the aws backend"
[[ -f $BUILD_DIR/awskms-dependencies ]] \
  || die "no awskms-dependencies marker in $BUILD_DIR -- reconfigure with a current CMakeLists"
SDK_TAG=$(node -p "require('./third_party/components.json').awsSdkTag")
[[ $(cat "$BUILD_DIR/awskms-dependencies") == "aws-sdk-cpp=$SDK_TAG" ]] \
  || die "refusing to package an AWS SDK dependency graph not covered by third_party/components.json"
# The RELOCATABLE cnf, not the build-tree one: the satellite ships a file whose
# module path is a token, and core substitutes it. Shipping the build-tree copy
# would bake in a path from the machine that built it.
[[ -f $BUILD_DIR/awskms.relocatable.cnf ]] \
  || die "no awskms.relocatable.cnf in $BUILD_DIR -- reconfigure with a current CMakeLists"

VERSION=$(node -p "require('./npm/core/package.json').version")

# One exact version across the core package and all six optional satellites.
# This is checked before any bytes are staged so a partial version bump cannot
# produce plausible-looking tarballs.
node -e '
  const p = require("./npm/core/package.json");
  const names = [
    "@keyobject/aws-kms-darwin-arm64",
    "@keyobject/aws-kms-darwin-x64",
    "@keyobject/aws-kms-linux-arm64",
    "@keyobject/aws-kms-linux-x64",
    "@keyobject/aws-kms-linuxmusl-arm64",
    "@keyobject/aws-kms-linuxmusl-x64",
  ];
  if (JSON.stringify(p.engines) !== JSON.stringify({ node: ">=26.7.0" })) {
    throw new Error("npm/core/package.json must require exactly Node.js >=26.7.0");
  }
  if (JSON.stringify(Object.keys(p.optionalDependencies).sort()) !== JSON.stringify(names.sort())) {
    throw new Error("the optional platform package set is incomplete or unexpected");
  }
  for (const name of names) {
    if (p.optionalDependencies[name] !== p.version) {
      throw new Error(`${name} must be pinned exactly to core ${p.version}`);
    }
  }
  if (p.publishConfig?.access !== "public") throw new Error("the scoped core package must publish as public");
' || die "core package metadata invariants failed"

echo "packing $TARGET $VERSION into $OUT"

# --- the platform package ---------------------------------------------------
sat="$OUT/platform"
mkdir -p "$sat"
# `libc` is npm's INSTALL-time gate and only means anything on linux; on darwin
# the key is dropped rather than emitted empty.
if [[ -n $LIBC ]]; then _libc="[\"$LIBC\"]"; fi
sed -e "s|@TARGET@|$TARGET|g" -e "s|@VERSION@|$VERSION|g" \
    -e "s|@OS@|$OS|g" -e "s|@CPU@|$CPU|g" -e "s|@MODULE@|$MODULE|g" \
    npm/platform/package.json.in \
  | if [[ -n $LIBC ]]; then sed "s|@LIBC@|${_libc}|"; else grep -v '"libc": @LIBC@,'; fi \
  > "$sat/package.json"
node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' "$sat/package.json" \
  || die "generated satellite package.json is not valid JSON"
cp "$BUILD_DIR/$MODULE" "$sat/"
cp "$BUILD_DIR/awskms.relocatable.cnf" "$sat/awskms.cnf"
cp LICENSE THIRD_PARTY_NOTICES.md "$sat/"
mkdir -p "$sat/third_party"
cp third_party/components.json "$sat/third_party/"
cp -R third_party/licenses "$sat/third_party/"

# One authoritative legal inventory serves source, archives, and npm. Validate
# it before packing, then require the staged bytes to be exact copies.
node scripts/check-licenses.mjs || die "authoritative third-party license inventory failed"
cmp -s THIRD_PARTY_NOTICES.md "$sat/THIRD_PARTY_NOTICES.md" \
  || die "staged third-party notice differs from the authoritative file"
cmp -s third_party/components.json "$sat/third_party/components.json" \
  || die "staged component manifest differs from the authoritative file"
for legal in third_party/licenses/*; do
  cmp -s "$legal" "$sat/$legal" \
    || die "staged $(basename "$legal") differs from the authoritative file"
done

node -e '
  const fs = require("node:fs");
  const [file, name, version, os, cpu, libc] = process.argv.slice(1);
  const p = JSON.parse(fs.readFileSync(file, "utf8"));
  if (p.name !== name || p.version !== version) throw new Error("generated name/version mismatch");
  const exact = (value, expected) =>
    Array.isArray(value) && value.length === 1 && value[0] === expected;
  if (!exact(p.os, os) || !exact(p.cpu, cpu)) throw new Error("generated os/cpu mismatch");
  if (libc ? !exact(p.libc, libc) : "libc" in p) throw new Error("generated libc mismatch");
  if (JSON.stringify(p.engines) !== JSON.stringify({ node: ">=26.7.0" })) {
    throw new Error("satellite must require exactly Node.js >=26.7.0");
  }
  if (p.publishConfig?.access !== "public") throw new Error("satellite must publish as public");
' "$sat/package.json" "@keyobject/aws-kms-$TARGET" "$VERSION" "$OS" "$CPU" "$LIBC" \
  || die "generated satellite metadata invariants failed"

(cd "$sat" && npm pack --silent >/dev/null 2>&1) || die "npm pack failed for the platform package"
pass "platform package packed ($(basename "$sat"/*.tgz))"

# --- the core package -------------------------------------------------------
core="$OUT/core"
mkdir -p "$core/bin"
cp npm/core/package.json npm/core/index.js npm/core/register.js LICENSE "$core/"
# Typings and the README ship WITH the package, not alongside it: `files` lists
# them, so leaving them out here would produce a tarball that npm publish would
# have included -- i.e. this check would be testing a different package.
cp npm/core/index.d.ts npm/core/register.d.ts npm/core/README.md "$core/"
cp npm/core/bin/awskms.js "$core/bin/"
# check.mjs is shipped rather than re-implemented, so all three distribution
# tiers run the same health check.
cp scripts/check.mjs "$core/"
(cd "$core" && npm pack --silent >/dev/null 2>&1) || die "npm pack failed for the core package"
pass "core package packed ($(basename "$core"/*.tgz))"

# Exact inventories catch both omissions and accidental publication of build or
# development files. npm implicitly includes README and LICENSE, so validate the
# packed tarballs rather than inferring their contents from `files`.
core_listing=$(tar tzf "$core"/*.tgz | sort)
core_expected=$(printf '%s\n' \
  package/LICENSE \
  package/README.md \
  package/bin/awskms.js \
  package/check.mjs \
  package/index.d.ts \
  package/index.js \
  package/package.json \
  package/register.d.ts \
  package/register.js | sort)
if [[ $core_listing == "$core_expected" ]]; then
  pass "core tarball has the exact public file inventory"
else
  bad "core tarball inventory differs"
  diff -u <(printf '%s\n' "$core_expected") <(printf '%s\n' "$core_listing") || true
fi

sat_listing=$(tar tzf "$sat"/*.tgz | sort)
sat_expected=$(printf '%s\n' \
  package/LICENSE \
  package/THIRD_PARTY_NOTICES.md \
  "package/$MODULE" \
  package/awskms.cnf \
  package/third_party/components.json \
  package/third_party/licenses/AWS-NOTICES.txt \
  package/third_party/licenses/AWS-SDK-THIRD-PARTY.txt \
  package/third_party/licenses/Ada-MIT.txt \
  package/third_party/licenses/Apache-2.0.txt \
  package/third_party/licenses/GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt \
  package/third_party/licenses/GPL-3.0.txt \
  package/package.json | sort)
if [[ $sat_listing == "$sat_expected" ]]; then
  pass "platform tarball has the exact binary and legal file inventory"
else
  bad "platform tarball inventory differs"
  diff -u <(printf '%s\n' "$sat_expected") <(printf '%s\n' "$sat_listing") || true
fi

if [[ ${AWSKMS_NPM_PACK_ONLY:-} == 1 ]]; then
  echo; echo "$OUT"
  (( fail )) && exit 1
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
(cd "$app" && npm install --silent --no-audit --no-fund --offline \
   --ignore-scripts \
   "$sat"/*.tgz "$core"/*.tgz >/dev/null 2>&1) \
  || die "npm install of the packed tarballs failed"
pass "both packages install into a clean project"

run() {
  local code=$1
  shift
  (cd "$app" && node -e "$code" "$@" 2>&1)
}

out=$(run 'import("@keyobject/aws-kms").then(m=>console.log(m.modulePath()))')
if [[ -f $out ]]; then pass "modulePath() resolves to a real file"; else bad "modulePath() -> $out"; fi

out=$(run 'import("@keyobject/aws-kms").then(m=>console.log(JSON.stringify(m.isSupported())))')
if [[ $out == *'"ok":true'* ]]; then pass "isSupported() -> ok"; else bad "isSupported() -> $out"; fi

config_state=$(run 'Promise.all([import("@keyobject/aws-kms"), import("node:fs"), import("node:path")]).then(([m, fs, path]) => {
  const first = m.opensslConfigPath();
  const second = m.opensslConfigPath();
  const dir = fs.statSync(path.dirname(first));
  const file = fs.statSync(first);
  const text = fs.readFileSync(first, "utf8");
  console.log(JSON.stringify({ first, same: first === second,
    dirMode: dir.mode & 0o777, fileMode: file.mode & 0o777,
    token: text.includes("$ENV::AWSKMS_MODULE"), quoted: /^\s*module\s*=\s*"/mu.test(text) }));
})')
cnf=$(node -e 'console.log(JSON.parse(process.argv[1]).first)' "$config_state")
if [[ -f $cnf ]] && [[ $config_state == *'"same":true'* ]] &&
   [[ $config_state == *'"dirMode":448'* ]] && [[ $config_state == *'"fileMode":256'* ]] &&
   [[ $config_state == *'"token":false'* ]] && [[ $config_state == *'"quoted":true'* ]]; then
  pass "opensslConfigPath() is stable, private, validated and safely quoted"
else
  bad "opensslConfigPath() state -> $config_state"
fi

# Tampering is detected in the same process instead of being silently reused.
out=$(run 'Promise.all([import("@keyobject/aws-kms"), import("node:fs")]).then(([m, fs]) => {
  const path = m.opensslConfigPath();
  const bytes = fs.readFileSync(path);
  bytes[0] ^= 1;
  fs.chmodSync(path, 0o600);
  fs.writeFileSync(path, bytes);
  fs.chmodSync(path, 0o400);
  try { m.opensslConfigPath(); console.log("SILENT"); }
  catch (error) { console.log(error.code); }
})')
if [[ $out == ERR_AWSKMS_TEMP_INTEGRITY ]]; then
  pass "private config tampering is detected"
else
  bad "config tamper detection -> $out"
fi

# Installed payloads are also snapshotted. A same-length mutation must fail the
# digest check even when the pathname and size are unchanged.
installed_config="$app/node_modules/@keyobject/aws-kms-$TARGET/awskms.cnf"
cp "$installed_config" "$installed_config.save"
out=$(run 'Promise.all([import("@keyobject/aws-kms"), import("node:fs")]).then(([m, fs]) => {
  m.modulePath();
  const path = process.argv[1];
  const bytes = fs.readFileSync(path);
  bytes[0] ^= 1;
  fs.writeFileSync(path, bytes);
  try { m.modulePath(); console.log("SILENT"); }
  catch (error) { console.log(error.code); }
})' "$installed_config")
mv "$installed_config.save" "$installed_config"
if [[ $out == ERR_AWSKMS_PACKAGE_INTEGRITY ]]; then
  pass "same-length installed payload tampering is detected by digest"
else
  bad "installed payload tamper detection -> $out"
fi

# Exact core/satellite version coupling is a runtime invariant, not merely a
# package-manager hint. Modify only the throwaway install and restore it before
# the remaining smoke tests.
installed_manifest="$app/node_modules/@keyobject/aws-kms-$TARGET/package.json"
cp "$installed_manifest" "$installed_manifest.save"
node -e '
  const fs = require("node:fs");
  const p = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  p.version = "9.9.9";
  fs.writeFileSync(process.argv[1], `${JSON.stringify(p, null, 2)}\n`);
' "$installed_manifest"
out=$(run 'import("@keyobject/aws-kms").then(m => {
  try { m.modulePath(); console.log("SILENT"); }
  catch (error) { console.log(error.code); }
})')
mv "$installed_manifest.save" "$installed_manifest"
if [[ $out == ERR_AWSKMS_VERSION_MISMATCH ]]; then
  pass "core/native version skew is rejected"
else
  bad "version skew -> $out"
fi

# Run the adversarial path checks against the installed tarballs. Every process
# and Worker shares one TMPDIR, so this exercises mkdtemp collision handling,
# validation, and archive copy-out without test-only runtime hooks.
if AWSKMS_NPM_TEST_APP="$app" \
   AWSKMS_NPM_TEST_TARGET="$TARGET" \
   AWSKMS_NPM_TEST_MODULE="$MODULE" \
   AWSKMS_NPM_TEST_ROOT="$OUT/npm-temp-acceptance" \
   node --test --test-reporter=spec test/npm-temp-paths.test.mjs; then
  pass "private temp paths resist precreation, tampering, and concurrency"
else
  bad "private temp-path acceptance fixture"
fi

# CJS consumers: require(ESM) is unflagged well below our floor, so the
# ESM-only package must still be require()-able.
out=$(cd "$app" && node -e 'console.log(typeof require("@keyobject/aws-kms").modulePath)' 2>&1)
if [[ $out == function ]]; then pass "require() works from CJS (require(ESM))"; else bad "require() from CJS -> $out"; fi

# The end that matters: does the provider actually load with that cnf?
out=$(cd "$app" && node --openssl-config="$cnf" \
        ./node_modules/@keyobject/aws-kms/check.mjs 2>&1 | tail -1)
if [[ $out == *"aws-kms is working"* ]]; then pass "the provider loads and is reachable"; else bad "check said: $out"; fi

# And through the bin, which is how most people will reach it.
out=$(cd "$app" && ./node_modules/.bin/keyobject-aws-kms check 2>&1 | tail -1)
if [[ $out == *"aws-kms is working"* ]]; then pass "bin: check"; else bad "bin check -> $out"; fi

# Neither CLI command silently replaces application OpenSSL configuration.
out=$(cd "$app" && node --openssl-config=/dev/null \
  ./node_modules/@keyobject/aws-kms/bin/awskms.js check 2>&1)
rc=$?
if (( rc != 0 )) && [[ $out == *ERR_AWSKMS_OPENSSL_CONFIG_EXISTS* ]] &&
   [[ $out == *"current node command line"* ]]; then
  pass "bin: check refuses to replace its Node command-line config"
else
  bad "bin check command-line refusal (rc=$rc) -> $out"
fi

out=$(cd "$app" && node --openssl-config=/dev/null \
  ./node_modules/@keyobject/aws-kms/bin/awskms.js check \
  --replace-openssl-config 2>&1 | tail -1)
if [[ $out == *"aws-kms is working"* ]]; then
  pass "bin: check explicitly replaces its Node command-line config"
else
  bad "bin check command-line replace -> $out"
fi

out=$(cd "$app" && OPENSSL_CONF=/dev/null \
  ./node_modules/.bin/keyobject-aws-kms check 2>&1)
rc=$?
if (( rc != 0 )) && [[ $out == *ERR_AWSKMS_OPENSSL_CONFIG_EXISTS* ]]; then
  pass "bin: check refuses to replace OPENSSL_CONF"
else
  bad "bin check config refusal (rc=$rc) -> $out"
fi

out=$(cd "$app" && OPENSSL_CONF=/dev/null \
  ./node_modules/.bin/keyobject-aws-kms check --replace-openssl-config 2>&1 | tail -1)
if [[ $out == *"aws-kms is working"* ]]; then
  pass "bin: check explicitly replaces OPENSSL_CONF"
else
  bad "bin check replace config -> $out"
fi

out=$(cd "$app" && OPENSSL_CONF=/dev/null \
  ./node_modules/.bin/keyobject-aws-kms exec -- node -e 'console.log("SILENT")' 2>&1)
rc=$?
if (( rc != 0 )) && [[ $out == *ERR_AWSKMS_OPENSSL_CONFIG_EXISTS* ]]; then
  pass "bin: exec refuses to replace OPENSSL_CONF"
else
  bad "bin exec config refusal (rc=$rc) -> $out"
fi

out=$(cd "$app" && OPENSSL_CONF=/dev/null \
  ./node_modules/.bin/keyobject-aws-kms exec --replace-openssl-config -- \
  node -e 'const{createPrivateKey}=require("crypto");
           try{createPrivateKey({key:new URL("aws-kms:")})}catch(e){console.log(e.code)}' \
  2>&1 | tail -1)
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then
  pass "bin: --replace-openssl-config explicitly replaces OPENSSL_CONF"
else
  bad "bin replace config -> $out"
fi

out=$(cd "$app" && NODE_OPTIONS=--openssl-config=/dev/null \
  ./node_modules/.bin/keyobject-aws-kms exec -- node -e 'console.log("SILENT")' 2>&1)
rc=$?
if (( rc != 0 )) && [[ $out == *ERR_AWSKMS_OPENSSL_CONFIG_EXISTS* ]]; then
  pass "bin: exec refuses to replace NODE_OPTIONS --openssl-config"
else
  bad "bin exec NODE_OPTIONS refusal (rc=$rc) -> $out"
fi

out=$(cd "$app" && NODE_OPTIONS=--openssl-config=/dev/null \
  ./node_modules/.bin/keyobject-aws-kms exec --replace-openssl-config -- \
  node -e 'const{createPrivateKey}=require("crypto");
           try{createPrivateKey({key:new URL("aws-kms:")})}catch(e){console.log(e.code)}' \
  2>&1 | tail -1)
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then
  pass "bin: explicit replacement overrides NODE_OPTIONS --openssl-config"
else
  bad "bin replace NODE_OPTIONS config -> $out"
fi

out=$(cd "$app" && ./node_modules/.bin/keyobject-aws-kms exec -- \
  node --openssl-config=/dev/null -e 'console.log("SILENT")' 2>&1)
rc=$?
if (( rc != 0 )) && [[ $out == *ERR_AWSKMS_OPENSSL_CONFIG_EXISTS* ]] &&
   [[ $out == *"target command line"* ]]; then
  pass "bin: exec refuses a target Node --openssl-config"
else
  bad "bin exec target config refusal (rc=$rc) -> $out"
fi

out=$(cd "$app" && ./node_modules/.bin/keyobject-aws-kms exec \
  --replace-openssl-config -- node --openssl-config /dev/null \
  -e 'const{createPrivateKey}=require("crypto");
      try{createPrivateKey({key:new URL("aws-kms:")})}catch(e){console.log(e.code)}' \
  2>&1 | tail -1)
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then
  pass "bin: explicit replacement removes a target Node --openssl-config"
else
  bad "bin replace target command config -> $out"
fi

out=$(cd "$app" && ./node_modules/.bin/keyobject-aws-kms exec -- \
        node -e 'const{createPrivateKey}=require("crypto");
                 try{createPrivateKey({key:new URL("aws-kms:")})}catch(e){console.log(e.code)}' 2>&1 | tail -1)
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then pass "bin: exec activates the provider for a child process"; else bad "bin exec -> $out"; fi

# NEGATIVE CONTROL FIRST. Without register(), and with no cnf, the provider must
# NOT be reachable -- otherwise every check below could be passing because of a
# stray OPENSSL_CONF in the environment rather than anything this package does.
out=$(run 'const {createPrivateKey}=require("crypto");
  try { createPrivateKey({key:new URL("aws-kms:")}) } catch(e){ console.log(e.code) }')
if [[ $out == ERR_OSSL_OSSL_STORE_UNSUPPORTED ]]; then
  pass "negative control: the provider is absent until something registers it"
else
  bad "expected the provider to be ABSENT without register(), got: $out"
fi

# The in-process route: no cnf, no CLI flag. This is what `register()` buys, and
# the only way to know it works is to do it.
out=$(run 'import("@keyobject/aws-kms/register").then(()=>{
  const {createPrivateKey}=require("crypto");
  try { createPrivateKey({key:new URL("aws-kms:")}) } catch(e){ console.log(e.code) }
})')
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then
  pass "import 'pkg/register' activates the provider -- no cnf, no flag"
else
  bad "register subpath -> $out"
fi

# Idempotent, and STILL WORKING afterwards. Asserting only "did not throw" would
# pass just as happily if register() had quietly done nothing at all.
out=$(run 'import("@keyobject/aws-kms").then(m=>{
  m.register(); m.register();
  const {createPrivateKey}=require("crypto");
  try { createPrivateKey({key:new URL("aws-kms:")}) } catch(e){ console.log(e.code) }
})')
if [[ $out == ERR_OSSL_AWSKMS_INVALID_URI ]]; then
  pass "register() twice is safe AND the provider still works"
else
  bad "double register() -> $out"
fi

# The claimed advantage over the cnf route is that failure is LOUD. A cnf that
# names a bad module produces no diagnostic whatsoever; this must throw.
out=$(run 'import("@keyobject/aws-kms").then(m=>{
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
out=$(run 'import("@keyobject/aws-kms/register").then(()=>{
  const {generateKeyPairSync}=require("crypto");
  console.log(!!generateKeyPairSync("ec",{namedCurve:"P-256"}).publicKey);
})')
if [[ $out == true ]]; then
  pass "generateKeyPair still works after register() (the property guard holds)"
else
  bad "generateKeyPair after register() -> $out"
fi

# OpenSSL's config grammar gives #, $, quotes and backslashes special meaning.
# Put only the satellite behind such a path: npm itself normalizes backslashes
# in a package working directory, while Node can resolve an installed symlink to
# one. Successfully loading the provider proves the rendered module value
# survived the config parser byte-for-byte.
path_app="$OUT/path-app"
special_satellite="$OUT/platform # dollar\$ quote\" back\\slash"
cp -R "$app" "$path_app"
cp -R "$path_app/node_modules/@keyobject/aws-kms-$TARGET" "$special_satellite"
mv "$path_app/node_modules/@keyobject/aws-kms-$TARGET" \
  "$path_app/node_modules/@keyobject/aws-kms-$TARGET-original"
ln -s "$special_satellite" "$path_app/node_modules/@keyobject/aws-kms-$TARGET"
special_cnf=$(cd "$path_app" && node -e \
  'import("@keyobject/aws-kms").then(m => console.log(m.opensslConfigPath()))')
out=$(cd "$path_app" && node --openssl-config="$special_cnf" \
  ./node_modules/@keyobject/aws-kms/check.mjs 2>&1 | tail -1)
if [[ $out == *"aws-kms is working"* ]]; then
  pass "OpenSSL config safely encodes #, $, quote and backslash in module paths"
else
  bad "special-character module path -> $out"
fi

echo
echo "project: $app"
if (( fail )); then echo "FAILED"; exit 1; fi
echo "all checks passed"
