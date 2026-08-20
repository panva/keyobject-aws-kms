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
  x86_64|amd64)
    [[ $OS != darwin ]] || die 'Intel macOS is not a supported distribution target'
    CPU=x64
    ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

# glibc and musl are different C libraries, not versions of one, so a Linux
# artifact needs a third term. Asked of node rather than sniffed from the
# filesystem, because this must agree EXACTLY with what npm/core/index.js
# computes at runtime -- if the packer and the resolver disagree, a correctly
# installed package fails to find itself. glibcVersionRuntime is present on
# glibc and absent on musl.
if [[ $OS == linux ]]; then
  if node -p "process.report.getReport().header.glibcVersionRuntime ?? ''" | grep -q .; then
    TARGET="linux-$CPU"
  else
    TARGET="linuxmusl-$CPU"
  fi
else
  TARGET="$OS-$CPU"
fi

VERSION=$(node -p "require('./npm/core/package.json').version")
echo "packing $TARGET $VERSION into $OUT"

# Target mapping, metadata rendering, legal staging, binary identity checks,
# npm packing, and exact tarball inventory checks live in one implementation.
# The release assembler imports that same implementation for all five targets.
node scripts/pack-npm.mjs \
  --build-dir "$BUILD_DIR" \
  --target "$TARGET" \
  --out "$OUT" \
  >/dev/null || die "npm package staging failed"

sat="$OUT/platform"
pass "platform package packed ($(basename "$sat"/*.tgz))"
core="$OUT/core"
pass "core package packed ($(basename "$core"/*.tgz))"
pass "core and platform tarballs have exact public inventories"
pass "npm uses the repository and rendered platform READMEs"

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
