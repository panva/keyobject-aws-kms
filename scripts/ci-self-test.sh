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

# GitHub and npm share one public landing page, while native satellites get a
# short target-specific README. Community files follow the same public surface
# used across the maintainer's other packages.
[[ ! -e $repo/npm/core/README.md ]] ||
  fail 'the npm package must not maintain a divergent README'
[[ -f $repo/npm/platform/README.md.in ]] ||
  fail 'the platform package README template is missing'
for heading in '## Quick Start' \
  '## [💗 Help the project](https://github.com/sponsors/panva)' \
  '## Performance and Concurrency' '## Compatibility Check' \
  '## Supported Keys' '## Documentation'; do
  grep -Fq "$heading" "$repo/README.md" ||
    fail "the public README is missing: $heading"
done
for required in CODE_OF_CONDUCT.md docs/README.md \
  .github/ISSUE_TEMPLATE/config.yml .github/ISSUE_TEMPLATE/bug-report.yml; do
  [[ -s $repo/$required ]] || fail "public community artifact is missing: $required"
done
grep -Fq 'security/advisories/new' "$repo/SECURITY.md" ||
  fail 'the security policy does not use private vulnerability reporting'
grep -Fq 'blank_issues_enabled: false' \
  "$repo/.github/ISSUE_TEMPLATE/config.yml" ||
  fail 'blank GitHub issues must remain disabled'

# Dependency updates must carry both versions in the commit subjects and in the
# generated PR body. Exercise both the pinned and vendored paths without the
# network so the scheduled workflow cannot quietly regress either format.
bump_fixture="$temporary/dependency-bump"
mkdir -p "$bump_fixture"/{cmake,scripts,third_party} \
  "$bump_fixture/fake-bin"
cp "$repo/scripts/bump-deps.sh" \
  "$repo/scripts/check-licenses.mjs" \
  "$repo/scripts/dependency-pr-body.sh" \
  "$repo/scripts/update-aws-sdk-components.mjs" "$bump_fixture/scripts/"
cp "$repo/third_party/components.json" "$bump_fixture/third_party/"
cp -R "$repo/third_party/licenses" "$bump_fixture/third_party/"
# Keep this transition fixture independent of the repository's current pin.
# In particular, every component that moved must look stale so its reviewed
# legal-file inventory is exercised even after the real bump is merged.
node - "$bump_fixture/third_party/components.json" <<'EOF'
const fs = require('node:fs');

const file = process.argv[2];
const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
manifest.awsSdkTag = '1.11.855';
for (const name of [
  'aws-cpp-sdk-core',
  'aws-cpp-sdk-kms',
  'aws-sdk-cpp-third-party',
]) {
  manifest.components.find((component) => component.name === name).version =
    '1.11.855';
}
const commits = new Map([
  ['aws-crt-cpp', '72f84bc327462f405c4994228fffe1eeb16cca72'],
  ['aws-c-cal', '9edd8eac2b21ca6a04535b91d60d361c2f1bb60f'],
  ['aws-c-io', '54350963b64dfc6c4b0ea623b08aa252aae3d7d7'],
  ['aws-c-s3', '1f29ef8871a27dc8b90325418780659bac534d71'],
  ['aws-c-sdkutils', 'cb14fea362c82c995eebd34e2e96590ab4e0ed58'],
  ['s2n-tls', 'f5f6c6c2ce2370de1aa3ade6899a7321d1127bb8'],
]);
for (const component of manifest.components) {
  if (commits.has(component.name)) component.commit = commits.get(component.name);
}
fs.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
EOF
cat > "$bump_fixture/cmake/FetchAwsSdkKms.cmake" <<'EOF'
set(AWSKMS_AWS_SDK_TAG "1.11.855" CACHE STRING
  "fixture")
EOF
cat > "$bump_fixture/third_party/vendored.manifest" <<'EOF'
ada | ada-url/ada | v3.2.7 | ada.cpp ada.h ada_c.h | LICENSE-MIT
EOF
cat > "$bump_fixture/scripts/update-vendored.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 3 && $1 == update && $2 == ada && $3 == v3.2.8 ]]
sed -i.bak 's/v3\.2\.7/v3.2.8/' third_party/vendored.manifest
rm -f third_party/vendored.manifest.bak
EOF
cat > "$bump_fixture/fake-bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == api && -n ${2:-} ]] || exit 64
case $2 in
  'repos/aws/aws-sdk-cpp/tags?per_page=100') printf '1.11.874\n' ;;
  'repos/ada-url/ada/releases/latest') printf 'v3.2.8\n' ;;
  *)
    node -e '
      const responses = require(process.argv[1]);
      const response = responses[process.argv[2]];
      if (response == null) {
        console.error(`unexpected gh request: ${process.argv[2]}`);
        process.exit(64);
      }
      process.stdout.write(JSON.stringify(response));
    ' "${FAKE_GH_RESPONSES:?}" "$2"
    ;;
esac
EOF
chmod 755 "$bump_fixture/scripts/"*.sh "$bump_fixture/fake-bin/gh"
chmod 755 "$bump_fixture/scripts/update-aws-sdk-components.mjs"
node - "$bump_fixture" <<'EOF'
const fs = require('node:fs');
const path = require('node:path');

const fixture = process.argv[2];
const crtCommit = '851d8d003c9d5150edab56807e2393013f3771de';
const gitlinks = {
  'crt/aws-c-auth': '4b5d524bf1a511b05e0fffe5bdc51800770b9427',
  'crt/aws-c-cal': '8aa2a48a09f93c65d4cf06388e143a6584de6321',
  'crt/aws-c-common': '3c69b871dfa1815231802febf1bb6899f84cccdb',
  'crt/aws-c-compression': 'd8264e64f698341eb03039b96b4f44702a9b3f83',
  'crt/aws-c-event-stream': '51bef3c44e1058b1689751539170b2e0f589ccdb',
  'crt/aws-c-http': '8aefd899fc3210bfd0e3fd414011a3cb708bf6e4',
  'crt/aws-c-io': 'e2946c99521fa12d285c9a0829c92b1bf713922b',
  'crt/aws-c-mqtt': '2ef9605ec9c50bea3f921e08022ddd57eed70901',
  'crt/aws-c-s3': 'a852faa2df3ab2b31fb4cfd64fd3379a2f4ae22e',
  'crt/aws-c-sdkutils': 'a1cc19f53b63658f1b1400b36f199eafeeb895a6',
  'crt/aws-checksums': '1d5f2f1f3e5d013aae8810878ceb5b3f6f258c4e',
  'crt/aws-lc': 'f6acf748df0ea6157d55e640730b38d21a7751cd',
  'crt/s2n': '66b1c94d1dfc99b237427cbde230eca63bb8b89c',
};
const repositories = Object.fromEntries(
  Object.keys(gitlinks).map((gitlink) => [
    gitlink,
    `https://github.com/awslabs/${gitlink === 'crt/s2n' ? 's2n' : gitlink.slice(4)}.git`,
  ]),
);
const gitmodules = Object.entries(repositories)
  .map(([gitlink, url]) => `[submodule "${gitlink}"]\n\tpath = ${gitlink}\n\turl = ${url}\n`)
  .join('');
const legalTree = (files) => ({
  truncated: false,
  tree: Object.entries(files).map(([file, sha]) => ({
    path: file, mode: '100644', type: 'blob', sha,
  })),
});
const crtTree = legalTree({
  LICENSE: 'd645695673349e3947e8e5ae42332d0ac3164cd7',
  NOTICE: '8b820137a0aa14f48ecaa89c3602139eaa2f7f88',
});
crtTree.tree.push(...Object.entries(gitlinks).map(([gitlink, sha]) => ({
  path: gitlink, mode: '160000', type: 'commit', sha,
})));
const responses = {
  'repos/aws/aws-sdk-cpp/contents/crt/aws-crt-cpp?ref=1.11.874': {
    sha: crtCommit,
    submodule_git_url: 'https://github.com/awslabs/aws-crt-cpp.git',
  },
  [`repos/awslabs/aws-crt-cpp/contents/.gitmodules?ref=${crtCommit}`]: {
    encoding: 'base64', content: Buffer.from(gitmodules).toString('base64'),
  },
  [`repos/awslabs/aws-crt-cpp/git/trees/${crtCommit}?recursive=1`]: crtTree,
  'repos/aws/aws-sdk-cpp/git/trees/1.11.874': legalTree({
    LICENSE: '8dada3edaf50dbc082c9a125058f25def75e625a',
    'LICENSE.txt': '3adf3884dda91cc70aca0b8553406b159a530702',
    'NOTICE.txt': '66bbe1f2efa5f06838ef6d68a4644c858a8f92fa',
  }),
  [`repos/awslabs/aws-c-cal/git/trees/${gitlinks['crt/aws-c-cal']}`]: legalTree({
    LICENSE: '67db8588217f266eb561f75fae738656325deac9',
    NOTICE: 'df81ba71af0026d3dab3ab7a9ad68bd15540b575',
  }),
  [`repos/awslabs/aws-c-io/git/trees/${gitlinks['crt/aws-c-io']}`]: legalTree({
    LICENSE: 'd645695673349e3947e8e5ae42332d0ac3164cd7',
    NOTICE: '7939cd2397dc0b7a4b1aa55f23ad6d97f5ad1211',
  }),
  [`repos/awslabs/aws-c-s3/git/trees/${gitlinks['crt/aws-c-s3']}`]: legalTree({
    LICENSE: '67db8588217f266eb561f75fae738656325deac9',
    NOTICE: '616fc5889451895dbf9768e6787c8308c33bef22',
  }),
  [`repos/awslabs/aws-c-sdkutils/git/trees/${gitlinks['crt/aws-c-sdkutils']}`]: legalTree({
    LICENSE: '67db8588217f266eb561f75fae738656325deac9',
    NOTICE: '616fc5889451895dbf9768e6787c8308c33bef22',
  }),
  [`repos/awslabs/s2n/git/trees/${gitlinks['crt/s2n']}`]: legalTree({
    LICENSE: 'd645695673349e3947e8e5ae42332d0ac3164cd7',
    NOTICE: 'f8bbcc301b59800d2f6ac5c1f82cb2d8bcff31b2',
  }),
};
const write = (name, value) => fs.writeFileSync(
  path.join(fixture, name), JSON.stringify(value),
);
write('gh-responses.json', responses);

const graphDrift = structuredClone(responses);
graphDrift[`repos/awslabs/aws-crt-cpp/git/trees/${crtCommit}?recursive=1`]
  .tree.push({
    path: 'crt/aws-c-new', mode: '160000', type: 'commit',
    sha: '1111111111111111111111111111111111111111',
  });
write('gh-responses-graph-drift.json', graphDrift);

const repositoryDrift = structuredClone(responses);
const modulesEndpoint = `repos/awslabs/aws-crt-cpp/contents/.gitmodules?ref=${crtCommit}`;
repositoryDrift[modulesEndpoint].content = Buffer.from(
  gitmodules.replace(
    'https://github.com/awslabs/aws-c-cal.git',
    'https://github.com/example/aws-c-cal.git',
  ),
).toString('base64');
write('gh-responses-repository-drift.json', repositoryDrift);

const legalDrift = structuredClone(responses);
const s2nEndpoint = `repos/awslabs/s2n/git/trees/${gitlinks['crt/s2n']}`;
legalDrift[s2nEndpoint].tree.find(({ path: file }) => file === 'NOTICE').sha =
  '2222222222222222222222222222222222222222';
write('gh-responses-legal-drift.json', legalDrift);
EOF

assert_component_update_fails() {
  local responses=$1 expected=$2 label=$3 before rc
  before=$(shasum -a 256 "$bump_fixture/third_party/components.json")
  set +e
  PATH="$bump_fixture/fake-bin:$PATH" \
    FAKE_GH_RESPONSES="$bump_fixture/$responses" \
    "$bump_fixture/scripts/update-aws-sdk-components.mjs" 1.11.874 \
    >"$bump_fixture/$label.out" 2>"$bump_fixture/$label.err"
  rc=$?
  set -e
  [[ $rc -ne 0 ]] || fail "$label bypassed AWS component review"
  grep -Fq "$expected" "$bump_fixture/$label.err" ||
    fail "$label failure is not actionable"
  [[ $(shasum -a 256 "$bump_fixture/third_party/components.json") == "$before" ]] ||
    fail "$label modified the component manifest"
}

assert_component_update_fails \
  gh-responses-graph-drift.json 'unexpected: crt/aws-c-new' graph-drift
assert_component_update_fails \
  gh-responses-repository-drift.json \
  'repository for crt/aws-c-cal changed' repository-drift
assert_component_update_fails \
  gh-responses-legal-drift.json \
  'awslabs/s2n NOTICE changed' legal-drift
git -C "$bump_fixture" init -q
git -C "$bump_fixture" config user.name fixture
git -C "$bump_fixture" config user.email fixture@example.com
git -C "$bump_fixture" config commit.gpgsign false
git -C "$bump_fixture" add cmake scripts third_party
git -C "$bump_fixture" commit -qm base
git -C "$bump_fixture" branch -M main
git -C "$bump_fixture" checkout -qb deps/bump
PATH="$bump_fixture/fake-bin:$PATH" \
  FAKE_GH_RESPONSES="$bump_fixture/gh-responses.json" \
  "$bump_fixture/scripts/bump-deps.sh" >/dev/null

bump_subjects=$(git -C "$bump_fixture" log --reverse --format='%s' main..HEAD)
expected_bump_subjects=$'build: bump aws-sdk-cpp from 1.11.855 to 1.11.874\nbuild: bump ada from v3.2.7 to v3.2.8'
[[ $bump_subjects == "$expected_bump_subjects" ]] || {
  diff -u <(printf '%s\n' "$expected_bump_subjects") \
    <(printf '%s\n' "$bump_subjects") >&2 || true
  fail 'dependency bump subjects do not include exact old and new versions'
}

component_summary=$(node -e '
  const manifest = require(process.argv[1]);
  const wanted = [
    "aws-crt-cpp", "aws-c-cal", "aws-c-io", "aws-c-s3",
    "aws-c-sdkutils", "s2n-tls",
  ];
  console.log(manifest.awsSdkTag);
  for (const name of wanted) {
    const component = manifest.components.find((entry) => entry.name === name);
    console.log(`${name}=${component.commit}`);
  }
' "$bump_fixture/third_party/components.json")
expected_component_summary=$(cat <<'EOF'
1.11.874
aws-crt-cpp=851d8d003c9d5150edab56807e2393013f3771de
aws-c-cal=8aa2a48a09f93c65d4cf06388e143a6584de6321
aws-c-io=e2946c99521fa12d285c9a0829c92b1bf713922b
aws-c-s3=a852faa2df3ab2b31fb4cfd64fd3379a2f4ae22e
aws-c-sdkutils=a1cc19f53b63658f1b1400b36f199eafeeb895a6
s2n-tls=66b1c94d1dfc99b237427cbde230eca63bb8b89c
EOF
)
[[ $component_summary == "$expected_component_summary" ]] ||
  fail 'AWS SDK bump did not refresh the exact component graph'
node "$bump_fixture/scripts/check-licenses.mjs" >/dev/null

bump_body=$("$bump_fixture/scripts/dependency-pr-body.sh" main)
expected_bump_body=$(cat <<'EOF'
Opened monthly by `.github/workflows/vendored.yml`.

## Changes

- Bump `aws-sdk-cpp` from `1.11.855` to `1.11.874`.
- Bump `ada` from `v3.2.7` to `v3.2.8`.

This branch is **reset from `main`** whenever the workflow runs and force-pushed, so it is always exactly `main` plus one commit per dependency that moved. It is derived state: do not commit onto it, and expect history to be rewritten.

**Mark this ready for review to run CI.** It is opened as a draft, and this repository gates CI behind a non-draft pull request. The `ready_for_review` action is an explicit CI trigger.

An `aws-sdk-cpp` bump moves vendored s2n. The build checks whether the local s2n compatibility patch is still applicable or can be removed.
EOF
)
[[ $bump_body == "$expected_bump_body" ]] || {
  diff -u <(printf '%s\n' "$expected_bump_body") \
    <(printf '%s\n' "$bump_body") >&2 || true
  fail 'dependency PR body does not contain the exact unwrapped transitions'
}

vendored_workflow="$repo/.github/workflows/vendored.yml"
grep -Fq -- "- cron: '0 6 1 * *'" "$vendored_workflow" ||
  fail 'dependency bump workflow is not scheduled monthly'
grep -Fq 'scripts/dependency-pr-body.sh origin/main > /tmp/pr-body.md' \
  "$vendored_workflow" || fail 'vendored workflow does not render the tested PR body'
grep -Fq '"repos/$GITHUB_REPOSITORY/pulls/$existing_pr_number"' \
  "$vendored_workflow" || fail 'vendored workflow does not refresh an existing PR body'
grep -Fq 'node-version-file: .node-version' "$vendored_workflow" ||
  fail 'dependency updater does not run on the project Node version'

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
grep -Fq 'brew untap aws/tap' "$macos_action" ||
  fail 'macOS must remove the unused untrusted AWS tap before installing ccache'
if grep -Eq 'brew trust aws/tap|HOMEBREW_NO_REQUIRE_TAP_TRUST' "$macos_action"; then
  fail 'macOS must not trust the AWS tap or disable Homebrew tap enforcement'
fi
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
  "$workflow") -eq 10 ]] || fail 'CI must define exactly 10 coordinate producers'
[[ $(grep -Ec '^  test-(glibc|macos|musl-experimental)-(x64|arm64)-(stub|aws):$' \
  "$workflow") -eq 10 ]] || fail 'CI must define exactly 10 coordinate consumers'
for legacy_job in build-glibc build-macos build-musl-experimental \
  test-glibc test-macos test-musl-experimental openssl-runtime; do
  [[ -z $(extract_yaml_job "$legacy_job" "$workflow") ]] ||
    fail "legacy aggregate CI job remains: $legacy_job"
done
for family in glibc macos musl-experimental; do
  case $family in
    glibc) action=ci-glibc; arches=(x64 arm64) ;;
    macos) action=ci-macos; arches=(arm64) ;;
    musl-experimental) action=ci-musl; arches=(x64 arm64) ;;
  esac
  for arch in "${arches[@]}"; do
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
      grep -Fq "          backend: $backend" <<<"$producer_job" ||
        fail "$producer has the wrong backend input"
      grep -Fq "uses: ./.github/actions/$action" <<<"$consumer_job" ||
        fail "$consumer does not use $action"
      grep -Fq '          phase: test' <<<"$consumer_job" ||
        fail "$consumer does not select the test phase"
      grep -Fq "          backend: $backend" <<<"$consumer_job" ||
        fail "$consumer has the wrong backend input"
      grep -Fq '          node-version: ${{ matrix.node-version }}' \
        <<<"$consumer_job" || fail "$consumer does not pass its Node version"
      grep -Fq "needs: [node-versions, $producer]" <<<"$consumer_job" ||
        fail "$consumer waits on more than its exact producer"
      if [[ $family != macos ]]; then
        grep -Fq "          arch: $arch" <<<"$producer_job" ||
          fail "$producer has the wrong architecture input"
        grep -Fq "          arch: $arch" <<<"$consumer_job" ||
          fail "$consumer has the wrong architecture input"
        grep -Eq '^          image: [^[:space:]]+$' <<<"$producer_job" ||
          fail "$producer does not pass its pinned container image"
        grep -Eq '^          image: [^[:space:]]+$' <<<"$consumer_job" ||
          fail "$consumer does not pass its pinned container image"
      elif grep -Eq '^          (arch|binary-arch):' \
        <<<"$producer_job"$'\n'"$consumer_job"; then
        fail 'the ARM-only macOS action must not accept architecture inputs'
      fi
      if [[ $family == musl-experimental ]]; then
        grep -Fq "if: always() && needs.node-versions.result == 'success' && needs.$producer.result == 'success'" \
          <<<"$consumer_job" ||
          fail "$consumer lost the experimental musl result guard"
      fi
    done
  done
done

macos_action="$repo/.github/actions/ci-macos/action.yml"
grep -Fq 'run: test "$(uname -m)" = arm64' "$macos_action" ||
  fail 'the macOS action does not require Apple silicon'
grep -Fq 'target=darwin-arm64' "$macos_action" ||
  fail 'the macOS action does not stage the ARM64 archive'
intel_macos_target='darwin-''x64'
if "$repo/scripts/package-archive.sh" "$temporary/missing-build" \
  "$intel_macos_target" "$temporary" >"$temporary/intel-archive.out" 2>&1; then
  fail 'archive packaging accepted the removed Intel macOS target'
fi
grep -Fq "unsupported archive target: $intel_macos_target" \
  "$temporary/intel-archive.out" ||
  fail 'archive packaging did not reject Intel macOS before reading build files'
grep -Fq "Intel macOS is not a supported distribution target" \
  "$repo/scripts/npm-pack.sh" ||
  fail 'npm packaging does not reject Intel macOS'

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
grep -Fq 'StringLike:' "$repo/scripts/real-kms-bootstrap.mjs" ||
  fail 'real-KMS OIDC subjects must support the release tag glob'
grep -Fq '${prefix}:ref:refs/tags/v*' "$repo/scripts/real-kms-bootstrap.mjs" ||
  fail 'real-KMS OIDC trust does not permit stable release tag runs'
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

# A release is driven only by pushing one stable tag. It reuses the full CI
# workflow, then stages the exact tested bytes; it must never acquire a token or
# a bypass around staged trusted publishing.
release_workflow="$repo/.github/workflows/release.yml"
[[ -s $release_workflow ]] || fail 'tag-only release workflow is missing'
[[ $(grep -Ec '^permissions: \{\}$' "$release_workflow") -eq 1 ]] ||
  fail 'release workflow must deny all token permissions by default'

assert_release_permissions() {
  local job=$1 expected=$2 block actual
  block=$(extract_yaml_job "$job" "$release_workflow")
  [[ -n $block ]] || fail "release workflow job is missing: $job"
  actual=$(awk '
    /^    permissions:$/ { permissions = 1; next }
    permissions && /^      [[:alnum:]-]+: (read|write)$/ {
      sub(/^      /, "")
      print
      next
    }
    permissions { exit }
  ' <<<"$block" | sort)
  expected=$(printf '%s\n' "$expected" | sort)
  [[ $actual == "$expected" ]] || {
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
    fail "$job has incorrect release token permissions"
  }
}

assert_release_permissions preflight $'contents: read\ndiscussions: read'
assert_release_permissions ci $'contents: read\nid-token: write'
assert_release_permissions assemble \
  $'actions: read\nartifact-metadata: write\nattestations: write\ncontents: read\nid-token: write'
assert_release_permissions stage-npm \
  $'actions: read\ncontents: read\nid-token: write'
assert_release_permissions wait-npm $'actions: read\ncontents: read'
assert_release_permissions integrate 'contents: write'
assert_release_permissions github-release \
  $'actions: read\ncontents: write\ndiscussions: write'
for job in wait-npm github-release; do
  release_job=$(extract_yaml_job "$job" "$release_workflow")
  grep -Fq 'uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020' \
    <<<"$release_job" || fail "$job relies on the runner's ambient Node"
  grep -Fq '          node-version-file: .node-version' <<<"$release_job" ||
    fail "$job does not use the declared Node release"
done

grep -Fq "tags: ['v[0-9]+.[0-9]+.[0-9]+']" "$release_workflow" ||
  fail 'release workflow does not accept every stable numeric tag'
if grep -Eq '^  (workflow_dispatch|schedule):' "$release_workflow"; then
  fail 'release workflow must only be triggered by a stable tag push'
fi
grep -Fq 'group: release' "$release_workflow" ||
  fail 'release workflow is not serialized'
grep -Fq 'cancel-in-progress: false' "$release_workflow" ||
  fail 'an active release must never be cancelled by a later tag'
grep -Fq 'uses: ./.github/workflows/ci.yml' "$release_workflow" ||
  fail 'release workflow does not call the authoritative CI workflow'
grep -Fq '      real_kms: true' "$release_workflow" ||
  fail 'release workflow does not require real AWS KMS coverage'
grep -Fq '      full_matrix: true' "$release_workflow" ||
  fail 'release workflow does not require the full KeySpec matrix'
grep -Fq 'npm@12.0.2' "$release_workflow" ||
  fail 'release workflow does not pin npm 12.0.2'
shared_release_action='panva/.github/.github/actions/npm-release@main'
[[ $(grep -Fc "uses: $shared_release_action" "$release_workflow") -eq 5 ]] ||
  fail 'release workflow must invoke the shared action directly from main'
if grep -Eq 'repository: panva/\.github|node_modules/\.panva-release' \
  "$release_workflow"; then
  fail 'release workflow must not clone the shared action repository'
fi
[[ $(grep -Fc "          - '@keyobject/aws-kms" "$release_workflow") -eq 6 ]] ||
  fail 'release workflow must stage exactly the core and five satellite packages'
grep -Fq 'actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d' \
  "$release_workflow" || fail 'release attestations are not immutably pinned'
grep -Fq '            dist/*.tar.gz' "$release_workflow" ||
  fail 'native archives are not attested'
grep -Fq '            dist/*.tgz' "$release_workflow" ||
  fail 'npm tarballs are not attested'
grep -Fq '          retention-days: 30' "$release_workflow" ||
  fail 'release payload does not have the required retry lifetime'
grep -Fq '          name: release-payload' "$release_workflow" ||
  fail 'release payload is not uploaded as one immutable handoff'
grep -Fq '          artifact-ids: ${{ steps.prior.outputs.id }}' \
  "$release_workflow" || fail 'prior release payload is not downloaded by artifact ID'
grep -Fq '          run-id: ${{ github.run_id }}' "$release_workflow" ||
  fail 'prior release payload download is not scoped to the current workflow run'
grep -Fq 'node scripts/release-lifecycle.mjs compare-payloads' \
  "$release_workflow" || fail 'release bytes are not locked across run attempts'
grep -Fq '          overwrite: true' "$release_workflow" ||
  fail 'an identical prior release payload cannot be replaced after validation'
grep -Fq 'actions/runs/${runId}/artifacts?per_page=100' \
  "$repo/scripts/release-lifecycle.mjs" ||
  fail 'prior payload lookup is not scoped to the current workflow run'
prior_line=$(grep -n -F 'artifact-ids: ${{ steps.prior.outputs.id }}' \
  "$release_workflow" | cut -d: -f1)
lock_line=$(grep -n -F 'node scripts/release-lifecycle.mjs compare-payloads' \
  "$release_workflow" | cut -d: -f1)
attest_line=$(grep -n -F 'uses: actions/attest@' "$release_workflow" | cut -d: -f1)
overwrite_line=$(grep -n -F '          overwrite: true' "$release_workflow" | cut -d: -f1)
[[ $prior_line -lt $lock_line && $lock_line -lt $attest_line && \
   $attest_line -lt $overwrite_line ]] ||
  fail 'prior payload equality must be proven before attestation and overwrite'
if grep -Eq '(NPM_TOKEN|NODE_AUTH_TOKEN|npm[[:space:]]+publish|publish_jsr:[[:space:]]+true)' \
  "$release_workflow"; then
  fail 'release workflow bypasses staged OIDC-only npm publishing'
fi
while IFS= read -r action; do
  ref=${action##*@}
  [[ $ref =~ ^[0-9a-f]{40}$ ]] ||
    fail "release workflow action is not pinned to a commit: $action"
done < <(sed -nE 's/^[[:space:]]*- uses: ([[:alnum:]_.-]+\/[[:alnum:]_.-]+@[[:alnum:]._-]+).*/\1/p' \
  "$release_workflow")

grep -Fq '  workflow_call:' "$workflow" ||
  fail 'CI is not callable from a tag release'
grep -Fq '      inputs.real_kms || (' "$workflow" ||
  fail 'called CI cannot enable real AWS KMS coverage'
grep -Fq "SUBSET: \${{ !inputs.full_matrix && '--smoke' || '' }}" "$workflow" ||
  fail 'called CI cannot enable the full real-KMS matrix'

node --test "$repo/scripts/test/release-version.test.mjs" \
  "$repo/scripts/test/release-lifecycle.test.mjs" \
  "$repo/scripts/test/release-packaging.test.mjs" >/dev/null

echo 'ok: CI helper regressions pass'
