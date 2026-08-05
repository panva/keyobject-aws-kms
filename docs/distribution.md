# DISTRIBUTION PLAN — three tiers

## 0. DECIDED / OPEN

**DECIDED (do not relitigate)**

- Three tiers: (1) build from source + cnf, (2) per-arch GitHub release tarballs + cnf, (3) npm, esbuild-shaped (core + one optional dependency per arch).
- **ONE native artifact per platform, in all tiers.** The napi dual-role result is MEASURED: a single `awskms.dylib` exports both `OSSL_provider_init` and `napi_register_module_v1`, works as a provider in the `openssl` CLI (no napi symbols in that host) and as an addon in Node, and still links no libcrypto. Cost: +448 bytes, one 142-line file. There is no second binary and no second release matrix.
- Tier-3 registration uses `OSSL_PROVIDER_add_builtin(NULL,"awskms",OSSL_provider_init)`, **not** `OSSL_PROVIDER_set_default_search_path` + by-name load. add_builtin has no filename constraint, no filesystem access, no second dlopen, and no process-global search-path side effect. (The search-path variant was also MEASURED working — and MEASURED to fail silently on a file named `awskms.node`, surfacing later as `ERR_OSSL_OSSL_STORE_UNSUPPORTED`.)
- The single napi reference (`napi_throw_error`) must be **weak**. NEGATIVE CONTROL MEASURED: a strong reference makes the provider fail to `dlopen` in the `openssl` CLI ("symbol not found in flat namespace"), because OpenSSL's DSO loader uses `RTLD_NOW` (flags 0x0002 observed). This is load-bearing, not stylistic.
- Tier 2 cnf is shipped **verbatim, byte-identical on every platform**, with `module = $ENV::AWSKMS_MODULE`. MEASURED: `$ENV::` expands inside `module =` on OpenSSL 3.5.7 (both Node linkage models) and 3.6.3; and an **unset** variable is a loud fatal — node exits 104 with `variable has no value ... line 14`. That is the only tier-2 misconfiguration in this whole space that is not silent.
- Release build targets: `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`. Tokens are exactly `${process.platform}-${process.arch}` so tier 3 composes package names with no mapping table.
- Linux release builds run inside `container: almalinux:9` with `gcc-toolset-13` and `-static-libstdc++ -static-libgcc`. MEASURED floor: exactly `GLIBC_2.34`, zero GLIBCXX/CXXABI/GCC version deps. Covers RHEL 9, Amazon Linux 2023 (incl. Lambda), Ubuntu 22.04+, Debian 12+. Building on the runner's own `ubuntu-24.04` costs `__isoc23_sscanf@GLIBC_2.38` and loses all of those. Cost of static libstdc++: +0.72 MB.
- macOS: pin `-DCMAKE_OSX_DEPLOYMENT_TARGET=13.5`. MEASURED: unset, the dylib records `minos` = the build host's OS (26.0 observed locally), so the floor becomes an accident of the runner image.
- Release artifacts are **aws backend**. `stub` is a test/dev build and is never published.
- No `postinstall` in tier 3. esbuild's `install.js` exists only to rescue `--no-optional`, is the origin of their `Expected "X" but got "Y"` bug, and MEASURED does not run at all under `ignore-scripts=true` (which is set globally in this user's `~/.npmrc`). Replace with a runtime version-skew check.
- `"engines": {"node": ">=26.7.0"}`. The STORE loader shipped in **26.7.0 (Current, 2026-08-05)** as `82712652cb`, so a plain release constraint is correct and no `-0` prerelease suffix is needed. (Were it ever pinned to an unreleased major, `>=X.0.0` semver-EXCLUDES `X.0.0-nightly…` and would need the `-0`.) `engines` is advisory anyway (install succeeds; only `engine-strict` gives EBADENGINE) — enforcement is the runtime probe.
- One health check, `scripts/awskms-doctor.mjs`, serves all three tiers. Its level-0 primitive is `createPrivateKey({key: new URL('awskms:')})`, a four-way discriminator costing zero network calls, zero credentials, zero IAM, zero extra flags. All four outcomes MEASURED.

**OPEN — these are genuinely undecided and are called out again in §9**

- ~~Node 27 GA is 2027-04-22~~ **SUPERSEDED 2026-08-05: the STORE loader was backported and ships in Node 26.7.0 (Current) TODAY**, as `82712652cb` / v26.x `58717685a1bc`, PR #63949, listed under notable changes in release proposal #65027. The earlier "no backport in flight" reading came from comparing against the main-branch SHA `565c3daebf9`; the cherry-pick has a different hash, so the compare reported *diverged*. There is no ~8.5-month gap and no backport decision to make.
- npm scope and package names. Placeholder below: `awskms-openssl-provider` (core) + `@awskms-openssl-provider/<platform>-<arch>` (satellites).
- Satellite filename: `awskms.node` (npm convention, `require()` works) vs `awskms.dylib`/`awskms.so` (canonical, cnf-fallback-proven). See §6 — this is a real fork.
- Whether tier 3 ships the addon route in v1 at all, given `--allow-addons` is a full sandbox escape.
- musl and win32: currently out. Naming reserves `linux-x64-musl` as a third token.
- OpenSSL header floor (see §8, item 9).

## 1. BLOCKERS

**B1 — RESOLVED 2026-08-05. The Linux aws-backend no longer links libcrypto.**
`cmake/ScrubLibcrypto.cmake` was rewritten: subprojects now find the real libcrypto (so their configure probes are accurate) and libcrypto is stripped from their `INTERFACE_LINK_LIBRARIES` after `add_subdirectory()`. Verified on ubuntu:24.04/arm64 — `readelf -d` clean, one export, `status: active` in the `openssl` CLI under `RTLD_NOW`, and all 223 OpenSSL symbols exported by a stock node v26.6.0. macOS unchanged. s2n's feature probes went from 0 TRUE / 19 FALSE to 11 TRUE / 8 FALSE as a side effect.
Two guard bugs it exposed, both fixed: `AssertNoStaticLibcrypto.cmake` detected only a *statically* absorbed libcrypto and passed on the broken build's dynamic `DT_NEEDED`; and `check-load.sh` counted *weak* undefined symbols as requirements, failing a module that loads (186 strong vs 9 weak — aws-c-cal weakly references OpenSSL 1.0.2-era APIs and chooses at runtime).
The original mechanism recorded here — "s2n's Findcrypto.cmake puts an absolute path on our link line" — was WRONG. The real cause was our own ordering: `find_package(OpenSSL)` creates a real `OpenSSL::Crypto` before any `if(NOT TARGET ...)` guard of ours can claim the name, and aws-c-cal's non-Apple branch propagates it PUBLIC.

**B2 — All three tiers are consumer-blocked on the OSSL_STORE loader reaching a release line.**
**RESOLVED 2026-08-05 — Node 26.7.0 (Current) ships the STORE loader.** All three tiers are consumable from a released Node as of today.
- Tier 1: publishable now, requires Node >= 26.7.0.
- Tier 2: publishable now. CI legs should test against **26.7.0** as the oldest supported node, not a nightly.
- Tier 3: publish to **`latest`**. The `next` dist-tag staging this document originally called for is unnecessary.

**B3 — `scripts/check-load.sh`'s "node boots with the provider activated" assertion is a no-op.**
MEASURED: `check-load.sh:130-138` destructures `getProviders` from `require('crypto')`, which does not exist on any Node (`typeof` → `undefined` on v27.0.0-pre and v26.6.0), then prints BOOTED unconditionally. It passes with a deliberately broken module path. This is the one script whose stated purpose is to close trap (a), and it is the gate every release leg is supposed to hang on. **Fix this before writing any workflow.** Whatever informed the "clean builds against 3.0.21/3.5.7/3.6.3/4.0.1" line in TODO.txt inherited this false coverage for the load half; the symbol audit in the same script is real and unaffected.

## 2. ARTIFACT COUNT PER PLATFORM: ONE

| tier | artifacts per platform | contents |
|---|---|---|
| 1 | 1 (built locally) | `awskms.{dylib,so}` → `${CMAKE_INSTALL_FULL_LIBDIR}/ossl-modules/`, `awskms.cnf` → `${CMAKE_INSTALL_FULL_SYSCONFDIR}/awskms/` |
| 2 | 1 tarball × 4 targets + `SHA256SUMS` | module, verbatim cnf, doctor, LICENSE, INSTALL.md |
| 3 | 1 satellite npm package × 4 targets + 1 core = **5 packages** | module + LICENSE per satellite; core is pure JS |

The napi dual-role result is what decides this. The earlier assumption — "the provider exports exactly one symbol and cannot be an N-API addon, so `register` costs a SECOND native binary per platform" — is superseded by measurement, not argument: `nm -gU build/awskms.dylib` → `_OSSL_provider_init` **and** `_napi_register_module_v1`; `otool -L` → only libc++ and libSystem; `nm -u -m | grep napi` → one line, `weak external _napi_throw_error (dynamically looked up)`. The registrar needs **zero** napi symbols on the happy path because `napi_env`/`napi_value` are opaque pointer typedefs, so the entry point is declared `void *napi_register_module_v1(void *env, void *exports)` and returns `exports` unchanged — no node headers, no `node-api-headers` dependency, no new undefined symbols. Node defaults the API version to `NODE_API_DEFAULT_MODULE_API_VERSION` when `node_api_module_get_api_version_v1` is absent (`node/src/node_binding.cc:519`), which we deliberately do not export.

MEASURED corollaries worth keeping: one binary works as an addon on statically-linked stock nodes (v26.6.0, v24.19.0, v22.23.2, v20.20.2) **and** the shared-openssl dev build; registration is idempotent (double `require` fine); `worker_threads` inherit it (libcrypto state is process-wide); dyld loads exactly **one** image even when the cnf loads it by path and `process.dlopen` loads it as an addon in the same process (`DYLD_PRINT_LIBRARIES=1` → one line) — so tiers 2 and 3 can coexist in one process.

## 3. TIER 1 — build from source + cnf

**What ships:** nothing. The repo is the artifact.

**What the user does:**
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAWSKMS_BACKEND=aws
cmake --build build --parallel
sudo cmake --install build
node scripts/awskms-doctor.mjs --openssl-config=/usr/local/etc/awskms/awskms.cnf
node --openssl-config=/usr/local/etc/awskms/awskms.cnf app.mjs
```

**What has to be built:**
- `scripts/awskms-doctor.mjs` (new; see §7).
- `cmake_minimum_required` 3.20 → **3.25**. MEASURED: `cmake/FetchAwsSdkKms.cmake:108` uses `add_subdirectory(... EXCLUDE_FROM_ALL SYSTEM)`; on CMake 3.22 that is `add_subdirectory called with incorrect number of arguments`. Also document **GCC >= 12**: MEASURED, GCC 11 rejects `third_party/ada/ada.cpp` with `call to non-constexpr function std::basic_string::empty()` (constexpr std::string) at `ada.h:9041` and `:9239`. Both fail loudly, so they are papercuts, not hazards — but the declared minimum is simply wrong and will mislead a from-source builder on any distro with CMake 3.22 or GCC 11.
- Decide the `cmake --install --prefix` papercut. MEASURED: it is **silently ignored** — install DESTINATIONs are absolute (`CMAKE_INSTALL_FULL_LIBDIR` / `CMAKE_INSTALL_FULL_SYSCONFDIR`) and CMake does not relocate absolute destinations. `DESTDIR=<stage> cmake --install build --prefix /opt/anything` put files under `<stage>/usr/local/…` with `module = /usr/local/lib/ossl-modules/awskms.dylib`; the `--prefix` had no effect anywhere. DESTDIR staging *does* work correctly and is what distro packaging needs. Either document DESTDIR as the only staging mechanism, or switch to relative DESTINATIONs.

**Traps:**
- (a) failed load silent — **REACHABLE**. Closed only by the doctor. `check-load.sh` currently pretends to close it and does not (B3).
- (b) missing `default = default_sect` → ncrypto CSPRNG abort at startup — **ELIMINATED** as long as the cnf comes from `cmake/awskms.cnf.in`. Reachable only if the user hand-merges into an existing `OPENSSL_CONF`.
- (c) absolute path with extension — **ELIMINATED**. CMake bakes `${CMAKE_INSTALL_FULL_LIBDIR}/ossl-modules/${AWSKMS_MODULE_BASENAME}`.
- (d) symbol skew — **REACHABLE**. Only defence is `scripts/check-load.sh <build> <oldest-node>`, which the from-source builder must be told to run. Put it in the README quick-start, not a footnote.

## 4. TIER 2 — GitHub release artifacts + cnf

**What ships**, per tag `v*`:
```
awskms-1.2.3-darwin-arm64.tar.gz
awskms-1.2.3-darwin-x64.tar.gz
awskms-1.2.3-linux-arm64.tar.gz
awskms-1.2.3-linux-x64.tar.gz
SHA256SUMS
```
Version without the leading `v` (`${GITHUB_REF_NAME#v}`) so it equals package.json `version` verbatim. Each tarball has one top-level dir `awskms-1.2.3-<platform>-<arch>/` containing:
```
awskms.so | awskms.dylib
awskms.cnf          # VERBATIM, identical bytes on every platform, module = $ENV::AWSKMS_MODULE
awskms-doctor.mjs
LICENSE
INSTALL.md
```
Not the generated cnf — it hardcodes an absolute install path and cannot be prebuilt. Not a template either: the `$ENV::` file *is* shippable bytes.

**What the user does:**
```
curl -LO https://github.com/<owner>/tiny-aws-kms-openssl-provider/releases/download/v1.2.3/awskms-1.2.3-linux-x64.tar.gz
gh attestation verify awskms-1.2.3-linux-x64.tar.gz \
  --repo <owner>/tiny-aws-kms-openssl-provider \
  --signer-workflow <owner>/tiny-aws-kms-openssl-provider/.github/workflows/release.yml \
  --deny-self-hosted-runners
shasum -a 256 -c SHA256SUMS --ignore-missing
tar xzf awskms-1.2.3-linux-x64.tar.gz -C /opt
export AWSKMS_MODULE=/opt/awskms-1.2.3-linux-x64/awskms.so
node /opt/awskms-1.2.3-linux-x64/awskms-doctor.mjs --openssl-config=/opt/awskms-1.2.3-linux-x64/awskms.cnf
node --openssl-config=/opt/awskms-1.2.3-linux-x64/awskms.cnf app.mjs
```
`--signer-workflow` is the load-bearing flag; `--repo` alone only proves "some workflow in that repo signed it."

**What has to be built: `.github/workflows/release.yml`**

```
on: { push: { tags: ['v*'] }, workflow_dispatch: }
permissions: {}            # repo convention; each job opts in

jobs:
  build:                   # matrix, fail-fast: false, permissions: { contents: read }
    target        runs-on            container
    darwin-arm64  macos-15           -
    darwin-x64    macos-15-intel     -
    linux-x64     ubuntu-24.04       almalinux:9
    linux-arm64   ubuntu-24.04-arm   almalinux:9

  release:                 # needs: build; NOT in a container (gh is on the runner, not in almalinux:9)
                           # permissions: contents: write, id-token: write,
                           #              attestations: write, artifact-metadata: write
```

`build` steps:
1. `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`
2. Linux only: `dnf -y install gcc-toolset-13 openssl-devel zlib-devel git make cmake` then `source /opt/rh/gcc-toolset-13/enable`. AlmaLinux 9's own repos supply GCC 13.3.1, CMake 3.31.8, OpenSSL 3.5.5 — no manylinux tooling.
3. `actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0`, path `build-aws/_deps/aws-sdk-cpp` with `!build-aws/_deps/aws-sdk-cpp/.git`, key `aws-sdk-cpp-1.11.855-${{ matrix.target }}`. `cmake/FetchAwsSdkKms.cmake:55` short-circuits on a `.awskms-fetched-<tag>` marker, so a restored tree skips the fetch exactly and a tag bump is a clean miss; excluding `.git` takes the entry 206 MB → 135 MB and is safe because no git command runs once the marker exists.
4. configure — macOS: `-DCMAKE_OSX_DEPLOYMENT_TARGET=13.5 -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"`; Linux: `-DCMAKE_MODULE_LINKER_FLAGS="-static-libstdc++ -static-libgcc"`. Both: `-DCMAKE_BUILD_TYPE=Release -DAWSKMS_BACKEND=aws`.
5. `cmake --build build-aws --parallel`
6. **HARD GATES**, in this order:
   - `scripts/check-load.sh build-aws <downloaded nightly>` — the symbol audit here is the only thing that catches trap (d), and it must run against the **oldest** node the release claims.
   - macOS only: `otool -l build-aws/awskms.dylib` assert `minos 13.5`. The failure is otherwise silent.
   - Linux only: `readelf -d build-aws/awskms.so` assert no `libcrypto` NEEDED (redundant with check-load.sh section 2, but make it explicit while B1 is fresh).
   - `AWSKMS_MODULE=build-aws/awskms.so node test/run.mjs` — the full aws-backend suite, **with no AWS credentials in scope**. MEASURED: `test/run.mjs` reads the `awskms-backend` marker CMake writes (`CMakeLists.txt:297`) and starts a local HTTP KMS stub whenever backend==aws and `AWSKMS_TEST_REAL` is unset.
7. stage tarball; `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1`

`release` steps:
1. `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1`
2. `shasum -a 256 awskms-*.tar.gz > SHA256SUMS`
3. `actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373 # v4.1.1` with `subject-checksums: SHA256SUMS` — one attested subject per line, so every asset is individually verifiable from a single step and the published checksums file is the same one that drove the attestation.
4. `gh release create "$GITHUB_REF_NAME" --verify-tag --notes-file … awskms-*.tar.gz SHA256SUMS` in a plain `run:` with `GH_TOKEN: ${{ github.token }}`. Deliberately not a third-party release action — `gh` removes one more party from the trust path.

Cost: ~120 CPU-seconds of compile for 597 TUs (MEASURED across four machines) ≈ 30-45s wall on a 4-CPU runner, plus a MEASURED 2m12s / 206 MB cold SDK fetch (1m53s of which is the 12 nested aws-crt-cpp submodules). Cold leg ≈ 5-7 min, warm ≈ 3-4 min, four legs in parallel. Note actions/cache evicts entries unused for 7 days, so a monthly release **normally misses** — budget the cold fetch as the base case, not the exception.

Do not run this in the same workflow as anything holding the KMS admin role. It needs no AWS credentials at all; keeping them apart means a compromised release action cannot reach `ScheduleKeyDeletion`.

**Traps:**
- (a) — **REACHABLE**. `awskms-doctor.mjs` in the tarball is the answer, and the INSTALL.md must lead with it.
- (b) — **ELIMINATED** by shipping the file verbatim. Reachable only for a user who merges our sections into their own `OPENSSL_CONF` by hand.
- (c) — **CONVERTED FROM SILENT TO LOUD** by `$ENV::AWSKMS_MODULE`. MEASURED: unset → rc=104, `error:07000068:configuration file routines:str_copy:variable has no value:crypto/conf/conf_def.c:758:line 14`. Mechanism is `node/src/node.cc:1231-1240`, which checks `ERR_peek_error()` after `OPENSSL_init_crypto` and early-returns `ERR_GET_REASON` as the exit code. **Residual gap: the variable set to a WRONG path is still silent (rc=0).** The doctor narrows, it does not eliminate.
- (d) — **REACHABLE**, unchanged. Only the CI symbol audit stands behind it. Note the Linux artifact's undefined-OpenSSL-symbol set is much larger than macOS's (s2n and aws-c-cal use libcrypto on Linux where macOS uses Security.framework), so the audit must run on both `linux-x64` and `linux-arm64` and is a real portability constraint once B1 is fixed.

**Corrections to carry into the release docs** (these were checked and refuted; do not propagate the originals):
- Do **not** write an "August 2027 end of x86_64 macOS" sunset. `macos-26-intel` exists — public beta 2026-02-06 (actions/runner-images#13637), GA 2026-02-26 — and is listed today as a standard x64 hosted runner in both the runner-images README and docs.github.com. The August-2027 date comes from a single closed Sept-2025 issue scoped to the `macos-15-intel` label's own window; it appears in no current doc. (Also: macOS 15 is Sequoia, not Sonoma — that issue mislabels it.)
- `darwin-x64` has **no hard sunset**. MEASURED on this arm64 machine: `cmake -DCMAKE_OSX_ARCHITECTURES=x86_64 -DAWSKMS_BACKEND=stub -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3` produced a shippable `awskms.dylib`, "Mach-O 64-bit bundle x86_64", 171448 bytes, one export, no libcrypto. Because the build is headers-only against OpenSSL and links `-Wl,-undefined,dynamic_lookup`, there is no x86_64 libcrypto to find. Any arm64 runner can emit the darwin-x64 artifact indefinitely. What genuinely has an end is native x86_64 **testing** — in that same cross-build the only failing target was `awskms_unit`, which does link libcrypto and hit `ld: symbol(s) not found for architecture x86_64` against Homebrew's arm64-only libcrypto. Write that, undated, rather than a fake deadline.
- `ubuntu-22.04` is not an option: deprecation begins 2026-09-17 (~6 weeks out), fully unsupported 2027-04-17, with brownout failures during the window.
- Pin `macos-15`, not `macos-latest` — since June 2026 `macos-latest` is macOS 26, and the runner image silently decides the artifact's `minos`.

**Rejected alternatives, recorded so they are not re-proposed:**
- `OPENSSL_MODULES` as the primary mechanism. It works on both linkage models and under `--permission` with no `--allow-fs-read` — but it is process-global and MEASURED to break Node's own `--openssl-legacy-provider` on a shared-openssl host (`Unable to load legacy provider` + `ERR_OSSL_EVP_UNSUPPORTED` for md4; without the var, md4 OK), and would break `pkcs11-provider` anywhere. Its forgotten-variable case is **silent** (rc=0). Document it only as an escape hatch. (It *is* mandatory for a stock node if used at all: MEASURED, a stock nodejs.org binary's compiled-in MODULESDIR is literally `/Users/admin/build/ws/out/$(BUILDTYPE)/obj.target/deps/openssl/lib/openssl-modules` — an unexpanded Make variable that can never resolve on any machine.)
- A relative `module =` path. MEASURED non-viable: resolved against the module *search dir*, never the cwd and never the cnf's own directory. `.include` with a relative path resolves against cwd, equally useless for a relocatable archive.
- Editing the system `openssl.cnf`'s `nodejs_conf` key ("route 4"). The mechanism is real and MEASURED end-to-end, but the safety argument is **refuted**: it is isolated from the `openssl` CLI only. MEASURED with a discriminator cnf naming a missing section, v20.20.2 / v22.23.2 / v24.19.0 / v26.6.0 / Homebrew v26.5.0 **all refuse to start**. Editing it loads awskms into every Node process on the box (npm, pnpm, corepack, CI agents, editor-embedded node), applies `?provider!=awskms` to all of them, and pays the 2.08 MB dlopen plus AWS SDK static init in each. Two further precision points if it is ever documented: `nodejs_conf` is a **key in the default section**, not a section (`CONF_modules_load()` does `NCONF_get_string(cnf, NULL, appname)`; a literal `[nodejs_conf]` header does nothing, silently — a fifth member of this repo's silent-failure family), so the edit goes **above** the first `[...]`; and system cnf files ship `config_diagnostics = 1`, which STRIPS `CONF_MFLAGS_IGNORE_MISSING_FILE`/`IGNORE_ERRORS`, inverting trap (a) into a machine-wide all-Node startup abort. Recommend against.

## 5. TIER 3 — npm

**BLOCKED on B2 for `latest`. Publishable to `next` today.**

**What ships (5 packages):**
```
awskms-openssl-provider                     # core, pure JS, ~20 KB, zero runtime deps
@awskms-openssl-provider/darwin-arm64       # os:[darwin] cpu:[arm64]
@awskms-openssl-provider/darwin-x64
@awskms-openssl-provider/linux-x64          # + libc:[glibc] if a musl split ever lands
@awskms-openssl-provider/linux-arm64
```
Satellites pinned in core's `optionalDependencies` to the **exact** core version (`"1.2.3"`, never `"^1.2.3"` — a caret range is how esbuild-style version skew becomes possible). Each satellite carries only `os`/`cpu` and contains the module + LICENSE. Size is settled: MEASURED 2,179,552 bytes raw / 861,691 gzipped per satellite, against `@esbuild/darwin-arm64`'s 10,574,305 unpacked which publishes routinely. A user installs exactly one (MEASURED: `added 2 packages`).

**What the user does:**
```
npm i awskms-openssl-provider@next
```
```js
import 'awskms-openssl-provider/register';   // or: node --import awskms-openssl-provider/register app.mjs
import { createPrivateKey } from 'node:crypto';
const key = createPrivateKey({ key: new URL('awskms:key-id=alias/signing') });
```
Under `--permission`, or where addons are unwanted:
```
node --openssl-config="$(npx awskms-openssl-provider config-path)" app.mjs
```

**Surface** (all sync — these run once at startup and async buys nothing):
- `modulePath(): string` — absolute path; throws the accumulated error if the satellite is missing.
- `register(): void` — in-process activation via the dual-role addon.
- `opensslConfigPath(opts?: {region?, profile?, endpoint?}): string` — **generates and writes** a cnf (it cannot be a pure getter; the file must embed the absolute module path, so it is machine-specific). Write once to a deterministic cached path keyed by module path + version, atomically, idempotent. Do **not** copy `test/cnf.mjs`'s `mkdtemp`-per-call, which would leak a directory per invocation.
- `isSupported(): {ok: boolean, reason?: string}` — non-throwing, combines satellite presence with the STORE-loader probe.
- `version: string`
- Subpaths `./register` (side-effect wrapper, with `"sideEffects"` declared so bundlers do not tree-shake it) and `./package.json`.
- `bin`: `awskms-openssl-provider` with subcommands `doctor`, `config-path`, and `exec -- node app.mjs` (re-execs node with the right `--openssl-config`). The `bin` is the highest-value ergonomic item and was missing from the original sketch.

**Resolution mechanics.** Ours is esbuild-shaped, not sharp-shaped: we need a filesystem **path** because OpenSSL dlopens the module. Use a **literal static map** from `${process.platform}-${os.arch()}` to package name (never a template string — bundlers must be able to see the specifiers), then `require.resolve(\`${pkg}/awskms.node\`)` relative to core's own file. Three traps, all MEASURED in the reference packages:
- If the satellite declares `exports`, the binary MUST be an explicit subpath or resolution fails.
- If the resolved path contains `/.zip/`, copy it out to a cache dir — Yarn PnP keeps files inside archives and `dlopen` cannot read them. esbuild does exactly this (`lib/main.js:2058-2076`).
- Self-check `path.basename(__filename)`/`__dirname` and throw a dedicated "cannot be bundled, mark as external" error, as esbuild does at `lib/main.js:2100`.

**Error message.** Follow sharp, not esbuild: accumulate every failure, then print a numbered copy-pasteable list. Must name: (i) `--omit=optional`/`--no-optional` → `npm install --include=optional`; (ii) cross-platform → `npm install --os=linux --cpu=x64`; (iii) the bundler case; (iv) unsupported platform, naming the actual `${platform}-${arch}` and pointing at tier 1; (v) **the capability case — Node too old — which is what users will hit most in the first year.** MEASURED, `--omit=optional` installs cleanly with no install-time signal at all and defers everything to first use, so this message is the entire user experience of the failure.

**Version-skew check instead of postinstall:** read the satellite's `package.json` at load and compare to core's, throwing precisely on mismatch. Catches the same corruption esbuild's `validateBinaryVersion()` catches (`Expected "X" but got "Y"`, `install.js:137`), at the moment it matters, with no install-time code execution — the right posture for a package in the signing path.

**Publishing.** Use npm Trusted Publishing (OIDC), but with the correct framing:
- **It cannot do a package's FIRST publish.** `docs.npmjs.com/cli/v12/commands/npm-trust`: "The package you're configuring must already exist on the npm registry"; npm/cli#8544 is still OPEN as of 2026-08-05. All five package names need a token-authenticated or interactive first publish, plus one more per future arch. The accurate claim is "no long-lived npm token in CI *once each package exists*", not "no token at all".
- Node >= 22.14.0 is necessary but **not sufficient**, and fails silently. MEASURED: v22.14.0 bundles npm 10.9.2 and no Node 22.x ever bundled npm >= 11.5.1 (v22.23.2 → 10.9.8); the first Node bundling npm >= 11.5.1 is **v24.5.0**. Use `actions/setup-node` with >= 24.5.0, or add an explicit `npm i -g npm@^11.5.1`. npm's OIDC helper is "intended to never throw" and logs at verbose/silly, so a wrong npm version or a missing `permissions: id-token: write` publishes without provenance, or fails on auth, with no visible error.
- `--access public` on **every** package's first publish, scoped or not. `libnpmpublish/lib/publish.js:219-238` calls `GET /-/package/<name>/visibility`, treats E404 as `{public:false}`, and throws `Can't generate provenance for new or private package`.
- Trusted-publisher config is **per package**, naming the exact workflow **filename**, and since 2026-05-20 requires explicitly selecting at least one allowed action. Five manual setups now, one per new arch later, and a workflow rename silently breaks publishing. With `workflow_call`, validation checks the **calling** workflow's filename.
- Provenance is SLSA v1 for GitHub Actions specifically (`libnpmpublish/lib/provenance.js`: the GHA branch emits in-toto Statement v1 + `https://slsa.dev/provenance/v1`; the GitLab branch emits Statement v0.1 + SLSA v0.2 with `buildType: .../gitlab/v0alpha1`). Not relevant here beyond not writing "GitHub Actions or GitLab CI … SLSA v1" in the docs.
- Neither the hosted-runner rule nor the case-sensitive `repository` match is enforced client-side — both are **registry-side rejections at publish time**. Get `repository` right in all five package.jsons before the first run.
- Attest **all five** packages. esbuild and sharp both attest core plus every satellite.
- Publishing each satellite from the job that **built** it is stronger provenance than consolidating; if you consolidate into one publish job, know that you are attesting the publisher, not the compiler. Self-hosted runners are unsupported for trusted publishing anyway, so the publish job must be GitHub-hosted.

**What has to be built:**
- `src/napi.c` — already written and measured; at `/Users/panva/repo/tiny-aws-kms-openssl-provider/.claude/worktrees/wf_24c31a2c-3e3-1/src/napi.c`.
- `npm/core/{package.json,index.cjs,index.mjs,register.cjs,register.mjs,bin/awskms.mjs}`
- `npm/platform/package.json.in` (templated per target at release time)
- `.github/workflows/npm-publish.yml`, jobs `build` (same matrix as release.yml, or reuse via `workflow_call` — remembering the caller-filename rule), `publish-satellites`, `publish-core`. Core must publish **after** all satellites exist, or its exact-pinned optionalDependencies are unresolvable.

**Traps:**
- (a) — **ELIMINATED on the addon route.** MEASURED with a temporary forced-failure hook: `process.dlopen` threw `ERR_AWSKMS_PROVIDER_REGISTRATION forced failure`, i.e. a failed registration throws out of `require()` instead of the cnf route's total silence. The weak `napi_throw_error` does resolve inside Node. **Reachable on the cnf fallback path**, where the doctor covers it.
- (b) — **ELIMINATED on the addon route** (no cnf; the addon calls `OSSL_PROVIDER_load(NULL,"default")` explicitly). Reachable on the cnf fallback.
- (c) — **ELIMINATED on the addon route.** `OSSL_PROVIDER_add_builtin` never touches the filesystem and has no filename constraint. This is the strongest single argument for tier 3 and for add_builtin over the search-path route.
- (d) — **REACHABLE, and its failure mode changes.** `uv_dlopen` uses `RTLD_LAZY` (`deps/uv/src/unix/dl.c:36`) where OpenSSL's DSO layer uses `RTLD_NOW` (`dso_dlfcn.c:85`). Since `add_builtin` + `OSSL_PROVIDER_load` calls `OSSL_provider_init` immediately, a missing host symbol is likely to present as a crash at registration rather than a silent no-load. **INFERRED, not measured — verify before shipping.** The CI symbol audit remains the real defence.

**The tier-3 tradeoff, stated honestly in the docs:** under `--permission`, tiers 1-2 need only `--allow-openssl-store`; tier 3's addon route additionally needs `--allow-addons` **and** `--allow-fs-read` (all MEASURED: without `--allow-addons`, "Cannot load native addon because loading addons is disabled"; without `--allow-openssl-store`, `require()` succeeds and then `createPrivateKey` gives `ERR_ACCESS_DENIED`). This is a genuine user-visible capability difference, not a test artifact. And it is qualitative, not quantitative: `--allow-openssl-store` is a scoped capability, `--allow-addons` is arbitrary native code — spending the whole permission model to buy one dlopen. That is why tier 3 must ship the cnf fallback and the `config-path` bin, so a `--permission` deployment can opt into `--openssl-config` and never grant addons.

## 6. THE FILENAME FORK (decide before writing the npm layout)

`OSSL_PROVIDER_add_builtin` frees the addon route from any filename constraint, so tier 3 *can* name the file `awskms.node` (npm convention; `require('./awskms.node')` works; MEASURED end to end with a plain `require()` and no node flags). Tier 2 wants `awskms.dylib`/`awskms.so`, which is the exact basename `-provider-path` lookup expects.

Two options:
1. **One name, `awskms.node`, in the satellite.** The cnf fallback then needs `module = /abs/path/awskms.node`. This *should* work — `provider_core.c:1007-1009` calls `DSO_convert_filename` (which appends the platform extension) only when `prov->path` is NULL, i.e. only for name-derived paths; an explicit `module =` value is used verbatim. **INFERRED from source, never measured with a `.node` extension. Measure it before committing.**
2. **Ship both names**, or ship `awskms.dylib`/`awskms.so` and load it with `process.dlopen(module, path)` directly rather than `require()` (which needs the `.node` extension for the CJS handler). Shipping both names costs 2× satellite size (npm tarballs do not preserve hardlinks) — 4.2 MB per satellite. Option 2b (canonical name + `process.dlopen`) costs nothing and keeps one name across all three tiers; it is probably the right answer if the measurement in option 1 fails.

## 7. `scripts/awskms-doctor.mjs` (new — serves all three tiers)

Dependency-free ESM, no imports beyond `node:crypto`/`node:fs`/`node:process`. Tier 1 installs it; tier 2 copies it into the archive; tier 3 exposes it as `npx awskms-openssl-provider doctor` plus a programmatic `assertProviderReady()`. `scripts/check-load.sh` calls it in place of its current hollow boot assertion (B3).

**Level 0 — always, no flags, no network, no credentials, no IAM:**
```js
try { createPrivateKey({ key: new URL('awskms:') }) } catch (e) { switch (e.code) { … } }
```
| code | meaning |
|---|---|
| `ERR_OSSL_AWSKMS_INVALID_URI` | PASS — provider registered, STORE loader live |
| `ERR_OSSL_OSSL_STORE_UNSUPPORTED` | FAIL — node takes URL keys, our provider is not there. **This is trap (a), finally caught.** |
| `ERR_INVALID_ARG_TYPE` | node predates the STORE loader; print `process.version`, say Node >= 26.7.0 |
| `ERR_ACCESS_DENIED` | `--permission` without `--allow-openssl-store` |

All four MEASURED. The no-network property is structural, not incidental: `src/store.c:88-90` runs `awskms_uri_parse` **before** `awskms_kms_get_public_key`, so the probe cannot bill a KMS call or need a credential.

**Level 1 — only when level 0 says "not registered".** Turn the silence into a sentence: report which config was in play (`process.execArgv`, `OPENSSL_CONF`, `NODE_OPTIONS`) or that none was; then statically parse that cnf and check, in the order they bite — `nodejs_conf` declared (an `openssl_conf`-only file is silently ignored by Node); `default = default_sect` with `activate = 1` (trap (b) — the doctor *cannot* observe this at runtime, because its absence aborts node before JS runs, so a static read is the only way to warn); resolve the `module` value **including our own `$ENV::` expansion**, `stat()` it, and complain specifically about a missing platform extension or a relative path.

**Level 2 — opt-in `--deep`** (needs `--allow-addons` under `--permission`): `process.dlopen({exports:{}}, modulePath)`. MEASURED: `Module did not self-register` on both v27 (shared) and v26.6.0 (static) means the file loaded, right arch, right format, eager deps resolved. Anything else is the raw dyld/ELF text nobody ever gets to see today. **Print honestly that this cannot rule out symbol skew** (RTLD_LAZY vs RTLD_NOW). The doctor must be a short-lived process that exits — on Linux the module is `-Wl,-z,nodelete` and will not be unmapped.

Also dump `err.opensslErrorStack`, which is exposed and carried a second entry in testing. Note MEASURED: the provider's error **data** string does not reach JS (`err.message` is exactly `error:40800001:awskms::awskms invalid uri` — the empty field between the colons is where data would be), but `err.reason` does, and reason strings are a compile-time `OSSL_ITEM` table (`src/err.h:29-51`, `src/provider.c:112-114`). So embedding `AWSKMS_VERSION` in a dedicated diagnostic reason code is a ~3-line change if you want the doctor to report the version of the module that actually loaded rather than the version of the package it came from. That is real API surface on a minimal module — see §9.

`OSSL_PROVIDER_available` is the correct instrument but the wrong tier: it is C-only, unreachable from tiers 1 and 2, which is precisely the argument for the URI probe being the universal check. The tier-3 registrar should call it right after `OSSL_PROVIDER_load` and throw if it returns 0; the two should agree.

## 8. EXISTING FILES THAT MUST CHANGE

1. **`src/napi.c`** — NEW. Two non-negotiable properties: entry point takes/returns `void*` (no node headers, no napi symbol on the happy path), and the single `napi_throw_error` reference is weak.
2. **`src/awskms.exported_symbols`** — currently exactly `_OSSL_provider_init`. Add `_napi_register_module_v1`.
3. **`src/awskms.map`** — global block is currently only `OSSL_provider_init;`. Add `napi_register_module_v1;`. Keep `local: *;`.
4. **`CMakeLists.txt:175`** — `set(AWSKMS_SOURCES ${AWSKMS_CORE_SOURCES})` → `set(AWSKMS_SOURCES ${AWSKMS_CORE_SOURCES} src/napi.c)`. In the shared list, so both backends get it.
5. **`CMakeLists.txt:32`** — `cmake_minimum_required(VERSION 3.20)` → `3.25`. Document GCC >= 12 in the same header comment.
6. **`CMakeLists.txt:297-314`** — add a third `configure_file` producing `build/awskms.relocatable.cnf` with `AWSKMS_MODULE_FILE` set to the literal `$ENV::AWSKMS_MODULE` (escape the `$` in CMake). **Do not install it** — it is a release-archive artifact only. Tier 1's absolute-path install copy stays exactly as it is; it is correct there.
7. **`CMakeLists.txt` install rules** — absolute DESTINATIONs mean `--prefix` is silently ignored. Document DESTDIR as the only staging mechanism, or switch to relative DESTINATIONs.
8. **`scripts/check-load.sh:28-36`** — the one-symbol assertion becomes an exact **sorted-set** compare against `{OSSL_provider_init, napi_register_module_v1}`. MEASURED: this is the *only* assertion the napi change breaks (`FAIL expected only OSSL_provider_init, got: OSSL_provider_init napi_register_module_v1`); every other check — no libcrypto, openssl CLI load, symbol audit, node boot — passed unchanged.
9. **`scripts/check-load.sh` — NEW section 1b**, "every `napi_*` reference must be WEAK". Darwin: `nm -m -u | grep _napi_ | grep -v 'weak external'`. ELF: `nm -D --undefined-only | awk '$1=="U" && $2 ~ /^napi_/'`. **This is the more valuable of the two assertions** — it is the only automated thing standing between a future contributor adding a plain `napi_*` call and the provider silently ceasing to load in every non-Node host. It catches the negative control. **The ELF branch has been written but never executed.**
10. **`scripts/check-load.sh:130-138`** — replace the hollow boot assertion with `"$node" --openssl-config="$CNF" scripts/awskms-doctor.mjs` and assert on its exit code (B3).
11. **`scripts/check-load.sh:14-16`** — `NODES=("$@")` dies with `NODES[@]: unbound variable` under macOS bash 3.2 when no node binaries are passed, despite the header documenting "With no node binaries it checks the openssl CLI only." Fix with `${NODES[@]+"${NODES[@]}"}`. Pre-existing, unrelated to any of this work.
12. **`cmake/ScrubLibcrypto.cmake`** — must also clear the absolute-path OpenSSL variables s2n consumes (B1), **after** its configure-time `check_symbol_exists` probing. Separately, `awskms_scrub_libcrypto()` calls `find_package(OpenSSL REQUIRED)` itself and uses `OPENSSL_INCLUDE_DIR` (lines 32-34), so it **ignores `AWSKMS_OPENSSL_INCLUDE_DIR`** — which is why the header floor cannot currently be pinned for aws-backend release builds.
13. **`test/cnf.mjs:20-47`** — its header claims it exists "so the two cannot drift", and it has already drifted from `cmake/awskms.cnf.in` (no comments, no region/profile/endpoint keys). There are now **four** independent generators of this file (`awskms.cnf.in`, the two CMake copies, `test/cnf.mjs`, and a fifth heredoc at `scripts/check-load.sh:69-85`). Collapse to one source of truth while touching this area.
14. **`scripts/check-openssl-matrix.sh`** — add a **runtime** `$ENV::` expansion check across 3.0.21 / 3.5.7 / 3.6.3 / 4.0.1. The existing matrix is header-only and does not cover this, and `$ENV::` is currently measured only on 3.5.7 and 3.6.3.
15. **`test/exports.test.mjs` — NO CHANGE.** Correcting the brief: this file tests **key-material export formats** (JWK/SPKI/PKCS#8/raw-public, node:crypto and WebCrypto, plus the refusal of every private format). It contains no assertion about the module's exported *symbols*. `scripts/check-load.sh` is the **only** place the symbol set is asserted anywhere in the repo. That makes items 8 and 9 more load-bearing than they look — there is no second net.

## 9. ORDER OF WORK (cheapest-useful-first)

**1. Fix `scripts/check-load.sh` (items 10, 11).** ~1 hour. Everything downstream is gated on this script telling the truth, and today its load assertion does not. Cheapest possible, highest leverage.

**2. Write `scripts/awskms-doctor.mjs`, level 0 + level 1.** Serves all three tiers, closes trap (a) everywhere, and step 1 needs it. No new dependencies, no native code, no AWS.

**3. ~~Fix B1~~ DONE 2026-08-05.** Linux artifacts for tiers 2 and 3 are unblocked. Steps 1 and 2 of this list were also partly done in the same pass: `check-load.sh`'s hollow boot assertion and its weak-symbol false positive are both fixed. `awskms-doctor.mjs` is still to write.

**4. `cmake_minimum_required` → 3.25, document GCC >= 12 (item 5).** Ten minutes; prevents a bad from-source experience for tier 1 users on RHEL/Ubuntu-22-era toolchains.

**5. Relocatable cnf (item 6) + collapse the four cnf generators (item 13) + `$ENV::` matrix check (item 14).** This is the whole tier-2 activation story and converts trap (c) from silent to loud.

**6. Write `.github/workflows/release.yml`. Ship tier 2.** With 1-5 done this is mostly assembly, and it gives you a real, verifiable, attested artifact — usable today by anyone on Node >= 26.7.0, and the input to tier 3.

**7. Land `src/napi.c` + items 2, 3, 4, 8, 9. Then verify on Linux.** Specifically: (a) `__attribute__((weak))` on an undefined function must resolve to 0 rather than fail under `RTLD_NOW` on ELF; (b) the interaction of `napi_register_module_v1` with `-Wl,-Bsymbolic-functions`, `-Wl,--exclude-libs,ALL` and the version script; (c) the ELF branch of the new 1b assertion. **All three are unexecuted.** Also: build `-DAWSKMS_BACKEND=aws` and re-run `check-load.sh` — the entire napi measurement was done on the stub backend, and the aws backend adds `CXX_VISIBILITY_PRESET hidden`, static AWS SDK archives, `--exclude-libs,ALL` and `awskms_assert_no_static_libcrypto`.

**8. Measure the filename fork (§6), then build `npm/` and `.github/workflows/npm-publish.yml`. Publish to `next`.** Do the five first publishes by hand with a token, then wire trusted publishing per package.

**9. Settle the OpenSSL header floor.** The project claims a 3.0 floor with no upper bound, but the header tree used at build time is whatever `find_package` finds — MEASURED as 3.6.3 (Homebrew), 3.0.2 (ubuntu:22.04), 3.0.13 (ubuntu:24.04), 3.5.5 (almalinux:9). A macro that expands to a newer function in newer headers compiles clean and fails at `dlopen` on a 3.0 host. Either give `ScrubLibcrypto` a way to honour `AWSKMS_OPENSSL_INCLUDE_DIR` and pin a 3.0 header tree for release builds, or add a release gate checking every undefined OpenSSL symbol against a real 3.0 libcrypto. Deferred to last because it is a latent correctness issue, not a blocker — but do not ship 1.0 without it.

## 10. FOR YOU TO DECIDE, NOT ME

1. ~~Pursue a v26.x backport?~~ **MOOT — it shipped in 26.7.0 on 2026-08-05.**
2. ~~Publish to `next` now or wait?~~ **MOOT — publish to `latest`.** The audience exists as of today.
3. **npm scope and package names.** Everything above uses placeholders.
4. **Does v1 include `register()` (the addon route) at all?** It costs nothing in artifacts now (that was the whole napi finding) but it costs `--allow-addons`, which is a full sandbox escape. A v1 that ships only the cnf route, with `register()` in v1.1, is defensible.
5. **The `require()`-time global side effect.** The registrar unconditionally calls `EVP_set_default_properties(NULL, "?provider!=awskms")` on the **default** libctx, overwriting whatever the application or another library had set, every time the module is required. An app that sets its own default property query silently loses it, and anything that fetched algorithms *before* the require used the old properties. Options: keep it (matches the cnf route's behaviour exactly), read-and-append, or refuse to overwrite a non-empty existing value and throw. Also note `add_builtin` registers on the **default libctx only** — an app using a non-default `OSSL_LIB_CTX` gets nothing. The cnf route has the same limitation so it is not a regression, but tier 3 should document it.
6. **§6, the filename fork** — after the measurement in step 8, if `module = /abs/awskms.node` does not load.
7. **glibc 2.34 / almalinux:9 as the Linux floor.** Going lower needs a glibc <= 2.33 base and buys only RHEL 8 / AL2 / Debian 11 / Ubuntu 20.04, all EOL or nearly so, at the cost of an OpenSSL-3.0-headers problem on AlmaLinux 8. I recommend 2.34; confirm.
8. **musl and win32 in or out for v1.** Both currently out. musl is a genuinely different artifact (different libc ABI, no symbol versioning, so none of the glibc analysis transfers) with no GitHub-hosted runner; Node itself classifies it Experimental. win32 needs different napi code entirely — `weak_import`/`weak` have no MSVC equivalent, so `awskms_fail()` as written will not port (the zero-napi-symbol happy path would work).
9. **Add a version-carrying reason string** so the doctor can report which module actually loaded? ~3 lines, but it is a reason code and a probe URI that exist purely for diagnostics, on a module whose whole ethos is minimality. Worth it only if you judge tier-2/tier-3 stale-module skew to be a real risk.
10. **The 4 permission-model tests** currently assume the cnf route (`--allow-openssl-store` only). Tier 3's addon route needs three grants. Decide whether they become parameterised over both routes or stay cnf-only with a separate addon-route suite.
11. **What `--openssl-config` clobbering means for your users.** Any `OPENSSL_CONF`/`--openssl-config` value **replaces** the host's OpenSSL configuration wholesale for that process. A tier-2 user who already has one (FIPS, corporate CA policy, a pkcs11 provider section) silently loses it. Either the shipped cnf carries an `.include` of an absolute system config, or the docs must tell people to merge into their existing file. Not measured; flagged as a design requirement you should rule on before the tier-2 INSTALL.md is written.
