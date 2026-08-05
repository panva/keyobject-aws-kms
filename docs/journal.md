# Journal — what was decided, measured, and why

The record behind the current state of this provider. It exists so that
`TODO.txt` can be *only* what is left, and so that decisions already paid for in
measurement are not re-litigated or re-attempted.

Read this when you want to know **why** something is the way it is. Read
`TODO.txt` when you want to know what is left.

Detail for several of these lives closer to the code and is authoritative there:

| topic | authoritative home |
| --- | --- |
| distribution plan, three tiers | `docs/distribution.md` |
| why Dependabot cannot update vendored ada | `scripts/update-vendored.sh` header |
| why libcrypto must stay off the link line | `cmake/ScrubLibcrypto.cmake` header |
| the four silent-failure traps of the cnf | `cmake/awskms.cnf.in` |
| real-KMS credentials, IAM, profiles | `docs/real-kms-setup.md` |

Entries keep their original identifiers (D1, T0, T3, F2, F3) because commit
messages and code comments refer to them.

---

## Current state

    398 Node tests pass (aws backend), 374 + 6 skipped (offline backend)
    219 C unit checks (OpenSSL 3.6.3) / 234 (4.0.1, where the mu oracle is live)
    clean builds against OpenSSL 3.0.21, 3.5.7, 3.6.3, 4.0.1
    module is 2.08 MB, exports only OSSL_provider_init, links no libcrypto
    verified on macOS (arm64) and Linux (arm64, docker ubuntu:24.04)

---

## Module size, and where it went

```
    5.11  start
    4.92  -ffile-prefix-map: 3393 absolute build paths removed
    4.65  -Oz instead of -O3 (nothing here is CPU-bound; the time is the round trip)
    3.46  -dead_strip / --gc-sections, paired with -ffunction-sections/-fdata-sections
    2.08  -Wl,-x in Release

    The single biggest item was never SDK code: __LINKEDIT held 18,616 symbols
    for a module that exports ONE, at 1.5 MB -- 44% of the file, more than all
    its code. Now 96 KB.

    What is left: ~1.08 MB code, 489 KB strings, 247 KB const, 96 KB symbols.
    Of the code, 13 KB is this provider. The rest is what a self-contained AWS
    client costs: s2n-tls 232K, sdk-core+smithy 263K, static inits/registries
    277K. Strings are 359 KB of error and exception text.

    The credential requirement is the shape of the binary: aws-c-auth is 18 KB,
    but resolving credentials from IMDS/ECS/SSO/STS makes HTTPS calls, dragging
    in TLS, HTTP/1.1+2, an event loop and sockets -- ~300 KB so that 18 KB can
    establish identity.

  WE ALREADY IMPLEMENT THE SDK'S DOCUMENTED SIZE RECIPE: MINIMIZE_SIZE,
  BUILD_ONLY=kms, USE_CRT_HTTP_CLIENT, BUILD_SHARED_LIBS=OFF, and
  CUSTOM_MEMORY_MANAGEMENT correctly defaulting off for static linking.
  Two documented levers deliberately not taken:
    ENABLE_VIRTUAL_OPERATIONS=OFF  would be the biggest remaining win -- vtables
      keep all ~50 KMS operations alive when we call two -- but the pre-generated
      KMSClient.h has a literal `virtual`, so it only bites with
      REGENERATE_CLIENTS, which needs python + java 8+ + maven. Without that it
      merely adds -ffunction-sections/-fdata-sections, which we already set.
    NO_ENCRYPTION  plausibly safe since SigV4 goes through aws-c-cal, but it
      would fail at RUNTIME rather than build time. Not a trade worth making in
      a signing provider.
  Other levers judged not worth it: dropping ada (~37 KB now, and it would mean
  hand-rolling WHATWG parsing) and dropping the C++ SDK for raw aws-c-* (aws-c-auth's
  default chain still lacks SSO profile-defined credentials, awslabs/aws-c-auth#228).
  identical results on a --shared-openssl node, a locally built bundled-static
  one, and a stock nodejs.org nightly, all OpenSSL 3.5.7
  ada vendored at 4.0.0, byte-identical to what Node main ships
```

---

## Decisions

[x] D1. Distribution -- DECIDED 2026-08-05. THREE TIERS:
          1) build from source + cnf          (works today; the repo is the artifact)
          2) per-arch GitHub release tarballs + cnf
          3) npm, esbuild-shaped: core package + one optional dependency per arch

        FULL PLAN: docs/distribution.md. It supersedes the "options a/b/c" at the
        end of this entry; everything else below is kept because it is the
        measurement record the plan rests on.

        THE ONE MEASUREMENT THAT CHANGED THE SHAPE: a single shared object can be
        BOTH the provider and its own N-API registrar. Built and run: awskms.dylib
        exports OSSL_provider_init AND napi_register_module_v1, loads as a
        provider in the openssl CLI (a host with no napi symbols) and as an addon
        in node, and still links no libcrypto. Cost +448 bytes. So the "second
        native artifact per platform" that the addon route was assumed to cost
        DOES NOT EXIST -- it is ONE artifact per platform in all three tiers.
        The napi reference must be WEAK: a strong one makes the provider fail to
        dlopen in the openssl CLI, because OpenSSL's DSO loader uses RTLD_NOW.

        THREE THINGS THAT MUST HAPPEN BEFORE ANY OF IT (see docs/distribution.md):
          B1  FIXED 2026-08-05. The Linux aws-backend no longer links libcrypto.
              Verified in docker (ubuntu:24.04, arm64, aws backend):
                readelf -d  -> libstdc++, libm, libgcc_s, libc, ld-linux only
                exports     -> OSSL_provider_init, nothing else
                openssl CLI -> status: active (RTLD_NOW, the strict loader)
                stock node v26.6.0 -> boots, generateKeyPair still works
                check-load.sh -> all 223 OpenSSL symbols exported by that node
              macOS re-verified unchanged: otool -L shows libSystem, Security,
              Network, CoreFoundation, libz, libc++ -- no libcrypto.

              THE FIX (cmake/ScrubLibcrypto.cmake, rewritten): let every
              subproject find the REAL libcrypto -- they need it for their
              configure probes and headers -- then strip libcrypto out of their
              INTERFACE_LINK_LIBRARIES after add_subdirectory(). Works because the
              SDK is BUILD_SHARED_LIBS=OFF, so every target is a static archive
              and an archive records no dependencies: their own LINK_LIBRARIES is
              untouched (they still compile correctly) while the INTERFACE is what
              propagates to consumers, and we are the consumer. Stopping it at our
              own target needs no cooperation from upstream and no fight over
              target names. It walks the SDK tree via BUILDSYSTEM_TARGETS rather
              than hardcoding names; it reported "stripped from the interface of
              s2n aws-c-cal", which is exactly what the diagnosis predicted.

              THE SECOND DEFECT WENT WITH IT. s2n's probes were 0 TRUE / 19 FALSE;
              they are now 11 TRUE / 8 FALSE, with GET0_CHAIN and PROVIDERS TRUE
              and HKDF legitimately FALSE (that probe looks for the BoringSSL /
              AWS-LC HKDF_* symbols, which OpenSSL does not provide). s2n is now
              compiled against what its libcrypto actually has.

              TWO GUARD BUGS THE FIX EXPOSED, both fixed:
                cmake/AssertNoStaticLibcrypto.cmake only ever detected a libcrypto
                  swallowed STATICALLY (symbols defined inside the module). It
                  passed cleanly on the broken build, which carried a DYNAMIC
                  NEEDED libcrypto.so.3. Same fatal outcome, different mechanism.
                  Now checks both, via otool -L / readelf -d.
                scripts/check-load.sh counted WEAK undefined symbols as
                  requirements. aws-c-cal carries weak references to the OpenSSL
                  1.0.2-era EVP_MD_CTX_create / EVP_MD_CTX_destroy /
                  HMAC_CTX_init / HMAC_CTX_cleanup and picks an API at runtime;
                  node exports none of them and needs to export none. Measured 186
                  strong vs 9 weak. The audit failed a module that is `status:
                  active` in the openssl CLI. Now filters weak on both platforms
                  ($1=="U" on ELF, grep -v 'weak external' on Darwin).

              UPSTREAM HAS NOTHING FOR US -- searched, with receipts, across
              aws-sdk-cpp, aws-crt-cpp, aws-c-cal, aws-c-io and s2n-tls. No knob
              expresses "compile against libcrypto headers, leave the symbols
              undefined, bind at dlopen"; every option only chooses WHICH
              libcrypto gets linked. BYO_CRYPTO is a dead end by declaration --
              aws-sdk-cpp cmake/external_dependencies.cmake:24 is
              message(FATAL_ERROR "BYO_CRYPTO is not currently implemented and has
              been broken since version 1.9") -- and a global code search for its
              API entry point finds zero call sites. Nobody has filed this
              scenario in any of the five repos; maintainers treat the transitive
              PUBLIC link as a feature. Do not go looking again.

              ALTERNATIVES TESTED AND REJECTED (so they are not re-proposed):
                INTERFACE_LINK_LIBRARIES_DIRECT_EXCLUDE  documented not to affect
                  INDIRECT dependencies, which is exactly how libcrypto reaches
                  us; measured leaving it on the link line
                LINK_LIBRARY_OVERRIDE  overrides link FEATURES, not items
                patchelf --remove-needed  leaves .gnu.version_r behind, and cannot
                  undo the macOS static-swallow at all
              Mutating another directory's target property is legal (non-imported
              targets are global) with no ordering hazard: add_subdirectory
              processes immediately and consumers materialise at generate time.

              TURNED ON WHILE HERE: S2N_ENFORCE_PROPER_LIBCRYPTO_FEATURE_PROBE
              (s2n#5579, merged, defaults OFF) in cmake/FetchAwsSdkKms.cmake. It
              makes a probe that cannot link libcrypto a configure-time
              FATAL_ERROR instead of a silently degraded s2n. It gates on a
              dedicated S2N_LIBCRYPTO_SANITY_PROBE, so a legitimately absent
              feature (the AWS-LC-only HKDF_*) still just reports FALSE. This is
              the guard that would have caught the 0/19 pathology at configure
              time rather than by accident.

              WEAK-VS-STRONG HAS NOW BITTEN TWICE, FROM OPPOSITE DIRECTIONS: the
              napi dual-role entry point MUST be weak or the provider fails to
              dlopen in a non-Node host under RTLD_NOW, and here weakness was
              misread as a requirement. Whatever asserts "every napi_* ref is
              weak" should share one weak/strong classifier with this audit.

              HISTORY, kept so the dead ends are not retried. Originally
              REPRODUCED 2026-08-05 as:
                readelf -d awskms.so -> NEEDED libcrypto.so.3
                CMakeFiles/awskms.dir/link.txt carries the absolute path
                /usr/lib/aarch64-linux-gnu/libcrypto.so
              Shipping it would load a SECOND OpenSSL with its own OSSL_LIB_CTX
              and error queue -- every error we raise becomes invisible to node,
              and d2i_PUBKEY_ex consults a libcrypto with no providers. That is
              the exact failure the no-libcrypto design exists to prevent.

              ROOT CAUSE, and it is OURS, not the SDK's. ScrubLibcrypto.cmake
              works by pre-creating crypto / OpenSSL::Crypto / AWS::crypto as
              header-only INTERFACE targets, relying on every finder guarding with
              if(NOT TARGET ...) -- its comment says "defining them first wins".
              We are not first. find_package(OpenSSL) creates a REAL
              OpenSSL::Crypto UNKNOWN IMPORTED target pointing at the absolute
              library, and it runs BEFORE the guards in two places: CMakeLists.txt
              :131, and ScrubLibcrypto.cmake:32 -- inside the scrub function
              itself, three lines above the guard meant to stub that very name.
              So the guard designed to protect the invariant is what lets the real
              target through. aws-c-cal's Linux branch then does
              list(APPEND PLATFORM_LIBS OpenSSL::Crypto) as a PUBLIC link and it
              propagates transitively to us.

              NOT a Linux-specific bug -- a platform-independent bug with a
              Linux-only SYMPTOM. aws-c-cal gates that branch on
              (NOT WIN32 AND NOT APPLE); macOS takes Security.framework and never
              consumes OpenSSL::Crypto, so the ordering has always been wrong and
              simply had no victim.

              TWO FIX ATTEMPTS, BOTH MEASURED, BOTH FAILED -- do not repeat:
                1. skip CMakeLists.txt:131 via AWSKMS_OPENSSL_INCLUDE_DIR
                   -> libcrypto.so.3 STILL in DT_NEEDED (line 32 does it anyway)
                2. replace ScrubLibcrypto.cmake:32's find_package with find_path
                   -> default config still broken (131 wins), AND it broke the
                      awskms_unit target, which legitimately DOES link libcrypto
              Reverted; macOS re-verified clean (otool -L: libc++ and libSystem
              only).

              THE FIX HAS TO REPLACE THE STRATEGY, NOT REORDER IT. Let every
              subproject find the REAL libcrypto, then strip OpenSSL::Crypto /
              AWS::crypto / crypto from the INTERFACE_LINK_LIBRARIES of the SDK
              targets awskms links, after add_subdirectory. Stops the propagation
              at our own target instead of fighting FindOpenSSL over a name, and
              leaves awskms_unit's real libcrypto alone. It also fixes the second
              defect below for free.

              SECOND DEFECT, FOUND ALONGSIDE: all 19 S2N_LIBCRYPTO_SUPPORTS_*
              probes evaluate FALSE -- including HKDF, PROVIDERS and GET0_CHAIN --
              against a host OpenSSL 3.0.13 that supports all three. s2n runs them
              as feature_probe(... LINK_LIBRARIES ${LINK_LIB}) where LINK_LIB is
              "crypto", and THAT name IS our stub (FindOpenSSL does not create it),
              so nothing links and every probe fails closed. So the two symptoms
              have OPPOSITE causes: OpenSSL::Crypto is too real, crypto is too
              fake. ScrubLibcrypto.cmake's comment claims leaving the OPENSSL_*
              variables alone keeps these probes accurate; it does not, because
              they go through the target rather than the variables. s2n is
              currently compiled as though libcrypto supports nothing.

              THREE LINUX CLAIMS SETTLED BY THE SAME BUILD, all previously
              inferred from macOS only:
                [x] exports are exactly OSSL_provider_init -- awskms.map and
                    --version-script work
                [ ] no libcrypto/libssl in NEEDED -- FAILS, this entry
                [x] 123 undefined OpenSSL symbols vs 68 on macOS. The trap (d)
                    symbol audit MUST run on Linux; the macOS audit covers barely
                    half the surface.

              ALSO: awskms_assert_no_static_libcrypto PASSED on this build. It
              looks for libcrypto symbols DEFINED INSIDE the module (a static
              absorb) and does not see a dynamic DT_NEEDED. Same fatal outcome,
              different mechanism, and check-load.sh section 2 does catch it -- so
              the post-build assert and the load check disagree about what "no
              second libcrypto" means. Widen the assert while fixing this.
          B2  GONE. The STORE loader SHIPPED IN NODE 26.7.0 (Current) on
              2026-08-05 -- 82712652cb on main, 58717685a1bc on v26.x, PR #63949,
              listed under notable changes in release proposal #65027. So the
              floor is a RELEASED node as of today, not a nightly:
                engines   ">=26.7.0"   (not ">=27.0.0-0")
                dist-tag  latest       (no `next` staging)
                CI        test against 26.7.0 as the oldest supported node
              The earlier "no backport in flight, ~8.5 months to Node 27 GA"
              reading was wrong because it compared against the MAIN-branch SHA
              565c3daebf9; the cherry-pick carries a different hash, so the
              compare reported "diverged" and looked like an absence.
          B3  scripts/check-load.sh's load assertion was a no-op -- FIXED
              2026-08-05. It destructured a getProviders that exists on no node
              and then printed BOOTED unconditionally, so it passed with a
              deliberately broken module path. The one check whose stated purpose
              was to close trap (a) was itself an instance of trap (a). Now probes
              a bare "awskms:" URI, which costs no network call and no
              credentials: ERR_OSSL_AWSKMS_INVALID_URI means our loader ran,
              ERR_OSSL_OSSL_STORE_UNSUPPORTED means the module never loaded, and
              ERR_INVALID_ARG_TYPE means the node predates the loader and is
              reported as a skip rather than a pass. Negative control fires.
              Also fixed: NODES[@] was unbound under macOS bash 3.2 in the
              documented "no node binaries" mode.

        TIER 2's cnf PROBLEM IS SOLVED, with no generator: ship ONE cnf, byte
        identical on every platform, with `module = $ENV::AWSKMS_MODULE`. OpenSSL
        expands $ENV:: inside `module =`, and an UNSET variable is a loud fatal
        (node exits 104) -- the only tier-2 misconfiguration in this space that is
        not silent. A wrong-but-set path is still silent; the doctor narrows that.

        Kept below: the measurement record.

    Distribution notes predating the decision. The calculus CHANGED 2026-08-05.

    FINDING THAT INVALIDATES A PREMISE HELD ALL ALONG. "A provider cannot be
    activated from inside a running process, so --openssl-config is mandatory"
    is true only of CONFIG-FILE activation. An N-API addon loads into the same
    process with the same libcrypto, so it can do it programmatically:

        EVP_set_default_properties(NULL, "?provider!=awskms");
        OSSL_PROVIDER_set_default_search_path(NULL, dir);
        OSSL_PROVIDER_load(NULL, "default");
        OSSL_PROVIDER_load(NULL, "awskms");

    Proven with a ~30-line addon on BOTH the shared-openssl dev build and a
    stock statically-linked nodejs.org nightly: no --openssl-config, no
    OPENSSL_CONF, key loads, signs, verifies -- and crypto.generateKeyPair still
    works, so the property guard holds when set this way too.

    That turns
        node --openssl-config=/abs/path/awskms.cnf app.mjs
    into
        import 'awskms-provider/register';

    and it removes the openssl.cnf entirely, which kills all four silent-failure
    traps at once rather than documenting them:
      (a) a failed load is silent          -> now a thrown JS Error carrying the
                                              OpenSSL reason
      (b) missing default_sect aborts node -> "default" is loaded explicitly
      (c) module path must be absolute,
          with the platform extension      -> resolved from node_modules in code
      (d) exported-symbol skew             -> still real, but surfaces at
                                              require() instead of at first use

    THREE WAYS TO ACTIVATE, all proven byte-identical on the wire (2 requests:
    GetPublicKey then Sign, keyId=alias/test-RSA_2048, RSASSA_PKCS1_V1_5_SHA_256,
    MessageType=DIGEST, len=32) on BOTH a --shared-openssl node and a stock
    statically-linked nightly:

      --openssl-config=<abs path>   no native artifact, but needs a generated cnf
                                    and carries all four silent-failure traps
      N-API addon                   NO FLAG AT ALL; costs a second native
                                    artifact per platform
      node:ffi (pure JS)            NO native artifact; costs --experimental-ffi

    node:ffi (added v26.1.0, Stability 1) can do it with no addon whatsoever:
    ffi.dlopen(null, ...) resolves out of the current process image, which
    reaches libcrypto in both linkage models. Caveats:
      - needs --experimental-ffi. It IS on the NODE_OPTIONS allowlist, so
        NODE_OPTIONS=--experimental-ffi works, but it is still a flag.
      - "only available in builds with FFI support" -- not guaranteed present,
        so any use needs a runtime capability check.
      - experimental, so the API may change.

    UNDER --permission, THE CONFIG FILE WINS AND IT IS NOT CLOSE. Every path
    needs --allow-openssl-store, since that is the permission Node added for
    STORE loaders. The programmatic ones need MORE, and measured minimums are:

      --openssl-config   --allow-openssl-store
      node:ffi           --allow-openssl-store --allow-ffi
      N-API addon        --allow-openssl-store --allow-addons --allow-fs-read

    ...BUT THAT ONLY HOLDS IF NOTHING IS DROPPED. Permissions can be dropped at
    runtime and never regained, which changes the comparison: the broad grants
    are needed only for a STARTUP WINDOW, not for the process lifetime.

    Measured end to end, scope name "openssl.store" (a DOT -- the CLI flag is
    --allow-openssl-store but the API scope is not hyphenated; passing
    "openssl-store" is silently a no-op on an unknown scope, and has() then
    reports false, which looks exactly like a successful drop):

      register via ffi         (needs --allow-ffi)
      process.permission.drop('ffi')            -> ffi ERR_ACCESS_DENIED
      createPrivateKey(url)    (needs --allow-openssl-store)
      process.permission.drop('openssl.store')  -> new key loads ERR_ACCESS_DENIED
      sign with the loaded key                  -> STILL WORKS

    The last line is the point: signing uses the already-loaded EVP_PKEY, not
    the store, so dropping openssl.store does not break it. Verified for the
    config-file path too, which reaches the same end state without ever holding
    ffi or addon rights.

    So the honest comparison is:
      - never dropping        -> the cnf needs the fewest grants, as above
      - dropping at startup   -> all three converge on the SAME steady state,
                                 differing only in what is briefly held
      - and the drop pattern beats every non-dropping variant, because after it
        a later compromise cannot load new KMS keys at all

    KEYOBJECTS SURVIVE THE DROP, AND TRANSFER ACROSS THREADS. Measured:
      - a KeyObject postMessage'd to a Worker signs there, after the main thread
        already dropped openssl.store. The key moves as a shared handle, not by
        re-loading from the store.
      - the public KeyObject the worker creates and sends BACK verifies in main.
      - so a provider-backed key round-trips, which also exercises the
        thread-safety design for real: two threads sharing one key.

    ...BUT THE DROP IS PER-THREAD. A newly spawned Worker starts from the
    ORIGINAL CLI GRANTS, not the dropped state:

        main:   dropped openssl.store; has() = false
        worker: can it load a NEW key? -> true

    So drop('openssl.store') alone is bypassable by spawning a worker. Node says
    as much -- "--allow-worker must be used with extreme caution. It could
    invalidate the permission model" -- and this is precisely how.

    THE COMPLETE RECIPE therefore needs both, in this order:

        const key = createPrivateKey({ key: url });   // load every key first
        process.permission.drop('openssl.store');     // no new keys in-thread
        process.permission.drop('worker');            // and no thread that
                                                      // would start over

    Verified: afterwards new Workers are ERR_ACCESS_DENIED and signing with the
    already-loaded key still works. A worker spawned BEFORE the drop keeps its
    own grants, so a worker pool must be created up front or not at all.

    Per-thread cuts the useful way too: a worker can be handed a signing key
    while being denied the ability to load any OTHER key -- a reasonable
    privilege-separation shape for a signing service.

    GOTCHA THAT COST A WRONG CONCLUSION HERE: the scope name is "openssl.store"
    with a DOT, while the CLI flag is --allow-openssl-store with hyphens.
    drop("openssl-store") is a silent no-op on an unknown scope, and has() then
    returns false -- indistinguishable from a successful drop. Anyone writing
    this pattern will hit it.

    THIS IS WORTH DOCUMENTING IN THE README REGARDLESS OF PACKAGING. It is a
    materially better posture than the provider currently describes, it is
    available today with no code changes, and the two gotchas above (per-thread
    drops, and the dot-vs-hyphen scope name) are both silent failures.

    NOTE it does NOT remove per-platform builds: the provider .so itself is
    still native. FFI removes the SECOND artifact (the shim), not the first.

    COSTS whichever way: prebuilt binaries per platform (darwin/linux x
    arm64/x64) and a release pipeline. The addon could be avoided entirely if
    the provider module also exported napi_register_module_v1 and doubled as its
    own registrar -- untested, and dlopening one file as both an addon and a
    provider needs thought.

    SUPERSEDED: the a/b/c options that stood here are answered by the three-tier
    decision above. See docs/distribution.md for what ships, in what order, and
    the eleven things still left for the user to rule on.

[x] D2. RESOLVED -- CI does not need to build Node at all.
        The STORE loader landed in nodejs/node main on 2026-08-02 as
        565c3daebf9, so the nightly builds carry it. A stock nightly was
        downloaded and the whole suite run against it: 397 aws-backend and 374
        offline tests pass, and check-load.sh reports every one of the 68
        OpenSSL symbols the module needs is exported.
        That binary is also the real deployment target -- unmodified, with
        statically linked bundled OpenSSL -- so it settles the static-linkage
        question better than the local bundled build did.
        Consequence: CI downloads a nightly and runs everything, instead of a
        20-60 minute Node build. T2 gets substantially cheaper and covers the
        full suite rather than the ~15 tests that do not need the loader.

        UPDATED 2026-08-05: it does not even need a nightly. The loader shipped
        in 26.7.0 (Current), so CI can pin a RELEASED node -- reproducible,
        and it doubles as the "oldest supported node" the trap (d) symbol audit
        in check-load.sh has to run against. Use 26.7.0 exactly, not `latest`:
        the audit is only as good as the oldest host it runs on. See D1/B2.

[x] D3. DONE. Account 859571461205, eu-central-1, both principals created by
        scripts/real-kms-bootstrap.mjs. See T0. Was:
        single most important piece of remaining verification, deliberately
        deferred until asked, and it is not optional before anyone relies on
        this.



---

## Completed tasks

[x] T0. THE REAL-KMS PASS -- DONE 2026-08-04, account 859571461205,
        eu-central-1. FULL 22-key matrix: 365 tests passed against real AWS KMS,
        0 failures, 6 skipped (all legitimately stub-only). Smoke subset ran
        first at 208 passing.

        THE HEADLINE: the stubs were faithful. Every assumption that only the
        real service could settle held on the first run -- signature encodings,
        PSS at digest-length salt, MessageType DIGEST for RSA/ECDSA and RAW for
        Ed25519, and EXTERNAL_MU accepted with our locally computed mu producing
        signatures that verify as ordinary pure ML-DSA. That last one was
        documentation-only until this run.

        ALSO SETTLED
          - ML_DSA_44 is available in eu-central-1 (F3, for that spec)
          - the credential path finally ran: superadmin -> AwskmsTestAdmin ->
            AwskmsTestSigner via profile chaining. It was the single most
            important untested thing, since not reinventing credential handling
            was the original constraint
          - least privilege holds: the whole suite ran as a principal with only
            kms:Sign and kms:GetPublicKey, so "the provider needs nothing else"
            is now tested rather than asserted
          - teardown left 0 keys billable, and its union-of-sources dedup and
            already-pending handling both exercised for real

        HARNESS BUG THE RUN EXPOSED (fixed): the provisioning skip had been
        applied to one describe block in sign.test.mjs and missed eight others,
        so a --smoke run tried to load the 14 keys it deliberately had not
        created -- 40 KEY_NOT_FOUND failures. Fixed with skipForAny(). This class
        of bug is invisible offline, where every spec is "provisioned", so only a
        real subset run could find it.

        FULL MATRIX RESULT
          [x] all 11 key specs verified against real KMS. RSA_2048/3072/4096,
              ECC_NIST_P256/P384/P521, ECC_SECG_P256K1, ECC_NIST_EDWARDS25519
              and ML_DSA_44/65/87 all created and exercised.
          [x] F3 ANSWERED: all three ML-DSA specs exist in eu-central-1. The
              region-availability worry was unfounded there, though it stays
              undocumented per spec, so the manifest/skip machinery earns its
              keep for other regions.
          [x] secp256k1 signed and verified; signatures are passed through
              un-normalised as designed, so the low-S caveat in the README holds.

        STILL OPEN
          [x] F2 ANSWERED 2026-08-04, by probing `aws kms sign` directly so the
              provider's own guard was bypassed. AWS enforces 1-4096, not the
              0-4096 its prose claims -- the blob constraint is authoritative:

                0 bytes     ValidationException: Member must have length
                            greater than or equal to 1
                1 byte      accepted
                4095, 4096  accepted
                4097        ValidationException: Member must have length
                            less than or equal to 4096

              So rejecting a zero-length message locally with
              ERR_OSSL_AWSKMS_EMPTY_MESSAGE is correct, and better than
              forwarding it: the caller gets a typed error instead of a generic
              ValidationException after paying for a round trip. The 4096 cap is
              exact, so the README's Ed25519 limit is right to the byte.

              Incidental, from the same probe: signing as AwskmsTestAdmin returns
              AccessDeniedException with an explicit deny, so the NeverSign
              statement works. That matters because the admin holds
              kms:PutKeyPolicy and could otherwise grant itself signing; an
              identity-policy Deny is the only thing a key-policy edit cannot
              override.
          [x] one Sign per signature -- DONE via CloudTrail, no trail needed.
              KMS API calls are management events, retained free for 90 days, so
              scripts/real-kms-audit.mjs needs only cloudtrail:LookupEvents (on
              the ADMIN role; the signer keeps holding nothing but kms:Sign and
              kms:GetPublicKey, since that is the claim under test).
              Measured: 5 signatures -> exactly 5 Sign, 1 key load -> exactly 1
              GetPublicKey, 5 local verifications -> 0 calls. Size probes cost
              nothing. Events took ~90s to appear; the script polls because AWS
              says up to ~15 min, which is why it is a command and not a test.

              The same lookup also confirmed the wire protocol from AWS's own
              records, across the earlier suite run: 249 Sign events, ZERO
              errors, all from AwskmsTestSigner, split 174 DIGEST / 39 RAW /
              36 EXTERNAL_MU. That is the service confirming the three message
              shapes rather than our stub agreeing with itself.

              Incidental: 794 GetPublicKey against 249 Sign, because the caching
              is per key OBJECT and the tests create them liberally. A
              long-lived KeyObject in production makes exactly one.

[x] T0-original. THE REAL-KMS PASS -- rationale, kept for context.

    WHY IT IS NOT OPTIONAL
    Every test so far runs against a stub, and both stubs were written from AWS
    documentation -- by the same reading of the same docs that produced the
    implementation. So the two agree by construction. Anywhere the docs are
    wrong, ambiguous, or were misread, the stubs encode the same mistake and no
    amount of stub testing can surface it. What is verified today is "the
    implementation matches my understanding of KMS", not "my understanding of
    KMS is correct". Only real credentials close that gap.

    Known places the docs were ambiguous or contradictory, i.e. the specific
    things most likely to be wrong:
      - Message minimum length: prose says 0-4096, the blob constraint says
        minimum 1 (see F2)
      - whether MessageType=DIGEST is rejected for ML-DSA at all (undocumented;
        we treat it as nonexistent)
      - ML-DSA availability per region (undocumented at key-spec granularity)
      - low-S / canonical S for secp256k1 (not documented either way; we pass
        KMS's bytes through untouched)

    WHAT ONLY REAL KMS COULD ANSWER -- ANSWERED 2026-08-04/05
      [x] signature encodings are what we assumed: RSA raw PKCS#1, ECDSA DER
          SEQUENCE{r,s}, Ed25519 64 raw bytes, ML-DSA raw. Every signature in the
          365-test full-matrix run was verified locally against the DEFAULT
          provider, so a wrong encoding could not have passed.
      [x] RSASSA_PSS really uses a digest-length salt. Local verification pins
          RSA_PSS_SALTLEN_DIGEST, so a different salt would have failed loudly;
          the PSS cases passed against real KMS.
      [x] EXTERNAL_MU is accepted and the signature verifies as ordinary pure
          ML-DSA. 36 EXTERNAL_MU calls in CloudTrail, all ML-DSA tests green.
          This was documentation-only until the first real run.
      [x] the 4096-byte RAW cap, exactly. Probed via `aws kms sign` directly:
          0 -> ValidationException (>= 1), 1/4095/4096 -> accepted,
          4097 -> ValidationException (<= 4096). See F2.
      [x] MessageType=DIGEST enforces the digest length per algorithm, exactly.
          Probed directly against RSASSA_PKCS1_V1_5_SHA_256, which wants 32:
            20, 31, 33, 48, 64 -> ValidationException
                                  "Digest is invalid length for algorithm ..."
            32                  -> accepted
          So DIGEST_LENGTH_MISMATCH is a real service constraint, and catching it
          locally saves a round trip rather than inventing a rule.
      [x] error shapes. Closed from both ends: the whole reason_for() table is
          covered offline (test/errors.test.mjs, via HTTP-stub fault injection
          that still goes through the real SDK), and real exception names have
          now been seen for real -- NotFoundException in CloudTrail, and
          ValidationException and AccessDeniedException from the direct probes.
          Original note:

          MOSTLY CLOSED, offline, in test/errors.test.mjs. The audit that
          prompted this found 11 of 23 reason codes raised by code no test
          reached. It is now 3, and none of the three is worth chasing.

          Closed by fault injection in BOTH stubs (markers in the key id;
          see src/kms_stub.c and test/kms-stub.mjs):
            UNSUPPORTED_KEY_SPEC     a KeySpec we do not implement (SM2)
            MALFORMED_PUBLIC_KEY     5 distinct branches -- empty, truncated and
                                     corrupt SPKI, an EC key delivered as RSA,
                                     and a P-256 key delivered as P-384 (the one
                                     a lazy EVP_PKEY_is_a check would miss)
            KEY_NOT_FOUND, KEY_DISABLED, KEY_PENDING_DELETION,
            INVALID_KEY_USAGE, ACCESS_DENIED, THROTTLED,
            GET_PUBLIC_KEY_FAILED, SIGN_FAILED
                                     the whole reason_for() table in kms_aws.cc,
                                     at BOTH load and sign time, plus the
                                     unmapped-exception fallback for each

          Closed without any stub help:
            UNSUPPORTED_PADDING      reachable straight from Node --
                                     RSA_NO_PADDING / OAEP / X931 on a sign call
            DIGEST_LENGTH_MISMATCH   NOT reachable from Node: every Node signing
                                     path computes the digest with the same
                                     EVP_MD it declared, so the length always
                                     agrees. Reachable from a non-Node caller,
                                     which is exactly the defence-in-depth this
                                     provider keeps on purpose -- so it is tested
                                     through `openssl pkeyutl`, and the audit
                                     grep misses it because the assertion is on
                                     the CLI's stderr rather than an err.code.

          Testing reason_for() turned out NOT to need real KMS, which was the
          assumption worth discarding: the HTTP stub can return any __type, and
          the request still goes through the real AWS SDK -- so these also pin
          down the SDK's own classification (that the wire string
          "DisabledException" becomes KMSErrors::DISABLED is a fact about
          aws-sdk-cpp, not about us, and this is the only place it is checked).

          NO_CREDENTIALS -- REACHED 2026-08-05, incidentally, while testing the
          demo npm package. It needs the credential chain to come up EMPTY, which
          the stub cannot arrange because it supplies dummy keys; the recipe is to
          starve every source at once:
            env -u AWS_PROFILE -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY \
                -u AWS_SESSION_TOKEN AWS_EC2_METADATA_DISABLED=true \
                AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
          -> ERR_OSSL_AWSKMS_NO_CREDENTIALS. Worth folding into errors.test.mjs;
          it is the last offline-reachable reason code that had no coverage.

          STILL UNTESTED, and deliberately:
            NO_REGION        unreachable by construction (see below)
            INTERNAL_ERROR   allocation failures and other can't-happen paths

          FOUND WHILE DOING THIS: the SDK RETRIES ThrottlingException with
          backoff, so ERR_OSSL_AWSKMS_THROTTLED surfaces only after retries are
          exhausted -- measured at ~4s for a sign, ~1.3s for a load. In
          crypto.sign()'s synchronous form that is 4 seconds of blocked event
          loop, not one round trip. Now asserted (the slowness IS the assertion:
          if it ever gets fast, retries have been lost) and documented in the
          README's operational notes.

          NO_REGION is unreachable by construction, not by omission: every
          aws-sdk-cpp ClientConfiguration constructor substitutes us-east-1 when
          its own resolution comes up empty, so an unset region cannot be told
          from a deliberate us-east-1 without duplicating the SDK's resolution
          order. The guard stays as defence in depth; the README documents the
          us-east-1 default instead of pretending we catch it.
      [x] THE WHOLE CREDENTIAL PATH -- the thing that most needed this. The
          assume-role chain ran for real: superadmin -> AwskmsTestAdmin ->
          AwskmsTestSigner, via ~/.aws/config profile chaining, with the SDK
          resolving all of it. Not reinventing credential handling was the
          original constraint, and it was entirely unexercised until now.
      [x] alias resolution: every key in both runs was reached as
          alias/test-<SPEC> or alias/other-<SPEC>.
      [x] GetPublicKey returns KeySpec, not the deprecated
          CustomerMasterKeySpec: all 11 specs parsed correctly from real
          responses, which would not happen if we were reading a missing field.
      [x] region resolution FROM A KEY ARN, proven in isolation. With
          AWS_REGION and AWS_DEFAULT_REGION deliberately set to the WRONG region
          (us-east-1) while the keys live in eu-central-1:
            load by ARN (carries eu-central-1) -> ACCEPTED
            load by alias (no region at all)   -> ERR_OSSL_AWSKMS_KEY_NOT_FOUND
          The negative control is what makes it conclusive: the ambient region
          really was wrong, so the ARN is what drove resolution.
      [ ] cross-account access via a key ARN. Single account so far.
      [x] KeyUsage rejection, closed via HTTP-stub fault injection
          (fault-keyusage), which reaches kms_aws.cc's guard through the real
          SDK. Deliberately NOT closed against real KMS: the admin role cannot
          create an ENCRYPT_DECRYPT key -- its policy pins kms:KeyUsage to
          SIGN_VERIFY, and it returns AccessDeniedException, which was verified.
          Testing this for real would mean weakening the very scoping that makes
          the harness safe, for a branch that is fully covered offline.
      [ ] throttling and retry behaviour under real concurrency. The retry
          BEHAVIOUR is measured against the stub (~4s for a sign), but a genuine
          quota breach has never happened.
      [ ] real latency, and whether the client timeouts are sane

    KEY INVENTORY THE EXISTING TESTS NEED
    The tests resolve keys as alias/test-<KEYSPEC> and alias/other-<KEYSPEC>,
    so a full run wants 2 keys for each of 11 specs = 22 keys:
      RSA_2048, RSA_3072, RSA_4096,
      ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, ECC_SECG_P256K1,
      ECC_NIST_EDWARDS25519,
      ML_DSA_44, ML_DSA_65, ML_DSA_87
    COST -- verified against the AWS KMS pricing page, correcting an earlier
    estimate here of "~$22/month" that was wrong by an order of magnitude.

    The $1 per key per month is prorated HOURLY, and:

      - a key SCHEDULED FOR DELETION is not charged at all. Quoted: "There is no
        charge for customer managed KMS keys that you manage and are scheduled
        for deletion."
      - a DISABLED key IS charged at the full rate. So parking keys disabled
        between runs is the one genuinely expensive option, and it matters
        because CancelKeyDeletion leaves a key DISABLED, not enabled.
      - CANCELLING deletion RE-BILLS THE WHOLE WINDOW: "If you cancel the
        deletion during the waiting period, the customer managed KMS key will
        incur charges as though it was never scheduled for deletion."

    DECIDED: create fresh every run, schedule deletion at the end, NEVER cancel.
    Key ARNs are therefore different every run and only the aliases are stable.

      22 keys x $1 x (hours alive / 720). A few-hour pass is ~$0.73, and about
      30 passes a month is ~$1 -- against ~$22/month for the alternative of
      reviving keys, since any revive inside the window back-bills the whole gap.

    Consequences that fall out of that choice:
      - nothing ever calls CancelKeyDeletion, so nothing needs EnableKey either
        (a freshly created key is already Enabled);
      - the ALIAS, not the ARN, is the stable handle the tests reference;
      - teardown MUST DeleteAlias before ScheduleKeyDeletion. An alias stays
        attached to its key for the whole pending window, so scheduling without
        freeing the name leaves alias/test-<SPEC> occupied by a dying key and the
        next run cannot provision for a week;
      - tests that need a real key ARN read it from the manifest setup writes,
        because there is no ARN to hardcode.

    Requests: $0.03 per 10,000 for RSA_2048 (at parity with symmetric, which is
    the detail most summaries get wrong), $0.15 per 10,000 for every other
    asymmetric key including all ECC and Ed25519. ML-DSA is NOT priced anywhere
    on the pricing page -- $0.15 is inference, not an AWS statement. At test
    volumes the exposure is cents either way, but do not quote it as fact.

    The free tier does not apply: asymmetric Sign/Verify/GetPublicKey are
    explicitly excluded, so every request in the suite is billed from the first.
    GetPublicKey is billable (it is named in that exclusion) but AWS publishes no
    rate for it -- UNCONFIRMED. Every key load does exactly one.

    [x] A cheap smoke subset for routine use, shipped as --smoke: one key per
        (RSA_2048, ECC_NIST_P256, ECC_NIST_EDWARDS25519, ML_DSA_44) = 4 SPECS,
        which is 8 keys, not 4 -- every spec needs its `other-` twin too or the
        wrong-key negative tests cannot run,
        which still covers every distinct code path -- DIGEST, RAW, EXTERNAL_MU,
        and both signature families. Keep the full 22-key matrix as an
        occasional exercise. Note that cost is now a weak reason to prefer the
        subset (~$0.13 vs ~$0.73 per pass); iteration speed is the real one.

    HARNESS -- BUILT. Everything below is in place and exercised offline; what
    remains is running it against a real account, which is the whole point of T0.

      [x] test/inventory.mjs is the single source of truth for the 22
          (role, keyspec) pairs. alias() THROWS on an unknown spec or role, so a
          test cannot reference a key the provisioner will not create, and the two
          cannot drift. All five test files resolve keys through it.
      [x] scripts/real-kms-keys.mjs -- setup / teardown / status / reap.
          Shells out to the `aws` CLI rather than taking an @aws-sdk dependency,
          which also keeps credential resolution AWS's own, the same constraint
          the provider is held to. --dry-run prints every call and makes none.
      [x] scripts/aws-cli.mjs -- CLI wrapper; service exceptions become STATES
          rather than failures, plus throttle retry and a DescribeKey poller
          (KMS is not read-your-writes consistent).
      [x] test/real-keys.mjs -- the only module that knows real KMS exists. In
          stub mode every accessor returns the stub defaults, so both modes run
          the SAME test files. Verified against a synthetic manifest.
      [x] .github/workflows/real-kms.yml and real-kms-reaper.yml
      [x] docs/real-kms-setup.md -- the credential/profile/IAM walkthrough
      [x] The two hardcoded fake ARNs, resolved differently on purpose:
            key/RSA_4096  -> realArn('test','RSA_4096') with the fake as
                             fallback; becomes the genuine ARN-to-region test
            key/RSA_2048  -> UNCHANGED, deliberately. The impossible account id
                             `1` is a FEATURE: the region conflict is detected
                             while parsing, so an unreachable ARN proves no
                             network call happens. A real ARN would destroy that
                             discrimination. Commented in place so nobody
                             "fixes" it.
      [x] The ;region=eu-central-1 attribute on the P-256 case, which WAS broken
          for real mode (it pinned a region the test bed is probably not in) --
          now regionAttr(), which also covers "explicit region equal to the
          ambient one is accepted, not treated as a conflict".
      [x] Skip rule: in real mode a spec absent from the manifest is skipped with
          the manifest's reason, composed with the OpenSSL-3.5 ML-DSA check and
          reporting WHICH applied. Without this a --smoke run would fail 14
          specs' worth of tests instead of skipping them.
      [x] run.mjs real mode no longer hard-requires AWS_PROFILE (CI has OIDC
          session vars and no profile). Now: AWS_REGION plus either a profile or
          (CI and AWS_SESSION_TOKEN) -- never a bare ambient fallback. Also
          asserts manifest.region == AWS_REGION, because a mismatch otherwise
          arrives as ~300 NotFoundExceptions that read like a provisioning bug.
      [x] --test-concurrency=1 in real mode: node --test runs files concurrently
          and a 22-spec matrix can burst past the per-region cryptographic
          request-rate quota, which surfaces as ERR_OSSL_AWSKMS_THROTTLED and
          looks like a provider bug.

      [x] "one Sign per signature" -- CLOSED via CloudTrail, see F-audit below. Was:
          service. The request-accounting suite reads the stub's HTTP log and
          correctly skips when AWSKMS_TEST_REAL=1. CloudTrail would work but is a
          separate exercise; the returned KeyId is a cheaper partial substitute
          (UNCONFIRMED whether the provider surfaces it today).
      [x] The four offline-reachable reason codes are closed, and so is the whole
          reason_for() mapping, which turned out not to need AWS after all. See
          the error-shapes entry above. 370 stub / 393 aws tests now pass.
      [x] Feed anything learned back into BOTH stubs. Nothing needed changing:
          the stubs were faithful on every point the real service could check,
          which is itself the headline result of T0.

    DESIGN DECISIONS AND THEIR REASONS
      - No explicit key policy at CreateKey. The default policy grants the account
        root full access, which is the condition that lets IAM policies govern the
        key. A hand-written one adds no capability and opens three routes to an
        unmanageable key, one of which -- a statement missing Action or Resource --
        is accepted silently and is completely ineffective.
      - Teardown is an `if: always()` step in the same job rather than a `needs:`
        job. always() runs on cancellation and !cancelled() does not, and a
        cancelled run is when keys are left billing. Only steps of an
        already-running job are documented to run after a cancellation.
      - concurrency: { group: awskms-real-kms, queue: max }, shared with the
        reaper. queue:max because the default queue:single silently cancels the
        second pending run. cancel-in-progress must stay false: cancelling a
        RUNNING run is what abandons provisioned keys.
      - Actions are pinned to full commit SHAs, never tags. A tag is mutable, and
        these jobs hold credentials that can create and delete KMS keys, so a
        repointed tag is a real compromise path rather than a theoretical one.
        .github/dependabot.yml is what keeps the pins from going stale silently;
        it rewrites the SHA and the trailing `# vX.Y.Z` comment together.
        Verify or refresh one by hand with:
          gh api repos/<owner>/<repo>/releases/latest --jq .tag_name
          gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha
      - No kms:MessageType condition pinning DIGEST on the signer policy, which
        an earlier version of this file proposed. It would break the suite
        outright: ED25519_SHA_512 requires RAW and ML-DSA uses RAW and
        EXTERNAL_MU, which are three different provider code paths.


[x] T3. Vendored-dependency updater -- DONE 2026-08-05.
        scripts/update-vendored.sh, third_party/vendored.manifest, and
        .github/workflows/vendored.yml. It deliberately does not track the
        host Node's ada: Node 26 ships 3.4.4 and Node 27 ships 4.0.0, so no one
        version matches every host, and re-parsing an already-normalised href is
        idempotent across conformant parsers anyway.

        CAN DEPENDABOT DO THIS? No, and not for a fixable reason. Its ecosystems
        key off a manifest or a git submodule and a vendored amalgamation is
        neither: upstream's singleheader/ holds amalgamate.py, NOT the generated
        ada.cpp/ada.h/ada_c.h, which exist only as RELEASE ASSETS. A submodule
        would mean running amalgamate.py at build time -- python plus codegen in
        the build -- trading away the hermetic offline build the vendoring is for.
        Renovate CAN match it (custom regex manager + github-releases datasource)
        but only rewrites the version STRING; it cannot fetch 1.1 MB of source.
        That is strictly worse than nothing on its own: a green PR claiming 4.1.0
        while shipping 4.0.0. dependabot.yml stays as it is -- it covers the
        Actions SHA pins, which is a genuinely different problem.

        SO THE TWO HALVES DEPENDABOT WOULD GIVE ARE SPLIT:
          verify  the vendored bytes ARE the release the manifest names, fetched
                  from upstream and compared. Plus: every ada_* identifier src/
                  uses exists in the vendored header, and the dependency README's
                  version line agrees with the manifest.
          check   recorded tag vs releases/latest. Exit 2 (not 1) so a drift
                  notification is not reported as a broken build, and one
                  parseable "drift: <name> <old> <new>" line per dep.
          update  fetch -> API check against the NEW header -> install -> rewrite
                  both records. The API check runs BEFORE anything is written, so
                  a breaking release leaves the tree untouched rather than half
                  updated.

        VERIFY IS THE LOAD-BEARING ONE, and it is what makes a bump honest: with
        it, editing a recorded version without applying it FAILS instead of
        looking applied. Exercised for real, all four:
          manifest bumped to v3.4.4, files left at 4.0.0 -> 3 byte FAILs, plus an
            independent FAIL from the README line. This is the lying-PR case.
          a hand-edited vendored file -> FAIL naming the file
          src/ calling an ada_* the header lacks -> FAIL naming the identifier
          update round trip 4.0.0 -> 3.4.4 -> 4.0.0 -> every file bit-identical
            to where it started, manifest and README rewritten in step

        Uses `gh` rather than curl, which is the same "shell out to the official
        CLI" stance scripts/aws-cli.mjs takes with `aws`, and avoids hand-parsing
        API JSON and hand-building asset URLs. Both gh routes were checked to
        return bytes identical to curl. The one cost: gh needs auth even for
        public reads, where curl does not -- in Actions that is one line,
        GH_TOKEN: ${{ github.token }}.

        Structured for more deps: the manifest carries repo, verbatim tag (tag
        schemes differ), and SEPARATE columns for release assets vs repo-tree
        files, because ada's amalgamation and its licence come from different
        places. The API-surface check stays ada-specific on purpose -- what "the
        API we depend on" means is per-dependency, not guessable for one that
        does not exist yet.

        Clean under shellcheck, which found a real bug: $name[[:space:]] in the
        manifest rewrite parses as an array subscript (SC1087). Incidentally, of
        the existing scripts check-openssl-matrix.sh is already clean and
        check-load.sh has only three SC2001 style suggestions -- so the shellcheck
        job in T2 will not arrive to a mess.

        The workflow's issue body avoids heredocs: a heredoc terminator has to
        sit at column 0, which ends the YAML block scalar the run: script lives
        in. Caught by parsing the YAML, not by review.

        NOT DONE HERE, deliberately: update does not build or test. CI does both
        on the resulting commit against the whole OpenSSL matrix, which is the
        stronger check than whatever is on the machine running the script.

        NOT worth doing: binding to the host Node's exported ada symbols instead
        of vendoring. Node does export all 27 ada C-API functions, so it works --
        but providers are dlopen'd RTLD_NOW, so it is all-or-nothing: the openssl
        CLI and libcrypto export zero ada symbols, and the module would fail to
        load there entirely with no diagnostic. It would also make parsing depend
        on the host's ada version, and those symbols are exported incidentally
        rather than as a supported Node interface. Upside was 0.46 MB of a
        5.11 MB module.


FOLLOW-UPS NOT BLOCKING ANYTHING

---

## Health check -- scripts/awskms-doctor.mjs (2026-08-05)

Built because a failed provider load is COMPLETELY SILENT: node prints nothing,
exits 0, and throws something unhelpful at the first `createPrivateKey`. A wrong
module path, a cnf node never read, and a node too old to have the STORE loader
are three different problems that present identically. Dependency-free ESM,
`node:` core only, so it can be copied verbatim into a release archive or an npm
package -- one check serving all three distribution tiers.

The full design is commented in the script itself; the two things worth not
re-deriving:

**The probe costs nothing.** Level 0 is a bare `awskms:` URI. `src/store.c`
parses the URI *before* calling `awskms_kms_get_public_key`, so an invalid one is
rejected during parsing: no network call, no credentials, no IAM permission, no
AWS account, nothing billable. That structural property is what makes it safe to
put in a README as the first thing a user runs.

**Four outcomes, each naming a different failure:**

| code | meaning |
| --- | --- |
| `ERR_OSSL_AWSKMS_INVALID_URI` | working -- our loader ran |
| `ERR_OSSL_OSSL_STORE_UNSUPPORTED` | loader present, provider absent. **This is trap (a), made visible.** |
| `ERR_INVALID_ARG_TYPE` | node predates 26.7.0 |
| `ERR_ACCESS_DENIED` | `--permission` without `--allow-openssl-store` |

Exit codes are 0 working / 1 broken / **2 cannot tell**, the last so
`check-load.sh` can skip rather than fail on a node that predates the loader.
`check-load.sh` delegates its probe to the doctor, so the discriminator has one
implementation and CI exercises the thing users are actually told to run.

It also inspects a cnf *without* activating it, when `--openssl-config` is passed
after the script name so node does not consume it. Not a nicety: an unset
`$ENV::` in `module =` is fatal at OpenSSL init, so with the cnf genuinely active
node exits before any JS runs, and inspect mode is the only way to diagnose it.

Nine paths verified end to end: working, no config, module missing,
`openssl_conf` without `nodejs_conf`, relative path, missing platform extension,
`$ENV::` set, `$ENV::` unset, and node-too-old (exit 2, with `check-load.sh`
skipping) on both macOS/v24 and Linux/26.6.0.

---

## Closed follow-ups

[x] F2. DONE -- KMS enforces 1-4096, contradicting its own 0-4096 prose.
        AWS's docs contradict themselves: the prose says "Messages can be
        0-4096 bytes", the Message blob constraint says "Minimum length of 1".
        We currently reject an empty message locally for Ed25519 with a clear
        error. If KMS accepts 0 bytes, that is a one-line change in
        src/signature.c (the AWSKMS_R_EMPTY_MESSAGE branch).
        Only reachable for Ed25519 -- RSA/ECDSA send a digest, ML-DSA sends mu.

[x] F3. DONE -- all three ML-DSA specs exist in eu-central-1.
        AWS does not document availability at key-spec granularity. The tests
        skip cleanly if a spec is unavailable.


LATER MILESTONES (explicitly out of scope for now)
