# tiny-aws-kms-openssl-provider
#
# Builds awskms.so / awskms.dylib: an OpenSSL 3.x+ provider module that fronts
# AWS KMS asymmetric keys.
#
# The single most important property of this build is that the module links NO
# libcrypto. It compiles against OpenSSL *headers* only, and every libcrypto
# symbol it references stays undefined in the shared object, to be bound at
# dlopen() time against whatever OpenSSL the host process already has. That is
# what makes one binary work in both of these:
#
#   (a) a stock nodejs.org `node`, whose bundled OpenSSL is statically linked --
#       there is no libcrypto.so anywhere, but node re-exports the whole
#       libcrypto ABI from its own executable;
#   (b) a `node` built --shared-openssl against a system libcrypto.
#
# Linking -lcrypto is not merely unnecessary in case (a), it is harmful: it pulls
# a second, different OpenSSL into the process, with its own OSSL_LIB_CTX,
# algorithm store and -- worst -- its own error queue, so every error this
# provider raises becomes invisible to the host.
#
# Quick start:
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --parallel
#   sudo cmake --install build
#
# Build against a specific OpenSSL's headers (this only sets the FLOOR of the
# supported runtime range; there is no upper bound):
#   cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
#   cmake -S . -B build -DAWSKMS_OPENSSL_INCLUDE_DIR=/nix/store/...-dev/include

cmake_minimum_required(VERSION 3.20)
project(awskms
  VERSION 0.1.0
  DESCRIPTION "OpenSSL provider for AWS KMS asymmetric keys"
  LANGUAGES C CXX)

include(GNUInstallDirs)
include(CTest)

# ---------------------------------------------------------------------------
# Reproducible, path-free __FILE__
# ---------------------------------------------------------------------------
# Without this the module ships the absolute path of every source file that used
# __FILE__ -- ours via OPENSSL_FILE in AWSKMS_raise, and far more from the AWS
# SDK's logging and assert macros. Measured at ~489 KB across 3393 strings, about
# 10% of the module, which is both dead weight and a disclosure of the build
# machine's directory layout in a distributed artifact.
#
# It is dead weight specifically because Node never surfaces file or line: it
# renders errors with ERR_error_string_n(), which emits only library and reason.
# The paths are reachable from the `openssl` CLI and a debugger, and relative
# ones serve both just as well.
#
# Set before any subproject is added so FetchContent's add_subdirectory inherits
# it; the SDK is the bulk of the saving. Both trees are mapped because the
# fetched SDK sources live under the BINARY dir, not the source dir.
include(CheckCCompilerFlag)
check_c_compiler_flag("-ffile-prefix-map=/x=." AWSKMS_HAVE_FILE_PREFIX_MAP)
if(AWSKMS_HAVE_FILE_PREFIX_MAP)
  add_compile_options(
    "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
    "-ffile-prefix-map=${CMAKE_BINARY_DIR}=.")
endif()

# ---------------------------------------------------------------------------
# Optimise for size, not speed
# ---------------------------------------------------------------------------
# This module is ~99% AWS SDK by volume and does two network round trips per key.
# Nothing in it is CPU-bound -- the time goes to KMS -- so -O3's inlining buys
# nothing measurable and costs code. Measured on the aws backend: -O3 gives a
# 2549 KB __text, -Oz gives 1501 KB, and the module drops 4.92 -> 4.65 MB. (The
# file shrinks less than the code because unwind tables grow and segments are
# page-aligned.)
#
# Set on the *_RELEASE variables, not CMAKE_C_FLAGS: CMake emits CMAKE_C_FLAGS
# first and CMAKE_C_FLAGS_RELEASE second, so a -Oz in the former is silently
# overridden by the -O3 in the latter.
# -Oz is clang and GCC 12+; older GCC only has -Os. Probed rather than assumed,
# because CI builds with gcc and an unknown -O flag is an error, not a warning.
check_c_compiler_flag("-Oz" AWSKMS_HAVE_OZ)
if(AWSKMS_HAVE_OZ)
  set(_awskms_size_opt "-Oz")
else()
  set(_awskms_size_opt "-Os")
endif()
foreach(_lang C CXX)
  string(REGEX REPLACE "-O[0-9sz]" "${_awskms_size_opt}" _rel "${CMAKE_${_lang}_FLAGS_RELEASE}")
  if(NOT _rel MATCHES "${_awskms_size_opt}")
    set(_rel "${_awskms_size_opt} ${_rel}")
  endif()
  set(CMAKE_${_lang}_FLAGS_RELEASE "${_rel} -ffunction-sections -fdata-sections"
      CACHE STRING "" FORCE)
endforeach()

option(AWSKMS_LINK_LIBCRYPTO
  "Link libcrypto normally instead of resolving OpenSSL symbols from the host \
process. Only correct when the host is known to use this very libcrypto." OFF)

set(AWSKMS_AWS_SDK "FETCH" CACHE STRING
  "How to obtain the AWS SDK for C++ when AWSKMS_BACKEND=aws: FETCH (sparse \
partial clone, built here) or SYSTEM (find_package(AWSSDK COMPONENTS kms)).")
set_property(CACHE AWSKMS_AWS_SDK PROPERTY STRINGS FETCH SYSTEM)

set(AWSKMS_BACKEND "stub" CACHE STRING
  "Which KMS backend to compile in: aws (the AWS SDK for C++) or stub (a local \
fake, no network and no credentials -- for tests and offline development).")
set_property(CACHE AWSKMS_BACKEND PROPERTY STRINGS aws stub)

set(AWSKMS_OPENSSL_INCLUDE_DIR "" CACHE PATH
  "OpenSSL header directory, when headers and libraries live in separate \
prefixes (nix, some SDK layouts). Overrides find_package.")

# ---------------------------------------------------------------------------
# OpenSSL: HEADERS ONLY
# ---------------------------------------------------------------------------
# find_package(OpenSSL) is used for exactly two things: locating an openssl/
# header tree, and reading the version so we can report it. OpenSSL::Crypto is
# deliberately never placed on a link line. "Compile against these headers, link
# nothing" is expressed as an INTERFACE target carrying only include directories
# -- with no INTERFACE_LINK_LIBRARIES it contributes nothing to the link.
if(AWSKMS_OPENSSL_INCLUDE_DIR)
  if(NOT EXISTS "${AWSKMS_OPENSSL_INCLUDE_DIR}/openssl/core_dispatch.h")
    message(FATAL_ERROR
      "AWSKMS_OPENSSL_INCLUDE_DIR=${AWSKMS_OPENSSL_INCLUDE_DIR} does not look \
like an OpenSSL header tree (no openssl/core_dispatch.h)")
  endif()
  set(_awskms_ssl_include "${AWSKMS_OPENSSL_INCLUDE_DIR}")
  set(_awskms_ssl_version "unknown (explicit include dir)")
else()
  find_package(OpenSSL 3.0 REQUIRED)
  set(_awskms_ssl_include "${OPENSSL_INCLUDE_DIR}")
  set(_awskms_ssl_version "${OPENSSL_VERSION}")
endif()

# The HEADER version, read from the headers themselves rather than from
# find_package, so it is known on both branches above -- the explicit-include-dir
# branch never runs find_package and so has no version to report. What matters
# for feature availability is what we COMPILE against, not what the host will
# turn out to have at dlopen time; those differ more often than one expects, and
# a distro on 3.0 headers under a node bundling 3.5 is the common case.
set(_awskms_ssl_header_version "0")
if(EXISTS "${_awskms_ssl_include}/openssl/opensslv.h")
  file(STRINGS "${_awskms_ssl_include}/openssl/opensslv.h" _v
    REGEX "^# *define +OPENSSL_VERSION_STR +\"[0-9]+\\.[0-9]+\\.[0-9]+\"")
  string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" _awskms_ssl_header_version "${_v}")
endif()

add_library(awskms_openssl_headers INTERFACE)
target_include_directories(awskms_openssl_headers SYSTEM INTERFACE
  "${_awskms_ssl_include}")

# ---------------------------------------------------------------------------
# ada -- WHATWG URL parsing
# ---------------------------------------------------------------------------
# Vendored (third_party/ada) rather than fetched, so a build on a server needs no
# network, at the latest upstream release. It does not track the host Node's ada:
# different Node lines ship different ada versions simultaneously, and re-parsing
# the already-normalised `new URL(x).href` is idempotent across conformant WHATWG
# parsers, so a fixed known version beats chasing the host's.
add_library(awskms_ada OBJECT third_party/ada/ada.cpp)
target_include_directories(awskms_ada PUBLIC third_party/ada)
set_target_properties(awskms_ada PROPERTIES
  # ada 4.x uses concepts and std::endian, so C++20 -- the same standard
  # Node.js builds it with.
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
  POSITION_INDEPENDENT_CODE ON)
# Not our code; do not fail the build on its warnings.
target_compile_options(awskms_ada PRIVATE -w)

# Everything except the KMS backend. The unit tests use this plus the stub
# backend: they exercise local parsing and never call KMS, so making them depend
# on the AWS SDK would only make them slow to build.
set(AWSKMS_CORE_SOURCES
  src/provider.c
  src/err.c
  src/uri.c
  src/keyspec.c
  src/spki.c
  src/key.c
  src/store.c
  src/keymgmt.c
  src/signature.c)

# The N-API entry point, so ONE artifact is both the OpenSSL provider and its own
# addon -- `import 'pkg/register'` then needs no second binary and no CLI flag.
# It costs 448 bytes and references exactly one napi symbol, WEAKLY, so the module
# still loads in hosts with no napi at all, such as the `openssl` CLI.
#
# In AWSKMS_SOURCES rather than AWSKMS_CORE_SOURCES on purpose: CORE is shared
# with awskms_unit, which is an ordinary EXECUTABLE and so is linked without
# -undefined dynamic_lookup. A weak-import symbol that no dylib provides is a
# hard link error there, not a zero -- so adding it to CORE breaks the unit build.
set(AWSKMS_SOURCES ${AWSKMS_CORE_SOURCES} src/napi.c)
if(AWSKMS_BACKEND STREQUAL "stub")
  list(APPEND AWSKMS_SOURCES src/kms_stub.c)
elseif(AWSKMS_BACKEND STREQUAL "aws")
  list(APPEND AWSKMS_SOURCES src/kms_aws.cc)
  include(cmake/ScrubLibcrypto.cmake)
  include(cmake/FetchAwsSdkKms.cmake)
  awskms_add_aws_sdk()
  # AFTER the SDK, deliberately. The subprojects are allowed to find the real
  # libcrypto -- they need it for their configure-time feature probes and their
  # headers -- and then we remove it from what they propagate to us. Trying to
  # neuter the targets beforehand is what the previous version did, and it could
  # not work: find_package(OpenSSL) creates a real OpenSSL::Crypto before any
  # `if(NOT TARGET ...)` guard of ours can claim the name. See ScrubLibcrypto.cmake.
  if(DEFINED _awskms_sdk_src)
    awskms_strip_libcrypto_interface("${_awskms_sdk_src}")
  else()
    # AWSKMS_AWS_SDK=SYSTEM: the targets are IMPORTED from find_package(AWSSDK)
    # and live in no directory of ours, so walk them by name instead.
    awskms_strip_libcrypto_from_targets(${AWSSDK_LINK_LIBRARIES})
  endif()
else()
  message(FATAL_ERROR "AWSKMS_BACKEND must be \"aws\" or \"stub\", got \"${AWSKMS_BACKEND}\"")
endif()

# ---------------------------------------------------------------------------
# The module
# ---------------------------------------------------------------------------
add_library(awskms MODULE ${AWSKMS_SOURCES} $<TARGET_OBJECTS:awskms_ada>)

target_link_libraries(awskms PRIVATE awskms_openssl_headers)
target_include_directories(awskms PRIVATE third_party/ada)

if(AWSKMS_BACKEND STREQUAL "aws")
  # Whole-archive is not wanted: only the referenced objects should come in.
  target_link_libraries(awskms PRIVATE aws-cpp-sdk-kms aws-cpp-sdk-core)
  set_target_properties(awskms PROPERTIES
    CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON
    CXX_VISIBILITY_PRESET hidden)
  awskms_assert_no_static_libcrypto(awskms)
endif()

target_compile_definitions(awskms PRIVATE
  AWSKMS_VERSION="${PROJECT_VERSION}"
  # We use no API deprecated in 3.0, so hold ourselves to it.
  OPENSSL_API_COMPAT=0x30000000L
  OPENSSL_NO_DEPRECATED)

target_compile_options(awskms PRIVATE
  -Wall -Wextra -Wno-unused-parameter -Wshadow -Wvla)

# A provider module is loaded by exact filename and has no consumers that link
# against it, so: no "lib" prefix, no soname, no version symlinks.
set_target_properties(awskms PROPERTIES
  PREFIX ""
  OUTPUT_NAME "awskms"
  C_STANDARD 11
  C_STANDARD_REQUIRED ON
  C_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
  POSITION_INDEPENDENT_CODE ON
  NO_SONAME ON)

if(APPLE)
  set_target_properties(awskms PROPERTIES SUFFIX ".dylib")
  set(AWSKMS_MODULE_BASENAME "awskms.dylib")
else()
  set_target_properties(awskms PROPERTIES SUFFIX ".so")
  set(AWSKMS_MODULE_BASENAME "awskms.so")
endif()

# ---------------------------------------------------------------------------
# Link and symbol hygiene
# ---------------------------------------------------------------------------
# Only OSSL_provider_init is exported. Note that -fvisibility=hidden alone is not
# enough for the entry point either way: it hides OSSL_provider_init too, and an
# export list cannot resurrect a symbol the compiler made local -- the module
# then loads as "not a provider". src/compat.h therefore marks it explicitly.
# Discard local symbols in Release. The module exports exactly ONE symbol, yet
# carried 18,616 of them -- a 1.5 MB __LINKEDIT, 44% of the file and larger than
# all the code in it. Nothing can call a local symbol from outside, so the only
# thing lost is function names in a crash backtrace, which is why it is scoped to
# Release: configure with -DCMAKE_BUILD_TYPE=RelWithDebInfo to keep them.
target_link_options(awskms PRIVATE "$<$<CONFIG:Release>:-Wl,-x>")

if(APPLE)
  target_link_options(awskms PRIVATE
    # Pairs with -ffunction-sections/-fdata-sections above; neither does anything
    # alone. Worth 1.19 MB here (4.65 -> 3.46) because only two KMS operations
    # are reachable from OSSL_provider_init, and the linker can now discard
    # per-function rather than per-object.
    "-Wl,-dead_strip"
    "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/src/awskms.exported_symbols")
  set_property(TARGET awskms APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/awskms.exported_symbols")
  if(NOT AWSKMS_LINK_LIBCRYPTO)
    # Two-level namespace records a source dylib per undefined symbol; this opts
    # the remainder into flat lookup so they bind to the host process image.
    target_link_options(awskms PRIVATE "-Wl,-undefined,dynamic_lookup")
  endif()
else()
  target_link_options(awskms PRIVATE
    # The GNU ld / lld spelling of -dead_strip; see the APPLE branch.
    "-Wl,--gc-sections"
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/awskms.map"
    # Bind our own references internally, and keep any static archive we later
    # link (the AWS SDK) from re-exporting its symbols.
    "-Wl,-Bsymbolic-functions"
    "-Wl,--exclude-libs,ALL"
    # OpenSSL dlclose()s providers; the AWS CRT leaves threads behind.
    "-Wl,-z,nodelete")
  set_property(TARGET awskms APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/awskms.map")
  # Never -z defs here: undefined symbols are the whole point.
endif()

if(AWSKMS_LINK_LIBCRYPTO)
  if(NOT TARGET OpenSSL::Crypto)
    message(FATAL_ERROR
      "AWSKMS_LINK_LIBCRYPTO=ON requires find_package(OpenSSL) to have found \
libraries; do not combine it with AWSKMS_OPENSSL_INCLUDE_DIR")
  endif()
  target_link_libraries(awskms PRIVATE OpenSSL::Crypto)
endif()

# ---------------------------------------------------------------------------
# Generated openssl.cnf
# ---------------------------------------------------------------------------
# Two copies: one pointing into the build tree (for running the tests before
# installing) and one pointing at the install location.
# Recorded next to the module so the test driver knows whether to start the HTTP
# KMS stub: the aws backend needs something to talk to, the stub backend does not.
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/awskms-backend" "${AWSKMS_BACKEND}\n")

# Whether the STUB backend can sign ML-DSA, which depends on the OpenSSL HEADERS
# this was built against rather than on the host it will run on. src/kms_stub.c
# needs EVP_PKEY_sign_message_init (a 3.5 linker symbol) for EXTERNAL_MU, and
# compiles that path out below 3.5.
#
# The distinction is easy to miss and cost a confusing CI failure: a node with a
# bundled OpenSSL 3.5 can generate ML-DSA keys perfectly well, so the tests'
# runtime probe says ML-DSA is available -- while the stub they are signing
# against was built on a distro shipping 3.0 headers and cannot sign it. The
# Whether the ML-DSA signing API exists AT ALL in the headers being compiled
# against. Separate from the marker below, which additionally asks whether the
# STUB is the backend; this one is a pure API-availability fact and is what the
# preprocessor must be told.
#
# It is passed as a compile definition rather than left to src/kms_stub.c
# rederiving it from OPENSSL_VERSION_NUMBER, because those two can DISAGREE. On
# an Intel macOS runner /usr/local/include is a default clang search path (on
# arm64 homebrew lives at /opt/homebrew, which is not), so cmake probed 3.0.21
# and reported it while the preprocessor resolved <openssl/evp.h> to a 3.5+ tree
# -- compiling in a call to EVP_PKEY_sign_message_init that the 3.0 libcrypto it
# then linked against does not export. awskms_unit failed to link on exactly one
# leg of the matrix. One source of truth: whatever cmake FOUND is what the code
# is told, so a mismatch becomes a link error against the same header set rather
# than a silent divergence.
if(_awskms_ssl_header_version VERSION_LESS 3.5)
  set(_awskms_mldsa_api 0)
else()
  set(_awskms_mldsa_api 1)
endif()
target_compile_definitions(awskms PRIVATE AWSKMS_MLDSA_API=${_awskms_mldsa_api})

# tests read this marker so they skip on the build-time fact rather than the
# runtime one. Only the stub is affected; the real backend never signs locally,
# and computes mu with SHAKE256, which is 3.0-era.
if(AWSKMS_BACKEND STREQUAL "stub" AND _awskms_ssl_header_version VERSION_LESS 3.5)
  set(_awskms_stub_mldsa "no")
  message(WARNING
    "OpenSSL headers are ${_awskms_ssl_header_version}; the stub backend cannot "
    "sign ML-DSA below 3.5, so those tests will be skipped. This says nothing "
    "about the provider itself -- only the test fake signs locally, and the real "
    "backend computes mu with SHAKE256, which is 3.0-era. Build against 3.5+ "
    "headers to exercise ML-DSA end to end.")
else()
  set(_awskms_stub_mldsa "yes")
endif()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/awskms-stub-mldsa" "${_awskms_stub_mldsa}\n")

set(AWSKMS_MODULE_FILE "$<TARGET_FILE:awskms>")
set(AWSKMS_CNF_FILE "${CMAKE_CURRENT_BINARY_DIR}/awskms.cnf")
configure_file(cmake/awskms.cnf.in "${CMAKE_CURRENT_BINARY_DIR}/awskms.cnf.tmp" @ONLY)
file(GENERATE OUTPUT "${AWSKMS_CNF_FILE}"
  INPUT "${CMAKE_CURRENT_BINARY_DIR}/awskms.cnf.tmp")

set(AWSKMS_INSTALL_MODULE_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/ossl-modules")
set(AWSKMS_INSTALL_CNF_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/awskms")
set(AWSKMS_MODULE_FILE "${AWSKMS_INSTALL_MODULE_DIR}/${AWSKMS_MODULE_BASENAME}")
set(AWSKMS_CNF_FILE "${AWSKMS_INSTALL_CNF_DIR}/awskms.cnf")
configure_file(cmake/awskms.cnf.in
  "${CMAKE_CURRENT_BINARY_DIR}/awskms.installed.cnf" @ONLY)

# A third copy, for a RELOCATABLE archive: byte-identical on every platform,
# because the module path is resolved from the environment at load rather than
# baked in. The other two copies cannot serve: both hardcode an absolute path,
# which is right for a build tree and for `cmake --install`, and impossible for a
# tarball the user unpacks wherever they like.
#
# `$ENV::NAME` is expanded by OpenSSL's config parser, and passes through
# configure_file untouched because CMake's own syntax is ${VAR} / $ENV{VAR}.
# Measured in all three states:
#   set correctly   the provider loads
#   UNSET           a loud fatal at OpenSSL init -- node refuses to start with
#                   "variable has no value". The only misconfiguration in this
#                   area that is not silent.
#   set but wrong   silent no-load, as any bad path is; scripts/awskms-doctor.mjs
#                   catches it and prints the expansion it resolved to.
#
# Not installed: this is a release-archive artifact, not something `cmake
# --install` should scatter into /usr/local/etc.
set(AWSKMS_MODULE_FILE "$ENV::AWSKMS_MODULE")
set(AWSKMS_CNF_FILE "/path/to/awskms.cnf")
configure_file(cmake/awskms.cnf.in
  "${CMAKE_CURRENT_BINARY_DIR}/awskms.relocatable.cnf" @ONLY)

install(TARGETS awskms LIBRARY DESTINATION "${AWSKMS_INSTALL_MODULE_DIR}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/awskms.installed.cnf"
  DESTINATION "${AWSKMS_INSTALL_CNF_DIR}" RENAME awskms.cnf)

# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------
# These link libcrypto normally -- they are ordinary programs, not a provider
# module, so the host-symbol-resolution trick does not apply. That means they
# need find_package(OpenSSL) to have located libraries, which it will not have if
# only a header directory was given.
if(BUILD_TESTING AND TARGET OpenSSL::Crypto)
  add_executable(awskms_unit
    test/unit_main.c
    test/unit_uri.c
    test/unit_spki.c
    test/unit_mu.c
    ${AWSKMS_CORE_SOURCES}
    src/kms_stub.c
    $<TARGET_OBJECTS:awskms_ada>)
  target_include_directories(awskms_unit PRIVATE src third_party/ada)
  target_compile_definitions(awskms_unit PRIVATE AWSKMS_MLDSA_API=${_awskms_mldsa_api})
  target_link_libraries(awskms_unit PRIVATE OpenSSL::Crypto)
  target_compile_definitions(awskms_unit PRIVATE
    AWSKMS_VERSION="${PROJECT_VERSION}"
    OPENSSL_API_COMPAT=0x30000000L
    OPENSSL_NO_DEPRECATED)
  target_compile_options(awskms_unit PRIVATE
    -Wall -Wextra -Wno-unused-parameter -Wshadow -Wvla)
  set_target_properties(awskms_unit PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
  add_test(NAME unit COMMAND awskms_unit)
elseif(BUILD_TESTING)
  message(STATUS "  unit tests      : skipped (no OpenSSL libraries located)")
endif()

message(STATUS "awskms ${PROJECT_VERSION}")
message(STATUS "  OpenSSL headers : ${_awskms_ssl_include} (${_awskms_ssl_version})")
message(STATUS "  link libcrypto  : ${AWSKMS_LINK_LIBCRYPTO}")
message(STATUS "  module          : ${AWSKMS_MODULE_BASENAME}")
message(STATUS "  kms backend     : ${AWSKMS_BACKEND}")
if(AWSKMS_BACKEND STREQUAL "stub")
  message(WARNING
    "AWSKMS_BACKEND=stub builds a module that talks to a local fake, not to AWS. "
    "Use -DAWSKMS_BACKEND=aws for anything real.")
endif()
