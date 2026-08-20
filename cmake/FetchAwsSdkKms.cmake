# Obtains a KMS-only AWS SDK for C++ and adds it to the build.
#
# Why not FetchContent: the SDK repository is ~1.9 GB checked out in full,
# almost all of it service clients we do not use. A blobless partial clone with a
# sparse checkout, skipping the other 400-odd services and aws-lc, brings that to
# ~200 MB and about two minutes; the build itself is ~10 seconds. FetchContent
# cannot express either the sparse checkout or the selective submodule init.
#
# Prefer a packaged SDK when one is present: -DAWSKMS_AWS_SDK=SYSTEM uses
# find_package(AWSSDK COMPONENTS kms).
#
# Two configure options are load-bearing rather than cosmetic:
#
#   USE_CRT_HTTP_CLIENT=ON   replaces libcurl with aws-c-http. On a stock
#       nodejs.org host, libcurl would drag libssl/libcrypto in behind it, giving
#       the process a second, different OpenSSL whose internal calls resolve
#       global-scope-first against node's statically bundled one. Opaque structs
#       like EVP_MD_CTX do not have a stable layout across 3.x, so that is
#       silent corruption rather than a link error.
#
#   USE_OPENSSL=ON           stops aws-crt-cpp building crt/aws-lc, which is a
#       second OpenSSL-API-compatible library whose symbols collide with the
#       host's by name. No linker flag makes that safe: -fvisibility=hidden does
#       not hide symbols inside a static archive, and an export list fixes the
#       export table but not intra-module binding, which was decided at
#       static-link time. s2n and aws-c-cal then compile against OpenSSL headers
#       and their libcrypto references stay undefined, binding to the same
#       OpenSSL this provider uses -- exactly one per process.

set(AWSKMS_AWS_SDK_TAG "1.11.855" CACHE STRING
  "aws-sdk-cpp tag to fetch when AWSKMS_AWS_SDK=FETCH")

function(_awskms_git)
  execute_process(COMMAND ${GIT_EXECUTABLE} ${ARGN}
    WORKING_DIRECTORY "${_awskms_sdk_src}"
    RESULT_VARIABLE _rc
    OUTPUT_VARIABLE _out
    ERROR_VARIABLE _err)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "git ${ARGN} failed:\n${_out}\n${_err}")
  endif()
endfunction()

function(awskms_add_aws_sdk)
  if(AWSKMS_AWS_SDK STREQUAL "SYSTEM")
    find_package(AWSSDK REQUIRED COMPONENTS kms)
    message(STATUS "  aws sdk         : system (${AWSSDK_VERSION})")
    return()
  endif()

  find_package(Git REQUIRED)
  set(_awskms_sdk_src "${CMAKE_BINARY_DIR}/_deps/aws-sdk-cpp" PARENT_SCOPE)
  set(_awskms_sdk_src "${CMAKE_BINARY_DIR}/_deps/aws-sdk-cpp")

  if(NOT EXISTS "${_awskms_sdk_src}/.awskms-fetched-${AWSKMS_AWS_SDK_TAG}")
    message(STATUS
      "fetching aws-sdk-cpp ${AWSKMS_AWS_SDK_TAG} (kms only; a few minutes the "
      "first time)")
    file(MAKE_DIRECTORY "${_awskms_sdk_src}")
    _awskms_git(init -q .)
    execute_process(COMMAND ${GIT_EXECUTABLE} remote add origin
      https://github.com/aws/aws-sdk-cpp.git
      WORKING_DIRECTORY "${_awskms_sdk_src}" ERROR_QUIET)
    _awskms_git(config core.sparseCheckout true)
    _awskms_git(config core.sparseCheckoutCone false)
    # Everything except the service clients we do not build, and aws-lc.
    file(WRITE "${_awskms_sdk_src}/.git/info/sparse-checkout"
      "/*\n"
      "!/generated/src/*\n"
      "/generated/src/aws-cpp-sdk-kms/\n"
      "!/tools/\n"
      "!/docs/\n"
      "!/crt/aws-crt-cpp/crt/aws-lc/\n")
    _awskms_git(fetch --depth 1 --filter=blob:none origin
      "refs/tags/${AWSKMS_AWS_SDK_TAG}")
    _awskms_git(checkout -q FETCH_HEAD)
    _awskms_git(submodule update --init --depth 1 --filter=blob:none
      crt/aws-crt-cpp)

    # aws-lc is excluded: USE_OPENSSL=ON means it is never built, and it is 318 MB.
    execute_process(
      COMMAND ${GIT_EXECUTABLE} config --file .gitmodules --get-regexp path
      WORKING_DIRECTORY "${_awskms_sdk_src}/crt/aws-crt-cpp"
      OUTPUT_VARIABLE _crt_mods OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCHALL "crt/[a-z0-9-]+" _crt_mods "${_crt_mods}")
    list(REMOVE_ITEM _crt_mods "crt/aws-lc")
    execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --depth 1
      --filter=blob:none ${_crt_mods}
      WORKING_DIRECTORY "${_awskms_sdk_src}/crt/aws-crt-cpp"
      RESULT_VARIABLE _rc)
    if(NOT _rc EQUAL 0)
      message(FATAL_ERROR "failed to fetch aws-crt-cpp submodules")
    endif()

    file(TOUCH "${_awskms_sdk_src}/.awskms-fetched-${AWSKMS_AWS_SDK_TAG}")
  endif()

  # The SDK reads these from the cache, so they must be set before it is added.
  set(BUILD_ONLY "kms" CACHE STRING "" FORCE)
  set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(AUTORUN_UNIT_TESTS OFF CACHE BOOL "" FORCE)
  set(MINIMIZE_SIZE ON CACHE BOOL "" FORCE)
  set(USE_CRT_HTTP_CLIENT ON CACHE BOOL "" FORCE)
  set(USE_OPENSSL ON CACHE BOOL "" FORCE)
  # OpenSSL KDF setters reject a NULL data pointer even when an input OSSL_PARAM
  # has length zero. s2n represents valid empty blobs that way, including the
  # unused salt in TLS 1.3 HKDF-Expand. Canonicalize empty KDF inputs before
  # compiling the vendored source; the patch validates the exact source shape.
  execute_process(
    COMMAND "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../scripts/patch-s2n-empty-kdf.sh"
            "${_awskms_sdk_src}"
    RESULT_VARIABLE _awskms_s2n_empty_kdf_patch_rc
    OUTPUT_VARIABLE _awskms_s2n_empty_kdf_patch_out
    ERROR_VARIABLE  _awskms_s2n_empty_kdf_patch_out)
  if(NOT _awskms_s2n_empty_kdf_patch_rc EQUAL 0)
    message(FATAL_ERROR "patching vendored s2n empty KDF parameters failed (rc=${_awskms_s2n_empty_kdf_patch_rc}):\n${_awskms_s2n_empty_kdf_patch_out}")
  endif()
  message(STATUS "${_awskms_s2n_empty_kdf_patch_out}")

  # The pinned s2n sources call ASN1_STRING_data(), which OpenSSL 4.0 removes.
  # Apply the compatibility patch after fetching and before add_subdirectory so
  # the patched sources are compiled. The script validates the exact call-site
  # count and requires review when upstream changes them.
  execute_process(
    # CMAKE_CURRENT_FUNCTION_LIST_DIR, not CMAKE_CURRENT_LIST_DIR: inside a
    # function body the latter resolves to the caller's list file, not this one.
    COMMAND "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../scripts/patch-s2n-openssl4.sh"
            "${_awskms_sdk_src}"
    RESULT_VARIABLE _awskms_s2n_patch_rc
    OUTPUT_VARIABLE _awskms_s2n_patch_out
    ERROR_VARIABLE  _awskms_s2n_patch_out)
  if(NOT _awskms_s2n_patch_rc EQUAL 0)
    message(FATAL_ERROR "patching vendored s2n for OpenSSL 4.0 failed (rc=${_awskms_s2n_patch_rc}):\n${_awskms_s2n_patch_out}")
  endif()
  message(STATUS "${_awskms_s2n_patch_out}")

  # Generated KMS mappers include an out-of-scope curve even when no caller asks
  # for it, which embeds that service identifier in the provider module. Unity
  # compilation brings both affected mappers into the linked object, so restrict
  # both before compilation. The script validates the exact
  # generated shape and fails configuration when the pinned SDK changes.
  execute_process(
    COMMAND "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../scripts/patch-aws-sdk-keyspec.sh"
            "${_awskms_sdk_src}"
    RESULT_VARIABLE _awskms_keyspec_patch_rc
    OUTPUT_VARIABLE _awskms_keyspec_patch_out
    ERROR_VARIABLE  _awskms_keyspec_patch_out)
  if(NOT _awskms_keyspec_patch_rc EQUAL 0)
    message(FATAL_ERROR "restricting the generated AWS KMS KeySpec mappers failed (rc=${_awskms_keyspec_patch_rc}):\n${_awskms_keyspec_patch_out}")
  endif()
  message(STATUS "${_awskms_keyspec_patch_out}")

  # s2n runs its libcrypto feature probes as try_compile during add_subdirectory.
  # If they cannot link a real libcrypto every S2N_LIBCRYPTO_SUPPORTS_* fails
  # CLOSED and s2n is built as though libcrypto supports nothing.
  # This option (s2n#5579, merged upstream, defaults OFF) turns that into a
  # configure-time FATAL_ERROR. It gates on a dedicated S2N_LIBCRYPTO_SANITY_PROBE,
  # so it fires only when the probes cannot link AT ALL -- a feature that is
  # legitimately absent, such as the AWS-LC-only HKDF_*, still just reports FALSE.
  set(S2N_ENFORCE_PROPER_LIBCRYPTO_FEATURE_PROBE ON CACHE BOOL "" FORCE)
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE BOOL "" FORCE)

  add_subdirectory("${_awskms_sdk_src}" "${CMAKE_BINARY_DIR}/_deps/aws-sdk-cpp-build"
    EXCLUDE_FROM_ALL SYSTEM)

  # Globals.cpp is the sole SDK source whose remapped __FILE__ would otherwise
  # retain the build-tree `_deps/.../src/...` layout. Use a target-local, more
  # specific mapping so diagnostics retain a useful basename without exposing a
  # private build path. The general source/binary mappings remain in force for
  # every other SDK and provider target.
  if(AWSKMS_HAVE_FILE_PREFIX_MAP)
    target_compile_options(aws-cpp-sdk-core PRIVATE
      "-ffile-prefix-map=${_awskms_sdk_src}/src/aws-cpp-sdk-core/source=aws-sdk-core")
  endif()
  message(STATUS "  aws sdk         : fetched ${AWSKMS_AWS_SDK_TAG} (kms only)")
endfunction()
