# Post-build guard: fails if the module defines OpenSSL symbols itself.
#
# A second libcrypto linked statically into the module is invisible to `otool -L`
# and `readelf -d`, produces no warning, and breaks the provider subtly -- its own
# error queue means every error it raises is invisible to the host. So it is
# checked on every build, not just in CI.
#
# Run via: cmake -DAWSKMS_MODULE=<path> -P AssertNoStaticLibcrypto.cmake

if(NOT DEFINED AWSKMS_MODULE OR NOT EXISTS "${AWSKMS_MODULE}")
  message(FATAL_ERROR "AWSKMS_MODULE must point at a built module")
endif()

find_program(NM_EXECUTABLE nm)
if(NOT NM_EXECUTABLE)
  message(STATUS "nm not found; skipping the static-libcrypto check")
  return()
endif()

if(APPLE)
  execute_process(COMMAND ${NM_EXECUTABLE} "${AWSKMS_MODULE}"
    OUTPUT_VARIABLE _syms ERROR_QUIET)
else()
  execute_process(COMMAND ${NM_EXECUTABLE} --defined-only "${AWSKMS_MODULE}"
    OUTPUT_VARIABLE _syms ERROR_QUIET)
endif()

# Locally defined text symbols only: lower-case 't' is a local definition, 'T' a
# global one. Either would mean a bundled libcrypto.
#
# EXACT names, anchored to end-of-line, rather than an EVP_* prefix. A prefix
# match also hits things that merely look like OpenSSL: `-Oz` leaves
# std::unique_ptr deleter thunks such as EVP_PKEY_free_pointer out of line, which
# `-O3` may inline, and neither is an OpenSSL symbol (libcrypto exports
# EVP_PKEY_free, not EVP_PKEY_free_pointer).
#
# Precision costs nothing here: a genuinely bundled libcrypto defines all of the
# names below, so matching any one of them is enough.
set(_openssl_canaries
  OPENSSL_init_crypto
  EVP_PKEY_free
  EVP_PKEY_CTX_new
  EVP_DigestInit_ex
  EVP_MD_fetch
  EVP_DigestSignInit
  d2i_PUBKEY
  CRYPTO_malloc
  ERR_set_mark)
string(REPLACE ";" "|" _canary_re "${_openssl_canaries}")
string(REGEX MATCHALL "[ \t][tT][ \t]_?(${_canary_re})[\r\n]" _hits "${_syms}")

list(LENGTH _hits _count)
if(_count GREATER 0)
  list(SUBLIST _hits 0 5 _sample)
  string(REPLACE ";" "\n    " _sample "${_sample}")
  message(FATAL_ERROR
    "${AWSKMS_MODULE} defines ${_count} OpenSSL symbols of its own.\n"
    "A second libcrypto has been linked into the module, which gives it a "
    "separate OSSL_LIB_CTX, algorithm store and error queue -- every error it "
    "raises would be invisible to the host process.\n"
    "Samples:\n    ${_sample}\n"
    "See cmake/ScrubLibcrypto.cmake: libcrypto must be stripped from the AWS "
    "SDK targets' INTERFACE_LINK_LIBRARIES.")
endif()

# --- the other half: a DYNAMIC dependency -----------------------------------
#
# The check above only sees a libcrypto swallowed *statically*, as symbols
# defined inside the module. A dynamically linked libcrypto instead appears in
# DT_NEEDED or LC_LOAD_DYLIB. Both mechanisms have the same fatal outcome, so
# both are checked.
if(APPLE)
  find_program(_dumper otool)
  set(_dump_args -L "${AWSKMS_MODULE}")
else()
  find_program(_dumper readelf)
  set(_dump_args -d "${AWSKMS_MODULE}")
endif()

if(_dumper)
  execute_process(COMMAND ${_dumper} ${_dump_args} OUTPUT_VARIABLE _deps ERROR_QUIET)
  # Match the library file name, not a path component: a build directory can
  # legitimately include text such as "libssl" in its name.
  # Covers both ELF's libcrypto.so.3 and Darwin's libcrypto.3.dylib spelling.
  string(REGEX MATCHALL
    "lib(crypto|ssl)(\\.[0-9]+)*\\.(so|dylib)(\\.[0-9]+)*"
    _dyn "${_deps}")
  if(_dyn)
    list(REMOVE_DUPLICATES _dyn)
    string(REPLACE ";" "\n    " _dyn_s "${_dyn}")
    message(FATAL_ERROR
      "${AWSKMS_MODULE} records a dynamic dependency on libcrypto/libssl:\n"
      "    ${_dyn_s}\n"
      "The module must resolve every OpenSSL symbol from the host process at "
      "dlopen() time. A libcrypto of its own gives it a separate OSSL_LIB_CTX, "
      "algorithm store and error queue -- every error it raises would be "
      "invisible to the host process.\n"
      "This normally means a subproject leaked libcrypto through its "
      "INTERFACE_LINK_LIBRARIES; see awskms_strip_libcrypto_interface() in "
      "cmake/ScrubLibcrypto.cmake.")
  endif()
else()
  message(STATUS "no otool/readelf; skipping the dynamic-libcrypto check")
endif()
