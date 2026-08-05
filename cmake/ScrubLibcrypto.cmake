# Keeps libcrypto off the module's link line while still letting the AWS SDK
# compile against its headers -- and, on Linux, probe it correctly.
#
# THE PROBLEM THIS SOLVES, which is not hypothetical -- both halves were observed:
#
#   macOS. Where the platform ships a static libcrypto.a (Homebrew's openssl@3
#   does), CMake resolves OpenSSL::Crypto to the archive, and because our module
#   links the SDK statically the entire libcrypto gets swallowed into
#   awskms.dylib: 1483 OpenSSL symbols defined *inside* the module, nothing in
#   `otool -L`, and zero undefined OpenSSL symbols. Completely invisible.
#
#   Linux. aws-c-cal's non-Apple branch does find_package(OpenSSL REQUIRED) and
#   target_link_libraries(... PUBLIC OpenSSL::Crypto), so the absolute path
#   /usr/lib/<triple>/libcrypto.so propagates transitively onto our link line and
#   lands in DT_NEEDED. s2n does the same via its own ${LINK_LIB}.
#
# Either way the module ends up with a SECOND libcrypto: a different
# OSSL_LIB_CTX, a different algorithm store and -- fatally -- a different ERR
# queue, so every error we raise is invisible to the host and d2i_PUBKEY_ex()
# consults a library with no providers configured.
#
# WHAT DID NOT WORK, so nobody tries it again. The previous approach pre-created
# `crypto` / `OpenSSL::Crypto` / `AWS::crypto` as header-only INTERFACE targets,
# relying on every finder's `if(NOT TARGET ...)` guard so that "defining them
# first wins". We were never first: find_package(OpenSSL) creates a real
# OpenSSL::Crypto before the guards run, both at CMakeLists.txt's own call and
# inside the scrub function itself. Worse, the half that DID take effect made
# things wrong in the other direction -- `crypto` resolved to our stub, so s2n's
# feature_probe(... LINK_LIBRARIES ${LINK_LIB}) could not link and all 19
# S2N_LIBCRYPTO_SUPPORTS_* probes evaluated FALSE against a libcrypto that
# supports them. Reordering cannot fix both: one name needs to be real and the
# other needs to be fake.
#
# WHAT WE DO INSTEAD. Let every subproject find the REAL libcrypto, so their
# configure-time probes are accurate and they compile against the right headers.
# Then, after add_subdirectory(), strip libcrypto out of the
# INTERFACE_LINK_LIBRARIES of the SDK's targets.
#
# That works because the SDK is built with BUILD_SHARED_LIBS=OFF: every one of
# those targets is a STATIC archive, and a static archive records no
# dependencies. Its own LINK_LIBRARIES is left untouched -- so it still compiles
# with the right include directories -- while INTERFACE_LINK_LIBRARIES is what
# propagates to consumers, and we are the consumer. Stopping it at our own target
# needs no cooperation from upstream and no fight over target names.

# Collects every buildsystem target at or below `dir`.
function(_awskms_collect_targets dir out)
  get_property(_subdirs DIRECTORY "${dir}" PROPERTY SUBDIRECTORIES)
  get_property(_here DIRECTORY "${dir}" PROPERTY BUILDSYSTEM_TARGETS)
  set(_all ${_here})
  foreach(_sub IN LISTS _subdirs)
    _awskms_collect_targets("${_sub}" _child)
    list(APPEND _all ${_child})
  endforeach()
  set(${out} "${_all}" PARENT_SCOPE)
endfunction()

# Every spelling the SDK, the CRT and s2n use to name libcrypto/libssl.
set(_AWSKMS_LIBCRYPTO_NAMES
  crypto ssl
  OpenSSL::Crypto OpenSSL::SSL
  AWS::crypto AWS::ssl
  LibCrypto::Crypto LibCrypto::SSL)

# Removes libcrypto from the *interface* of every target under `dir`, so it does
# not reach anything that links them. Call AFTER the SDK's add_subdirectory().
function(awskms_strip_libcrypto_interface dir)
  _awskms_collect_targets("${dir}" _targets)
  awskms_strip_libcrypto_from_targets(${_targets})
endfunction()

# The same, for targets named explicitly -- used for AWSKMS_AWS_SDK=SYSTEM, where
# the targets are IMPORTED and belong to no directory of ours.
function(awskms_strip_libcrypto_from_targets)
  set(_targets ${ARGN})

  set(_touched "")
  foreach(_t IN LISTS _targets)
    if(NOT TARGET ${_t})
      continue()
    endif()
    get_target_property(_type ${_t} TYPE)
    if(_type STREQUAL "UTILITY")
      continue()
    endif()
    get_target_property(_libs ${_t} INTERFACE_LINK_LIBRARIES)
    if(NOT _libs)
      continue()
    endif()

    set(_kept "")
    set(_changed FALSE)
    foreach(_lib IN LISTS _libs)
      # Match the bare/namespaced target names, the same names wrapped in a
      # $<LINK_ONLY:...>, and absolute paths to the library file itself.
      set(_bare "${_lib}")
      if(_bare MATCHES "^\\$<LINK_ONLY:(.+)>$")
        set(_bare "${CMAKE_MATCH_1}")
      endif()
      if(_bare IN_LIST _AWSKMS_LIBCRYPTO_NAMES
         OR _bare MATCHES "/lib(crypto|ssl)\\.(so|dylib|a)(\\.[0-9.]+)?$"
         OR _bare STREQUAL "-lcrypto" OR _bare STREQUAL "-lssl")
        set(_changed TRUE)
      else()
        list(APPEND _kept "${_lib}")
      endif()
    endforeach()

    if(_changed)
      set_target_properties(${_t} PROPERTIES INTERFACE_LINK_LIBRARIES "${_kept}")
      list(APPEND _touched ${_t})
    endif()
  endforeach()

  if(_touched)
    list(JOIN _touched " " _joined)
    message(STATUS "  libcrypto       : stripped from the interface of ${_joined}")
  else()
    # Not fatal: on macOS aws-c-cal takes the Security.framework branch and may
    # legitimately reference no libcrypto at all. The post-build assertions are
    # what actually guarantee the outcome.
    message(STATUS "  libcrypto       : no target interface referenced it")
  endif()
endfunction()

# Asserts, after the fact, that no second libcrypto ended up in the module --
# whether swallowed statically (symbols defined inside) or recorded dynamically
# (a DT_NEEDED / LC_LOAD_DYLIB entry). Those are different mechanisms with the
# same fatal outcome, and an earlier version of this check only covered the
# first: it passed on a Linux build that had libcrypto.so.3 in DT_NEEDED.
# Cheap, and the failure mode is silent, so it runs on every build.
function(awskms_assert_no_static_libcrypto target)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND}
      -DAWSKMS_MODULE=$<TARGET_FILE:${target}>
      -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/AssertNoStaticLibcrypto.cmake"
    VERBATIM
    COMMENT "checking that no second libcrypto was linked into ${target}")
endfunction()
