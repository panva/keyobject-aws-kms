#!/usr/bin/env python3
"""Exercise the N-API registrar against an exact dynamically loaded libcrypto."""

import ctypes
import glob
import os
import sys


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


if len(sys.argv) != 4:
    fail("usage: ci-check-register.py <module> <openssl-prefix> <supported|unsupported>")

module, prefix, expectation = sys.argv[1:]
if expectation not in {"supported", "unsupported"}:
    fail("expectation must be supported or unsupported")

candidates = sorted(
    glob.glob(os.path.join(prefix, "lib", "libcrypto.so*"))
    + glob.glob(os.path.join(prefix, "lib", "libcrypto*.dylib"))
)
candidates = [path for path in candidates if os.path.isfile(path) and ".a" not in path]
if not candidates:
    fail(f"no shared libcrypto found under {prefix}")

crypto = ctypes.CDLL(candidates[0], mode=ctypes.RTLD_GLOBAL)
provider = ctypes.CDLL(os.path.abspath(module), mode=ctypes.RTLD_GLOBAL)

crypto.EVP_default_properties_enable_fips.argtypes = [ctypes.c_void_p, ctypes.c_int]
crypto.EVP_default_properties_enable_fips.restype = ctypes.c_int
crypto.EVP_set_default_properties.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
crypto.EVP_set_default_properties.restype = ctypes.c_int
crypto.EVP_default_properties_is_fips_enabled.argtypes = [ctypes.c_void_p]
crypto.EVP_default_properties_is_fips_enabled.restype = ctypes.c_int
crypto.OSSL_PROVIDER_available.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
crypto.OSSL_PROVIDER_available.restype = ctypes.c_int

register = provider.napi_register_module_v1
register.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
register.restype = ctypes.c_void_p

if crypto.EVP_set_default_properties(None, b"?application.test_policy=yes") != 1:
    fail("could not set an arbitrary default property before registration")
if crypto.EVP_default_properties_enable_fips(None, 1) != 1:
    fail("could not enable the fips=yes default property before registration")

register(None, None)
register(None, None)

if crypto.EVP_default_properties_is_fips_enabled(None) != 1:
    fail("registration changed the process fips=yes property")

available = crypto.OSSL_PROVIDER_available(None, b"aws-kms") == 1
if expectation == "supported" and not available:
    fail("registration did not activate aws-kms")
if expectation == "unsupported" and available:
    fail("registration unexpectedly activated aws-kms without the property getter")

if expectation == "supported":
    getter = crypto.EVP_get1_default_properties
    getter.argtypes = [ctypes.c_void_p]
    getter.restype = ctypes.c_char_p
    properties = getter(None)
    if not properties or b"fips=yes" not in properties:
        fail("the preserved property query lost fips=yes")
    if b"?application.test_policy=yes" not in properties:
        fail("registration dropped an unrelated default property")
    if b"?keyobject.aws_kms!=yes" not in properties:
        fail("the registrar preference was not appended")

print(f"ok: registration {expectation}; fips=yes preserved; provider available={available}")
