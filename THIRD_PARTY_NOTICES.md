# Third-party notices

The distributed native provider incorporates the components recorded in
[`third_party/components.json`](third_party/components.json). That manifest is
the authoritative inventory used by packaging checks.

AWS SDK for C++ and AWS Common Runtime components are distributed under the
Apache License 2.0. Their upstream attribution notices are reproduced under
`third_party/licenses/`.

The linked dependency graph also incorporates the following components:

- [cJSON 1.7.19](https://github.com/DaveGamble/cJSON/tree/v1.7.19), through
  both AWS SDK for C++ and `aws-c-common`, under the MIT License;
- [tinyxml2 11.0.0](https://github.com/leethomason/tinyxml2/tree/11.0.0),
  through AWS SDK for C++, under the zlib License;
- [libcbor 0.13.0](https://github.com/PJK/libcbor/tree/v0.13.0), through
  `aws-c-common`, under the MIT License; and
- [xxHash 0.8.3](https://github.com/Cyan4973/xxHash/tree/v0.8.3), through
  `aws-checksums`, under the BSD 2-Clause License.

At configure time, this project modifies these Apache-licensed upstream files:

- `s2n-tls/crypto/s2n_kdf.h` normalizes valid empty KDF parameters for OpenSSL;
- `s2n-tls/crypto/s2n_certificate.c` and
  `s2n-tls/tls/s2n_x509_validator.c` replace removed read-only OpenSSL API calls;
  and
- AWS SDK for C++ `generated/src/aws-cpp-sdk-kms/source/model/KeySpec.cpp` and
  `DataKeyPairSpec.cpp` remove mapper constructs for a KeySpec this provider
  does not support.

Those files therefore differ from their upstream versions. The source
repository records the exact, self-invalidating transformations in
`scripts/patch-*.sh`.

The Ada URL parser is distributed under the MIT License.

Darwin artifacts incorporate declarations from Apple's CommonCrypto SPI header,
mirrored by the pinned `aws-c-cal` dependency. Its copyright notice and the
Apple Public Source License 2.0 are reproduced under `third_party/licenses/`,
with a link to the exact incorporated source.

Linux artifacts statically link `libstdc++` and `libgcc`. Their GPLv3 license and
the GCC Runtime Library Exception 3.1 are reproduced under
`third_party/licenses/`. The exception permits eligible compiled target code to
be conveyed under terms of the distributor's choice; it does not change this
project's MIT license.

Every binary archive and npm satellite must contain this notice, a manifest
filtered to its target, and every license or notice referenced by that manifest.
