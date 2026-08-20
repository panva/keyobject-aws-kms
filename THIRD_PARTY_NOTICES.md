# Third-party notices

The distributed native provider incorporates the components recorded in
[`third_party/components.json`](third_party/components.json). That manifest is
the authoritative inventory used by packaging checks.

AWS SDK for C++ and AWS Common Runtime components are distributed under the
Apache License 2.0. Their upstream attribution notices, including the additional
AWS SDK third-party terms, are reproduced under `third_party/licenses/`.

The Ada URL parser is distributed under the MIT License.

Linux artifacts statically link `libstdc++` and `libgcc`. Their GPLv3 license and
the GCC Runtime Library Exception 3.1 are reproduced under
`third_party/licenses/`. The exception permits eligible compiled target code to
be conveyed under terms of the distributor's choice; it does not change this
project's MIT license.

Every binary archive and npm satellite must contain this notice, the component
manifest, and the complete `third_party/licenses/` directory.
