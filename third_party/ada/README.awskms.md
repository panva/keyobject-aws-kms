ada 4.0.0, vendored from the amalgamated single-file release.
Upstream: https://github.com/ada-url/ada
Licence: MIT (see LICENSE-MIT)

Vendored rather than fetched so builds are hermetic and work offline, and
tracked at the latest upstream release.

The version above is not just a note: `scripts/update-vendored.sh verify` checks
these files byte-for-byte against the release named in
`third_party/vendored.manifest`, and checks that this line agrees with it. So a
version recorded here that was never actually applied fails CI rather than
sitting in the tree looking applied. Use `update-vendored.sh update ada` to move
it; editing either record by hand only breaks the check.

It deliberately does NOT track whatever ada the host Node ships. That was the
original rationale and it does not hold: supported Node lines carry different ada
versions at the same time -- as of 2026-08-05, Node 26.7.0 and main ship 4.0.0,
Node 24 ships 3.4.4 and Node 22 ships 2.9.2 -- so no single vendored version can
match every host, and chasing one would make URI parsing depend on which Node
loaded the module.

Parity is not needed anyway. Node hands the loader `new URL(x).href`, which is
already normalised, and re-parsing a normalised href is idempotent across
conformant WHATWG parsers. A fixed, known version is worth more than a moving
approximation of the host's.
