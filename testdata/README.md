# Test data

`draft-19-testvectors.json` holds the test vectors of
[draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/),
Appendix E. The file is unchanged from `src/testvectors.json` at the
`draft-ietf-lamps-pq-composite-sigs-19` tag of
[lamps-wg/draft-composite-sigs](https://github.com/lamps-wg/draft-composite-sigs).

SHA-256: `a60f697f9fd94c3cd5e4501a40c4396d9a9ffc7cf0f8a1ddd87dedbb46a7abf0`

Every private key in the file is published test data. None of them protects anything.

The vectors are Code Components of an IETF document and are used under the Revised BSD License in
[LICENSE-draft-19-testvectors](LICENSE-draft-19-testvectors). The rest of the repository is
licensed under Apache-2.0.

`TestVectors` in the root package checks every supported algorithm against this file: the raw and
PKCS #8 key encodings byte for byte, both published signatures, a fresh signature from the loaded
private key and the self-signed certificate. `TestVectorsCoverEverySupportedAlgorithm` fails when an
algorithm has no vector. The vectors for Ed448, the Brainpool curves and the ML-DSA components on
their own are present in the file and skipped, because the library does not implement them.

Fuzzing saves failing inputs under `testdata/fuzz` in the package directory. Commit such an input
together with the fix, so the regression test keeps it.
