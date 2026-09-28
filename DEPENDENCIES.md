# Dependencies

The implementation is original and uses only the Go standard library. Third-party material is used
for testing and documentation only.

| Dependency | Use | License |
| --- | --- | --- |
| draft-ietf-lamps-pq-composite-sigs-19 test vectors | Known-answer tests in `testdata` | Revised BSD License, see `testdata/LICENSE-draft-19-testvectors` |
| Bouncy Castle 1.86 (`bcprov`, `bcpkix`, `bcutil`) | Independent implementation in the interoperability tests, downloaded by `make test-interop` | MIT |
| OpenJDK | Runs the Bouncy Castle verifier in the interoperability tests | GPL-2.0 with Classpath Exception |
| MkDocs, Material for MkDocs and PyMdown Extensions | Documentation site build | BSD-2-Clause, MIT and MIT |

The Bouncy Castle jars are pinned by version and SHA-256 digest in the `Makefile` and are not
redistributed. The documentation toolchain is pinned in `docs/requirements.txt`. Each dependency
retains its own license and notices.
