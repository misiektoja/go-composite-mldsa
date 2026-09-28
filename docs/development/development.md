# Development

How to build, check and change the library. Contribution rules are in
[CONTRIBUTING.md](https://github.com/misiektoja/go-composite-mldsa/blob/main/CONTRIBUTING.md).

## Prerequisites

* Go at the version `go.mod` declares. Every Make target runs with exactly that toolchain, which Go
  downloads on first use when the installed version differs.
* A JDK and `curl` for the interoperability tests. CI uses Temurin 27. The verifier needs at
  least Java 16 for the APIs it uses, but versions before 27 are not tested. See
  [Testing](testing.md).
* Python 3 with the pinned MkDocs dependencies for the documentation site, installed by
  `make docs-deps`.

Linters and other tools are downloaded into `bin/` at pinned versions by the Make targets that
need them.

## Repository layout

| Path | Content |
| --- | --- |
| root package `compositemldsa` | Algorithms, keys, encodings, signing and verification |
| `compositex509/` | Certificates, certificate requests and revocation lists with composite keys |
| `testdata/` | The draft-19 test vectors and their license |
| `examples/` | Runnable programs, built with the root module |
| `interop/` | A separate module with the Bouncy Castle tests and the Java verifier |
| `docs/` | This site |

## Common commands

```bash
make test           # go vet and the tests under the race detector
make lint           # golangci-lint over both modules
make actionlint     # lint the GitHub Actions workflows
make fuzz           # fuzz every parser for FUZZ_TIME each, 20s by default
make test-interop   # exchange artifacts with Bouncy Castle, needs Java
make docs-build     # strict MkDocs build
make help           # every target
```

`make lint-fix` applies the fixes golangci-lint offers. `make tidy-check` fails when either
module's `go.mod` is not tidy. `make govulncheck` reports known vulnerabilities that reach the code
and `make gitleaks` scans the tree and history for credentials.

## Documentation

The site is built with MkDocs and the Material theme from `docs/` and `mkdocs.yml`. Set `PYTHON`
when the MkDocs toolchain lives in a virtual environment:

```bash
make docs-deps PYTHON=.venv/bin/python
make docs-serve PYTHON=.venv/bin/python
```

`make docs-build` runs with `--strict`, so a broken link, a missing anchor or a page absent from
the navigation fails the build. CI runs the same build on every change to the documentation and
publishes the site from the default branch.

Package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-composite-mldsa)
comes from the Go doc comments. User-facing behavior changes belong in both places. The example on
[Getting started](../getting-started.md) is included from `examples/hierarchy`, so change the
program and the page follows.

## Test artifacts

Coverage profiles, the Bouncy Castle jars and the release check export go under `.cache/tests` by
default. Set `TEST_SCRATCH` to an absolute path to use another directory. These files must never be
committed.

## Code style

`.editorconfig` records the whitespace rules. `gofmt` and golangci-lint enforce the rest. Every
exported identifier carries a doc comment. A change to the construction, an encoding or a check
cites the draft section and comes with a negative test.
