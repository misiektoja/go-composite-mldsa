# Contributing

go-composite-mldsa is a Go library for composite ML-DSA signatures. Bug reports, interoperability results and code contributions are welcome. Usage questions belong in Discussions, as [SUPPORT.md](SUPPORT.md) describes.

## Before contributing

Contribute only code you have the right to license under Apache-2.0. Do not copy code from another composite ML-DSA implementation without checking its license and naming the source in the pull request. Other implementations may inform behavior, but the code here is written independently.

Never commit private keys other than published test vectors, credentials or non-public documents. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the formatting, vet, lint, test, interoperability, documentation and supply chain checks.

## Development checks

Run these before submitting a change:

```bash
make lint
make test
make test-interop
make docs-build
```

`make test` runs `go vet` and the tests under the race detector, including the draft's test vectors. `make lint` runs golangci-lint at the version CI uses, installed under `bin/`. `make test-interop` needs a JDK and downloads the pinned Bouncy Castle jars. CI uses Java 27. `make docs-build` builds the documentation site strictly and needs `make docs-deps` once. Run `make actionlint` when a workflow changes, `make govulncheck` when a dependency changes and `make fuzz` when parsing code changes. `make help` lists every target.

[Development](https://misiektoja.github.io/go-composite-mldsa/development/development/) and [Testing](https://misiektoja.github.io/go-composite-mldsa/development/testing/) describe the repository layout, the test levels and where test artifacts go.

A change to the construction, an encoding or a check cites the draft section and comes with a negative test. Interoperability claims name the other implementation and its version. User-facing behavior changes update the Go doc comments and the relevant page under `docs/`.

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Compatibility

The module uses semantic versioning and the public API may change in minor releases before v1.0.0. [Compatibility policy](https://misiektoja.github.io/go-composite-mldsa/reference/compatibility/) states what may change and how draft updates are handled.

## Releasing

A release is started by pushing a version tag that is reachable from `main` and by nothing else. [Release process](https://misiektoja.github.io/go-composite-mldsa/development/release-process/) lists the steps, the checks and the artifacts every release carries.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes, four spaces for Java plus two-space indentation for YAML and TOML. Markdown keeps meaningful trailing spaces. `LICENSE` and the test vectors remain verbatim.
