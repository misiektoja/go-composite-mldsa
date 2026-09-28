# go-composite-mldsa

[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-composite-mldsa.svg)](https://pkg.go.dev/github.com/misiektoja/go-composite-mldsa)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-composite-mldsa/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-composite-mldsa/actions/workflows/test.yml)
[![Interoperability](https://github.com/misiektoja/go-composite-mldsa/actions/workflows/interop.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-composite-mldsa/actions/workflows/interop.yml)
[![Supply chain](https://github.com/misiektoja/go-composite-mldsa/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-composite-mldsa/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-composite-mldsa&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-composite-mldsa)

go-composite-mldsa is a Go library for **post-quantum composite ML-DSA** signatures as specified in
[draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/).

A composite key pairs a post-quantum ML-DSA key with a traditional RSA, ECDSA or Ed25519 key. Every
signature carries one signature from each and verifies only when both do. A certificate signed
this way stays trustworthy as long as either algorithm remains unbroken, which is the point of a
migration period where ML-DSA is still new.

The library has two packages and no dependencies outside the Go standard library:

* `compositemldsa` generates, encodes, signs and verifies with the 15 composite algorithms the
  standard library can build
* `compositex509` creates and verifies certificates, certificate requests and revocation lists
  signed by composite keys or carrying composite subject keys. Every other key type passes
  through to `crypto/x509`

## Contents

* [Install](#install)
* [Algorithms](#algorithms)
* [Getting started](#getting-started)
* [Documentation](#documentation)
* [Support](#support)
* [License](#license)

## Install

```bash
go get github.com/misiektoja/go-composite-mldsa
```

The module needs Go 1.27.1 or newer.

```go
import (
	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)
```

## Algorithms

| ML-DSA | Traditional component |
| --- | --- |
| ML-DSA-44 | RSA-2048 PSS, RSA-2048 PKCS #1 v1.5, Ed25519, ECDSA P-256 |
| ML-DSA-65 | RSA-3072 PSS, RSA-3072 PKCS #1 v1.5, RSA-4096 PSS, RSA-4096 PKCS #1 v1.5, ECDSA P-256, ECDSA P-384, Ed25519 |
| ML-DSA-87 | ECDSA P-384, RSA-3072 PSS, RSA-4096 PSS, ECDSA P-521 |

The Brainpool and Ed448 combinations of the draft are not supported because the Go standard library
does not implement those curves. The
[algorithm reference](https://misiektoja.github.io/go-composite-mldsa/reference/algorithms/) lists
names, OIDs and sizes.

Every supported algorithm passes the draft's published test vectors and exchanges keys,
signatures, certificates, requests and revocation lists with Bouncy Castle in both directions.

### Limitations

* The draft is not yet an RFC. The library follows draft-19 exactly and a later draft or the RFC
  may change the construction.
* `x509.Certificate.Verify` cannot build chains through composite certificates. Check each link
  with `compositex509.CheckSignatureFrom`.
* OCSP responses, CMS and TLS are out of scope. The raw signing API covers any structure that
  signs DER bytes under an algorithm identifier.

[Known limitations](https://misiektoja.github.io/go-composite-mldsa/known-limitations/) explains
each one.

## Getting started

Sign and verify a message:

```go
key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
if err != nil {
	log.Fatal(err)
}
signature, err := key.Sign(nil, message, nil)
if err != nil {
	log.Fatal(err)
}
err = compositemldsa.Verify(key.PublicKey(), message, signature, nil)
```

Issue certificates from a composite CA with the `crypto/x509` templates you already use:

```go
der, err := compositex509.CreateCertificate(rand.Reader, template, caCert, subjectPublicKey, caKey)
```

[examples/hierarchy](examples/hierarchy/) builds a root CA, a device certificate from a
certificate request and a revocation list, verifies them and writes PEM files:

```bash
go run ./examples/hierarchy out
```

[Getting started](https://misiektoja.github.io/go-composite-mldsa/getting-started/) walks through
the same steps.

## Documentation

Full documentation is at
[misiektoja.github.io/go-composite-mldsa](https://misiektoja.github.io/go-composite-mldsa/). The
package documentation on
[pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-composite-mldsa) describes every exported
identifier.

## Support

[SUPPORT.md](SUPPORT.md) says where to ask questions and report bugs.
[SECURITY.md](SECURITY.md) describes how to report a vulnerability privately.
[CONTRIBUTING.md](CONTRIBUTING.md) covers the development checks.

## License

Apache-2.0, see [LICENSE](LICENSE). The draft's test vectors in `testdata` keep their own Revised
BSD License, see [testdata/README.md](testdata/README.md).
