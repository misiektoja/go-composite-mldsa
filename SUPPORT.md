# Getting help

Start with the [documentation site](https://misiektoja.github.io/go-composite-mldsa/). [Getting started](https://misiektoja.github.io/go-composite-mldsa/getting-started/) signs a message and builds a small certificate hierarchy. The guides cover keys and encodings, signatures and certificates. The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-composite-mldsa) describes every exported identifier. [Tested implementations](https://misiektoja.github.io/go-composite-mldsa/interoperability/tested-implementations/) names what each release was checked against.

## Check your integration first

Most problems come from one of these:

* Both sides must implement the same draft version. The library follows draft-ietf-lamps-pq-composite-sigs-19. Other draft versions may differ in the message representative or the OIDs, so their signatures may not verify here.
* A pre-hashed message must use the algorithm's own pre-hash. `Algorithm.PreHash` names it.
* `x509.Certificate.Verify` cannot follow composite signatures. Use `compositex509.CheckSignatureFrom` for each link.
* The FIPS 140-3 Go Cryptographic Module v1.0.0 has no ML-DSA, so key generation and verification fail in that mode.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a usage question or discuss an idea | [Discussions](https://github.com/misiektoja/go-composite-mldsa/discussions) |
| Report something broken | [Bug report](https://github.com/misiektoja/go-composite-mldsa/issues/new?template=bug_report.yml) |
| Request a capability | [Feature request](https://github.com/misiektoja/go-composite-mldsa/issues/new?template=feature_request.yml) |
| Report a vulnerability | [Private security advisory](https://github.com/misiektoja/go-composite-mldsa/security/advisories/new), never a public issue |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the go-composite-mldsa version, the Go version, the algorithm and the other implementation with its version when the problem is interoperability. Attach the error text and the certificate, request, public key or signature that fails.

Never post a private key that protects anything real. See [SECURITY.md](SECURITY.md).

## What to expect

This project is maintained in spare time, so replies are best effort with no response time attached. Only the latest release receives fixes, as [SECURITY.md](SECURITY.md) describes, so reproduce the problem on the current version before reporting it.
