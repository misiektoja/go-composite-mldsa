# go-composite-mldsa

go-composite-mldsa is a Go library for composite ML-DSA signatures as specified in
[draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/).

ML-DSA is the post-quantum signature algorithm of FIPS 204. It is new and many operators do not
want to rely on it alone yet. A composite key pairs an ML-DSA key with a traditional RSA, ECDSA or
Ed25519 key. Every composite signature holds one signature from each component and verifies only
when both are valid. A forger has to break both algorithms, so a certificate signed this way stays
trustworthy while either one holds.

To the rest of a PKI a composite key looks like any other key. It has one algorithm identifier, one
`SubjectPublicKeyInfo` and one signature value, so certificates, certificate requests and
revocation lists keep their usual structure.

## What the library provides

| Package | Purpose |
| --- | --- |
| `compositemldsa` | Generate keys, encode them as raw bytes, PKIX and PKCS #8, sign and verify |
| `compositex509` | Create and verify certificates, certificate requests and revocation lists with composite keys, passing every other key type through to `crypto/x509` |

The module needs Go 1.27.1 or newer and imports nothing outside the standard library.

## Where to go next

* [Getting started](getting-started.md) signs a message and builds a certificate hierarchy.
* [Keys and encodings](guide/keys.md), [Signatures](guide/signatures.md) and
  [Certificates, requests and CRLs](guide/certificates.md) explain the API.
* [Algorithms](reference/algorithms.md) lists the 15 supported algorithms with OIDs and sizes.
* [Known limitations](known-limitations.md) lists what the library does not do.
