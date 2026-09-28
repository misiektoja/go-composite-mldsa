# Release notes

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-09-28

The first release of **go-composite-mldsa**, a Go library for **post-quantum composite ML-DSA** signatures as specified in draft-ietf-lamps-pq-composite-sigs-19.

A composite key pairs ML-DSA with RSA, ECDSA or Ed25519. Its signature is valid only when both components verify. The library needs Go 1.27.1 or newer and has no dependencies outside the standard library.

This release was tested with the draft-19 test vectors and **Bouncy Castle 1.86**.

### Signatures

* **15 composite algorithms** - Every draft-19 combination of ML-DSA-44, ML-DSA-65 or ML-DSA-87 with RSA-PSS, RSA PKCS #1 v1.5, ECDSA P-256, P-384, P-521 or Ed25519. Keys implement `crypto.Signer` and `crypto.MessageSigner`. An optional context string binds a signature to an application. Callers can pass a message digest instead of the message.
* **Standard encodings** - Raw keys and PKIX `SubjectPublicKeyInfo` and PKCS #8 encodings match the draft byte for byte. Parsing is strict: wrong sizes, parameters, unexpected RSA moduli and mismatched public keys are rejected.

### Certificates

* **Composite CAs and subjects** - `compositex509` creates and verifies certificates, certificate requests and revocation lists signed by a composite key or carrying a composite subject key. It takes the usual `crypto/x509` templates and passes every other key type through to `crypto/x509`, so a composite CA can issue ECDSA or RSA certificates and a classical CA can certify a composite key.
* **Key usage checks** - A composite subject key is refused encryption and key agreement usages, as the draft requires.

### Known limitations

* **Draft algorithm** - The construction follows draft-19. A later draft or the RFC may change it and a release will follow the change.
* **No Brainpool or Ed448** - The Go standard library does not implement those curves.
* **No chain building through composite certificates** - `x509.Certificate.Verify` does not understand them. Verify each link with `compositex509.CheckSignatureFrom`.
* **No FIPS mode** - The FIPS 140-3 Go Cryptographic Module v1.0.0 has no ML-DSA.
