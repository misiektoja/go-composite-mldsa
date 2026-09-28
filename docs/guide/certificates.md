# Certificates, requests and CRLs

`crypto/x509` parses certificates, certificate requests and revocation lists that use composite
keys, but it cannot create or verify them. `compositex509` fills that gap. Its functions take the
same arguments as their `crypto/x509` counterparts and call `crypto/x509` unchanged when no
composite key is involved, so one code path serves every key type.

| Task | `crypto/x509` | `compositex509` |
| --- | --- | --- |
| Issue a certificate | `CreateCertificate` | `CreateCertificate` |
| Create a certificate request | `CreateCertificateRequest` | `CreateCertificateRequest` |
| Create a revocation list | `CreateRevocationList` | `CreateRevocationList` |
| Verify a certificate signature | `cert.CheckSignatureFrom(parent)` | `CheckSignatureFrom(cert, parent)` |
| Verify a request signature | `csr.CheckSignature()` | `CheckCertificateRequestSignature(csr)` |
| Verify a revocation list signature | `rl.CheckSignatureFrom(issuer)` | `CheckRevocationListSignatureFrom(rl, issuer)` |
| Read a public key | `ParsePKIXPublicKey` | `ParsePKIXPublicKey` |

## Issuing certificates

`CreateCertificate` handles every combination:

* a composite CA signing a composite, ECDSA, RSA, Ed25519 or ML-DSA subject key
* an ECDSA, RSA, Ed25519 or ML-DSA CA signing a composite subject key
* neither key composite, which goes straight to `x509.CreateCertificate`

```go
der, err := compositex509.CreateCertificate(rand.Reader, template, caCert, subjectKey, caKey)
```

A few rules differ from `crypto/x509`:

* `template.SignatureAlgorithm` must be zero when the CA key is composite. The algorithm follows
  from the key.
* A composite subject key may only sign. Its key usage must include at least one of
  `DigitalSignature`, `ContentCommitment`, `CertSign` or `CRLSign`. It must not include
  `KeyEncipherment`, `DataEncipherment`, `KeyAgreement`, `EncipherOnly` or `DecipherOnly`, as
  section 5.2 of the draft requires. A key usage extension in `ExtraExtensions` is checked the
  same way.
* A CA certificate without `SubjectKeyId` gets the first 20 bytes of the SHA-256 hash of the
  composite public key, as `crypto/x509` does for other keys.

Every certificate is signed, verified against the signer's public key and parsed before it is
returned.

## Certificate requests

A composite key signs its own request, which proves possession of both components:

```go
der, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
	Subject: pkix.Name{CommonName: "device-0001"},
}, key)
```

A CA checks the request and extracts the key before issuing:

```go
csr, err := x509.ParseCertificateRequest(der)
if err != nil {
	return err
}
if err := compositex509.CheckCertificateRequestSignature(csr); err != nil {
	return err
}
subjectKey, err := compositex509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
```

`csr.PublicKey` is nil for a composite key, so always read it through `ParsePKIXPublicKey`.

## Revocation lists

```go
der, err := compositex509.CreateRevocationList(rand.Reader, template, caCert, caKey)
```

The composite signer must hold the key named in the issuer certificate.

## Verifying chains

`x509.Certificate.Verify` cannot follow a composite signature, so chain building through a
composite certificate fails. Check each link with `CheckSignatureFrom`, which applies the same
basic constraints and key usage checks as `crypto/x509`, then apply the remaining path validation
rules your application needs, such as validity periods, name constraints and revocation.

```go
if err := compositex509.CheckSignatureFrom(leaf, intermediate); err != nil {
	return err
}
if err := compositex509.CheckSignatureFrom(intermediate, root); err != nil {
	return err
}
```

`SignatureAlgorithm` reports which composite algorithm signed a DER certificate, request or
revocation list.

## Other signed structures

OCSP responses, timestamps and similar structures sign the DER encoding of a to-be-signed part
under an algorithm identifier. Sign that encoding with an empty context and no pre-hash. Write the
algorithm identifier with `Algorithm.OID()` and absent parameters:

```go
signature, err := key.Sign(rand.Reader, tbsDER, nil)
if err != nil {
	return err
}
algorithm := pkix.AlgorithmIdentifier{Algorithm: key.Algorithm().OID()}
```

Verify with `compositemldsa.Verify(publicKey, tbsDER, signature, nil)`.
