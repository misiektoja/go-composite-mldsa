# Known limitations

## The draft may still change

The library implements draft-ietf-lamps-pq-composite-sigs-19. If a later draft or the RFC changes
the construction, the encodings or the OIDs, signatures and certificates made now may not verify
under the new rules. The [Compatibility policy](reference/compatibility.md) describes how such a
change is released. Plan on reissuing composite certificates when the final RFC is published.

## Brainpool and Ed448 combinations

MLDSA65-ECDSA-brainpoolP256r1-SHA512, MLDSA87-ECDSA-brainpoolP384r1-SHA512 and
MLDSA87-Ed448-SHAKE256 are not supported, because the Go standard library implements neither the
Brainpool curves nor Ed448. Keys, certificates and signatures that use them fail to parse.

## No chain building

`x509.Certificate.Verify` cannot verify composite signatures, so it cannot build or validate a
chain that contains a composite certificate. `compositex509.CheckSignatureFrom` checks one link at
a time and the application applies the remaining path validation rules itself.
[Verifying chains](guide/certificates.md#verifying-chains) shows how.

## Public keys in parsed structures

`crypto/x509` leaves `PublicKey` nil for composite keys in parsed certificates and requests. Read
the key with `compositex509.ParsePKIXPublicKey` on `RawSubjectPublicKeyInfo`.

## Protocols beyond X.509

OCSP responses, CMS, TLS and other protocols are not implemented. OCSP responses and other
structures that sign DER bytes under an algorithm identifier can use the raw signing API, as
[Other signed structures](guide/certificates.md#other-signed-structures) describes. CMS and TLS
need their own specifications for composite signatures.

## Private key storage

Private keys are held in memory and encoded in clear. There is no built-in encryption of PKCS #8
files and no hardware module integration. A remote signer that implements `crypto.Signer` works
with `compositex509`.

## FIPS mode

The FIPS 140-3 Go Cryptographic Module v1.0.0 has no ML-DSA, so composite keys cannot be generated,
loaded or verified in that mode.
