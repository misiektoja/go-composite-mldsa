# Algorithms

The library implements the 15 draft-19 algorithms whose components the Go standard library
provides. Names match the draft and Bouncy Castle. OIDs are under `id-alg` (1.3.6.1.5.5.7.6) and
were allocated early by IANA, according to section 8.1.2 of the draft. `Algorithm.String` returns
the name. `AlgorithmFromName` and `AlgorithmFromOID` map a name or OID back to the constant.

| Constant | Name | OID | Pre-hash | Traditional component |
| --- | --- | --- | --- | --- |
| `MLDSA44RSA2048PSSSHA256` | MLDSA44-RSA2048-PSS-SHA256 | 1.3.6.1.5.5.7.6.37 | SHA-256 | RSASSA-PSS, SHA-256, 32-byte salt |
| `MLDSA44RSA2048PKCS15SHA256` | MLDSA44-RSA2048-PKCS15-SHA256 | 1.3.6.1.5.5.7.6.38 | SHA-256 | RSASSA-PKCS1-v1_5, SHA-256 |
| `MLDSA44Ed25519SHA512` | MLDSA44-Ed25519-SHA512 | 1.3.6.1.5.5.7.6.39 | SHA-512 | Ed25519 |
| `MLDSA44ECDSAP256SHA256` | MLDSA44-ECDSA-P256-SHA256 | 1.3.6.1.5.5.7.6.40 | SHA-256 | ECDSA P-256, SHA-256 |
| `MLDSA65RSA3072PSSSHA512` | MLDSA65-RSA3072-PSS-SHA512 | 1.3.6.1.5.5.7.6.41 | SHA-512 | RSASSA-PSS, SHA-256, 32-byte salt |
| `MLDSA65RSA3072PKCS15SHA512` | MLDSA65-RSA3072-PKCS15-SHA512 | 1.3.6.1.5.5.7.6.42 | SHA-512 | RSASSA-PKCS1-v1_5, SHA-256 |
| `MLDSA65RSA4096PSSSHA512` | MLDSA65-RSA4096-PSS-SHA512 | 1.3.6.1.5.5.7.6.43 | SHA-512 | RSASSA-PSS, SHA-384, 48-byte salt |
| `MLDSA65RSA4096PKCS15SHA512` | MLDSA65-RSA4096-PKCS15-SHA512 | 1.3.6.1.5.5.7.6.44 | SHA-512 | RSASSA-PKCS1-v1_5, SHA-384 |
| `MLDSA65ECDSAP256SHA512` | MLDSA65-ECDSA-P256-SHA512 | 1.3.6.1.5.5.7.6.45 | SHA-512 | ECDSA P-256, SHA-256 |
| `MLDSA65ECDSAP384SHA512` | MLDSA65-ECDSA-P384-SHA512 | 1.3.6.1.5.5.7.6.46 | SHA-512 | ECDSA P-384, SHA-384 |
| `MLDSA65Ed25519SHA512` | MLDSA65-Ed25519-SHA512 | 1.3.6.1.5.5.7.6.48 | SHA-512 | Ed25519 |
| `MLDSA87ECDSAP384SHA512` | MLDSA87-ECDSA-P384-SHA512 | 1.3.6.1.5.5.7.6.49 | SHA-512 | ECDSA P-384, SHA-384 |
| `MLDSA87RSA3072PSSSHA512` | MLDSA87-RSA3072-PSS-SHA512 | 1.3.6.1.5.5.7.6.52 | SHA-512 | RSASSA-PSS, SHA-256, 32-byte salt |
| `MLDSA87RSA4096PSSSHA512` | MLDSA87-RSA4096-PSS-SHA512 | 1.3.6.1.5.5.7.6.53 | SHA-512 | RSASSA-PSS, SHA-384, 48-byte salt |
| `MLDSA87ECDSAP521SHA512` | MLDSA87-ECDSA-P521-SHA512 | 1.3.6.1.5.5.7.6.54 | SHA-512 | ECDSA P-521, SHA-512 |

The pre-hash is applied to the message before both components sign. The hash in the last column
is the one the traditional component uses on the message representative.

## Sizes

Sizes in bytes of the raw encodings. RSA private keys and ECDSA signatures vary by a few bytes
because DER drops leading zeros.

| Name | Public key | Private key | Signature |
| --- | --- | --- | --- |
| MLDSA44-RSA2048-PSS-SHA256 | 1582 | about 1220 | 2676 |
| MLDSA44-RSA2048-PKCS15-SHA256 | 1582 | about 1220 | 2676 |
| MLDSA44-Ed25519-SHA512 | 1344 | 64 | 2484 |
| MLDSA44-ECDSA-P256-SHA256 | 1377 | 83 | up to 2492 |
| MLDSA65-RSA3072-PSS-SHA512 | 2350 | about 1800 | 3693 |
| MLDSA65-RSA3072-PKCS15-SHA512 | 2350 | about 1800 | 3693 |
| MLDSA65-RSA4096-PSS-SHA512 | 2478 | about 2380 | 3821 |
| MLDSA65-RSA4096-PKCS15-SHA512 | 2478 | about 2380 | 3821 |
| MLDSA65-ECDSA-P256-SHA512 | 2017 | 83 | up to 3381 |
| MLDSA65-ECDSA-P384-SHA512 | 2049 | 96 | up to 3413 |
| MLDSA65-Ed25519-SHA512 | 1984 | 64 | 3373 |
| MLDSA87-ECDSA-P384-SHA512 | 2689 | 96 | up to 4731 |
| MLDSA87-RSA3072-PSS-SHA512 | 2990 | about 1800 | 5011 |
| MLDSA87-RSA4096-PSS-SHA512 | 3118 | about 2380 | 5139 |
| MLDSA87-ECDSA-P521-SHA512 | 2725 | 114 | up to 4766 |

## Choosing an algorithm

The draft leaves the choice to the operator. As a starting point:

* `MLDSA65ECDSAP256SHA512` for end-entity keys, with ML-DSA-65 at NIST security category 3
* `MLDSA87ECDSAP384SHA512` for long-lived CA keys, with ML-DSA-87 at category 5
* an RSA combination only when relying parties or hardware require RSA, since it adds several
  hundred bytes to every key and signature
* `MLDSA44` combinations only for constrained devices, since ML-DSA-44 is category 2

Check that every relying party supports the algorithm before issuing with it.

## Not supported

| Name | OID | Reason |
| --- | --- | --- |
| MLDSA65-ECDSA-brainpoolP256r1-SHA512 | 1.3.6.1.5.5.7.6.47 | No Brainpool curves in the Go standard library |
| MLDSA87-ECDSA-brainpoolP384r1-SHA512 | 1.3.6.1.5.5.7.6.50 | No Brainpool curves in the Go standard library |
| MLDSA87-Ed448-SHAKE256 | 1.3.6.1.5.5.7.6.51 | No Ed448 in the Go standard library |

`AlgorithmFromOID` and `AlgorithmFromName` report false for these algorithms. Parsing a key or
signature that uses them fails.
