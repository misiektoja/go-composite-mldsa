# Security model

This page states what a composite signature protects against, what the library checks and what
remains the caller's responsibility.

## What a composite signature guarantees

A composite signature is valid only when the ML-DSA signature and the traditional signature are
both valid. According to section 9.2 of the draft:

* A classical attacker cannot forge a signature while either component is secure against
  classical attacks.
* A quantum attacker cannot forge a signature while ML-DSA remains secure.
* Composite signatures are not strongly unforgeable. Given two signatures over the same message,
  anyone can combine their halves into a third valid one. An ECDSA component can also be
  modified into another valid signature. Do not use signature bytes as unique identifiers.

Both components sign a message representative that starts with a fixed prefix and the algorithm's
label. The ML-DSA component also uses the label as its context. Splitting a composite signature
therefore does not yield a signature over the original message.

## What the library checks

* `Verify` fails unless both components verify. There is no mode that accepts one component.
* Parsing accepts only the encodings the draft fixes. Wrong sizes, algorithm parameters, RSA moduli
  of another size, points on another curve, non-canonical component encodings and trailing data
  are rejected. [Keys and encodings](../guide/keys.md#strict-parsing) lists the rules.
* A PKCS #8 key that includes its public key must match the private key.
* `compositex509` verifies every signature it creates before returning the certificate, request or
  revocation list, including signatures from remote signers.
* Composite subject keys are refused encryption and key agreement usages.
* `CheckSignatureFrom` and `CheckRevocationListSignatureFrom` apply the basic constraints and key
  usage checks of `crypto/x509` to a composite parent.

## What the caller must do

* **Never reuse component keys.** Generate every composite key with `GenerateKey`. Combining an
  existing RSA or ECDSA key with a new ML-DSA key is forbidden by section 9.3 of the draft, as is
  using a component on its own. Both weaken the separation between the two signatures.
* **Check component keys for revocation.** A CA that refuses keys revoked for compromise should
  check each component key as well as the composite key, as section 9.3 of the draft recommends.
* **Validate the whole chain.** `CheckSignatureFrom` checks one link. Validity periods, name
  constraints, policies and revocation are the caller's job, because `x509.Certificate.Verify`
  does not run on composite chains.
* **Protect private keys.** The raw and PKCS #8 encodings hold the ML-DSA seed and the traditional
  private key in clear. Store them encrypted or keep them in a signing service.

## Implementation

The components come from the Go standard library: `crypto/mldsa`, `crypto/ecdsa`, `crypto/rsa`
and `crypto/ed25519`. The library adds the composite construction, the encodings and the X.509
integration. It does no arithmetic of its own. Side-channel properties are those of the standard
library implementations.

The library has not had an external security review.

## FIPS 140-3

The FIPS 140-3 Go Cryptographic Module v1.0.0 does not include ML-DSA, so generating, loading and
verifying composite keys fails when that module is selected. The library itself is not FIPS
validated. Section 10.2 of the draft gives non-authoritative guidance on certifying a composite
implementation when only one component is FIPS approved.
