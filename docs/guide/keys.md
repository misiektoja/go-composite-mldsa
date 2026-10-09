# Keys and encodings

A composite key pair is one ML-DSA key pair and one traditional key pair that are only ever used
together. The algorithm fixes both components, for example `MLDSA65ECDSAP256SHA512` pairs
ML-DSA-65 with ECDSA on P-256.

## Generating keys

```go
key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
```

`GenerateKey` creates both components fresh. The draft forbids reusing a component key in another
composite key or on its own, because a key used in both settings weakens the guarantee that the
two signatures cannot be separated. Do not build a composite key from an existing RSA or ECDSA key.

`*PrivateKey` implements `crypto.Signer` and `crypto.MessageSigner`. `key.PublicKey()` returns the
`*PublicKey`. `key.Public()` returns the same key as `crypto.PublicKey`.

## Encodings

| Form | Public key | Private key |
| --- | --- | --- |
| Raw bytes | `pk.Bytes()` and `NewPublicKey` | `sk.Bytes()` and `NewPrivateKey` |
| DER | `MarshalPKIXPublicKey` and `ParsePKIXPublicKey`, a `SubjectPublicKeyInfo` | `MarshalPKCS8PrivateKey` and `ParsePKCS8PrivateKey`, PKCS #8 |
| PEM | DER in a `PUBLIC KEY` block | DER in a `PRIVATE KEY` block |

The raw public key is the ML-DSA public key followed by the traditional one: an RSA
`RSAPublicKey`, an uncompressed ECDSA point or 32 Ed25519 bytes. The raw private key is the 32-byte
ML-DSA seed followed by an RSA `RSAPrivateKey`, an ECDSA `ECPrivateKey` or the 32-byte Ed25519
seed. The DER forms wrap the raw bytes under the algorithm's OID with parameters absent. These are
the encodings of section 4 and section 5 of the draft. The library reproduces the draft's test
vectors byte for byte.

Store a private key as PKCS #8:

```go
der, err := compositemldsa.MarshalPKCS8PrivateKey(key)
if err != nil {
	return err
}
err = os.WriteFile("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
```

`MarshalPKCS8PrivateKey` writes a version 0 `PrivateKeyInfo`. `ParsePKCS8PrivateKey` also accepts
a version 1 `OneAsymmetricKey` and checks that an included public key matches the private key.
Attributes must be well formed and are discarded.

## Keys of any type

`compositex509.ParsePKIXPublicKey`, `MarshalPKIXPublicKey`, `ParsePKCS8PrivateKey` and
`MarshalPKCS8PrivateKey` work like their `crypto/x509` counterparts and also handle composite keys.
Use them where a program reads keys of several types:

```go
key, err := compositex509.ParsePKCS8PrivateKey(der)
if err != nil {
	return err
}
switch k := key.(type) {
case *compositemldsa.PrivateKey:
	// composite
case *ecdsa.PrivateKey:
	// classical
default:
	_ = k
}
```

## Strict parsing

Parsing rejects anything the draft does not allow:

* algorithm identifiers with parameters
* keys of the wrong length for the algorithm
* RSA keys whose modulus is not exactly the size the algorithm names
* ECDSA points that are not on the algorithm's curve
* traditional keys in any encoding other than the single DER form section 4 of the draft fixes,
  such as an ECDSA private key that carries its public key
* ML-DSA private keys in the expanded form, since the draft stores only the seed
* PKCS #8 keys with malformed attributes, a malformed public key or elements after the public key
* trailing data after any structure

## Components

`pk.MLDSAPublicKey()` and `pk.TraditionalPublicKey()` expose the components for inspection, for
example to check a component against a revocation list. The draft recommends that a CA checking a
new composite key for earlier compromise also checks each component key. Never verify with a
component on its own.
