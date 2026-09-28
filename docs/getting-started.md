# Getting started

This page signs a message with a composite key, then builds a small certificate hierarchy.

## Install

```bash
go get github.com/misiektoja/go-composite-mldsa
```

The module needs Go 1.27.1 or newer.

## Sign and verify

```go
key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
if err != nil {
	log.Fatal(err)
}
message := []byte("hello, post-quantum world")
signature, err := key.Sign(nil, message, nil)
if err != nil {
	log.Fatal(err)
}
if err := compositemldsa.Verify(key.PublicKey(), message, signature, nil); err != nil {
	log.Fatal(err)
}
```

`Verify` returns nil only when both the ML-DSA signature and the ECDSA signature are valid.

If you are unsure which algorithm to use, `MLDSA65ECDSAP256SHA512` is a reasonable default for
end-entity keys and `MLDSA87ECDSAP384SHA512` for long-lived CA keys.
[Algorithms](reference/algorithms.md) compares all of them.

## Build a certificate hierarchy

The example program in `examples/hierarchy` creates a composite root CA, has a device create a
certificate request with its own composite key, issues the device certificate from that request
and publishes an empty revocation list. It checks every signature and writes the results as PEM
files into the directory you name.

```bash
go run ./examples/hierarchy out
```

```text
root CA    MLDSA87-ECDSA-P384-SHA512
device     MLDSA65-ECDSA-P256-SHA512
all signatures verified, files written to out
```

The program refuses to overwrite existing files and writes the private keys with mode 0600.

```go
--8<-- "examples/hierarchy/main.go"
```

## What to change for production

* Keep CA private keys in the storage your policy requires. `compositex509` accepts any
  `crypto.Signer` whose public key is a `*compositemldsa.PublicKey`, so a remote signing service
  works as well as an in-memory key.
* Check that every relying party understands the algorithm you choose.
  [Tested implementations](interoperability/tested-implementations.md) lists what is known to work.
* Verify chains with `compositex509.CheckSignatureFrom`, because `x509.Certificate.Verify` cannot.
