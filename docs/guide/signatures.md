# Signatures

A composite signature is the ML-DSA signature followed by the traditional signature. Both are
computed over a message representative that binds the signature to the composite algorithm, so
neither part can be reused as a signature over the original message.

## Signing and verifying

```go
signature, err := key.Sign(nil, message, nil)
if err != nil {
	return err
}
err = compositemldsa.Verify(key.PublicKey(), message, signature, nil)
```

`Verify` returns nil only when both component signatures are valid. The random source passed to
`Sign` is used by the ECDSA and RSA-PSS components. A nil reader selects `crypto/rand`.

## Contexts

A context string binds a signature to one application. A signature made with one context does not
verify with another, including the empty one.

```go
opts := &compositemldsa.Options{Context: "example.com firmware v1"}
signature, err := key.Sign(nil, message, opts)
if err != nil {
	return err
}
err = compositemldsa.Verify(key.PublicKey(), message, signature, opts)
```

The context is at most 255 bytes. X.509 structures always use the empty context.

## Signing a digest

Every algorithm hashes the message first with its pre-hash, SHA-256 or SHA-512 as
`Algorithm.PreHash` reports. A caller that already holds that digest can sign it directly:

```go
digest := sha512.Sum512(message)
opts := &compositemldsa.Options{Hash: crypto.SHA512}
signature, err := key.Sign(nil, digest[:], opts)
if err != nil {
	return err
}
err = compositemldsa.Verify(key.PublicKey(), digest[:], signature, opts)
```

The result is an ordinary composite signature. It also verifies without `Hash` against the full
message. A hash other than the algorithm's pre-hash is refused. This is the external pre-hashing of
section 10.5 of the draft, useful when a hardware module or a remote service signs.

`SignMessage` from `crypto.MessageSigner` always takes the full message. `crypto.SignMessage`
therefore works with a composite key without any special handling.

## Remote signers

Code that only needs a `crypto.Signer` does not require a `*compositemldsa.PrivateKey`. For
`compositex509`, a signer qualifies when its `Public` method returns a `*compositemldsa.PublicKey`
and its `Sign` method signs the full message when `opts.HashFunc()` is zero. Every signature it
produces is verified before a certificate, request or revocation list is returned, so a faulty
signer is caught at creation time.

## Signature properties

A composite signature cannot be forged while either component remains secure against the attacker
in question. It is not strongly unforgeable. Someone holding two different signatures over the same
message can combine their halves into a third valid signature. An ECDSA signature can also be
modified into another valid one. Protocols that identify objects by their signature bytes must not
rely on signatures being unique. Section 9.2 of the draft analyses this.
