# Tested implementations

Every release is checked against the draft's published test vectors and against an independent
implementation. The checks run in CI on every change.

## Draft test vectors

`make test` loads the test vectors of draft-ietf-lamps-pq-composite-sigs-19 for all 15 supported
algorithms. For each one it checks that:

* the raw public and private keys load and their PKIX and PKCS #8 encodings match the vectors byte
  for byte
* both published signatures verify with the right context and fail with the wrong one
* a fresh signature from the loaded private key verifies
* the published self-signed certificate carries the same key and a valid signature

## Bouncy Castle

`make test-interop` exchanges artifacts with Bouncy Castle in both directions for all 15
algorithms. Release 0.1.0 was tested with Bouncy Castle 1.86.

| Direction | Checked |
| --- | --- |
| Go to Bouncy Castle | Root certificate algorithm identifier and self-signature, a composite leaf and an ECDSA leaf issued by the composite root, a revocation list, a certificate request, raw signatures with and without a context, rejection of the wrong context, import of a PKCS #8 private key and a signature made with it |
| Bouncy Castle to Go | A self-signed root, a leaf, a revocation list and a certificate request created by Bouncy Castle, raw signatures with and without a context. Go also loads its PKCS #8 private key and issues a further certificate with it |

The test fails when a check is missing from the Java output, so a check cannot pass by not running.

## OpenSSL

OpenSSL 3.6.4 parses composite certificates and prints their fields, but reports the public key as
not loadable and cannot verify composite signatures. This was observed manually and is not part of
the automated tests.

## Adding an implementation

Interoperability reports are welcome. Open an issue with the implementation, its version, the
algorithms tried and the artifacts that failed or passed.
