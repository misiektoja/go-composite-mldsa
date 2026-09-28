# Testing

The library is tested at four levels: the draft's test vectors, unit tests, fuzz targets and an
independent implementation in a separate module. This page explains how to run each level and what
it proves.

## Test vectors and unit tests

```bash
make test
```

Runs `go vet` and every test under the race detector with coverage written to the scratch
directory. The root package tests load the draft-19 test vectors for all 15 algorithms and check
encodings, signatures and the published certificates, as
[Tested implementations](../interoperability/tested-implementations.md#draft-test-vectors)
describes. Further tests cover signing options, context and pre-hash handling, tampered signatures,
label separation between algorithms and malformed keys.

The `compositex509` tests build a composite hierarchy for every algorithm, mixed hierarchies with
ECDSA, RSA, RSA-PSS, Ed25519 and ML-DSA issuers, remote and faulty signers. They also cover the
cases that must be refused.

## Fuzzing

```bash
make fuzz
make fuzz FUZZ_TIME=2m
```

Fuzzes public key and PKCS #8 parsing, signature verification and certificate signature checks for
`FUZZ_TIME` each. CI runs 30 seconds per target on every push. Go writes a failing input under the
package's `testdata/fuzz` directory. Commit that input with the fix so it stays a regression test.

The target passes `-fuzzminimizetime 0`, so Go does not minimize inputs. Minimization stalls the
workers for seconds at a time and a worker that is still busy when `FUZZ_TIME` expires makes Go
report the run as failed with `context deadline exceeded`. Set `FUZZ_MINIMIZE_TIME` to a duration
such as `1m` when a crash is found and a smaller reproducer is wanted.

## Interoperability

```bash
make test-interop
```

Downloads the pinned Bouncy Castle jars from Maven Central, checks their SHA-256 digests and runs
`interop/java/CompositeInterop.java` with the `java` found on `PATH`. Go writes certificates,
revocation lists, requests, keys and signatures for every algorithm. The Java program verifies
them, writes its own set and reports one line per check. The Go test then verifies the Bouncy
Castle set and fails when any expected check is missing.

The program runs as a single-file Java source, so no build tool is needed. Set `BC_VERSION` and the
matching digests in the `Makefile` to test another Bouncy Castle release.
