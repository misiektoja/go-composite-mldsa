// Package compositemldsa implements the composite ML-DSA signatures of
// draft-ietf-lamps-pq-composite-sigs-19, which pair an ML-DSA key with an RSA, ECDSA or Ed25519 key.
// A composite signature is valid only when both component signatures are valid, so it stays secure
// while either algorithm remains unbroken.
package compositemldsa
