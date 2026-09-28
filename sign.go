package compositemldsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
)

// The fixed prefix of every message representative, from section 2.2 of the draft.
const prefix = "CompositeAlgorithmSignatures2025"

// Longest application context the draft allows.
const maxContextSize = 255

var errInvalidSignature = errors.New("compositemldsa: invalid signature")

// Options for signing and verification. A nil *Options means an empty context and an unhashed
// message.
type Options struct {
	// Binds the signature to an application context of at most 255 bytes. X.509 and other PKIX
	// uses keep it empty.
	Context string

	// When not zero, the message is the digest of the real message under this hash, which must be
	// the pre-hash of the algorithm. Section 10.5 of the draft describes this external pre-hashing.
	Hash crypto.Hash
}

// Returns the hash of an externally pre-hashed message. It is zero when the message is not hashed.
func (o *Options) HashFunc() crypto.Hash {
	if o == nil {
		return 0
	}
	return o.Hash
}

// Signs message with both components.
//
// With a zero opts.HashFunc the complete message is signed. When opts.HashFunc is the pre-hash of
// the algorithm, message must be its digest. opts may be *Options to set a context. The random
// source is used by the traditional component. A nil source selects crypto/rand.
func (sk *PrivateKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	context, hash := signerOptions(opts)
	representative, err := messageRepresentative(sk.alg, message, context, hash)
	if err != nil {
		return nil, err
	}
	return sk.signRepresentative(random, representative)
}

// Signs the complete message. A non-zero opts.HashFunc must be the pre-hash of the algorithm, which
// is then applied here, so the result matches Sign with the digest.
func (sk *PrivateKey) SignMessage(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	context, hash := signerOptions(opts)
	if hash != 0 && hash != sk.alg.PreHash() {
		return nil, fmt.Errorf("compositemldsa: %s pre-hashes with %s, not %s", sk.alg, sk.alg.PreHash(), hash)
	}
	representative, err := messageRepresentative(sk.alg, message, context, 0)
	if err != nil {
		return nil, err
	}
	return sk.signRepresentative(random, representative)
}

// Verifies signature over message with both components. It returns nil only when both component
// signatures are valid.
func Verify(pk *PublicKey, message, signature []byte, opts *Options) error {
	if pk == nil || !pk.alg.valid() {
		return errUnknownAlgorithm
	}
	representative, err := messageRepresentative(pk.alg, message, opts.context(), opts.HashFunc())
	if err != nil {
		return err
	}
	d := &registry[pk.alg]
	n := d.mldsa().SignatureSize()
	if len(signature) <= n {
		return errInvalidSignature
	}
	if err := mldsa.Verify(pk.mldsa, representative, signature[:n], &mldsa.Options{Context: pk.alg.label()}); err != nil {
		return errInvalidSignature
	}
	if !verifyTraditional(d, pk.trad, representative, signature[n:]) {
		return errInvalidSignature
	}
	return nil
}

// Returns the context of the options, which is empty for nil options.
func (o *Options) context() string {
	if o == nil {
		return ""
	}
	return o.Context
}

// Extracts the context and pre-hash from signer options of any type.
func signerOptions(opts crypto.SignerOpts) (string, crypto.Hash) {
	if opts == nil {
		return "", 0
	}
	if o, ok := opts.(*Options); ok {
		return o.context(), o.HashFunc()
	}
	return "", opts.HashFunc()
}

// Builds M' = Prefix || Label || len(ctx) || ctx || PH(M) from section 2.2 of the draft.
func messageRepresentative(alg Algorithm, message []byte, context string, hash crypto.Hash) ([]byte, error) {
	if len(context) > maxContextSize {
		return nil, fmt.Errorf("compositemldsa: context is %d bytes, the limit is %d", len(context), maxContextSize)
	}
	preHash := alg.PreHash()
	messageDigest := message
	switch {
	case hash == 0:
		messageDigest = digest(preHash, message)
	case hash != preHash:
		return nil, fmt.Errorf("compositemldsa: %s pre-hashes with %s, not %s", alg, preHash, hash)
	case len(message) != preHash.Size():
		return nil, fmt.Errorf("compositemldsa: pre-hashed message is %d bytes, %s digests are %d",
			len(message), preHash, preHash.Size())
	}
	label := alg.label()
	out := make([]byte, 0, len(prefix)+len(label)+1+len(context)+len(messageDigest))
	out = append(out, prefix...)
	out = append(out, label...)
	out = append(out, byte(len(context))) //nolint:gosec // The length was checked against maxContextSize above.
	out = append(out, context...)
	return append(out, messageDigest...), nil
}

// Signs the message representative with the ML-DSA component and then the traditional component.
func (sk *PrivateKey) signRepresentative(random io.Reader, representative []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	d := &registry[sk.alg]
	mldsaSig, err := sk.mldsa.Sign(nil, representative, &mldsa.Options{Context: sk.alg.label()})
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: ML-DSA component: %w", err)
	}
	var tradSig []byte
	switch k := sk.trad.(type) {
	case *ecdsa.PrivateKey:
		tradSig, err = ecdsa.SignASN1(random, k, digest(d.tradHash, representative))
	case *rsa.PrivateKey:
		if d.trad == tradRSAPSS {
			opts := &rsa.PSSOptions{SaltLength: d.pssSalt, Hash: d.tradHash}
			tradSig, err = rsa.SignPSS(random, k, d.tradHash, digest(d.tradHash, representative), opts)
		} else {
			tradSig, err = rsa.SignPKCS1v15(nil, k, d.tradHash, digest(d.tradHash, representative))
		}
	case ed25519.PrivateKey:
		tradSig = ed25519.Sign(k, representative)
	default:
		err = fmt.Errorf("unsupported key type %T", sk.trad)
	}
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: traditional component: %w", err)
	}
	return append(mldsaSig, tradSig...), nil
}

// Verifies the traditional component signature over the message representative.
func verifyTraditional(d *details, pub crypto.PublicKey, representative, signature []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest(d.tradHash, representative), signature)
	case *rsa.PublicKey:
		if d.trad == tradRSAPSS {
			opts := &rsa.PSSOptions{SaltLength: d.pssSalt, Hash: d.tradHash}
			return rsa.VerifyPSS(k, d.tradHash, digest(d.tradHash, representative), signature, opts) == nil
		}
		return rsa.VerifyPKCS1v15(k, d.tradHash, digest(d.tradHash, representative), signature) == nil
	case ed25519.PublicKey:
		return len(signature) == ed25519.SignatureSize && ed25519.Verify(k, representative, signature)
	default:
		return false
	}
}

// Hashes data with h.
func digest(h crypto.Hash, data []byte) []byte {
	state := h.New()
	state.Write(data)
	return state.Sum(nil)
}
