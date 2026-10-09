package compositemldsa

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Holds an ML-DSA public key and a traditional public key that are only valid together.
//
// A PublicKey is safe for concurrent use.
type PublicKey struct {
	alg   Algorithm
	mldsa *mldsa.PublicKey
	// *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey, matching alg.
	trad    crypto.PublicKey
	encoded []byte
}

// Holds the ML-DSA seed and traditional private key of one composite key pair. It implements
// crypto.Signer and crypto.MessageSigner and always signs the complete message.
//
// A PrivateKey is safe for concurrent use.
type PrivateKey struct {
	alg   Algorithm
	mldsa *mldsa.PrivateKey
	// *rsa.PrivateKey, *ecdsa.PrivateKey or ed25519.PrivateKey, matching alg.
	trad    crypto.Signer
	pub     *PublicKey
	encoded []byte
}

// Without SignMessage, crypto.SignMessage would silently fall back to Sign.
var _ crypto.MessageSigner = (*PrivateKey)(nil)

var errUnknownAlgorithm = errors.New("compositemldsa: unknown algorithm")

// Generates a fresh composite key pair. Both components are newly generated, as section 3.1 of the
// draft requires.
func GenerateKey(alg Algorithm) (*PrivateKey, error) {
	if !alg.valid() {
		return nil, errUnknownAlgorithm
	}
	d := &registry[alg]
	mk, err := mldsa.GenerateKey(d.mldsa())
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: generating the ML-DSA component: %w", err)
	}
	var trad crypto.Signer
	switch d.trad {
	case tradRSAPSS, tradRSAPKCS1:
		trad, err = rsa.GenerateKey(rand.Reader, d.rsaBits)
	case tradECDSA:
		trad, err = ecdsa.GenerateKey(d.curve(), rand.Reader)
	case tradEd25519:
		_, trad, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: generating the traditional component: %w", err)
	}
	return newPrivateKey(alg, mk, trad, nil)
}

// Decodes a raw composite public key, the ML-DSA public key followed by the traditional public key.
func NewPublicKey(alg Algorithm, encoding []byte) (*PublicKey, error) {
	if !alg.valid() {
		return nil, errUnknownAlgorithm
	}
	d := &registry[alg]
	n := d.mldsa().PublicKeySize()
	if len(encoding) <= n {
		return nil, fmt.Errorf("compositemldsa: %s public key is too short", alg)
	}
	mk, err := mldsa.NewPublicKey(d.mldsa(), encoding[:n])
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: %s ML-DSA public key: %w", alg, err)
	}
	trad, err := parseTraditionalPublicKey(d, encoding[n:])
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: %s traditional public key: %w", alg, err)
	}
	return &PublicKey{alg: alg, mldsa: mk, trad: trad, encoded: bytes.Clone(encoding)}, nil
}

// Decodes a raw composite private key, the 32-byte ML-DSA seed followed by the traditional private
// key.
func NewPrivateKey(alg Algorithm, encoding []byte) (*PrivateKey, error) {
	if !alg.valid() {
		return nil, errUnknownAlgorithm
	}
	d := &registry[alg]
	if len(encoding) <= mldsa.PrivateKeySize {
		return nil, fmt.Errorf("compositemldsa: %s private key is too short", alg)
	}
	mk, err := mldsa.NewPrivateKey(d.mldsa(), encoding[:mldsa.PrivateKeySize])
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: %s ML-DSA private key: %w", alg, err)
	}
	tradEncoding := encoding[mldsa.PrivateKeySize:]
	trad, err := parseTraditionalPrivateKey(d, tradEncoding)
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: %s traditional private key: %w", alg, err)
	}
	// Section 4 of the draft fixes one DER form per component. The standard library parsers also
	// accept trailing data and an embedded ECDSA public key, which would then survive in Bytes.
	canonical, err := marshalTraditionalPrivateKey(d, trad)
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: %s traditional private key: %w", alg, err)
	}
	if !bytes.Equal(canonical, tradEncoding) {
		return nil, fmt.Errorf("compositemldsa: %s traditional private key is not in the encoding the draft requires", alg)
	}
	return newPrivateKey(alg, mk, trad, encoding)
}

// Assembles a private key and derives its public key. A nil encoding is computed from the components.
func newPrivateKey(alg Algorithm, mk *mldsa.PrivateKey, trad crypto.Signer, encoding []byte) (*PrivateKey, error) {
	d := &registry[alg]
	tradPublic, err := marshalTraditionalPublicKey(trad.Public())
	if err != nil {
		return nil, fmt.Errorf("compositemldsa: %s traditional public key: %w", alg, err)
	}
	pub := &PublicKey{alg: alg, mldsa: mk.PublicKey(), trad: trad.Public()}
	pub.encoded = append(pub.mldsa.Bytes(), tradPublic...)
	if encoding == nil {
		tradPrivate, err := marshalTraditionalPrivateKey(d, trad)
		if err != nil {
			return nil, fmt.Errorf("compositemldsa: %s traditional private key: %w", alg, err)
		}
		encoding = append(mk.Bytes(), tradPrivate...)
	} else {
		encoding = bytes.Clone(encoding)
	}
	return &PrivateKey{alg: alg, mldsa: mk, trad: trad, pub: pub, encoded: encoding}, nil
}

// Returns the algorithm of the key.
func (pk *PublicKey) Algorithm() Algorithm {
	return pk.alg
}

// Returns the raw composite public key, the ML-DSA public key followed by the traditional one.
func (pk *PublicKey) Bytes() []byte {
	return bytes.Clone(pk.encoded)
}

// Returns the ML-DSA component. It must not be used as a standalone key.
func (pk *PublicKey) MLDSAPublicKey() *mldsa.PublicKey {
	return pk.mldsa
}

// Returns the traditional component as *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey. It
// must not be used as a standalone key.
func (pk *PublicKey) TraditionalPublicKey() crypto.PublicKey {
	return pk.trad
}

// Reports whether x is a composite public key with the same algorithm and encoding.
func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	return ok && other != nil && pk.alg == other.alg && bytes.Equal(pk.encoded, other.encoded)
}

// Returns the algorithm of the key.
func (sk *PrivateKey) Algorithm() Algorithm {
	return sk.alg
}

// Returns the raw composite private key, the ML-DSA seed followed by the traditional private key.
func (sk *PrivateKey) Bytes() []byte {
	return bytes.Clone(sk.encoded)
}

// Returns the public key as *PublicKey, as crypto.Signer requires.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return sk.pub
}

// Returns the public key of the pair.
func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pub
}

// Reports whether x is a composite private key with the same algorithm and components.
func (sk *PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PrivateKey)
	if !ok || other == nil || sk.alg != other.alg || !sk.mldsa.Equal(other.mldsa) {
		return false
	}
	trad, ok := sk.trad.(interface{ Equal(crypto.PrivateKey) bool })
	return ok && trad.Equal(other.trad)
}

// Encodes a traditional public key in the form section 4 of the draft requires.
func marshalTraditionalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(k), nil
	case *ecdsa.PublicKey:
		return k.Bytes()
	case ed25519.PublicKey:
		return bytes.Clone(k), nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}
}

// Decodes a traditional public key and checks that it matches the algorithm exactly.
func parseTraditionalPublicKey(d *details, der []byte) (crypto.PublicKey, error) {
	switch d.trad {
	case tradRSAPSS, tradRSAPKCS1:
		k, err := x509.ParsePKCS1PublicKey(der)
		if err != nil {
			return nil, err
		}
		if k.N.BitLen() != d.rsaBits {
			return nil, fmt.Errorf("RSA modulus has %d bits, want %d", k.N.BitLen(), d.rsaBits)
		}
		if !bytes.Equal(x509.MarshalPKCS1PublicKey(k), der) {
			return nil, errors.New("RSA public key is not DER encoded")
		}
		return k, nil
	case tradECDSA:
		return ecdsa.ParseUncompressedPublicKey(d.curve(), der)
	case tradEd25519:
		if len(der) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 public key has %d bytes", len(der))
		}
		return ed25519.PublicKey(bytes.Clone(der)), nil
	default:
		return nil, errUnknownAlgorithm
	}
}

// RFC 5915 ECPrivateKey without the publicKey field, as section 4 of the draft requires.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
}

var curveOIDs = map[elliptic.Curve]asn1.ObjectIdentifier{
	elliptic.P256(): {1, 2, 840, 10045, 3, 1, 7},
	elliptic.P384(): {1, 3, 132, 0, 34},
	elliptic.P521(): {1, 3, 132, 0, 35},
}

// Encodes a traditional private key in the form section 4 of the draft requires.
func marshalTraditionalPrivateKey(d *details, key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		scalar, err := k.Bytes()
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(ecPrivateKey{Version: 1, PrivateKey: scalar, NamedCurveOID: curveOIDs[d.curve()]})
	case ed25519.PrivateKey:
		return k.Seed(), nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// Decodes a traditional private key and checks that it matches the algorithm exactly.
func parseTraditionalPrivateKey(d *details, der []byte) (crypto.Signer, error) {
	switch d.trad {
	case tradRSAPSS, tradRSAPKCS1:
		k, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, err
		}
		if k.N.BitLen() != d.rsaBits {
			return nil, fmt.Errorf("RSA modulus has %d bits, want %d", k.N.BitLen(), d.rsaBits)
		}
		return k, nil
	case tradECDSA:
		k, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, err
		}
		if k.Curve != d.curve() {
			return nil, fmt.Errorf("ECDSA key is on %s, want %s", k.Curve.Params().Name, d.curve().Params().Name)
		}
		return k, nil
	case tradEd25519:
		if len(der) != ed25519.SeedSize {
			return nil, fmt.Errorf("Ed25519 private key has %d bytes", len(der))
		}
		return ed25519.NewKeyFromSeed(der), nil
	default:
		return nil, errUnknownAlgorithm
	}
}
