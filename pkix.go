package compositemldsa

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// RFC 5280 SubjectPublicKeyInfo.
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// RFC 5958 OneAsymmetricKey. Version 0 is PrivateKeyInfo and may not carry the public key.
type oneAsymmetricKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue  `asn1:"optional,tag:0"`
	PublicKey  asn1.BitString `asn1:"optional,tag:1"`
}

// Encodes the public key as a DER SubjectPublicKeyInfo with parameters absent.
func MarshalPKIXPublicKey(pk *PublicKey) ([]byte, error) {
	if pk == nil || !pk.alg.valid() {
		return nil, errUnknownAlgorithm
	}
	return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: pk.alg.OID()},
		PublicKey: asn1.BitString{Bytes: pk.encoded, BitLength: 8 * len(pk.encoded)},
	})
}

// Decodes a DER SubjectPublicKeyInfo that holds a composite public key.
func ParsePKIXPublicKey(der []byte) (*PublicKey, error) {
	var spki subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("compositemldsa: parsing SubjectPublicKeyInfo: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("compositemldsa: trailing data after SubjectPublicKeyInfo")
	}
	alg, err := algorithmFromIdentifier(spki.Algorithm)
	if err != nil {
		return nil, err
	}
	if spki.PublicKey.BitLength != 8*len(spki.PublicKey.Bytes) {
		return nil, errors.New("compositemldsa: public key BIT STRING has unused bits")
	}
	pk, err := NewPublicKey(alg, spki.PublicKey.Bytes)
	if err != nil {
		return nil, err
	}
	// encoding/asn1 ignores extra elements at the end of a SEQUENCE, so only the one DER encoding
	// of the key is accepted.
	if canonical, err := MarshalPKIXPublicKey(pk); err != nil || !bytes.Equal(canonical, der) {
		return nil, errors.New("compositemldsa: SubjectPublicKeyInfo is not DER encoded")
	}
	return pk, nil
}

// Encodes the private key as a DER PKCS #8 PrivateKeyInfo with parameters absent.
func MarshalPKCS8PrivateKey(sk *PrivateKey) ([]byte, error) {
	if sk == nil || !sk.alg.valid() {
		return nil, errUnknownAlgorithm
	}
	return asn1.Marshal(oneAsymmetricKey{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: sk.alg.OID()},
		PrivateKey: sk.encoded,
	})
}

// Decodes a DER PKCS #8 PrivateKeyInfo or OneAsymmetricKey that holds a composite private key. An
// included public key must match the private key.
func ParsePKCS8PrivateKey(der []byte) (*PrivateKey, error) {
	var key oneAsymmetricKey
	if rest, err := asn1.Unmarshal(der, &key); err != nil {
		return nil, fmt.Errorf("compositemldsa: parsing PKCS #8: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("compositemldsa: trailing data after PKCS #8")
	}
	hasPublicKey := key.PublicKey.BitLength != 0 || len(key.PublicKey.Bytes) != 0
	switch {
	case key.Version != 0 && key.Version != 1:
		return nil, fmt.Errorf("compositemldsa: unsupported PKCS #8 version %d", key.Version)
	case key.Version == 0 && hasPublicKey:
		return nil, errors.New("compositemldsa: PKCS #8 version 0 cannot carry a public key")
	}
	alg, err := algorithmFromIdentifier(key.Algorithm)
	if err != nil {
		return nil, err
	}
	sk, err := NewPrivateKey(alg, key.PrivateKey)
	if err != nil {
		return nil, err
	}
	matches := key.PublicKey.BitLength == 8*len(key.PublicKey.Bytes) && bytes.Equal(key.PublicKey.Bytes, sk.pub.encoded)
	if hasPublicKey && !matches {
		return nil, errors.New("compositemldsa: PKCS #8 public key does not match the private key")
	}
	return sk, nil
}

// Maps an algorithm identifier to a supported algorithm. Parameters must be absent, as section 5.3
// of the draft requires.
func algorithmFromIdentifier(id pkix.AlgorithmIdentifier) (Algorithm, error) {
	alg, ok := AlgorithmFromOID(id.Algorithm)
	if !ok {
		return 0, fmt.Errorf("compositemldsa: unsupported algorithm %s", id.Algorithm)
	}
	if len(id.Parameters.FullBytes) != 0 {
		return 0, fmt.Errorf("compositemldsa: %s algorithm identifier carries parameters", alg)
	}
	return alg, nil
}
