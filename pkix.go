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

// RFC 5958 OneAsymmetricKey. Version 0 is PrivateKeyInfo and may not carry the public key. The
// public key stays raw so that an empty BIT STRING is told apart from an absent one.
type oneAsymmetricKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue `asn1:"optional,tag:0"`
	PublicKey  asn1.RawValue `asn1:"optional,tag:1"`
}

// RFC 5912 Attribute, a type and a non-empty SET of values of any type.
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

var errMalformedAttributes = errors.New("compositemldsa: malformed PKCS #8 attributes")

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
// included public key must match the private key. Attributes must be well formed and are
// discarded. Elements after the public key are rejected.
func ParsePKCS8PrivateKey(der []byte) (*PrivateKey, error) {
	var key oneAsymmetricKey
	if rest, err := asn1.Unmarshal(der, &key); err != nil {
		return nil, fmt.Errorf("compositemldsa: parsing PKCS #8: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("compositemldsa: trailing data after PKCS #8")
	}
	// encoding/asn1 ignores extra elements at the end of a SEQUENCE. The raw fields re-encode
	// verbatim, so a difference means the input had such elements.
	if canonical, err := asn1.Marshal(key); err != nil || !bytes.Equal(canonical, der) {
		return nil, errors.New("compositemldsa: PKCS #8 is not DER encoded")
	}
	hasPublicKey := len(key.PublicKey.FullBytes) != 0
	switch {
	case key.Version != 0 && key.Version != 1:
		return nil, fmt.Errorf("compositemldsa: unsupported PKCS #8 version %d", key.Version)
	case key.Version == 0 && hasPublicKey:
		return nil, errors.New("compositemldsa: PKCS #8 version 0 cannot carry a public key")
	}
	if err := checkAttributes(key.Attributes); err != nil {
		return nil, err
	}
	alg, err := algorithmFromIdentifier(key.Algorithm)
	if err != nil {
		return nil, err
	}
	sk, err := NewPrivateKey(alg, key.PrivateKey)
	if err != nil {
		return nil, err
	}
	if hasPublicKey {
		var publicKey asn1.BitString
		if rest, err := asn1.UnmarshalWithParams(key.PublicKey.FullBytes, &publicKey, "tag:1"); err != nil || len(rest) != 0 {
			return nil, errors.New("compositemldsa: malformed PKCS #8 public key")
		}
		if publicKey.BitLength != 8*len(publicKey.Bytes) || !bytes.Equal(publicKey.Bytes, sk.pub.encoded) {
			return nil, errors.New("compositemldsa: PKCS #8 public key does not match the private key")
		}
	}
	return sk, nil
}

// Checks that PKCS #8 attributes are a SET OF Attribute as RFC 5958 defines them. An absent field
// passes.
func checkAttributes(attributes asn1.RawValue) error {
	if len(attributes.FullBytes) == 0 {
		return nil
	}
	if !attributes.IsCompound {
		return errMalformedAttributes
	}
	for rest := attributes.Bytes; len(rest) > 0; {
		element := rest
		var attr attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &attr); err != nil {
			return errMalformedAttributes
		}
		element = element[:len(element)-len(rest)]
		values := attr.Values
		if values.Class != asn1.ClassUniversal || values.Tag != asn1.TagSet || !values.IsCompound || len(values.Bytes) == 0 {
			return errMalformedAttributes
		}
		for body := values.Bytes; len(body) > 0; {
			var value asn1.RawValue
			if body, err = asn1.Unmarshal(body, &value); err != nil {
				return errMalformedAttributes
			}
		}
		// Rejects elements after the values, which encoding/asn1 would ignore.
		if again, err := asn1.Marshal(attr); err != nil || !bytes.Equal(again, element) {
			return errMalformedAttributes
		}
	}
	return nil
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
