package compositex509

import (
	"crypto/x509"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
)

// Encodes a composite key or any key crypto/x509 supports as a DER SubjectPublicKeyInfo.
func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	if pk, ok := pub.(*compositemldsa.PublicKey); ok {
		return compositemldsa.MarshalPKIXPublicKey(pk)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// Decodes a DER SubjectPublicKeyInfo. Composite keys are returned as *compositemldsa.PublicKey and
// every other key as crypto/x509 returns it.
func ParsePKIXPublicKey(der []byte) (any, error) {
	pk, err := compositePublicKey(der)
	if err != nil || pk != nil {
		return pk, err
	}
	return x509.ParsePKIXPublicKey(der)
}

// Encodes a composite key or any key crypto/x509 supports as a DER PKCS #8 PrivateKeyInfo.
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	if sk, ok := key.(*compositemldsa.PrivateKey); ok {
		return compositemldsa.MarshalPKCS8PrivateKey(sk)
	}
	return x509.MarshalPKCS8PrivateKey(key)
}

// Decodes a DER PKCS #8 private key. Composite keys are returned as *compositemldsa.PrivateKey and
// every other key as crypto/x509 returns it.
func ParsePKCS8PrivateKey(der []byte) (any, error) {
	elements, err := sequenceElements(der)
	if err == nil && len(elements) >= 2 {
		if _, ok, err := compositeAlgorithm(elements[1]); err != nil {
			return nil, err
		} else if ok {
			return compositemldsa.ParsePKCS8PrivateKey(der)
		}
	}
	return x509.ParsePKCS8PrivateKey(der)
}

// Decodes a DER SubjectPublicKeyInfo when it names a composite algorithm and returns nil for any
// other algorithm.
func compositePublicKey(der []byte) (*compositemldsa.PublicKey, error) {
	elements, err := sequenceElements(der)
	if err != nil || len(elements) != 2 {
		return nil, nil
	}
	if _, ok, err := compositeAlgorithm(elements[0]); err != nil || !ok {
		return nil, err
	}
	return compositemldsa.ParsePKIXPublicKey(der)
}
