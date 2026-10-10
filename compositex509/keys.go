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
// every other key as crypto/x509 returns it. The key is nil when the error is not.
func ParsePKIXPublicKey(der []byte) (any, error) {
	pk, err := compositePublicKey(der)
	if err != nil {
		return nil, err
	}
	if pk != nil {
		return pk, nil
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
// every other key as crypto/x509 returns it. The key is nil when the error is not.
func ParsePKCS8PrivateKey(der []byte) (any, error) {
	elements, err := sequenceElements(der)
	if err == nil && len(elements) >= 2 && namesCompositeAlgorithm(elements[1]) {
		// Returning the typed result directly would wrap a nil *PrivateKey in a non-nil any.
		sk, err := compositemldsa.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		return sk, nil
	}
	return x509.ParsePKCS8PrivateKey(der)
}

// Decodes a DER SubjectPublicKeyInfo when it names a composite algorithm. It returns nil for any
// other algorithm and for input that is not a SubjectPublicKeyInfo, which crypto/x509 then reports.
func compositePublicKey(der []byte) (*compositemldsa.PublicKey, error) {
	elements, err := sequenceElements(der)
	if err != nil || len(elements) != 2 || !namesCompositeAlgorithm(elements[0]) {
		return nil, nil
	}
	return compositemldsa.ParsePKIXPublicKey(der)
}
