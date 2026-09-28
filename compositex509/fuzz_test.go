package compositex509_test

import (
	"crypto/rand"
	"crypto/x509"
	"testing"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

func FuzzParsePKIXPublicKey(f *testing.F) {
	for _, alg := range compositemldsa.Algorithms() {
		spki, err := compositex509.MarshalPKIXPublicKey(vectorKey(f, alg).Public())
		if err != nil {
			f.Fatal(err)
		}
		f.Add(spki)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		pub, err := compositex509.ParsePKIXPublicKey(der)
		if err != nil {
			return
		}
		if _, err := compositex509.MarshalPKIXPublicKey(pub); err != nil {
			t.Fatalf("accepted key of type %T does not re-encode: %v", pub, err)
		}
	})
}

// Parses arbitrary certificates and checks them against a composite issuer and themselves.
func FuzzCertificate(f *testing.F) {
	key := vectorKey(f, compositemldsa.MLDSA44ECDSAP256SHA256)
	root, err := compositex509.CreateCertificate(rand.Reader, caTemplate("Fuzz Root"), caTemplate("Fuzz Root"), key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(root)
	if err != nil {
		f.Fatal(err)
	}
	leaf, err := compositex509.CreateCertificate(rand.Reader, leafTemplate("fuzz.example.test"), issuer, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(root)
	f.Add(leaf)
	f.Fuzz(func(t *testing.T, der []byte) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return
		}
		_, _, _ = compositex509.SignatureAlgorithm(cert.Raw)
		_, _ = compositex509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
		_ = compositex509.CheckSignatureFrom(cert, issuer)
		_ = compositex509.CheckSignatureFrom(cert, cert)
	})
}
