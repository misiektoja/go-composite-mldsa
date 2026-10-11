package compositex509_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
			if pub != nil {
				t.Fatalf("failed parse returned a %T key", pub)
			}
			return
		}
		if _, err := compositex509.MarshalPKIXPublicKey(pub); err != nil {
			t.Fatalf("accepted key of type %T does not re-encode: %v", pub, err)
		}
	})
}

// Parses arbitrary PKCS #8 input. A composite key or any key crypto/x509 accepts must come back as
// that key and re-encode, and a failed parse must return a nil key.
func FuzzParsePKCS8PrivateKey(f *testing.F) {
	for _, alg := range []compositemldsa.Algorithm{compositemldsa.MLDSA44Ed25519SHA512, compositemldsa.MLDSA65ECDSAP256SHA512, compositemldsa.MLDSA87RSA4096PSSSHA512} {
		der, err := compositex509.MarshalPKCS8PrivateKey(vectorKey(f, alg))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	for _, key := range []any{ecKey, edKey} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
	}
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sec1)
	f.Fuzz(func(t *testing.T, der []byte) {
		key, err := compositex509.ParsePKCS8PrivateKey(der)
		if err != nil && key != nil {
			t.Fatalf("failed parse returned a %T key", key)
		}
		if want, wantErr := compositemldsa.ParsePKCS8PrivateKey(der); wantErr == nil {
			if !want.Equal(key) {
				t.Fatalf("composite key parsed as %T, %v", key, err)
			}
		} else if want, wantErr := x509.ParsePKCS8PrivateKey(der); wantErr == nil {
			if equal, ok := want.(interface{ Equal(crypto.PrivateKey) bool }); !ok || !equal.Equal(key) {
				t.Fatalf("%T key accepted by crypto/x509 parsed as %T, %v", want, key, err)
			}
		}
		if err != nil {
			return
		}
		again, err := compositex509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("accepted key of type %T does not re-encode: %v", key, err)
		}
		parsed, err := compositex509.ParsePKCS8PrivateKey(again)
		if equal, ok := key.(interface{ Equal(crypto.PrivateKey) bool }); err != nil || !ok || !equal.Equal(parsed) {
			t.Fatalf("accepted key of type %T does not round-trip: %v", key, err)
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
