package compositemldsa_test

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
)

// Test vectors published with draft-ietf-lamps-pq-composite-sigs-19. See testdata/README.md.
type vectorFile struct {
	Message []byte   `json:"m"`
	Context []byte   `json:"ctx"`
	Tests   []vector `json:"tests"`
}

type vector struct {
	ID               string `json:"tcId"`
	PublicKey        []byte `json:"pk"`
	Certificate      []byte `json:"x5c"`
	PrivateKey       []byte `json:"sk"`
	PKCS8            []byte `json:"sk_pkcs8"`
	Signature        []byte `json:"s"`
	ContextSignature []byte `json:"sWithContext"`
}

// Decodes the published vectors once. encoding/json decodes the base64 fields into byte slices.
var decodedVectors = sync.OnceValues(func() (vectorFile, error) {
	var vf vectorFile
	data, err := os.ReadFile("testdata/draft-19-testvectors.json")
	if err == nil {
		err = json.Unmarshal(data, &vf)
	}
	return vf, err
})

// Returns the published vectors.
func loadVectors(t testing.TB) vectorFile {
	t.Helper()
	vf, err := decodedVectors()
	if err != nil {
		t.Fatal(err)
	}
	return vf
}

// Returns the algorithm a vector names. It reports false for pure ML-DSA and unsupported composites.
func vectorAlgorithm(v vector) (compositemldsa.Algorithm, bool) {
	for _, alg := range compositemldsa.Algorithms() {
		if v.ID == "id-"+alg.String() {
			return alg, true
		}
	}
	return 0, false
}

func TestVectorsCoverEverySupportedAlgorithm(t *testing.T) {
	vf := loadVectors(t)
	seen := map[compositemldsa.Algorithm]bool{}
	unsupported := []string{}
	for _, v := range vf.Tests {
		if alg, ok := vectorAlgorithm(v); ok {
			seen[alg] = true
		} else if !strings.HasPrefix(v.ID, "id-ML-DSA-") {
			unsupported = append(unsupported, v.ID)
		}
	}
	for _, alg := range compositemldsa.Algorithms() {
		if !seen[alg] {
			t.Errorf("no vector for %s", alg)
		}
	}
	want := []string{"id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", "id-MLDSA87-Ed448-SHAKE256"}
	if strings.Join(unsupported, ",") != strings.Join(want, ",") {
		t.Errorf("unsupported vectors = %v, want %v", unsupported, want)
	}
}

func TestVectors(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Tests {
		alg, ok := vectorAlgorithm(v)
		if !ok {
			continue
		}
		t.Run(alg.String(), func(t *testing.T) {
			pk, err := compositemldsa.NewPublicKey(alg, v.PublicKey)
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}
			if !bytes.Equal(pk.Bytes(), v.PublicKey) {
				t.Error("public key does not round-trip")
			}

			sk, err := compositemldsa.NewPrivateKey(alg, v.PrivateKey)
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}
			if !bytes.Equal(sk.Bytes(), v.PrivateKey) {
				t.Error("private key does not round-trip")
			}
			if !sk.PublicKey().Equal(pk) {
				t.Error("private key derives a different public key")
			}

			parsed, err := compositemldsa.ParsePKCS8PrivateKey(v.PKCS8)
			if err != nil {
				t.Fatalf("ParsePKCS8PrivateKey: %v", err)
			}
			if !parsed.Equal(sk) {
				t.Error("PKCS #8 key differs from the raw key")
			}
			if der, err := compositemldsa.MarshalPKCS8PrivateKey(sk); err != nil || !bytes.Equal(der, v.PKCS8) {
				t.Errorf("MarshalPKCS8PrivateKey differs from the vector: %v", err)
			}

			if err := compositemldsa.Verify(pk, vf.Message, v.Signature, nil); err != nil {
				t.Errorf("vector signature: %v", err)
			}
			opts := &compositemldsa.Options{Context: string(vf.Context)}
			if err := compositemldsa.Verify(pk, vf.Message, v.ContextSignature, opts); err != nil {
				t.Errorf("vector signature with context: %v", err)
			}
			if compositemldsa.Verify(pk, vf.Message, v.ContextSignature, nil) == nil {
				t.Error("context signature verified without the context")
			}
			if compositemldsa.Verify(pk, vf.Message, v.Signature, opts) == nil {
				t.Error("signature verified with a context it was not made for")
			}

			sig, err := sk.Sign(nil, vf.Message, opts)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if err := compositemldsa.Verify(pk, vf.Message, sig, opts); err != nil {
				t.Errorf("own signature: %v", err)
			}

			checkVectorCertificate(t, alg, pk, v.Certificate)
		})
	}
}

// Checks that the vector's self-signed certificate carries the public key and a valid signature.
func checkVectorCertificate(t *testing.T, alg compositemldsa.Algorithm, pk *compositemldsa.PublicKey, der []byte) {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	certKey, err := compositemldsa.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	if !certKey.Equal(pk) {
		t.Error("certificate carries a different public key")
	}
	if spki, err := compositemldsa.MarshalPKIXPublicKey(pk); err != nil || !bytes.Equal(spki, cert.RawSubjectPublicKeyInfo) {
		t.Errorf("MarshalPKIXPublicKey differs from the certificate: %v", err)
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm struct{ Algorithm asn1.ObjectIdentifier }
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatal(err)
	}
	if !outer.Algorithm.Algorithm.Equal(alg.OID()) {
		t.Errorf("certificate signature algorithm %s, want %s", outer.Algorithm.Algorithm, alg.OID())
	}
	if err := compositemldsa.Verify(pk, cert.RawTBSCertificate, cert.Signature, nil); err != nil {
		t.Errorf("certificate signature: %v", err)
	}
}
