package compositemldsa_test

import (
	"bytes"
	"testing"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
)

func FuzzParsePKIXPublicKey(f *testing.F) {
	for _, v := range loadVectors(f).Tests {
		if alg, ok := vectorAlgorithm(v); ok {
			pk, err := compositemldsa.NewPublicKey(alg, v.PublicKey)
			if err != nil {
				f.Fatal(err)
			}
			spki, err := compositemldsa.MarshalPKIXPublicKey(pk)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(spki)
		}
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		pk, err := compositemldsa.ParsePKIXPublicKey(der)
		if err != nil {
			return
		}
		again, err := compositemldsa.MarshalPKIXPublicKey(pk)
		if err != nil || !bytes.Equal(again, der) {
			t.Fatalf("accepted SubjectPublicKeyInfo does not re-encode identically: %v", err)
		}
	})
}

func FuzzParsePKCS8PrivateKey(f *testing.F) {
	for _, v := range loadVectors(f).Tests {
		if _, ok := vectorAlgorithm(v); ok {
			f.Add(v.PKCS8)
		}
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		sk, err := compositemldsa.ParsePKCS8PrivateKey(der)
		if err != nil {
			return
		}
		again, err := compositemldsa.MarshalPKCS8PrivateKey(sk)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := compositemldsa.ParsePKCS8PrivateKey(again)
		if err != nil || !parsed.Equal(sk) {
			t.Fatalf("accepted private key does not round-trip: %v", err)
		}
	})
}

func FuzzVerify(f *testing.F) {
	vf := loadVectors(f)
	var keys []*compositemldsa.PublicKey
	for _, v := range vf.Tests {
		if alg, ok := vectorAlgorithm(v); ok {
			pk, err := compositemldsa.NewPublicKey(alg, v.PublicKey)
			if err != nil {
				f.Fatal(err)
			}
			keys = append(keys, pk)
			f.Add(uint8(len(keys)-1), v.Signature)
		}
	}
	f.Fuzz(func(t *testing.T, index uint8, signature []byte) {
		// Only a crash is a failure. Valid signatures other than the seeds exist, such as an ECDSA
		// component with s replaced by n - s.
		_ = compositemldsa.Verify(keys[int(index)%len(keys)], vf.Message, signature, nil)
	})
}
