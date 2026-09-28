package compositemldsa_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
)

// Returns the published private key of alg, so tests do not wait for RSA key generation.
func vectorKey(t testing.TB, alg compositemldsa.Algorithm) *compositemldsa.PrivateKey {
	t.Helper()
	for _, v := range loadVectors(t).Tests {
		if a, ok := vectorAlgorithm(v); ok && a == alg {
			sk, err := compositemldsa.NewPrivateKey(alg, v.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			return sk
		}
	}
	t.Fatalf("no vector for %s", alg)
	return nil
}

func TestAlgorithmMetadata(t *testing.T) {
	algs := compositemldsa.Algorithms()
	if len(algs) != 15 {
		t.Fatalf("%d algorithms, want 15", len(algs))
	}
	arcs := map[compositemldsa.Algorithm]int{
		compositemldsa.MLDSA44RSA2048PSSSHA256:    37,
		compositemldsa.MLDSA44RSA2048PKCS15SHA256: 38,
		compositemldsa.MLDSA44Ed25519SHA512:       39,
		compositemldsa.MLDSA44ECDSAP256SHA256:     40,
		compositemldsa.MLDSA65RSA3072PSSSHA512:    41,
		compositemldsa.MLDSA65RSA3072PKCS15SHA512: 42,
		compositemldsa.MLDSA65RSA4096PSSSHA512:    43,
		compositemldsa.MLDSA65RSA4096PKCS15SHA512: 44,
		compositemldsa.MLDSA65ECDSAP256SHA512:     45,
		compositemldsa.MLDSA65ECDSAP384SHA512:     46,
		compositemldsa.MLDSA65Ed25519SHA512:       48,
		compositemldsa.MLDSA87ECDSAP384SHA512:     49,
		compositemldsa.MLDSA87RSA3072PSSSHA512:    52,
		compositemldsa.MLDSA87RSA4096PSSSHA512:    53,
		compositemldsa.MLDSA87ECDSAP521SHA512:     54,
	}
	for _, alg := range algs {
		want := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, arcs[alg]}
		if !alg.OID().Equal(want) {
			t.Errorf("%s OID %s, want %s", alg, alg.OID(), want)
		}
		if got, ok := compositemldsa.AlgorithmFromOID(want); !ok || got != alg {
			t.Errorf("AlgorithmFromOID(%s) = %s, %v", want, got, ok)
		}
		wantHash := crypto.SHA512
		if strings.HasSuffix(alg.String(), "-SHA256") {
			wantHash = crypto.SHA256
		}
		if alg.PreHash() != wantHash {
			t.Errorf("%s pre-hash %s, want %s", alg, alg.PreHash(), wantHash)
		}
		if want := "MLDSA" + strings.TrimPrefix(alg.MLDSAParameters().String(), "ML-DSA-"); !strings.HasPrefix(alg.String(), want) {
			t.Errorf("%s ML-DSA parameters %s", alg, alg.MLDSAParameters())
		}
	}
	// Brainpool, Ed448 and pre-standard prototype OIDs are not supported.
	for _, oid := range []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 6, 47},
		{1, 3, 6, 1, 5, 5, 7, 6, 50},
		{1, 3, 6, 1, 5, 5, 7, 6, 51},
		{2, 16, 840, 1, 114027, 80, 9, 1, 4},
		{2, 16, 840, 1, 114027, 80, 8, 1, 4},
	} {
		if alg, ok := compositemldsa.AlgorithmFromOID(oid); ok {
			t.Errorf("AlgorithmFromOID(%s) = %s", oid, alg)
		}
	}
	var zero compositemldsa.Algorithm
	if zero.OID() != nil || zero.PreHash() != 0 || zero.String() == "" {
		t.Error("the zero Algorithm must report no OID and no pre-hash")
	}
}

func TestGenerateKey(t *testing.T) {
	for _, alg := range compositemldsa.Algorithms() {
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			sk, err := compositemldsa.GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			if sk.Algorithm() != alg || sk.PublicKey().Algorithm() != alg {
				t.Fatal("key reports the wrong algorithm")
			}
			again, err := compositemldsa.NewPrivateKey(alg, sk.Bytes())
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}
			if !again.Equal(sk) || !bytes.Equal(again.Bytes(), sk.Bytes()) {
				t.Error("private key does not round-trip")
			}
			pk, err := compositemldsa.NewPublicKey(alg, sk.PublicKey().Bytes())
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}
			if !pk.Equal(sk.Public()) {
				t.Error("public key does not round-trip")
			}
			message := []byte("composite round trip")
			sig, err := sk.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := compositemldsa.Verify(pk, message, sig, nil); err != nil {
				t.Fatal(err)
			}
			other, err := compositemldsa.GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			if other.Equal(sk) || other.PublicKey().Equal(pk) {
				t.Error("two generated keys compare equal")
			}
			if compositemldsa.Verify(other.PublicKey(), message, sig, nil) == nil {
				t.Error("signature verified under another key")
			}
		})
	}
}

func TestComponentKeyTypes(t *testing.T) {
	for _, alg := range compositemldsa.Algorithms() {
		pk := vectorKey(t, alg).PublicKey()
		if pk.MLDSAPublicKey().Parameters() != alg.MLDSAParameters() {
			t.Errorf("%s ML-DSA component has parameters %s", alg, pk.MLDSAPublicKey().Parameters())
		}
		name := alg.String()
		switch k := pk.TraditionalPublicKey().(type) {
		case *rsa.PublicKey:
			if !strings.Contains(name, "-RSA") {
				t.Errorf("%s has an RSA component", alg)
			}
		case *ecdsa.PublicKey:
			if !strings.Contains(name, "-ECDSA-"+strings.ReplaceAll(k.Curve.Params().Name, "-", "")+"-") {
				t.Errorf("%s has an ECDSA %s component", alg, k.Curve.Params().Name)
			}
		case ed25519.PublicKey:
			if !strings.Contains(name, "-Ed25519-") {
				t.Errorf("%s has an Ed25519 component", alg)
			}
		default:
			t.Errorf("%s has a %T component", alg, k)
		}
	}
}

func TestSignOptions(t *testing.T) {
	message := []byte("external pre-hashing")
	for _, alg := range []compositemldsa.Algorithm{compositemldsa.MLDSA44ECDSAP256SHA256, compositemldsa.MLDSA65Ed25519SHA512, compositemldsa.MLDSA87RSA3072PSSSHA512} {
		t.Run(alg.String(), func(t *testing.T) {
			sk := vectorKey(t, alg)
			pk := sk.PublicKey()
			var digest []byte
			if alg.PreHash() == crypto.SHA256 {
				sum := sha256.Sum256(message)
				digest = sum[:]
			} else {
				sum := sha512.Sum512(message)
				digest = sum[:]
			}

			sig, err := sk.Sign(nil, digest, alg.PreHash())
			if err != nil {
				t.Fatalf("Sign with a digest: %v", err)
			}
			if err := compositemldsa.Verify(pk, message, sig, nil); err != nil {
				t.Errorf("digest signature over the message: %v", err)
			}
			if err := compositemldsa.Verify(pk, digest, sig, &compositemldsa.Options{Hash: alg.PreHash()}); err != nil {
				t.Errorf("digest signature over the digest: %v", err)
			}

			sig, err = sk.SignMessage(nil, message, &compositemldsa.Options{Context: "app", Hash: alg.PreHash()})
			if err != nil {
				t.Fatalf("SignMessage: %v", err)
			}
			if err := compositemldsa.Verify(pk, message, sig, &compositemldsa.Options{Context: "app"}); err != nil {
				t.Errorf("SignMessage signature: %v", err)
			}
			if sig, err = crypto.SignMessage(sk, nil, message, crypto.Hash(0)); err != nil {
				t.Fatalf("crypto.SignMessage: %v", err)
			}
			if err := compositemldsa.Verify(pk, message, sig, nil); err != nil {
				t.Errorf("crypto.SignMessage signature: %v", err)
			}

			if _, err := sk.Sign(nil, digest, crypto.SHA384); err == nil {
				t.Error("signed with a hash that is not the pre-hash")
			}
			if _, err := sk.SignMessage(nil, message, crypto.SHA384); err == nil {
				t.Error("SignMessage accepted a hash that is not the pre-hash")
			}
			if _, err := sk.Sign(nil, digest[1:], alg.PreHash()); err == nil {
				t.Error("signed a digest of the wrong length")
			}
			long := &compositemldsa.Options{Context: strings.Repeat("x", 256)}
			if _, err := sk.Sign(nil, message, long); err == nil {
				t.Error("signed with a 256-byte context")
			}
			if err := compositemldsa.Verify(pk, message, sig, long); err == nil {
				t.Error("verified with a 256-byte context")
			}
			if sig, err = sk.Sign(nil, message, &compositemldsa.Options{Context: strings.Repeat("x", 255)}); err != nil {
				t.Errorf("255-byte context: %v", err)
			} else if err := compositemldsa.Verify(pk, message, sig, &compositemldsa.Options{Context: strings.Repeat("x", 255)}); err != nil {
				t.Errorf("255-byte context: %v", err)
			}
		})
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	message := []byte("both components must verify")
	for _, alg := range compositemldsa.Algorithms() {
		t.Run(alg.String(), func(t *testing.T) {
			sk := vectorKey(t, alg)
			pk := sk.PublicKey()
			sig, err := sk.Sign(nil, message, nil)
			if err != nil {
				t.Fatal(err)
			}
			mldsaSize := alg.MLDSAParameters().SignatureSize()
			for name, index := range map[string]int{"ML-DSA component": 10, "traditional component": len(sig) - 5} {
				bad := bytes.Clone(sig)
				bad[index] ^= 0x01
				if compositemldsa.Verify(pk, message, bad, nil) == nil {
					t.Errorf("verified with a modified %s", name)
				}
			}
			for name, bad := range map[string][]byte{
				"ML-DSA signature only":  sig[:mldsaSize],
				"truncated":              sig[:len(sig)-1],
				"trailing byte":          append(bytes.Clone(sig), 0),
				"empty":                  nil,
				"traditional part moved": append(bytes.Clone(sig[mldsaSize:]), sig[:mldsaSize]...),
			} {
				if compositemldsa.Verify(pk, message, bad, nil) == nil {
					t.Errorf("verified a signature that is %s", name)
				}
			}
			if compositemldsa.Verify(pk, append(bytes.Clone(message), '.'), sig, nil) == nil {
				t.Error("verified a different message")
			}
		})
	}
}

// The label binds each signature to its algorithm, so a component signature that would verify
// under another combination with the same traditional key type is still rejected.
func TestLabelSeparatesAlgorithms(t *testing.T) {
	a := vectorKey(t, compositemldsa.MLDSA65RSA4096PSSSHA512)
	b := vectorKey(t, compositemldsa.MLDSA65RSA4096PKCS15SHA512)
	message := []byte("label separation")
	sig, err := a.Sign(nil, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Same ML-DSA-65 and RSA-4096 sizes, so only the label and padding differ.
	forged, err := compositemldsa.NewPublicKey(compositemldsa.MLDSA65RSA4096PKCS15SHA512, a.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if compositemldsa.Verify(forged, message, sig, nil) == nil {
		t.Error("signature verified under another algorithm with the same component keys")
	}
	if compositemldsa.Verify(b.PublicKey(), message, sig, nil) == nil {
		t.Error("signature verified under another key")
	}
	if compositemldsa.Verify(nil, message, sig, nil) == nil {
		t.Error("verified with a nil key")
	}
}

func TestParseRejectsMalformedKeys(t *testing.T) {
	rsaVector := vectorKey(t, compositemldsa.MLDSA44RSA2048PSSSHA256)
	p256 := vectorKey(t, compositemldsa.MLDSA44ECDSAP256SHA256)
	ed := vectorKey(t, compositemldsa.MLDSA44Ed25519SHA512)

	cases := []struct {
		name string
		alg  compositemldsa.Algorithm
		pub  []byte
	}{
		{"RSA-2048 key for an RSA-3072 algorithm", compositemldsa.MLDSA65RSA3072PSSSHA512, append(vectorKey(t, compositemldsa.MLDSA65RSA3072PSSSHA512).PublicKey().MLDSAPublicKey().Bytes(), rsaVector.PublicKey().Bytes()[1312:]...)},
		{"P-256 point for a P-384 algorithm", compositemldsa.MLDSA65ECDSAP384SHA512, append(vectorKey(t, compositemldsa.MLDSA65ECDSAP384SHA512).PublicKey().MLDSAPublicKey().Bytes(), p256.PublicKey().Bytes()[1312:]...)},
		{"short Ed25519 key", compositemldsa.MLDSA44Ed25519SHA512, ed.PublicKey().Bytes()[:len(ed.PublicKey().Bytes())-1]},
		{"long Ed25519 key", compositemldsa.MLDSA44Ed25519SHA512, append(ed.PublicKey().Bytes(), 0)},
		{"ML-DSA key only", compositemldsa.MLDSA44Ed25519SHA512, ed.PublicKey().Bytes()[:1312]},
		{"compressed point", compositemldsa.MLDSA44ECDSAP256SHA256, append(p256.PublicKey().Bytes()[:1312], append([]byte{0x02}, p256.PublicKey().Bytes()[1313:1345]...)...)},
		{"trailing data after RSA key", compositemldsa.MLDSA44RSA2048PSSSHA256, append(rsaVector.PublicKey().Bytes(), 0)},
		{"unknown algorithm", 0, ed.PublicKey().Bytes()},
	}
	for _, c := range cases {
		if _, err := compositemldsa.NewPublicKey(c.alg, c.pub); err == nil {
			t.Errorf("NewPublicKey accepted %s", c.name)
		}
	}

	otherCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := otherCurve.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := asn1.Marshal(struct {
		Version    int
		PrivateKey []byte
		Curve      asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	}{1, scalar, asn1.ObjectIdentifier{1, 3, 132, 0, 34}})
	if err != nil {
		t.Fatal(err)
	}
	// crypto/x509 includes the public key, which section 4 of the draft excludes.
	sameCurve, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	withPublicKey, err := x509.MarshalECPrivateKey(sameCurve)
	if err != nil {
		t.Fatal(err)
	}
	privateCases := []struct {
		name string
		alg  compositemldsa.Algorithm
		priv []byte
	}{
		{"P-384 key for a P-256 algorithm", compositemldsa.MLDSA44ECDSAP256SHA256, append(p256.Bytes()[:32], p384DER...)},
		{"RSA-2048 key for an RSA-4096 algorithm", compositemldsa.MLDSA65RSA4096PSSSHA512, rsaVector.Bytes()},
		{"ECDSA key with its public key", compositemldsa.MLDSA44ECDSAP256SHA256, append(p256.Bytes()[:32], withPublicKey...)},
		{"trailing data after ECDSA key", compositemldsa.MLDSA44ECDSAP256SHA256, append(p256.Bytes(), 0)},
		{"trailing data after RSA key", compositemldsa.MLDSA44RSA2048PSSSHA256, append(rsaVector.Bytes(), 0)},
		{"trailing data after Ed25519 seed", compositemldsa.MLDSA44Ed25519SHA512, append(ed.Bytes(), 0)},
		{"seed only", compositemldsa.MLDSA44Ed25519SHA512, ed.Bytes()[:32]},
		{"short Ed25519 seed", compositemldsa.MLDSA44Ed25519SHA512, ed.Bytes()[:63]},
		{"unknown algorithm", 0, ed.Bytes()},
	}
	for _, c := range privateCases {
		if _, err := compositemldsa.NewPrivateKey(c.alg, c.priv); err == nil {
			t.Errorf("NewPrivateKey accepted %s", c.name)
		}
	}
}

func TestPKIXEncodings(t *testing.T) {
	sk := vectorKey(t, compositemldsa.MLDSA65ECDSAP256SHA512)
	spki, err := compositemldsa.MarshalPKIXPublicKey(sk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if pk, err := compositemldsa.ParsePKIXPublicKey(spki); err != nil || !pk.Equal(sk.Public()) {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		t.Fatal(err)
	}
	if len(info.Algorithm.Parameters.FullBytes) != 0 {
		t.Error("SubjectPublicKeyInfo carries parameters")
	}

	withNull := info
	withNull.Algorithm.Parameters = asn1.NullRawValue
	prototype := info
	prototype.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 9, 1, 5}
	unusedBits := info
	unusedBits.PublicKey.BitLength--
	extraElement := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
		Extra     asn1.RawValue
	}{info.Algorithm, info.PublicKey, asn1.NullRawValue}
	for name, v := range map[string]any{"NULL parameters": withNull, "prototype OID": prototype, "unused bits": unusedBits, "an extra element": extraElement} {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := compositemldsa.ParsePKIXPublicKey(der); err == nil {
			t.Errorf("ParsePKIXPublicKey accepted %s", name)
		}
	}
	if _, err := compositemldsa.ParsePKIXPublicKey(append(bytes.Clone(spki), 0)); err == nil {
		t.Error("ParsePKIXPublicKey accepted trailing data")
	}

	pkcs8, err := compositemldsa.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	type oneAsymmetricKey struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		PublicKey  asn1.BitString `asn1:"optional,tag:1"`
	}
	var key oneAsymmetricKey
	if _, err := asn1.Unmarshal(pkcs8, &key); err != nil {
		t.Fatal(err)
	}
	withPublic := key
	withPublic.Version = 1
	withPublic.PublicKey = asn1.BitString{Bytes: sk.PublicKey().Bytes(), BitLength: 8 * len(sk.PublicKey().Bytes())}
	der, err := asn1.Marshal(withPublic)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := compositemldsa.ParsePKCS8PrivateKey(der); err != nil || !parsed.Equal(sk) {
		t.Errorf("OneAsymmetricKey with a matching public key: %v", err)
	}

	other := vectorKey(t, compositemldsa.MLDSA65ECDSAP384SHA512)
	mismatch := withPublic
	mismatch.PublicKey = asn1.BitString{Bytes: other.PublicKey().Bytes(), BitLength: 8 * len(other.PublicKey().Bytes())}
	v0WithPublic := withPublic
	v0WithPublic.Version = 0
	v2 := key
	v2.Version = 2
	nullParams := key
	nullParams.Algorithm.Parameters = asn1.NullRawValue
	for name, v := range map[string]oneAsymmetricKey{"mismatched public key": mismatch, "version 0 with a public key": v0WithPublic, "version 2": v2, "NULL parameters": nullParams} {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := compositemldsa.ParsePKCS8PrivateKey(der); err == nil {
			t.Errorf("ParsePKCS8PrivateKey accepted %s", name)
		}
	}
	if _, err := compositemldsa.MarshalPKIXPublicKey(nil); err == nil {
		t.Error("MarshalPKIXPublicKey accepted a nil key")
	}
	if _, err := compositemldsa.MarshalPKCS8PrivateKey(nil); err == nil {
		t.Error("MarshalPKCS8PrivateKey accepted a nil key")
	}
}
