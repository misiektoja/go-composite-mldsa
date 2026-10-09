package compositex509_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

// Decodes the private keys published with the draft once, so tests do not wait for RSA key
// generation.
var vectorKeys = sync.OnceValues(func() (map[compositemldsa.Algorithm]*compositemldsa.PrivateKey, error) {
	data, err := os.ReadFile("../testdata/draft-19-testvectors.json")
	if err != nil {
		return nil, err
	}
	var vf struct {
		Tests []struct {
			ID         string `json:"tcId"`
			PrivateKey []byte `json:"sk"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, err
	}
	keys := map[compositemldsa.Algorithm]*compositemldsa.PrivateKey{}
	for _, alg := range compositemldsa.Algorithms() {
		for _, v := range vf.Tests {
			if v.ID == "id-"+alg.String() {
				if keys[alg], err = compositemldsa.NewPrivateKey(alg, v.PrivateKey); err != nil {
					return nil, err
				}
			}
		}
	}
	return keys, nil
})

// Returns the published private key of alg.
func vectorKey(t testing.TB, alg compositemldsa.Algorithm) *compositemldsa.PrivateKey {
	t.Helper()
	keys, err := vectorKeys()
	if err != nil {
		t.Fatal(err)
	}
	if keys[alg] == nil {
		t.Fatalf("no vector key for %s", alg)
	}
	return keys[alg]
}

var serial int64

// Returns a CA template with the given common name.
func caTemplate(name string) *x509.Certificate {
	serial++
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

// Returns an end-entity template with the given DNS name.
func leafTemplate(name string) *x509.Certificate {
	serial++
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

// Creates and parses a certificate.
func issue(t *testing.T, template, parent *x509.Certificate, pub, priv any) *x509.Certificate {
	t.Helper()
	der, err := compositex509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestCompositeHierarchy(t *testing.T) {
	for _, alg := range compositemldsa.Algorithms() {
		t.Run(alg.String(), func(t *testing.T) {
			rootKey := vectorKey(t, alg)
			root := issue(t, caTemplate("Composite Root"), caTemplate("Composite Root"), rootKey.Public(), rootKey)
			if err := compositex509.CheckSignatureFrom(root, root); err != nil {
				t.Fatalf("root self-signature: %v", err)
			}
			if got, ok, err := compositex509.SignatureAlgorithm(root.Raw); err != nil || !ok || got != alg {
				t.Errorf("SignatureAlgorithm = %s, %v, %v", got, ok, err)
			}
			if root.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm || root.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
				t.Error("crypto/x509 recognised a composite algorithm, the pass-through logic needs review")
			}
			sum := sha256.Sum256(rootKey.PublicKey().Bytes())
			if !bytes.Equal(root.SubjectKeyId, sum[:20]) {
				t.Error("root subject key identifier is not the truncated SHA-256 of the key")
			}
			pub, err := compositex509.ParsePKIXPublicKey(root.RawSubjectPublicKeyInfo)
			if err != nil || !rootKey.PublicKey().Equal(pub.(crypto.PublicKey)) {
				t.Fatalf("root public key: %v", err)
			}

			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := issue(t, leafTemplate("device.example.test"), root, &leafKey.PublicKey, rootKey)
			if err := compositex509.CheckSignatureFrom(leaf, root); err != nil {
				t.Errorf("ECDSA leaf from composite root: %v", err)
			}
			if !bytes.Equal(leaf.AuthorityKeyId, root.SubjectKeyId) {
				t.Error("leaf authority key identifier does not name the root")
			}
			if !leafKey.PublicKey.Equal(leaf.PublicKey) {
				t.Error("leaf carries the wrong public key")
			}

			other := vectorKey(t, compositemldsa.MLDSA87ECDSAP384SHA512)
			compositeLeaf := issue(t, leafTemplate("composite.example.test"), root, other.Public(), rootKey)
			if err := compositex509.CheckSignatureFrom(compositeLeaf, root); err != nil {
				t.Errorf("composite leaf from composite root: %v", err)
			}
			if leafPub, err := compositex509.ParsePKIXPublicKey(compositeLeaf.RawSubjectPublicKeyInfo); err != nil || !other.PublicKey().Equal(leafPub.(crypto.PublicKey)) {
				t.Errorf("composite leaf public key: %v", err)
			}
			if len(compositeLeaf.SubjectKeyId) != 0 {
				t.Error("end-entity certificate received a subject key identifier it did not ask for")
			}

			crlDER, err := compositex509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:     big.NewInt(1),
				ThisUpdate: time.Now(),
				NextUpdate: time.Now().Add(time.Hour),
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now(), ReasonCode: 1},
				},
			}, root, rootKey)
			if err != nil {
				t.Fatalf("CreateRevocationList: %v", err)
			}
			crl, err := x509.ParseRevocationList(crlDER)
			if err != nil {
				t.Fatal(err)
			}
			if err := compositex509.CheckRevocationListSignatureFrom(crl, root); err != nil {
				t.Errorf("CRL signature: %v", err)
			}
			if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
				t.Error("CRL lost its entry")
			}

			csrDER, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "request"}, DNSNames: []string{"request.example.test"}}, rootKey)
			if err != nil {
				t.Fatalf("CreateCertificateRequest: %v", err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatal(err)
			}
			if err := compositex509.CheckCertificateRequestSignature(csr); err != nil {
				t.Errorf("CSR signature: %v", err)
			}
			if csr.DNSNames[0] != "request.example.test" {
				t.Error("CSR lost its requested name")
			}
		})
	}
}

// Standard library issuers sign composite subordinate CAs that in turn sign standard keys.
func TestMixedHierarchies(t *testing.T) {
	composite := vectorKey(t, compositemldsa.MLDSA65ECDSAP256SHA512)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	issuers := []struct {
		name      string
		key       crypto.Signer
		algorithm x509.SignatureAlgorithm
		want      x509.SignatureAlgorithm
	}{
		{"ECDSA P-384", p384, 0, x509.ECDSAWithSHA384},
		{"RSA PKCS #1", rsaKey, 0, x509.SHA256WithRSA},
		{"RSA-PSS", rsaKey, x509.SHA512WithRSAPSS, x509.SHA512WithRSAPSS},
		{"Ed25519", edKey, 0, x509.PureEd25519},
		{"ML-DSA-65", mlKey, 0, x509.MLDSA65},
	}
	for _, is := range issuers {
		t.Run(is.name, func(t *testing.T) {
			rootTemplate := caTemplate("Classical Root")
			rootTemplate.SignatureAlgorithm = is.algorithm
			root := issue(t, rootTemplate, rootTemplate, is.key.Public(), is.key)
			subTemplate := caTemplate("Composite Sub CA")
			subTemplate.SignatureAlgorithm = is.algorithm
			sub := issue(t, subTemplate, root, composite.Public(), is.key)
			if sub.SignatureAlgorithm != is.want {
				t.Errorf("signature algorithm %s, want %s", sub.SignatureAlgorithm, is.want)
			}
			if err := sub.CheckSignatureFrom(root); err != nil {
				t.Errorf("crypto/x509 check of the composite sub CA: %v", err)
			}
			if err := compositex509.CheckSignatureFrom(sub, root); err != nil {
				t.Errorf("compositex509 check of the composite sub CA: %v", err)
			}
			if !bytes.Equal(sub.AuthorityKeyId, root.SubjectKeyId) {
				t.Error("sub CA authority key identifier does not name the root")
			}
			leaf := issue(t, leafTemplate("leaf.example.test"), sub, is.key.Public(), composite)
			if err := compositex509.CheckSignatureFrom(leaf, sub); err != nil {
				t.Errorf("standard leaf from composite sub CA: %v", err)
			}
		})
	}
}

// A composite signer that is not a *compositemldsa.PrivateKey, such as a remote signing service.
type remoteSigner struct {
	key   *compositemldsa.PrivateKey
	calls int
}

func (s *remoteSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *remoteSigner) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	if opts.HashFunc() != 0 {
		return nil, errors.New("remote signer only signs complete messages")
	}
	return s.key.Sign(random, message, nil)
}

func TestRemoteSigner(t *testing.T) {
	signer := &remoteSigner{key: vectorKey(t, compositemldsa.MLDSA44ECDSAP256SHA256)}
	root := issue(t, caTemplate("Remote Root"), caTemplate("Remote Root"), signer.Public(), signer)
	if err := compositex509.CheckSignatureFrom(root, root); err != nil {
		t.Fatal(err)
	}
	if signer.calls != 1 {
		t.Errorf("signer called %d times, want once", signer.calls)
	}
}

// Returns a signer whose signatures are always invalid.
type brokenSigner struct{ *compositemldsa.PrivateKey }

func (s brokenSigner) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.PrivateKey.Sign(random, message, opts)
	if err == nil {
		sig[0] ^= 1
	}
	return sig, err
}

func TestCreateRejects(t *testing.T) {
	rootKey := vectorKey(t, compositemldsa.MLDSA65ECDSAP384SHA512)
	otherKey := vectorKey(t, compositemldsa.MLDSA87ECDSAP521SHA512)
	root := issue(t, caTemplate("Root"), caTemplate("Root"), rootKey.Public(), rootKey)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	withAlgorithm := leafTemplate("a.example.test")
	withAlgorithm.SignatureAlgorithm = x509.ECDSAWithSHA256
	encipherment := leafTemplate("b.example.test")
	encipherment.KeyUsage |= x509.KeyUsageKeyEncipherment
	agreement := leafTemplate("c.example.test")
	agreementUsage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x08}, BitLength: 5})
	if err != nil {
		t.Fatal(err)
	}
	agreement.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: agreementUsage}}
	empty := leafTemplate("d.example.test")
	emptyUsage, err := asn1.Marshal(asn1.BitString{})
	if err != nil {
		t.Fatal(err)
	}
	empty.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: emptyUsage}}

	cases := []struct {
		name     string
		template *x509.Certificate
		parent   *x509.Certificate
		pub      any
		priv     any
	}{
		{"a SignatureAlgorithm for a composite signer", withAlgorithm, root, &ecKey.PublicKey, rootKey},
		{"a signer that does not hold the parent key", leafTemplate("e.example.test"), root, &ecKey.PublicKey, otherKey},
		{"a standard signer for a composite parent", leafTemplate("f.example.test"), root, otherKey.Public(), ecKey},
		{"key encipherment for a composite key", encipherment, root, otherKey.Public(), rootKey},
		{"key agreement for a composite key in an extra extension", agreement, root, otherKey.Public(), rootKey},
		{"an empty key usage extension for a composite key", empty, root, otherKey.Public(), rootKey},
		{"a signer returning invalid signatures", leafTemplate("g.example.test"), root, &ecKey.PublicKey, brokenSigner{rootKey}},
		{"a private key that is not a signer", leafTemplate("h.example.test"), root, &ecKey.PublicKey, "not a key"},
	}
	for _, c := range cases {
		if _, err := compositex509.CreateCertificate(rand.Reader, c.template, c.parent, c.pub, c.priv); err == nil {
			t.Errorf("CreateCertificate accepted %s", c.name)
		}
	}

	if _, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA256}, rootKey); err == nil {
		t.Error("CreateCertificateRequest accepted a SignatureAlgorithm for a composite signer")
	}
	if _, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{ExtraExtensions: agreement.ExtraExtensions}, rootKey); err == nil {
		t.Error("CreateCertificateRequest accepted key agreement for a composite key")
	}

	list := func() *x509.RevocationList {
		return &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}
	}
	if _, err := compositex509.CreateRevocationList(rand.Reader, list(), root, otherKey); err == nil {
		t.Error("CreateRevocationList accepted a signer that does not hold the issuer key")
	}
	noCRLSign := caTemplate("No CRL Sign")
	noCRLSign.KeyUsage = x509.KeyUsageCertSign
	issuerWithoutCRLSign := issue(t, noCRLSign, noCRLSign, otherKey.Public(), otherKey)
	if _, err := compositex509.CreateRevocationList(rand.Reader, list(), issuerWithoutCRLSign, otherKey); err == nil {
		t.Error("CreateRevocationList accepted an issuer without the cRLSign usage")
	}
	withListAlgorithm := list()
	withListAlgorithm.SignatureAlgorithm = x509.ECDSAWithSHA384
	if _, err := compositex509.CreateRevocationList(rand.Reader, withListAlgorithm, root, rootKey); err == nil {
		t.Error("CreateRevocationList accepted a SignatureAlgorithm for a composite signer")
	}
	if _, err := compositex509.CreateRevocationList(rand.Reader, list(), root, nil); err == nil {
		t.Error("CreateRevocationList accepted a nil signer")
	}
}

func TestCheckRejects(t *testing.T) {
	rootKey := vectorKey(t, compositemldsa.MLDSA65Ed25519SHA512)
	otherKey := vectorKey(t, compositemldsa.MLDSA44Ed25519SHA512)
	root := issue(t, caTemplate("Root"), caTemplate("Root"), rootKey.Public(), rootKey)
	other := issue(t, caTemplate("Root"), caTemplate("Root"), otherKey.Public(), otherKey)
	leafTmpl := leafTemplate("leaf.example.test")
	leaf := issue(t, leafTmpl, root, otherKey.Public(), rootKey)

	if err := compositex509.CheckSignatureFrom(leaf, other); err == nil {
		t.Error("verified under a composite parent of another algorithm")
	}
	if err := compositex509.CheckSignatureFrom(root, leaf); !errors.As(err, new(x509.ConstraintViolationError)) {
		t.Errorf("end-entity parent: %v, want a constraint violation", err)
	}
	noCertSign := caTemplate("No Cert Sign")
	noCertSign.KeyUsage = x509.KeyUsageCRLSign
	crlOnly := issue(t, noCertSign, noCertSign, rootKey.Public(), rootKey)
	if err := compositex509.CheckSignatureFrom(leaf, crlOnly); !errors.As(err, new(x509.ConstraintViolationError)) {
		t.Errorf("parent without keyCertSign: %v, want a constraint violation", err)
	}

	tampered := *leaf
	tampered.RawTBSCertificate = bytes.Clone(leaf.RawTBSCertificate)
	tampered.RawTBSCertificate[len(tampered.RawTBSCertificate)-1] ^= 1
	if err := compositex509.CheckSignatureFrom(&tampered, root); err == nil {
		t.Error("verified a modified certificate")
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecRoot := issue(t, caTemplate("EC Root"), caTemplate("EC Root"), &ecKey.PublicKey, ecKey)
	if err := compositex509.CheckSignatureFrom(leaf, ecRoot); err == nil {
		t.Error("verified a composite signature under an ECDSA parent")
	}

	crlDER, err := compositex509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(7), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, root, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := compositex509.CheckRevocationListSignatureFrom(crl, other); err == nil {
		t.Error("verified a CRL under another composite key")
	}
	if err := compositex509.CheckRevocationListSignatureFrom(crl, leaf); !errors.As(err, new(x509.ConstraintViolationError)) {
		t.Errorf("CRL from an end-entity parent: %v, want a constraint violation", err)
	}
	noCRLSign := caTemplate("No CRL Sign")
	noCRLSign.KeyUsage = x509.KeyUsageCertSign
	certOnly := issue(t, noCRLSign, noCRLSign, rootKey.Public(), rootKey)
	if err := compositex509.CheckRevocationListSignatureFrom(crl, certOnly); !errors.As(err, new(x509.ConstraintViolationError)) {
		t.Errorf("CRL from a parent without cRLSign: %v, want a constraint violation", err)
	}

	csrDER, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "request"}}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	csr.RawTBSCertificateRequest = bytes.Clone(csr.RawTBSCertificateRequest)
	csr.RawTBSCertificateRequest[len(csr.RawTBSCertificateRequest)-1] ^= 1
	if err := compositex509.CheckCertificateRequestSignature(csr); err == nil {
		t.Error("verified a modified request")
	}
}

// Keys and structures without a composite key take the crypto/x509 paths unchanged.
func TestPassThrough(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := compositex509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub, err := compositex509.ParsePKIXPublicKey(spki); err != nil || !ecKey.PublicKey.Equal(pub.(crypto.PublicKey)) {
		t.Errorf("ECDSA SubjectPublicKeyInfo: %v", err)
	}
	pkcs8, err := compositex509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := compositex509.ParsePKCS8PrivateKey(pkcs8); err != nil || !ecKey.Equal(key.(crypto.PrivateKey)) {
		t.Errorf("ECDSA PKCS #8: %v", err)
	}
	composite := vectorKey(t, compositemldsa.MLDSA87RSA4096PSSSHA512)
	pkcs8, err = compositex509.MarshalPKCS8PrivateKey(composite)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := compositex509.ParsePKCS8PrivateKey(pkcs8); err != nil || !composite.Equal(key.(crypto.PrivateKey)) {
		t.Errorf("composite PKCS #8: %v", err)
	}
	if _, err := compositex509.ParsePKIXPublicKey([]byte{0x30, 0x00}); err == nil {
		t.Error("ParsePKIXPublicKey accepted an empty SEQUENCE")
	}

	root := issue(t, caTemplate("EC Root"), caTemplate("EC Root"), &ecKey.PublicKey, ecKey)
	if _, ok, err := compositex509.SignatureAlgorithm(root.Raw); ok || err != nil {
		t.Errorf("SignatureAlgorithm of an ECDSA certificate = %v, %v", ok, err)
	}
	if err := compositex509.CheckSignatureFrom(root, root); err != nil {
		t.Error(err)
	}
	csrDER, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ec"}}, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := compositex509.CheckCertificateRequestSignature(csr); err != nil {
		t.Error(err)
	}
	crlDER, err := compositex509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, root, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := compositex509.CheckRevocationListSignatureFrom(crl, root); err != nil {
		t.Error(err)
	}
}

// A failed parse returns an untyped nil key, as crypto/x509 does, so a nil check on the key is
// reliable.
func TestParseErrorsReturnNilKey(t *testing.T) {
	sk := vectorKey(t, compositemldsa.MLDSA44Ed25519SHA512)
	spki, err := compositex509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		t.Fatal(err)
	}
	info.Algorithm.Parameters = asn1.NullRawValue
	withParameters, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	info.Algorithm.Parameters = asn1.RawValue{}
	info.PublicKey.Bytes = info.PublicKey.Bytes[:100]
	info.PublicKey.BitLength = 800
	shortKey, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{"composite key with parameters": withParameters, "short composite key": shortKey, "empty SEQUENCE": {0x30, 0x00}} {
		if pub, err := compositex509.ParsePKIXPublicKey(der); err == nil || pub != nil {
			t.Errorf("ParsePKIXPublicKey(%s) = %#v, %v", name, pub, err)
		}
	}

	pkcs8, err := compositex509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(pkcs8, &key); err != nil {
		t.Fatal(err)
	}
	key.PrivateKey = key.PrivateKey[:10]
	shortPrivate, err := asn1.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{"short composite key": shortPrivate, "empty SEQUENCE": {0x30, 0x00}} {
		if priv, err := compositex509.ParsePKCS8PrivateKey(der); err == nil || priv != nil {
			t.Errorf("ParsePKCS8PrivateKey(%s) = %#v, %v", name, priv, err)
		}
	}
}
