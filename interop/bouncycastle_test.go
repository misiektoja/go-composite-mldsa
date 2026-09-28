package interop

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

// Checks recorded by the Java program for every algorithm. A missing line fails the test, so a
// check cannot pass by not running.
var javaChecks = []string{
	"root-algorithm-identifier",
	"root-self-signature",
	"composite-leaf-signature",
	"ecdsa-leaf-signature",
	"crl-signature",
	"csr-signature",
	"raw-signature",
	"raw-signature-with-context",
	"raw-signature-wrong-context-rejected",
	"pkcs8-import",
	"produce",
}

var (
	message = []byte("Composite ML-DSA interoperability with Bouncy Castle")
	context = []byte("go-composite-mldsa interop")
)

// Artifacts made by Go for one algorithm, kept for the checks after the Java run.
type goArtifacts struct {
	leafKey *compositemldsa.PrivateKey
}

// Go and Bouncy Castle each create certificates, revocation lists, requests, private keys and raw
// signatures for every algorithm and verify the other side's output.
func TestBouncyCastle(t *testing.T) {
	classpath := os.Getenv("BC_CLASSPATH")
	if classpath == "" {
		t.Fatal("BC_CLASSPATH must name the Bouncy Castle bcprov, bcpkix and bcutil jars, run make test-interop")
	}
	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatalf("java is required: %v", err)
	}
	dir := t.TempDir()
	produced := map[compositemldsa.Algorithm]goArtifacts{}
	for _, alg := range compositemldsa.Algorithms() {
		produced[alg] = writeGoArtifacts(t, filepath.Join(dir, "go", alg.String()), alg)
	}

	cmd := exec.CommandContext(t.Context(), java, "-cp", classpath, filepath.Join("java", "CompositeInterop.java"), dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, runErr := cmd.Output()
	passed := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		t.Log(line)
		fields := strings.Fields(line)
		switch {
		case len(fields) >= 3 && fields[0] == "PASS":
			passed[fields[1]+" "+fields[2]] = true
		case len(fields) >= 1 && fields[0] == "FAIL":
			t.Errorf("Bouncy Castle: %s", line)
		}
	}
	if runErr != nil {
		t.Errorf("Java run failed: %v\n%s", runErr, stderr.String())
	}
	for _, alg := range compositemldsa.Algorithms() {
		for _, check := range javaChecks {
			if !passed[alg.String()+" "+check] {
				t.Errorf("Bouncy Castle did not pass %s for %s", check, alg)
			}
		}
	}

	for _, alg := range compositemldsa.Algorithms() {
		t.Run(alg.String(), func(t *testing.T) {
			checkBouncyCastleArtifacts(t, filepath.Join(dir, "bc", alg.String()), alg)
			signature := readFile(t, filepath.Join(dir, "go", alg.String(), "bc-signature.bin"))
			if err := compositemldsa.Verify(produced[alg].leafKey.PublicKey(), message, signature, nil); err != nil {
				t.Errorf("signature Bouncy Castle made with the Go private key: %v", err)
			}
		})
	}
}

// Writes a composite root, a composite and an ECDSA leaf, a revocation list, a request, the leaf
// private key and raw signatures.
func writeGoArtifacts(t *testing.T, dir string, alg compositemldsa.Algorithm) goArtifacts {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootKey, err := compositemldsa.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := compositemldsa.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Go Composite Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := compositex509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: name},
			DNSNames:              []string{name},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
	}
	leafDER, err := compositex509.CreateCertificate(rand.Reader, leafTemplate(2, "composite.example.test"), root, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ecLeafDER, err := compositex509.CreateCertificate(rand.Reader, leafTemplate(3, "ecdsa.example.test"), root, &ecKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := compositex509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: now, ReasonCode: 1}},
	}, root, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "request"}, DNSNames: []string{"request.example.test"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := compositemldsa.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := leafKey.Sign(nil, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	contextSignature, err := leafKey.Sign(nil, message, &compositemldsa.Options{Context: string(context)})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"root.der":              rootDER,
		"leaf.der":              leafDER,
		"ecleaf.der":            ecLeafDER,
		"crl.der":               crlDER,
		"csr.der":               csrDER,
		"leaf-key.p8":           keyDER,
		"message.bin":           message,
		"context.bin":           context,
		"signature.bin":         signature,
		"context-signature.bin": contextSignature,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return goArtifacts{leafKey: leafKey}
}

// Verifies everything Bouncy Castle produced for one algorithm with the Go library.
func checkBouncyCastleArtifacts(t *testing.T, dir string, alg compositemldsa.Algorithm) {
	root := parseCertificate(t, readFile(t, filepath.Join(dir, "root.der")))
	leaf := parseCertificate(t, readFile(t, filepath.Join(dir, "leaf.der")))
	if got, ok, err := compositex509.SignatureAlgorithm(root.Raw); err != nil || !ok || got != alg {
		t.Errorf("root signature algorithm = %s, %v, %v", got, ok, err)
	}
	if err := compositex509.CheckSignatureFrom(root, root); err != nil {
		t.Errorf("root self-signature: %v", err)
	}
	if err := compositex509.CheckSignatureFrom(leaf, root); err != nil {
		t.Errorf("leaf signature: %v", err)
	}
	crl, err := x509.ParseRevocationList(readFile(t, filepath.Join(dir, "crl.der")))
	if err != nil {
		t.Fatal(err)
	}
	if err := compositex509.CheckRevocationListSignatureFrom(crl, root); err != nil {
		t.Errorf("CRL signature: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(readFile(t, filepath.Join(dir, "csr.der")))
	if err != nil {
		t.Fatal(err)
	}
	if err := compositex509.CheckCertificateRequestSignature(csr); err != nil {
		t.Errorf("CSR signature: %v", err)
	}

	leafPub, err := compositex509.ParsePKIXPublicKey(leaf.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, ok := leafPub.(*compositemldsa.PublicKey)
	if !ok || leafKey.Algorithm() != alg {
		t.Fatalf("leaf public key is %T", leafPub)
	}
	if err := compositemldsa.Verify(leafKey, message, readFile(t, filepath.Join(dir, "signature.bin")), nil); err != nil {
		t.Errorf("raw signature: %v", err)
	}
	if err := compositemldsa.Verify(leafKey, message, readFile(t, filepath.Join(dir, "context-signature.bin")), &compositemldsa.Options{Context: string(context)}); err != nil {
		t.Errorf("raw signature with context: %v", err)
	}

	rootKey, err := compositemldsa.ParsePKCS8PrivateKey(readFile(t, filepath.Join(dir, "root-key.p8")))
	if err != nil {
		t.Fatalf("Bouncy Castle PKCS #8: %v", err)
	}
	rootPub, err := compositex509.ParsePKIXPublicKey(root.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !rootKey.PublicKey().Equal(rootPub.(crypto.PublicKey)) {
		t.Error("Bouncy Castle private key derives a different public key than its certificate")
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	child, err := compositex509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{CommonName: "issued with the Bouncy Castle key"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}, root, &ecKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("issuing with the Bouncy Castle root key: %v", err)
	}
	if err := compositex509.CheckSignatureFrom(parseCertificate(t, child), root); err != nil {
		t.Errorf("certificate issued with the Bouncy Castle root key: %v", err)
	}
}

// Reads a file or fails the test.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Parses a DER certificate or fails the test.
func parseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
