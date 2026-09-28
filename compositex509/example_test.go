package compositex509_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

// Creates a composite root CA, issues an ECDSA certificate from it and verifies the signature.
func ExampleCreateCertificate() {
	caKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP384SHA512)
	if err != nil {
		log.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Composite Root"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := compositex509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serverDER, err := compositex509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server.example.com"},
		DNSNames:     []string{"server.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 3, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	server, err := x509.ParseCertificate(serverDER)
	if err != nil {
		log.Fatal(err)
	}

	algorithm, _, err := compositex509.SignatureAlgorithm(server.Raw)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(algorithm, compositex509.CheckSignatureFrom(server, ca) == nil)
	// Output: MLDSA65-ECDSA-P384-SHA512 true
}
