// Command hierarchy creates a composite ML-DSA root CA, a device certificate issued from a
// certificate request and an empty revocation list, verifies every signature and writes the
// results as PEM files.
//
// Usage:
//
//	go run ./examples/hierarchy <directory>
package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hierarchy <directory>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

// Creates, verifies and writes the hierarchy into dir.
func run(dir string) error {
	now := time.Now()

	rootKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA87ECDSAP384SHA512)
	if err != nil {
		return err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Example Composite Root CA"},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := compositex509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		return fmt.Errorf("creating the root certificate: %w", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}
	if err := compositex509.CheckSignatureFrom(root, root); err != nil {
		return fmt.Errorf("verifying the root certificate: %w", err)
	}

	// The device proves possession of its key with a composite-signed certificate request.
	deviceKey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
	if err != nil {
		return err
	}
	csrDER, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device-0001"},
	}, deviceKey)
	if err != nil {
		return fmt.Errorf("creating the certificate request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return err
	}
	if err := compositex509.CheckCertificateRequestSignature(csr); err != nil {
		return fmt.Errorf("verifying the certificate request: %w", err)
	}
	requestedKey, err := compositex509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}

	deviceDER, err := compositex509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial(),
		Subject:      csr.Subject,
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, root, requestedKey, rootKey)
	if err != nil {
		return fmt.Errorf("issuing the device certificate: %w", err)
	}
	device, err := x509.ParseCertificate(deviceDER)
	if err != nil {
		return err
	}
	if err := compositex509.CheckSignatureFrom(device, root); err != nil {
		return fmt.Errorf("verifying the device certificate: %w", err)
	}

	crlDER, err := compositex509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.AddDate(0, 0, 7),
	}, root, rootKey)
	if err != nil {
		return fmt.Errorf("creating the revocation list: %w", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return err
	}
	if err := compositex509.CheckRevocationListSignatureFrom(crl, root); err != nil {
		return fmt.Errorf("verifying the revocation list: %w", err)
	}

	rootKeyDER, err := compositemldsa.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		return err
	}
	deviceKeyDER, err := compositemldsa.MarshalPKCS8PrivateKey(deviceKey)
	if err != nil {
		return err
	}
	// The output directory is whatever the person running the example names.
	if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // G703: the path is the caller's choice.
		return err
	}
	out, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	files := []struct {
		name, blockType string
		der             []byte
		mode            os.FileMode
	}{
		{"root.pem", "CERTIFICATE", rootDER, 0o644},
		{"root-key.pem", "PRIVATE KEY", rootKeyDER, 0o600},
		{"device.csr.pem", "CERTIFICATE REQUEST", csrDER, 0o644},
		{"device.pem", "CERTIFICATE", deviceDER, 0o644},
		{"device-key.pem", "PRIVATE KEY", deviceKeyDER, 0o600},
		{"root.crl.pem", "X509 CRL", crlDER, 0o644},
	}
	for _, f := range files {
		if err := writePEM(out, f.name, f.blockType, f.der, f.mode); err != nil {
			return err
		}
	}
	fmt.Printf("root CA    %s\n", rootKey.Algorithm())
	fmt.Printf("device     %s\n", deviceKey.Algorithm())
	fmt.Printf("all signatures verified, files written to %s\n", dir)
	return nil
}

// Returns a random 128-bit certificate serial number.
func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal(err)
	}
	return n
}

// Writes one PEM block to a new file in dir and refuses to replace an existing one.
func writePEM(dir *os.Root, name, blockType string, der []byte, mode os.FileMode) error {
	f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s exists, choose an empty directory", filepath.Join(dir.Name(), name))
	}
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
