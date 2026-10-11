package compositex509

import (
	"crypto"
	"crypto/x509"
	"io"
)

// Works like x509.CreateCertificateRequest and also accepts a composite signer. Without one it
// calls x509.CreateCertificateRequest unchanged.
//
// template.SignatureAlgorithm must be zero for a composite signer. A requested key usage, from
// ExtraExtensions or an extensionRequest in Attributes, must include a signing usage and no
// encryption or key agreement usage.
func CreateCertificateRequest(random io.Reader, template *x509.CertificateRequest, priv any) ([]byte, error) {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errorf("certificate private key does not implement crypto.Signer")
	}
	signerKey := compositeSignerKey(signer)
	if signerKey == nil {
		return x509.CreateCertificateRequest(random, template, priv)
	}
	if template.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return nil, errorf("SignatureAlgorithm must be zero for a composite signer")
	}
	spki, err := MarshalPKIXPublicKey(signerKey)
	if err != nil {
		return nil, err
	}
	placeholder, err := placeholderSigner(signerKey)
	if err != nil {
		return nil, err
	}
	layout, err := x509.CreateCertificateRequest(random, template, placeholder)
	if err != nil {
		return nil, err
	}
	// crypto/x509 merges ExtraExtensions into an extensionRequest from Attributes and lets the
	// Attributes value win, so the encoded request is what gets checked.
	requested, err := x509.ParseCertificateRequest(layout)
	if err != nil {
		return nil, errorf("parsing request layout: %w", err)
	}
	if err := checkKeyUsage(0, requested.Extensions); err != nil {
		return nil, err
	}
	infoLayout, _, err := signedParts(layout)
	if err != nil {
		return nil, errorf("parsing request layout: %w", err)
	}
	elements, err := sequenceElements(infoLayout)
	if err != nil || len(elements) != 4 || !hasTag(elements, 0, tagInteger) ||
		!hasTag(elements, requestKeyIndex, tagSequence) {
		return nil, errorf("unexpected CertificationRequestInfo layout from crypto/x509")
	}
	elements[requestKeyIndex] = spki
	info, err := sequence(elements...)
	if err != nil {
		return nil, err
	}
	algorithm, err := algorithmIdentifier(signerKey.Algorithm())
	if err != nil {
		return nil, err
	}
	signature, err := signComposite(random, signer, signerKey, info)
	if err != nil {
		return nil, err
	}
	der, err := signedStructure(info, algorithm, signature)
	if err != nil {
		return nil, err
	}
	if _, err := x509.ParseCertificateRequest(der); err != nil {
		return nil, errorf("created request does not parse: %w", err)
	}
	return der, nil
}

// Works like csr.CheckSignature and also verifies requests signed by a composite key.
func CheckCertificateRequestSignature(csr *x509.CertificateRequest) error {
	pk, err := compositePublicKey(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	if pk == nil {
		return csr.CheckSignature()
	}
	return verifySigned(pk, csr.Raw, csr.RawTBSCertificateRequest, csr.Signature)
}
