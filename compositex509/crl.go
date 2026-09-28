package compositex509

import (
	"crypto"
	"crypto/x509"
	"io"
)

// Works like x509.CreateRevocationList and also accepts a composite signer. Without one it calls
// x509.CreateRevocationList unchanged.
//
// template.SignatureAlgorithm must be zero for a composite signer. Unlike crypto/x509, a composite
// signer must hold the issuer's key when the issuer certificate names one.
func CreateRevocationList(random io.Reader, template *x509.RevocationList, issuer *x509.Certificate, priv crypto.Signer) ([]byte, error) {
	if priv == nil {
		return nil, errorf("revocation list signer is nil")
	}
	signerKey := compositeSignerKey(priv)
	if signerKey == nil || template == nil || issuer == nil {
		return x509.CreateRevocationList(random, template, issuer, priv)
	}
	if template.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return nil, errorf("SignatureAlgorithm must be zero for a composite signer")
	}
	if err := checkParentKey(issuer, priv); err != nil {
		return nil, err
	}
	placeholder, err := placeholderSigner(signerKey)
	if err != nil {
		return nil, err
	}
	layout, err := x509.CreateRevocationList(random, template, issuer, placeholder)
	if err != nil {
		return nil, err
	}
	tbsLayout, _, err := signedParts(layout)
	if err != nil {
		return nil, errorf("parsing revocation list layout: %w", err)
	}
	elements, err := sequenceElements(tbsLayout)
	if err != nil || len(elements) < 5 || !hasTag(elements, 0, tagInteger) ||
		!hasTag(elements, crlSignatureIndex, tagSequence) {
		return nil, errorf("unexpected TBSCertList layout from crypto/x509")
	}
	algorithm, err := algorithmIdentifier(signerKey.Algorithm())
	if err != nil {
		return nil, err
	}
	elements[crlSignatureIndex] = algorithm
	tbs, err := sequence(elements...)
	if err != nil {
		return nil, err
	}
	signature, err := signComposite(random, priv, signerKey, tbs)
	if err != nil {
		return nil, err
	}
	der, err := signedStructure(tbs, algorithm, signature)
	if err != nil {
		return nil, err
	}
	if _, err := x509.ParseRevocationList(der); err != nil {
		return nil, errorf("created revocation list does not parse: %w", err)
	}
	return der, nil
}

// Works like rl.CheckSignatureFrom(parent) and also verifies revocation lists signed by a composite
// parent key. It applies the same basic constraints and key usage checks as crypto/x509.
func CheckRevocationListSignatureFrom(rl *x509.RevocationList, parent *x509.Certificate) error {
	pk, err := compositePublicKey(parent.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	if pk == nil {
		return rl.CheckSignatureFrom(parent)
	}
	if parent.Version == 3 && !parent.BasicConstraintsValid || parent.BasicConstraintsValid && !parent.IsCA {
		return x509.ConstraintViolationError{}
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return x509.ConstraintViolationError{}
	}
	return verifySigned(pk, rl.Raw, rl.RawTBSRevocationList, rl.Signature)
}
