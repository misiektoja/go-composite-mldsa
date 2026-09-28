package compositex509

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"io"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
)

// Works like x509.CreateCertificate and also accepts composite keys as pub, as the signer behind
// priv or both. Without a composite key it calls x509.CreateCertificate unchanged.
//
// A composite signer is any crypto.Signer whose Public method returns *compositemldsa.PublicKey
// and whose Sign method signs the complete message when opts.HashFunc is zero. The signature
// algorithm follows from the key, so template.SignatureAlgorithm must be zero for a composite
// signer. A composite subject key must not be given encryption or key agreement usages. A missing
// SubjectKeyId of a CA certificate is derived from the SHA-256 hash of the subject public key, as
// crypto/x509 does.
func CreateCertificate(random io.Reader, template, parent *x509.Certificate, pub, priv any) ([]byte, error) {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errorf("certificate private key does not implement crypto.Signer")
	}
	signerKey := compositeSignerKey(signer)
	subjectKey, compositeSubject := pub.(*compositemldsa.PublicKey)
	if signerKey == nil && !compositeSubject {
		return x509.CreateCertificate(random, template, parent, pub, priv)
	}
	if err := checkParentKey(parent, signer); err != nil {
		return nil, err
	}

	tmpl := *template
	par := *parent
	// The placeholder signer cannot match the parent key, so the check was done above instead.
	par.PublicKey = nil
	if signerKey != nil && tmpl.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return nil, errorf("SignatureAlgorithm must be zero for a composite signer")
	}
	var subjectSPKI []byte
	if compositeSubject {
		if err := checkKeyUsage(tmpl.KeyUsage, tmpl.ExtraExtensions); err != nil {
			return nil, err
		}
		var err error
		if subjectSPKI, err = compositemldsa.MarshalPKIXPublicKey(subjectKey); err != nil {
			return nil, err
		}
		if len(tmpl.SubjectKeyId) == 0 && tmpl.IsCA {
			// RFC 7093 section 2 method 1, the crypto/x509 default.
			sum := sha256.Sum256(subjectKey.Bytes())
			tmpl.SubjectKeyId = sum[:20]
		}
	}

	placeholder, err := placeholderSigner(signerKeyOrPublic(signerKey, signer))
	if err != nil {
		return nil, err
	}
	layoutKey := pub
	if compositeSubject {
		layoutKey = placeholder.Public()
	}
	layout, err := x509.CreateCertificate(random, &tmpl, &par, layoutKey, placeholder)
	if err != nil {
		return nil, err
	}
	tbsLayout, algorithm, err := signedParts(layout)
	if err != nil {
		return nil, errorf("parsing certificate layout: %w", err)
	}
	elements, err := sequenceElements(tbsLayout)
	if err != nil || !hasTag(elements, 0, tagExplicitZero) || !hasTag(elements, certSignatureIndex, tagSequence) ||
		!hasTag(elements, certPublicKeyIndex, tagSequence) {
		return nil, errorf("unexpected TBSCertificate layout from crypto/x509")
	}
	if compositeSubject {
		elements[certPublicKeyIndex] = subjectSPKI
	}
	if signerKey != nil {
		if algorithm, err = algorithmIdentifier(signerKey.Algorithm()); err != nil {
			return nil, err
		}
		elements[certSignatureIndex] = algorithm
	}
	tbs, err := sequence(elements...)
	if err != nil {
		return nil, err
	}

	var signature []byte
	if signerKey != nil {
		signature, err = signComposite(random, signer, signerKey, tbs)
	} else {
		var parsed *x509.Certificate
		if parsed, err = x509.ParseCertificate(layout); err != nil {
			return nil, errorf("parsing certificate layout: %w", err)
		}
		signature, err = signStandard(random, signer, parsed.SignatureAlgorithm, tbs)
	}
	if err != nil {
		return nil, err
	}
	der, err := signedStructure(tbs, algorithm, signature)
	if err != nil {
		return nil, err
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, errorf("created certificate does not parse: %w", err)
	}
	return der, nil
}

// Returns the composite key when there is one and the signer's own key otherwise.
func signerKeyOrPublic(signerKey *compositemldsa.PublicKey, signer crypto.Signer) crypto.PublicKey {
	if signerKey != nil {
		return signerKey
	}
	return signer.Public()
}

// Checks that the signer holds the parent's key when the parent names one, as crypto/x509 does.
func checkParentKey(parent *x509.Certificate, signer crypto.Signer) error {
	want := parent.PublicKey
	if want == nil && len(parent.RawSubjectPublicKeyInfo) > 0 {
		var err error
		if want, err = ParsePKIXPublicKey(parent.RawSubjectPublicKeyInfo); err != nil {
			return errorf("parsing the parent public key: %w", err)
		}
	}
	if want == nil {
		return nil
	}
	have, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !have.Equal(want) {
		return errorf("provided PrivateKey doesn't match parent's PublicKey")
	}
	return nil
}

// Works like cert.CheckSignatureFrom(parent) and also verifies signatures from a composite parent
// key. It applies the same basic constraints and key usage checks as crypto/x509.
func CheckSignatureFrom(cert, parent *x509.Certificate) error {
	pk, err := compositePublicKey(parent.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	if pk == nil {
		return cert.CheckSignatureFrom(parent)
	}
	// RFC 5280 section 4.2.1.9, as enforced by crypto/x509.
	if parent.Version == 3 && !parent.BasicConstraintsValid || parent.BasicConstraintsValid && !parent.IsCA {
		return x509.ConstraintViolationError{}
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}
	return verifySigned(pk, cert.Raw, cert.RawTBSCertificate, cert.Signature)
}

// Verifies the composite signature of a parsed certificate, request or revocation list.
func verifySigned(pk *compositemldsa.PublicKey, raw, tbs, signature []byte) error {
	alg, ok, err := SignatureAlgorithm(raw)
	if err != nil {
		return err
	}
	if !ok || alg != pk.Algorithm() {
		return errorf("signature algorithm does not match the %s signer key", pk.Algorithm())
	}
	return compositemldsa.Verify(pk, tbs, signature, nil)
}
