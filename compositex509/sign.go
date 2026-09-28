package compositex509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"sync"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
)

// RSA key generation is slow, so one placeholder is kept. It never signs anything that is kept.
var placeholderRSA = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

// Returns a key that crypto/x509 accepts in place of a signer or subject key while laying out a
// structure. Its signature algorithm matches pub, so crypto/x509 picks the identifier the real
// signer needs. Composite keys get an ECDSA placeholder whose identifier is replaced afterwards.
func placeholderSigner(pub crypto.PublicKey) (crypto.Signer, error) {
	switch k := pub.(type) {
	case *compositemldsa.PublicKey:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case *ecdsa.PublicKey:
		return ecdsa.GenerateKey(k.Curve, rand.Reader)
	case *rsa.PublicKey:
		return placeholderRSA()
	case ed25519.PublicKey:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	case *mldsa.PublicKey:
		return mldsa.GenerateKey(k.Parameters())
	default:
		return nil, errorf("unsupported signer public key type %T", pub)
	}
}

// Returns the composite public key of signer. It is nil when the signer holds another key type.
func compositeSignerKey(signer crypto.Signer) *compositemldsa.PublicKey {
	pk, _ := signer.Public().(*compositemldsa.PublicKey)
	return pk
}

// Signs tbs with a composite signer and checks the result, as crypto/x509 does for other keys.
func signComposite(random io.Reader, signer crypto.Signer, pk *compositemldsa.PublicKey, tbs []byte) ([]byte, error) {
	signature, err := signer.Sign(random, tbs, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if err := compositemldsa.Verify(pk, tbs, signature, nil); err != nil {
		return nil, errorf("signature returned by signer is invalid: %w", err)
	}
	return signature, nil
}

// Signs tbs with a standard library key under the algorithm crypto/x509 selected and checks the
// result, mirroring crypto/x509.
func signStandard(random io.Reader, signer crypto.Signer, algorithm x509.SignatureAlgorithm, tbs []byte) ([]byte, error) {
	opts, err := signerOptions(algorithm)
	if err != nil {
		return nil, err
	}
	signature, err := crypto.SignMessage(signer, random, tbs, opts)
	if err != nil {
		return nil, err
	}
	check := &x509.Certificate{PublicKey: signer.Public()}
	if err := check.CheckSignature(algorithm, tbs, signature); err != nil {
		return nil, errorf("signature returned by signer is invalid: %w", err)
	}
	return signature, nil
}

// The signer options crypto/x509 uses for each signature algorithm it creates. SHA-1 and MD5 are
// absent because crypto/x509 refuses to sign with them.
var signerOptionsByAlgorithm = map[x509.SignatureAlgorithm]crypto.SignerOpts{
	x509.SHA256WithRSA:    crypto.SHA256,
	x509.SHA384WithRSA:    crypto.SHA384,
	x509.SHA512WithRSA:    crypto.SHA512,
	x509.ECDSAWithSHA256:  crypto.SHA256,
	x509.ECDSAWithSHA384:  crypto.SHA384,
	x509.ECDSAWithSHA512:  crypto.SHA512,
	x509.SHA256WithRSAPSS: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
	x509.SHA384WithRSAPSS: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384},
	x509.SHA512WithRSAPSS: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512},
	x509.PureEd25519:      crypto.Hash(0),
	x509.MLDSA44:          crypto.Hash(0),
	x509.MLDSA65:          crypto.Hash(0),
	x509.MLDSA87:          crypto.Hash(0),
}

// Returns the signer options crypto/x509 uses for a signature algorithm.
func signerOptions(algorithm x509.SignatureAlgorithm) (crypto.SignerOpts, error) {
	opts, ok := signerOptionsByAlgorithm[algorithm]
	if !ok {
		return nil, errorf("unsupported signature algorithm %s", algorithm)
	}
	return opts, nil
}

// Key usage bits a composite key may carry and bits it must never carry, from section 5.2 of the
// draft.
const (
	signingUsages = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
		x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	forbiddenUsages = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly
)

var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// decipherOnly is the last bit RFC 5280 defines.
const lastKeyUsageBit = 8

// Checks the key usage a structure built from usage and extra would carry. An extra key usage
// extension replaces usage, as it does in crypto/x509.
func checkKeyUsage(usage x509.KeyUsage, extra []pkix.Extension) error {
	present := usage != 0
	for _, ext := range extra {
		if !ext.Id.Equal(oidKeyUsage) {
			continue
		}
		var bits asn1.BitString
		if rest, err := asn1.Unmarshal(ext.Value, &bits); err != nil || len(rest) != 0 {
			return errorf("malformed key usage extension")
		}
		usage, present = 0, true
		for i := range bits.BitLength {
			if bits.At(i) == 0 {
				continue
			}
			if i > lastKeyUsageBit {
				return errorf("key usage extension sets undefined bit %d", i)
			}
			usage |= x509.KeyUsage(1) << i
		}
		break
	}
	switch {
	case !present:
		return nil
	case usage&forbiddenUsages != 0:
		return errorf("composite keys only sign, key usage %#x includes an encryption or key agreement bit", int(usage))
	case usage&signingUsages == 0:
		return errorf("key usage of a composite key must include a signing bit")
	default:
		return nil
	}
}
