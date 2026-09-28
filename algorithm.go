package compositemldsa

import (
	"crypto"
	"crypto/elliptic"
	"crypto/mldsa"

	// Registers the pre-hash and component hash functions.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
)

// Identifies one composite ML-DSA signature algorithm. The zero value is not a valid algorithm.
type Algorithm int

// The draft-ietf-lamps-pq-composite-sigs-19 algorithms whose components the Go standard library
// implements. The brainpool and Ed448 combinations are not supported.
const (
	MLDSA44RSA2048PSSSHA256 Algorithm = iota + 1
	MLDSA44RSA2048PKCS15SHA256
	MLDSA44Ed25519SHA512
	MLDSA44ECDSAP256SHA256
	MLDSA65RSA3072PSSSHA512
	MLDSA65RSA3072PKCS15SHA512
	MLDSA65RSA4096PSSSHA512
	MLDSA65RSA4096PKCS15SHA512
	MLDSA65ECDSAP256SHA512
	MLDSA65ECDSAP384SHA512
	MLDSA65Ed25519SHA512
	MLDSA87ECDSAP384SHA512
	MLDSA87RSA3072PSSSHA512
	MLDSA87RSA4096PSSSHA512
	MLDSA87ECDSAP521SHA512
	algorithmEnd
)

type traditional int

const (
	tradRSAPSS traditional = iota + 1
	tradRSAPKCS1
	tradECDSA
	tradEd25519
)

// Fixed properties of one composite algorithm.
type details struct {
	name    string
	oid     asn1.ObjectIdentifier
	mldsa   func() mldsa.Parameters
	preHash crypto.Hash
	trad    traditional
	// Hash used inside the traditional component: the ECDSA or RSA digest.
	tradHash crypto.Hash
	curve    func() elliptic.Curve
	rsaBits  int
	pssSalt  int
}

// Registered under 1.3.6.1.5.5.7.6 (id-alg) by IANA for the composite signature draft.
func compositeOID(arc int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, arc}
}

// One row per algorithm keeps the table comparable with section 6 of the draft.
//
//nolint:lll
var registry = [algorithmEnd]details{
	MLDSA44RSA2048PSSSHA256:    {name: "MLDSA44-RSA2048-PSS-SHA256", oid: compositeOID(37), mldsa: mldsa.MLDSA44, preHash: crypto.SHA256, trad: tradRSAPSS, tradHash: crypto.SHA256, rsaBits: 2048, pssSalt: 32},
	MLDSA44RSA2048PKCS15SHA256: {name: "MLDSA44-RSA2048-PKCS15-SHA256", oid: compositeOID(38), mldsa: mldsa.MLDSA44, preHash: crypto.SHA256, trad: tradRSAPKCS1, tradHash: crypto.SHA256, rsaBits: 2048},
	MLDSA44Ed25519SHA512:       {name: "MLDSA44-Ed25519-SHA512", oid: compositeOID(39), mldsa: mldsa.MLDSA44, preHash: crypto.SHA512, trad: tradEd25519},
	MLDSA44ECDSAP256SHA256:     {name: "MLDSA44-ECDSA-P256-SHA256", oid: compositeOID(40), mldsa: mldsa.MLDSA44, preHash: crypto.SHA256, trad: tradECDSA, tradHash: crypto.SHA256, curve: elliptic.P256},
	MLDSA65RSA3072PSSSHA512:    {name: "MLDSA65-RSA3072-PSS-SHA512", oid: compositeOID(41), mldsa: mldsa.MLDSA65, preHash: crypto.SHA512, trad: tradRSAPSS, tradHash: crypto.SHA256, rsaBits: 3072, pssSalt: 32},
	MLDSA65RSA3072PKCS15SHA512: {name: "MLDSA65-RSA3072-PKCS15-SHA512", oid: compositeOID(42), mldsa: mldsa.MLDSA65, preHash: crypto.SHA512, trad: tradRSAPKCS1, tradHash: crypto.SHA256, rsaBits: 3072},
	MLDSA65RSA4096PSSSHA512:    {name: "MLDSA65-RSA4096-PSS-SHA512", oid: compositeOID(43), mldsa: mldsa.MLDSA65, preHash: crypto.SHA512, trad: tradRSAPSS, tradHash: crypto.SHA384, rsaBits: 4096, pssSalt: 48},
	MLDSA65RSA4096PKCS15SHA512: {name: "MLDSA65-RSA4096-PKCS15-SHA512", oid: compositeOID(44), mldsa: mldsa.MLDSA65, preHash: crypto.SHA512, trad: tradRSAPKCS1, tradHash: crypto.SHA384, rsaBits: 4096},
	MLDSA65ECDSAP256SHA512:     {name: "MLDSA65-ECDSA-P256-SHA512", oid: compositeOID(45), mldsa: mldsa.MLDSA65, preHash: crypto.SHA512, trad: tradECDSA, tradHash: crypto.SHA256, curve: elliptic.P256},
	MLDSA65ECDSAP384SHA512:     {name: "MLDSA65-ECDSA-P384-SHA512", oid: compositeOID(46), mldsa: mldsa.MLDSA65, preHash: crypto.SHA512, trad: tradECDSA, tradHash: crypto.SHA384, curve: elliptic.P384},
	MLDSA65Ed25519SHA512:       {name: "MLDSA65-Ed25519-SHA512", oid: compositeOID(48), mldsa: mldsa.MLDSA65, preHash: crypto.SHA512, trad: tradEd25519},
	MLDSA87ECDSAP384SHA512:     {name: "MLDSA87-ECDSA-P384-SHA512", oid: compositeOID(49), mldsa: mldsa.MLDSA87, preHash: crypto.SHA512, trad: tradECDSA, tradHash: crypto.SHA384, curve: elliptic.P384},
	MLDSA87RSA3072PSSSHA512:    {name: "MLDSA87-RSA3072-PSS-SHA512", oid: compositeOID(52), mldsa: mldsa.MLDSA87, preHash: crypto.SHA512, trad: tradRSAPSS, tradHash: crypto.SHA256, rsaBits: 3072, pssSalt: 32},
	MLDSA87RSA4096PSSSHA512:    {name: "MLDSA87-RSA4096-PSS-SHA512", oid: compositeOID(53), mldsa: mldsa.MLDSA87, preHash: crypto.SHA512, trad: tradRSAPSS, tradHash: crypto.SHA384, rsaBits: 4096, pssSalt: 48},
	MLDSA87ECDSAP521SHA512:     {name: "MLDSA87-ECDSA-P521-SHA512", oid: compositeOID(54), mldsa: mldsa.MLDSA87, preHash: crypto.SHA512, trad: tradECDSA, tradHash: crypto.SHA512, curve: elliptic.P521},
}

// Returns every supported algorithm in OID order.
func Algorithms() []Algorithm {
	out := make([]Algorithm, 0, algorithmEnd-1)
	for a := Algorithm(1); a < algorithmEnd; a++ {
		out = append(out, a)
	}
	return out
}

// Returns the supported algorithm registered under oid.
func AlgorithmFromOID(oid asn1.ObjectIdentifier) (Algorithm, bool) {
	for a := Algorithm(1); a < algorithmEnd; a++ {
		if registry[a].oid.Equal(oid) {
			return a, true
		}
	}
	return 0, false
}

// Reports whether a is one of the supported algorithms.
func (a Algorithm) valid() bool {
	return a > 0 && a < algorithmEnd
}

// Returns the algorithm name used in the draft, such as "MLDSA65-ECDSA-P256-SHA512".
func (a Algorithm) String() string {
	if !a.valid() {
		return "unknown composite ML-DSA algorithm"
	}
	return registry[a].name
}

// Returns the object identifier of the algorithm. Algorithm identifiers carry no parameters.
func (a Algorithm) OID() asn1.ObjectIdentifier {
	if !a.valid() {
		return nil
	}
	return append(asn1.ObjectIdentifier(nil), registry[a].oid...)
}

// Returns the hash applied to the message before both components sign it.
func (a Algorithm) PreHash() crypto.Hash {
	if !a.valid() {
		return 0
	}
	return registry[a].preHash
}

// Returns the parameter set of the ML-DSA component.
func (a Algorithm) MLDSAParameters() mldsa.Parameters {
	if !a.valid() {
		return mldsa.Parameters{}
	}
	return registry[a].mldsa()
}

// Returns the signature label that domain-separates this algorithm.
func (a Algorithm) label() string {
	return "COMPSIG-" + registry[a].name
}
