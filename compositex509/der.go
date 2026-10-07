package compositex509

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
)

// Identifier octets of the elements rewritten in structures produced by crypto/x509.
const (
	tagSequence     = 0x30
	tagInteger      = 0x02
	tagExplicitZero = 0xa0
)

// Positions of the rewritten elements. Certificates always start with the explicit version.
const (
	certSignatureIndex = 2
	certPublicKeyIndex = 6
	requestKeyIndex    = 2
	crlSignatureIndex  = 1
)

// Returns an error whose message carries the package prefix.
func errorf(format string, args ...any) error {
	return fmt.Errorf("compositex509: "+format, args...)
}

// Splits a DER SEQUENCE into the complete encodings of its elements.
func sequenceElements(der []byte) ([][]byte, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after SEQUENCE")
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("not a SEQUENCE")
	}
	var elements [][]byte
	for body := seq.Bytes; len(body) > 0; {
		var element asn1.RawValue
		if body, err = asn1.Unmarshal(body, &element); err != nil {
			return nil, err
		}
		elements = append(elements, element.FullBytes)
	}
	return elements, nil
}

// Encodes DER elements as a SEQUENCE.
func sequence(elements ...[]byte) ([]byte, error) {
	body := bytes.Join(elements, nil)
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

// Return the signed content and algorithm from a three-element signed structure.
func signedParts(der []byte) (tbs, algorithm []byte, err error) {
	elements, err := sequenceElements(der)
	if err != nil {
		return nil, nil, err
	}
	if len(elements) != 3 {
		return nil, nil, errors.New("signed structure does not have three parts")
	}
	return elements[0], elements[1], nil
}

// Encodes a signed structure from its signed part, signature algorithm and signature value.
func signedStructure(tbs, algorithm, signature []byte) ([]byte, error) {
	value, err := asn1.Marshal(asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)})
	if err != nil {
		return nil, err
	}
	return sequence(tbs, algorithm, value)
}

// Returns the DER algorithm identifier of a composite algorithm, whose parameters are absent.
func algorithmIdentifier(alg compositemldsa.Algorithm) ([]byte, error) {
	return asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: alg.OID()})
}

// Reports whether elements has an element at index that starts with the identifier octet tag.
func hasTag(elements [][]byte, index int, tag byte) bool {
	return index < len(elements) && len(elements[index]) > 0 && elements[index][0] == tag
}

// Maps a DER algorithm identifier to a composite algorithm. It reports false for any other
// algorithm and fails when a composite identifier carries parameters.
func compositeAlgorithm(der []byte) (compositemldsa.Algorithm, bool, error) {
	var id pkix.AlgorithmIdentifier
	if rest, err := asn1.Unmarshal(der, &id); err != nil {
		return 0, false, errorf("parsing algorithm identifier: %w", err)
	} else if len(rest) != 0 {
		return 0, false, errorf("trailing data after algorithm identifier")
	}
	alg, ok := compositemldsa.AlgorithmFromOID(id.Algorithm)
	if !ok {
		return 0, false, nil
	}
	if len(id.Parameters.FullBytes) != 0 {
		return 0, false, errorf("%s algorithm identifier carries parameters", alg)
	}
	return alg, true, nil
}

// Returns the composite algorithm that signed a DER certificate, request or revocation list. It
// reports false when another algorithm signed it.
func SignatureAlgorithm(signed []byte) (compositemldsa.Algorithm, bool, error) {
	_, algorithm, err := signedParts(signed)
	if err != nil {
		return 0, false, errorf("parsing signed structure: %w", err)
	}
	return compositeAlgorithm(algorithm)
}
