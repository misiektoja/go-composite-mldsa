// Package compositex509 extends crypto/x509 to composite ML-DSA keys. Its functions mirror their
// crypto/x509 counterparts and pass every other key type straight through to crypto/x509, so a
// caller can switch to them without separate code paths.
//
// crypto/x509 parses certificates, requests and revocation lists that carry composite keys or
// signatures, but leaves the public key nil and cannot create or verify them. Use
// ParsePKIXPublicKey on the RawSubjectPublicKeyInfo to get the key, CheckSignatureFrom,
// CheckCertificateRequestSignature and CheckRevocationListSignatureFrom to verify signatures and
// the Create functions to sign. Certificate.Verify cannot build chains through composite
// certificates, so check each link with CheckSignatureFrom and apply the remaining path validation
// rules the application needs.
package compositex509
