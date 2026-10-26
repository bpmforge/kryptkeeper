// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

// ACME device attestation, device-attest-01 (W40-02, D-316/D-317).
//
// Spec: draft-ietf-acme-device-attest-10 (10 August 2026),
// https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/ . The draft
// leaves the verification procedures to the attestation formats, so the two
// formats offered here cite their own sources:
//   - "tpm":   WebAuthn level 3 section 8.3 (and 8.3.1 for the AIK certificate),
//     https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation . Its attToBeSigned
//     is the key authorization (draft section 5).
//   - "apple": Apple Managed Device Attestation,
//     https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web .
//     Apple signs before the client's account key exists, so, as draft section
//     5 describes for external attestation authorities, the freshness code in
//     the leaf is SHA-256 of the challenge TOKEN, not of the key
//     authorization. The brief for this ticket said "key authorization"; Apple's
//     published text and the smallstep reference implementation both say token
//     and a real device can only ever satisfy that, so token it is (D-316).

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"

	"kryptkeeper/internal/ca"
)

const (
	identifierTypePermanent = "permanent-identifier"
	challengeDeviceAttest   = "device-attest-01"

	// maxPermanentIdentifierLen keeps the identifier inside an X.520 commonName
	// (64) because it is also written there.
	maxPermanentIdentifierLen = 64

	errBadAttestationStatement = "urn:ietf:params:acme:error:badAttestationStatement"
)

var (
	oidAppleSerialNumber = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 1}
	oidAppleUDID         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}
	oidAppleFreshness    = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 11, 1}

	oidTCGKpAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	oidTCGManufacturer     = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidSubjectAltNameExt   = asn1.ObjectIdentifier{2, 5, 29, 17}

	// draft-ietf-acme-device-attest-10 section 3.1 assigner-value.
	assignerOIDPattern = regexp.MustCompile(`^(?:[01]\.(?:[1-3]?[0-9])|2\.(?:0|[1-9][0-9]*))(?:\.(?:0|[1-9][0-9]*))*$`)
)

// DeviceAttestationConfig turns device-attest-01 on. A nil root pool leaves
// that attestation format off; with both nil the identifier type is not
// accepted at all (D-316 rule 1). No root is embedded: the operator supplies
// the Apple Enterprise Attestation Root CA and the TPM manufacturer bundle.
type DeviceAttestationConfig struct {
	AppleRoots *x509.CertPool
	TPMRoots   *x509.CertPool
	// DeviceAllowed reports whether identifier (as written in the order) is in
	// the operator's device inventory for the CA issuing this request (D-317
	// rule 1). It must fail closed: an error refuses.
	DeviceAllowed func(ctx context.Context, caID, identifier string) (bool, error)
	// TemplateAllows reports whether the template carries the explicit
	// device-attestation flag (D-317 rule 2).
	TemplateAllows func(ctx context.Context, templateID string) (bool, error)
	// DefaultTemplateID is the template governing the default directory
	// (KRYPTKEEPER_ACME_TEMPLATE); a provisioner brings its own.
	DefaultTemplateID string
	Now               func() time.Time
}

type deviceAttestation struct {
	cfg DeviceAttestationConfig
	dec cbor.DecMode
}

// WithDeviceAttestation enables the device-attest-01 challenge. It is a no-op
// when neither root pool is set.
func (s *Server) WithDeviceAttestation(cfg DeviceAttestationConfig) *Server {
	if cfg.AppleRoots == nil && cfg.TPMRoots == nil {
		return s
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// An attestation object is small and shallow; the limits bound what an
	// unauthenticated-size body can make the decoder allocate.
	dec, err := cbor.DecOptions{
		MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16,
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		return s
	}
	s.device = &deviceAttestation{cfg: cfg, dec: dec}
	return s
}

// parsePermanentIdentifier checks v against the draft section 3.1 production
// (device-identifier-value ["/" assigner-value]) and returns the pieces. The
// device part stays byte-for-byte as sent: serial numbers can be case
// sensitive, so nothing is normalised (section 3.2).
func parsePermanentIdentifier(v string) (ca.PermanentIdentifier, error) {
	if !utf8.ValidString(v) {
		return ca.PermanentIdentifier{}, errors.New("identifier is not valid UTF-8")
	}
	dev, assigner, hasAssigner := strings.Cut(v, "/")
	if dev == "" {
		return ca.PermanentIdentifier{}, errors.New("identifier needs a device part")
	}
	if len(dev) > maxPermanentIdentifierLen {
		return ca.PermanentIdentifier{}, fmt.Errorf("device part must be at most %d bytes", maxPermanentIdentifierLen)
	}
	for _, r := range dev {
		if r < 0x20 || r == 0x7f {
			return ca.PermanentIdentifier{}, errors.New("device part must not contain control characters")
		}
	}
	out := ca.PermanentIdentifier{Value: dev}
	if !hasAssigner {
		return out, nil
	}
	if !assignerOIDPattern.MatchString(assigner) {
		return ca.PermanentIdentifier{}, errors.New("assigner must be a dotted-decimal object identifier")
	}
	for _, part := range strings.Split(assigner, ".") {
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || len(part) > 9 {
			return ca.PermanentIdentifier{}, errors.New("assigner arc is out of range")
		}
		out.Assigner = append(out.Assigner, n)
	}
	return out, nil
}

// sameIdentifier is the octet-for-octet comparison of draft section 3.2.
func sameIdentifier(a, b ca.PermanentIdentifier) bool {
	return a.Value == b.Value && a.Assigner.Equal(b.Assigner)
}

// attestationFailure is a refusal whose text is safe to return to the client:
// it names the failed check and never echoes attestation content.
type attestationFailure string

func (e attestationFailure) Error() string { return string(e) }

func failf(format string, a ...any) error { return attestationFailure(fmt.Sprintf(format, a...)) }

// attestationResult is a verified attestation: the device key, the identifiers
// the evidence names, and the format that carried it.
type attestationResult struct {
	Format      string
	Key         crypto.PublicKey
	Identifiers []ca.PermanentIdentifier
}

// attestationObject is the WebAuthn attestation object (WebAuthn section
// 6.5.4). authData is ignored: draft section 5 says it carries nothing
// meaningful for ACME.
type attestationObject struct {
	Fmt     string          `cbor:"fmt"`
	AttStmt cbor.RawMessage `cbor:"attStmt"`
}

type appleStatement struct {
	X5C [][]byte `cbor:"x5c"`
}

type tpmStatement struct {
	Ver      string   `cbor:"ver"`
	Alg      int64    `cbor:"alg"`
	X5C      [][]byte `cbor:"x5c"`
	Sig      []byte   `cbor:"sig"`
	CertInfo []byte   `cbor:"certInfo"`
	PubArea  []byte   `cbor:"pubArea"`
}

// verify checks attObj against the challenge. token and keyAuth are the
// challenge's; accounts are bound by tpm through keyAuth and by the
// unique per-challenge token for apple.
func (d *deviceAttestation) verify(attObj []byte, token, keyAuth string) (*attestationResult, error) {
	var ao attestationObject
	if err := d.dec.Unmarshal(attObj, &ao); err != nil {
		return nil, failf("attObj is not a well-formed attestation object")
	}
	now := d.cfg.Now()
	switch ao.Fmt {
	case "apple":
		if d.cfg.AppleRoots == nil {
			return nil, failf("attestation format %q is not enabled", ao.Fmt)
		}
		var st appleStatement
		if err := d.dec.Unmarshal(ao.AttStmt, &st); err != nil {
			return nil, failf("apple attestation statement is malformed")
		}
		return verifyApple(st, d.cfg.AppleRoots, token, now)
	case "tpm":
		if d.cfg.TPMRoots == nil {
			return nil, failf("attestation format %q is not enabled", ao.Fmt)
		}
		var st tpmStatement
		if err := d.dec.Unmarshal(ao.AttStmt, &st); err != nil {
			return nil, failf("tpm attestation statement is malformed")
		}
		return verifyTPM(st, d.cfg.TPMRoots, keyAuth, now)
	}
	return nil, failf("attestation format is not supported")
}

const maxAttestationChain = 5

// verifyChain parses x5c and builds a path from its first certificate to a
// configured root. Revocation is not checked (see DEVICE_ATTESTATION.md).
func verifyChain(x5c [][]byte, roots *x509.CertPool, now time.Time, tolerateCriticalSAN bool) (*x509.Certificate, error) {
	if len(x5c) == 0 || len(x5c) > maxAttestationChain {
		return nil, failf("x5c must hold 1 to %d certificates", maxAttestationChain)
	}
	leaf, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return nil, failf("x5c leaf certificate is malformed")
	}
	inter := x509.NewCertPool()
	for _, der := range x5c[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, failf("x5c intermediate certificate is malformed")
		}
		inter.AddCert(c)
	}
	if tolerateCriticalSAN {
		// Go flags a critical SAN it cannot fully decode (an AIK carries only a
		// directoryName and otherNames) as unhandled; the SAN is parsed here.
		kept := leaf.UnhandledCriticalExtensions[:0]
		for _, id := range leaf.UnhandledCriticalExtensions {
			if !id.Equal(oidSubjectAltNameExt) {
				kept = append(kept, id)
			}
		}
		leaf.UnhandledCriticalExtensions = kept
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		// The leaf's own EKU is a vendor OID; the chain is judged by roots and
		// validity, and the AIK EKU is checked separately.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, failf("attestation certificate does not chain to a trusted root")
	}
	return leaf, nil
}

func verifyApple(st appleStatement, roots *x509.CertPool, token string, now time.Time) (*attestationResult, error) {
	leaf, err := verifyChain(st.X5C, roots, now, false)
	if err != nil {
		return nil, err
	}
	var nonce []byte
	var ids []ca.PermanentIdentifier
	for _, ext := range leaf.Extensions {
		switch {
		case ext.Id.Equal(oidAppleFreshness):
			nonce = unwrapOctets(ext.Value)
		case ext.Id.Equal(oidAppleSerialNumber), ext.Id.Equal(oidAppleUDID):
			if v := unwrapString(ext.Value); v != "" {
				ids = append(ids, ca.PermanentIdentifier{Value: v})
			}
		}
	}
	want := sha256.Sum256([]byte(token))
	if nonce == nil || subtle.ConstantTimeCompare(nonce, want[:]) != 1 {
		return nil, failf("freshness code does not match the challenge token")
	}
	if len(ids) == 0 {
		return nil, failf("attestation names no device identifier")
	}
	return &attestationResult{Format: "apple", Key: leaf.PublicKey, Identifiers: ids}, nil
}

// unwrapOctets returns the extension payload as raw bytes. Apple's extension
// content is the raw value (checked against the smallstep reference); a DER
// OCTET STRING wrapper is tolerated because the comparison that follows is an
// exact match either way.
func unwrapOctets(v []byte) []byte {
	var inner []byte
	if rest, err := asn1.Unmarshal(v, &inner); err == nil && len(rest) == 0 {
		return inner
	}
	return v
}

func unwrapString(v []byte) string {
	var s asn1.RawValue
	if rest, err := asn1.Unmarshal(v, &s); err == nil && len(rest) == 0 && s.Class == asn1.ClassUniversal &&
		(s.Tag == asn1.TagUTF8String || s.Tag == asn1.TagPrintableString || s.Tag == asn1.TagIA5String) {
		return string(s.Bytes)
	}
	return string(v)
}

func verifyTPM(st tpmStatement, roots *x509.CertPool, keyAuth string, now time.Time) (*attestationResult, error) {
	if st.Ver != "2.0" {
		return nil, failf("tpm statement version must be 2.0")
	}
	if len(st.Sig) == 0 || len(st.CertInfo) == 0 || len(st.PubArea) == 0 {
		return nil, failf("tpm statement is missing sig, certInfo or pubArea")
	}
	aik, err := verifyChain(st.X5C, roots, now, true)
	if err != nil {
		return nil, err
	}
	ids, err := checkAIKCertificate(aik)
	if err != nil {
		return nil, err
	}
	hash, _, ok := coseSignature(st.Alg)
	if !ok {
		return nil, failf("signature algorithm is not accepted (ES256, ES384, RS256, RS384)")
	}
	h := hash.New()
	h.Write([]byte(keyAuth))
	key, err := verifyTPMStatement(aik.PublicKey, st.Alg, st.CertInfo, st.PubArea, st.Sig, h.Sum(nil))
	if err != nil {
		return nil, attestationFailure(err.Error())
	}
	return &attestationResult{Format: "tpm", Key: key, Identifiers: ids}, nil
}

// checkAIKCertificate enforces WebAuthn section 8.3.1 and extracts the device
// identifier. The AIK certificate is issued by the operator's attestation CA,
// which is the party that knows which serial the TPM belongs to, so the serial
// is carried the way the draft does for certificates: an RFC 4043
// PermanentIdentifier in the SAN. An AIK certificate without one proves a TPM
// but no device, so it is refused (D-316 rule 3).
func checkAIKCertificate(c *x509.Certificate) ([]ca.PermanentIdentifier, error) {
	switch {
	case c.Version != 3:
		return nil, failf("AIK certificate must be version 3")
	case len(c.RawSubject) != 2 || c.RawSubject[0] != 0x30 || c.RawSubject[1] != 0x00:
		return nil, failf("AIK certificate subject must be empty")
	case c.IsCA:
		return nil, failf("AIK certificate must not be a CA")
	}
	hasEKU := false
	for _, eku := range c.UnknownExtKeyUsage {
		if eku.Equal(oidTCGKpAIKCertificate) {
			hasEKU = true
		}
	}
	if !hasEKU {
		return nil, failf("AIK certificate lacks the tcg-kp-AIKCertificate extended key usage")
	}
	hasManufacturer, err := sanHasTPMManufacturer(c.Extensions)
	if err != nil || !hasManufacturer {
		return nil, failf("AIK certificate SAN lacks the TPM manufacturer attribute")
	}
	pids, _, err := ca.SANPermanentIdentifiers(c.Extensions)
	if err != nil || len(pids) == 0 {
		return nil, failf("AIK certificate names no permanent identifier")
	}
	return pids, nil
}

// sanHasTPMManufacturer looks for the TCG manufacturer attribute
// (2.23.133.2.1) in a directoryName of the SAN, TPM 2.0 EK Credential Profile
// section 3.2.9, as WebAuthn 8.3.1 requires.
func sanHasTPMManufacturer(exts []pkix.Extension) (bool, error) {
	for _, ext := range exts {
		if !ext.Id.Equal(oidSubjectAltNameExt) {
			continue
		}
		var seq asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &seq); err != nil || len(rest) != 0 {
			return false, errors.New("malformed SAN")
		}
		rest := seq.Bytes
		for len(rest) > 0 {
			var gn asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
				return false, errors.New("malformed SAN")
			}
			if gn.Class != asn1.ClassContextSpecific || gn.Tag != 4 {
				continue
			}
			var rdns pkix.RDNSequence
			if _, err := asn1.Unmarshal(gn.Bytes, &rdns); err != nil {
				continue
			}
			for _, rdn := range rdns {
				for _, atv := range rdn {
					if atv.Type.Equal(oidTCGManufacturer) {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

// publicKeyThumbprint is base64url(SHA-256(PKIX DER)): the one form stored on
// the authorization and recomputed from the CSR at finalize (D-316 rule 2).
func publicKeyThumbprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
