// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

var (
	ErrCANotFound      = errors.New("ca not found")
	ErrInvalidCSR      = errors.New("invalid certificate signing request")
	ErrPolicyViolation = errors.New("template policy violation")
	// ErrCANotActive and ErrCANoSigningKey let API layers report a
	// CA-state problem as a conflict instead of a backend outage.
	ErrCANotActive    = errors.New("ca is not active")
	ErrCANoSigningKey = errors.New("ca has no signing key")
	// ErrCARevoked marks a CA that is revoked, or has a revoked ancestor.
	// It is joined with ErrCANotActive so existing 409 mapping still applies.
	ErrCARevoked = errors.New("ca is revoked")
	// ErrCAAlreadyRevoked: RevokeCA on a CA that is already revoked.
	ErrCAAlreadyRevoked = errors.New("ca is already revoked")
	// ErrCANotDeletable: DeleteCA on a CA that is neither revoked nor expired.
	ErrCANotDeletable = errors.New("ca must be revoked or expired before deletion")
	// ErrCAHasChildren: DeleteCA on a CA that still has child CAs.
	ErrCAHasChildren = errors.New("ca has child cas")

	// ErrUnknownKeyStorageType is returned when a CA is saved with a backend
	// label outside the canonical vocabulary (W23-10).
	ErrUnknownKeyStorageType = errors.New("unknown key storage type")
)

// NormalizeKeyStorageType maps an engine/env backend label onto the canonical
// API and DB vocabulary: software | pkcs11 | vault | cloud_kms | external.
// The engine keeps the env spelling ("cloudkms") in memory; normalising at the
// DB and API edges keeps the label identical before and after a restart.
func NormalizeKeyStorageType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "":
		return "software"
	case "cloudkms", "cloud-kms":
		return "cloud_kms"
	default:
		return s
	}
}

func validKeyStorageType(s string) bool {
	switch s {
	case "software", "pkcs11", "vault", "cloud_kms", "external":
		return true
	}
	return false
}

// CA represents a Certificate Authority with its certificate and key reference.
type CA struct {
	ID          string
	Name        string
	Type        string // "root" or "intermediate"
	KeyID       string // references keystore.Store
	Certificate *x509.Certificate
	CertPEM     []byte
	// CSRPEM is the PKCS#10 request of an issuing CA awaiting its offline-signed
	// certificate (status pending_certificate); cleared on completion (W23-04).
	CSRPEM     []byte
	ParentCAID string // empty for root CAs
	Status     string // "active", "suspended"
	CreatedAt  time.Time
	// KeyStorageType records which keystore.Store backend actually holds
	// KeyID's private key ("software", "pkcs11", "vault", "cloudkms"). It is
	// immutable after creation: the store never updates it (W23-10).
	// W19-08: previously hardcoded to "software" everywhere it was read,
	// so an HSM-held CA key was misreported as software-custody — a false
	// claim about key custody, not a cosmetic label. Empty for CAs with no
	// keystore-backed key (ImportCA/ImportCAChain).
	KeyStorageType string
	// ConnectorID names the issuer connector an external CA (Type "external")
	// delegates signing to; empty for hub CAs (W36-02, D-304).
	ConnectorID string
	// ExternalTrustPEM is the PEM bundle of CA certificates every upstream
	// response must chain to. It is the operator's statement of which CA the
	// upstream may sign with, so an upstream cannot silently switch issuers.
	ExternalTrustPEM []byte
}

// IssuanceRequest contains the parameters for certificate issuance.
type IssuanceRequest struct {
	CSR *x509.CertificateRequest
	// PQCCSR is set instead of CSR for a hand-rolled ML-DSA CSR (G-67/W4-07) --
	// x509.CertificateRequest.CheckSignature() cannot verify an ML-DSA
	// signature, so a PQC CSR is parsed+verified up front (see
	// ParseCertificateRequestMLDSA) rather than faked into the stdlib type.
	// HybridCSR is set instead of CSR/PQCCSR for a hand-rolled hybrid CSR
	// (G-68/W4-08) -- both its primary and alt self-signatures are verified
	// up front by ParseCertificateRequestHybrid. Exactly one of
	// CSR/PQCCSR/HybridCSR must be set.
	PQCCSR         *PQCCertificateRequest
	HybridCSR      *HybridCertificateRequest
	TemplateID     string
	Policy         *TemplatePolicy // optional; enforced before signing when non-nil
	Validity       time.Duration
	KeyUsage       x509.KeyUsage
	ExtKeyUsage    []x509.ExtKeyUsage
	DNSNames       []string
	IPAddresses    []net.IP
	URIs           []*url.URL // URI SANs (e.g. SPIFFE IDs: spiffe://td/path)
	OCSPServer     []string
	CRLDistPoints  []string
	IsCA           bool
	MaxPathLen     int
	MaxPathLenZero bool
	// Subject, when set, is used instead of the CSR's subject. A protocol
	// that authenticates the requester (W20-08 WSTEP) binds the certificate
	// to that identity; the CSR then only proves possession of the key.
	Subject *pkix.Name
	// CallerNamesOnly makes the SANs come solely from DNSNames/IPAddresses/
	// URIs above. Without it an empty caller list falls back to the CSR's
	// SANs, which would let an authenticated requester name any host.
	CallerNamesOnly bool
	// Backdate moves NotBefore this far before the issue time, never before
	// the issuing CA's own NotBefore. A client whose clock trails the CA's
	// by a moment otherwise sees a not-yet-valid certificate; Windows
	// CertEnroll refuses to install one (CERT_E_EXPIRED). Zero keeps
	// NotBefore at the issue time.
	Backdate time.Duration
	// ExtraExtensions are added verbatim, for protocol-specific markers
	// such as the Microsoft certificate-template extension autoenrollment
	// matches on. Extensions under id-ce (2.5.29) or id-pe
	// (1.3.6.1.5.5.7.1) are refused: those carry the trust semantics the
	// engine itself controls (SANs, key usage, constraints, AIA), and an
	// extra extension with the same OID would replace the engine's.
	ExtraExtensions []pkix.Extension
	// PermanentIdentifiers are written into the SAN as RFC 4043
	// PermanentIdentifier otherNames (W40-02 device attestation). Only a hub
	// CA can carry them: an external CA signs its own SAN, so the issuer
	// refuses the request rather than issue without the identifier.
	PermanentIdentifiers []PermanentIdentifier
}

// IssuedCertificate is the result of a successful issuance.
type IssuedCertificate struct {
	Certificate  *x509.Certificate
	CertPEM      []byte
	SerialNumber *big.Int
	Fingerprint  string
	// ChainPEM is the verified issuer chain (leaf excluded, self-signed root
	// excluded) when the certificate came from an external CA; empty for hub
	// CAs, whose chain callers build from GetCAChain.
	ChainPEM []byte
}

// Service is the CA engine interface.
type Service interface {
	// CreateRootCA generates a new self-signed root CA.
	CreateRootCA(name string, subject pkix.Name, algo keystore.Algorithm, validity time.Duration) (*CA, error)

	// CreateIntermediateCA generates a new intermediate CA signed by a parent.
	CreateIntermediateCA(name string, subject pkix.Name, algo keystore.Algorithm, parentCAID string, validity time.Duration) (*CA, error)

	// ImportCA imports a self-signed root CA certificate (without private key).
	// Returns an error if the certificate is not self-signed; use ImportCAChain for intermediates.
	ImportCA(name string, certPEM []byte) (*CA, error)

	// ImportCAChain imports an intermediate CA along with its full issuer chain.
	// The PEM may contain multiple certificates; the first must be the intermediate,
	// and subsequent entries must form a complete chain to a self-signed root.
	// Returns an error if signatures do not verify across the chain.
	ImportCAChain(name string, chainPEM []byte) (*CA, error)

	// IssueCertificate signs a CSR using the specified CA.
	IssueCertificate(caID string, req IssuanceRequest) (*IssuedCertificate, error)

	// GetCA retrieves a CA by ID.
	GetCA(id string) (*CA, error)

	// GetCAChain returns the certificate chain from leaf CA to root.
	GetCAChain(id string) ([]*CA, error)

	// ListCAs returns all CAs.
	ListCAs() ([]*CA, error)

	// UpdateCAStatus changes the status of a CA (active, suspended, revoked).
	UpdateCAStatus(id, status string) error

	// RotateCA re-keys a CA in place, re-issuing its certificate under a
	// fresh key, and records the event in the rotation ledger (W9-04/G-35).
	RotateCA(caID string, opts RotateCAOptions) (RotateCAResult, error)
}
