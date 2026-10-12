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
	"time"

	"kryptkeeper/internal/keystore"
)

var (
	ErrCANotFound      = errors.New("ca not found")
	ErrInvalidCSR      = errors.New("invalid certificate signing request")
	ErrPolicyViolation = errors.New("template policy violation")
)

// CA represents a Certificate Authority with its certificate and key reference.
type CA struct {
	ID          string
	Name        string
	Type        string // "root" or "intermediate"
	KeyID       string // references keystore.Store
	Certificate *x509.Certificate
	CertPEM     []byte
	ParentCAID  string // empty for root CAs
	Status      string // "active", "suspended"
	CreatedAt   time.Time
	// KeyStorageType records which keystore.Store backend actually holds
	// KeyID's private key ("software", "pkcs11", "vault", "cloudkms").
	// W19-08: previously hardcoded to "software" everywhere it was read,
	// so an HSM-held CA key was misreported as software-custody — a false
	// claim about key custody, not a cosmetic label. Empty for CAs with no
	// keystore-backed key (ImportCA/ImportCAChain).
	KeyStorageType string
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
}

// IssuedCertificate is the result of a successful issuance.
type IssuedCertificate struct {
	Certificate  *x509.Certificate
	CertPEM      []byte
	SerialNumber *big.Int
	Fingerprint  string
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
