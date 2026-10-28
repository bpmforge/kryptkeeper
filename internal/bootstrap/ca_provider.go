// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"kryptkeeper/internal/logging"
)

const caProviderEnv = "APP_CA_PROVIDER"

const (
	caProviderFile = "file"
)

var caProviderWarnf = logging.Warnf

type CAListItem struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	DisplayName    string  `json:"display_name"`
	Type           string  `json:"type"`
	ParentCAID     *string `json:"parent_ca_id"`
	Status         string  `json:"status"`
	KeyStorageType string  `json:"key_storage_type"`
	// ConnectorID names the issuer connector behind an external CA (W36-02).
	ConnectorID string `json:"connector_id,omitempty"`
	// RevocationSigning is how CRLs/OCSP for this CA are signed: ml-dsa for an
	// ML-DSA CA key, else classical (W31-05).
	RevocationSigning            string `json:"revocation_signing"`
	CertificateFingerprintSHA256 string `json:"certificate_fingerprint_sha256"`
	// CertificatePEM is the actual PEM-armored certificate bytes (W19-01: the
	// chain?format=pem export previously had no real certificate data to
	// serve and fabricated a "PEM" block by wrapping the SHA-256 fingerprint
	// hex string in BEGIN/END CERTIFICATE markers -- a string that looks like
	// a certificate but is not one, undetected because no real ACME/EST/SCEP
	// client had ever fetched a CA chain from a live hub to feed to openssl).
	CertificatePEM string `json:"certificate_pem,omitempty"`
	// Warnings are advisory notes about the CA (e.g. Ed25519 client compatibility).
	Warnings              []string `json:"warnings,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points"`
	OCSPServiceURL        *string  `json:"ocsp_service_url"`
	Certificate           *struct {
		FingerprintSHA256 string `json:"fingerprint_sha256"`
		SubjectDN         string `json:"subject_dn"`
		ValidFrom         string `json:"valid_from"`
		ValidUntil        string `json:"valid_until"`
		PublicKeyAlg      string `json:"public_key_algorithm"`
		KeySizeBits       int    `json:"key_size_bits"`
	} `json:"certificate,omitempty"`
	// CSRPEM is the PKCS#10 request of an issuing CA awaiting its offline-signed
	// certificate (status pending_certificate). Public data; never key material.
	CSRPEM                   string `json:"csr_pem,omitempty"`
	ActiveIssuedCertificates int    `json:"active_issued_certificates,omitempty"`
	CreatedAt                string `json:"created_at"`
	UpdatedAt                string `json:"updated_at"`
}

type CAListQuery struct {
	Limit  int
	Offset int
	Type   string
	Status string
}

type CAListResult struct {
	Items []CAListItem
	Total int
	Limit int
}

type CAStatusChange struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
}

type CAUpdateRequest struct {
	DisplayName           *string   `json:"display_name"`
	CRLDistributionPoints *[]string `json:"crl_distribution_points"`
	OCSPServiceURL        *string   `json:"ocsp_service_url"`
}

var (
	errCANotFound            = errors.New("ca not found")
	errCAConflict            = errors.New("ca state conflict")
	errCAImmutableField      = errors.New("ca immutable field")
	errCAInvalidUpdateFields = errors.New("ca invalid update fields")
	errCAUnprocessable       = errors.New("ca unprocessable")
	// errCAUpdateUnsupported marks an update the CA's kind cannot take (an
	// external CA's CRL/OCSP pointers); the handler answers 422.
	errCAUpdateUnsupported = errors.New("an external CA's CRL and OCSP are its upstream's")
	errCACreateUnsupported = errors.New("ca create not supported by this provider")
	errCARotateUnsupported = errors.New("ca key rotation not supported by this provider")
	// errCARotationRolledBack marks a rotation that failed and was undone (W23-16).
	errCARotationRolledBack = errors.New("ca key rotation failed and was rolled back")
)

// CAKeyRotationResult is the API-layer view of a completed CA re-key
// (W9-04/G-35). KeyID is unchanged from before rotation -- the CA's
// keystore key rotates in place under the same ID. LedgerPersisted is
// false only when the key rotation and certificate re-issuance succeeded
// but the audit-ledger row failed to write -- the rotation itself is
// still fully in effect; see the handler for how this is surfaced.
type CAKeyRotationResult struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	KeyID           string `json:"key_id"`
	RotatedAt       string `json:"rotated_at"`
	LedgerID        string `json:"ledger_id"`
	LedgerPersisted bool   `json:"ledger_persisted"`
}

// CARotator is an optional CAProvider capability: callers should
// type-assert a CAProvider to CARotator before use, mirroring
// keystore.HybridKeyLoader's established optional-capability pattern in
// this codebase. Only the engine-backed provider (real crypto active)
// implements it -- the file-backed provider has no keystore keys to rotate.
type CARotator interface {
	RotateCAKey(ctx context.Context, id string, algorithm string) (CAKeyRotationResult, error)
}

// CARevoker is an optional CAProvider capability (W23-34): irreversible CA
// revocation. Callers must reach it only through a dual-control approval.
type CARevoker interface {
	RevokeCA(ctx context.Context, id string) (CARevokeResult, error)
	// CARevokeBlastRadius counts active certificates under the CA and its
	// descendants, plus the descendant CAs.
	CARevokeBlastRadius(ctx context.Context, id string) (certs, descendants int, err error)
}

// CARevokeResult is the outcome of an executed CA revocation.
type CARevokeResult struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
	StatusOnly    bool   `json:"status_only"`
	AffectedCerts int    `json:"affected_certs"`
	DescendantCAs int    `json:"descendant_cas"`
	RevokedAt     string `json:"revoked_at"`
}

// CAImporter is an optional CAProvider capability (W23-03): import an
// external self-signed root as a keyless trust anchor and remove it again.
// Only the engine-backed provider implements it.
type CAImporter interface {
	ImportRootCA(ctx context.Context, name string, certPEM []byte) (CAListItem, error)
	CheckTrustAnchorRemovable(ctx context.Context, id string) error
	RemoveTrustAnchor(ctx context.Context, id string) error
}

// ExternalCACreator is an optional CAProvider capability (W36-02): record a CA
// whose signing is delegated to an issuer connector. Only the engine-backed
// provider implements it.
type ExternalCACreator interface {
	CreateExternalCA(ctx context.Context, name, connectorID string, trustPEM []byte) (CAListItem, error)
}

// CACSRProvider is an optional CAProvider capability (W23-04): the offline-root
// flow where an issuing CA's key lives in the hub, its CSR is signed elsewhere
// and the signed certificate is uploaded back.
type CACSRProvider interface {
	GetCSR(ctx context.Context, id string) (string, error)
	CompleteCA(ctx context.Context, id string, certPEM []byte) (CAListItem, error)
}

// CACreateRequest is the payload for creating a new CA.
type CACreateRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Type        string `json:"type"`      // "root" or "intermediate"
	Algorithm   string `json:"algorithm"` // one of caSupportedAlgorithms
	ValidityStr string `json:"validity"`  // e.g. "10y", "3650d", or RFC3339 duration
	ParentCAID  string `json:"parent_ca_id,omitempty"`
	SubjectCN   string `json:"subject_cn"`
	SubjectOrg  string `json:"subject_org,omitempty"`
	// KeyStorageType picks the key backend for this CA (canonical vocabulary,
	// W23-11); empty means the hub default.
	KeyStorageType string `json:"key_storage_type,omitempty"`
}

type CAProvider interface {
	ListCAs(context.Context, CAListQuery) (CAListResult, error)
	GetCA(context.Context, string) (CAListItem, bool, error)
	GetCAChain(context.Context, string) ([]CAListItem, bool, error)
	UpdateCA(context.Context, string, CAUpdateRequest) (CAListItem, error)
	DeleteCA(context.Context, string) error
	SuspendCA(context.Context, string) (CAStatusChange, error)
	ActivateCA(context.Context, string) (CAStatusChange, error)
	CreateCA(context.Context, CACreateRequest) (CAListItem, error)
}

func NewCAProviderFromEnv() CAProvider {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(caProviderEnv)))
	switch mode {
	case "", caProviderFile:
		return NewFileCAProviderFromEnv()
	default:
		caProviderWarnf("warning: unknown APP_CA_PROVIDER=%q; falling back to file", mode)
		return NewFileCAProviderFromEnv()
	}
}

func parseCALimit(raw string, defaultLimit int) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultLimit
	}
	limit, err := strconv.Atoi(trimmed)
	if err != nil || limit <= 0 {
		return defaultLimit
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func parseCAOffset(raw string) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}
	offset, err := strconv.Atoi(trimmed)
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}
