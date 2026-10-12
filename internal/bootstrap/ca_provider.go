// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
)

const caProviderEnv = "APP_CA_PROVIDER"

const (
	caProviderFile = "file"
)

var caProviderWarnf = log.Printf

type CAListItem struct {
	ID                           string  `json:"id"`
	Name                         string  `json:"name"`
	DisplayName                  string  `json:"display_name"`
	Type                         string  `json:"type"`
	ParentCAID                   *string `json:"parent_ca_id"`
	Status                       string  `json:"status"`
	KeyStorageType               string  `json:"key_storage_type"`
	CertificateFingerprintSHA256 string  `json:"certificate_fingerprint_sha256"`
	// CertificatePEM is the actual PEM-armored certificate bytes (W19-01: the
	// chain?format=pem export previously had no real certificate data to
	// serve and fabricated a "PEM" block by wrapping the SHA-256 fingerprint
	// hex string in BEGIN/END CERTIFICATE markers -- a string that looks like
	// a certificate but is not one, undetected because no real ACME/EST/SCEP
	// client had ever fetched a CA chain from a live hub to feed to openssl).
	CertificatePEM        string   `json:"certificate_pem,omitempty"`
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
	errCACreateUnsupported   = errors.New("ca create not supported by this provider")
	errCARotateUnsupported   = errors.New("ca key rotation not supported by this provider")
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

// CACreateRequest is the payload for creating a new CA.
type CACreateRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Type        string `json:"type"`      // "root" or "intermediate"
	Algorithm   string `json:"algorithm"` // "ecdsaP256", "ecdsaP384", "rsa3072"
	ValidityStr string `json:"validity"`  // e.g. "10y", "3650d", or RFC3339 duration
	ParentCAID  string `json:"parent_ca_id,omitempty"`
	SubjectCN   string `json:"subject_cn"`
	SubjectOrg  string `json:"subject_org,omitempty"`
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
