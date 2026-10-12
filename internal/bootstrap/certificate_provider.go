// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
)

const certificateProviderEnv = "APP_CERTIFICATE_PROVIDER"

const (
	certificateProviderFile = "file"
	certificateProviderCA   = "ca"
)

var certificateProviderWarnf = log.Printf

type CertificateItem struct {
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	SerialNumber       string   `json:"serial_number"`
	CommonName         string   `json:"common_name"`
	SubjectDN          string   `json:"subject_dn"`
	SubjectAltNames    []string `json:"subject_alt_names"`
	URISANs            []string `json:"uri_sans,omitempty"` // URI SANs (e.g. SPIFFE IDs)
	IssuerCN           string   `json:"issuer_cn"`
	IssuerDN           string   `json:"issuer_dn"`
	CAID               string   `json:"ca_id"`
	TemplateID         string   `json:"template_id"`
	TeamID             string   `json:"team_id"`
	ValidFrom          string   `json:"valid_from"`
	ValidUntil         string   `json:"valid_until"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	KeySizeBits        int      `json:"key_size_bits"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	ExtendedKeyUsage   []string `json:"extended_key_usage"`
	KeyUsage           []string `json:"key_usage"`
	ChainComplete      bool     `json:"chain_complete"`
	ChainTrusted       bool     `json:"chain_trusted"`
	PQCVulnerable      bool     `json:"pqc_vulnerable"`
	PQCReadiness       string   `json:"pqc_readiness"` // not_applicable, vulnerable, migration_ready, quantum_safe
	RiskScore          int      `json:"risk_score"`
	RiskFlags          []string `json:"risk_flags"`
	Grade              string   `json:"grade"`
	RenewalMethod      string   `json:"renewal_method"`
	RenewalStatus      string   `json:"renewal_status"`
	Source             string   `json:"source"`
	// Estate model (W11-01, V5/D-106): where the certificate came from and
	// who manages it. Values enforced by migration 000043's CHECKs.
	Origin          string `json:"origin"`           // internal|imported|discovered|synced
	ManagementState string `json:"management_state"` // managed|external|unmanaged
	// RenewalConnectorID is the upstream connector a takeover chose
	// (W11-03/W11-04); empty = internal renewal path.
	RenewalConnectorID string  `json:"renewal_connector_id,omitempty"`
	PredecessorFP      *string `json:"predecessor_fingerprint,omitempty"`
	SuccessorFP        *string `json:"successor_fingerprint,omitempty"`
	RevokedAt          *string `json:"revoked_at,omitempty"`
	RevocationReason   *int    `json:"revocation_reason,omitempty"`
	ETag               int     `json:"etag,omitempty"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
	// Ownership fields — settable via PATCH /api/v1/certificates/{fp}/ownership.
	OwnerEmail  string   `json:"owner_email,omitempty"`
	OwnerTeam   string   `json:"owner_team,omitempty"`
	ServiceName string   `json:"service_name,omitempty"`
	Labels      []string `json:"labels,omitempty"`
}

type CertificateEndpoint struct {
	ID              string `json:"id"`
	Hostname        string `json:"hostname"`
	IPAddress       string `json:"ip_address"`
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
	CurrentlyActive bool   `json:"currently_active"`
}

type CertificateDetail struct {
	CertificateItem
	Endpoints []CertificateEndpoint `json:"endpoints"`
}

type CertificateListQuery struct {
	Limit      int
	Offset     int
	Q          string
	CAID       string
	TemplateID string
	TeamID     string
	Status     string
	Grades     []string
	Order      string
	// W11-01 estate filters.
	Origin          string
	ManagementState string
}

type CertificateListResult struct {
	Items []CertificateItem
	Total int
	Limit int
}

type CertificateChainItem struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	CommonName        string `json:"common_name"`
	ValidFrom         string `json:"valid_from"`
	ValidUntil        string `json:"valid_until"`
	RenewalStatus     string `json:"renewal_status"`
	Position          string `json:"position"`
}

type CertificateChainResult struct {
	CurrentFingerprint string                 `json:"current_fingerprint"`
	Chain              []CertificateChainItem `json:"chain"`
}

type CertificateRevokeRequest struct {
	ReasonCode int    `json:"reason_code"`
	ReasonText string `json:"reason_text"`
}

type CertificateRevokeResult struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	RenewalStatus     string `json:"renewal_status"`
	RevokedAt         string `json:"revoked_at"`
	RevocationReason  int    `json:"revocation_reason"`
}

type CertificateIssueRequest struct {
	CAID       string                 `json:"ca_id"`
	TemplateID string                 `json:"template_id"`
	CSRPEM     string                 `json:"csr_pem"`
	TeamID     string                 `json:"team_id"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type CertificateIssueResult struct {
	CertificateItem
}

type CertificateRenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

type CertificateImportRequest struct {
	CertificatePEM string `json:"certificate_pem"`
	TeamID         string `json:"team_id"`
	Notes          string `json:"notes"`
}

type CertificateDownloadResult struct {
	ContentType string
	Filename    string
	Body        []byte
}

var (
	errCertificateNotFound  = errors.New("certificate not found")
	errCertificateConflict  = errors.New("certificate conflict")
	errCertificateInvalid   = errors.New("certificate invalid")
	errCertificateForbidden = errors.New("certificate forbidden")
	errApprovalRequired     = errors.New("approval required")
)

// CertificateOwnershipRequest sets ownership metadata on a certificate.
type CertificateOwnershipRequest struct {
	OwnerEmail  string   `json:"owner_email"`
	OwnerTeam   string   `json:"owner_team"`
	ServiceName string   `json:"service_name"`
	Labels      []string `json:"labels"`
}

type CertificateProvider interface {
	ListCertificates(context.Context, CertificateListQuery) (CertificateListResult, error)
	GetCertificate(context.Context, string) (CertificateDetail, bool, error)
	GetCertificateChain(context.Context, string) (CertificateChainResult, bool, error)
	IssueCertificate(context.Context, CertificateIssueRequest) (CertificateIssueResult, error)
	RenewCertificate(context.Context, string, CertificateRenewRequest) (CertificateIssueResult, error)
	RevokeCertificate(context.Context, string, CertificateRevokeRequest) (CertificateRevokeResult, error)
	DownloadCertificate(context.Context, string, string, bool) (CertificateDownloadResult, error)
	ImportCertificate(context.Context, CertificateImportRequest) (CertificateIssueResult, error)
	UpdateOwnership(context.Context, string, CertificateOwnershipRequest) (CertificateItem, error)
	// UpdateEstate transitions a certificate's estate bookkeeping (W11-03
	// takeover): management state and chosen renewal path. Empty fields are
	// left unchanged.
	UpdateEstate(context.Context, string, EstateUpdate) (CertificateItem, error)
}

// EstateUpdate is a partial estate transition. Empty string = unchanged.
type EstateUpdate struct {
	Origin             string `json:"origin,omitempty"`
	ManagementState    string `json:"management_state,omitempty"`
	RenewalMethod      string `json:"renewal_method,omitempty"`
	RenewalConnectorID string `json:"renewal_connector_id,omitempty"`
	// RenewalStatus propagates upstream lifecycle (W11-05 sync): a cert the
	// original CA revoked is revoked here too, without touching our own
	// revocation machinery.
	RenewalStatus string `json:"renewal_status,omitempty"`
}

// RenewalStatus is the renewal_status vocabulary. It must match the
// certificates.renewal_status CHECK constraint (migrations 000002/000073) and
// the docs/openapi.yaml enum. The CertificateItem field stays a plain string
// (it is the JSON/DB shape); code that reads or writes it uses these constants.
// The list filter's status query value (certificate_index.go) is a separate,
// derived vocabulary (active/revoked from RevokedAt), not a renewal_status.
type RenewalStatus string

const (
	RenewalStatusActive          RenewalStatus = "active"
	RenewalStatusRenewed         RenewalStatus = "renewed"
	RenewalStatusExpired         RenewalStatus = "expired"
	RenewalStatusRevoked         RenewalStatus = "revoked"
	RenewalStatusReissueRequired RenewalStatus = "reissue_required" // written by the CA-key compromise flow
)

var renewalStatuses = []RenewalStatus{
	RenewalStatusActive, RenewalStatusRenewed, RenewalStatusExpired,
	RenewalStatusRevoked, RenewalStatusReissueRequired,
}

func validRenewalStatus(s string) bool {
	for _, v := range renewalStatuses {
		if s == string(v) {
			return true
		}
	}
	return false
}

// renewalStatusList is the vocabulary for error messages, so the text cannot
// drift from validRenewalStatus.
func renewalStatusList() string {
	names := make([]string, len(renewalStatuses))
	for i, v := range renewalStatuses {
		names[i] = string(v)
	}
	return strings.Join(names, ", ")
}

func NewCertificateProviderFromEnv() CertificateProvider {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(certificateProviderEnv)))
	switch mode {
	case "", certificateProviderFile:
		return NewFileCertificateProviderFromEnv()
	default:
		certificateProviderWarnf("warning: unknown APP_CERTIFICATE_PROVIDER=%q; falling back to file", mode)
		return NewFileCertificateProviderFromEnv()
	}
}

func parseCertificateLimit(raw string, defaultLimit int) int {
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

func parseCertificateOffset(raw string) int {
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

func parseCertificateIssueRequest(raw []byte) (CertificateIssueRequest, error) {
	var req CertificateIssueRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return CertificateIssueRequest{}, errCertificateInvalid
	}
	if strings.TrimSpace(req.CAID) == "" || strings.TrimSpace(req.TemplateID) == "" || strings.TrimSpace(req.CSRPEM) == "" {
		return CertificateIssueRequest{}, errCertificateInvalid
	}
	return req, nil
}

func parseCertificateRenewRequest(raw []byte) (CertificateRenewRequest, error) {
	var req CertificateRenewRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return CertificateRenewRequest{}, errCertificateInvalid
	}
	if strings.TrimSpace(req.CSRPEM) == "" {
		return CertificateRenewRequest{}, errCertificateInvalid
	}
	return req, nil
}

func parseCertificateImportRequest(raw []byte) (CertificateImportRequest, error) {
	var req CertificateImportRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return CertificateImportRequest{}, errCertificateInvalid
	}
	if strings.TrimSpace(req.CertificatePEM) == "" {
		return CertificateImportRequest{}, errCertificateInvalid
	}
	return req, nil
}
