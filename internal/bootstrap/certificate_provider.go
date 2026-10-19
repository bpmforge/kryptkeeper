// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"

	"kryptkeeper/internal/logging"
)

const certificateProviderEnv = "APP_CERTIFICATE_PROVIDER"

const (
	certificateProviderFile = "file"
	certificateProviderCA   = "ca"
)

var certificateProviderWarnf = logging.Warnf

type CertificateItem struct {
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	SerialNumber      string   `json:"serial_number"`
	CommonName        string   `json:"common_name"`
	SubjectDN         string   `json:"subject_dn"`
	SubjectAltNames   []string `json:"subject_alt_names"`
	URISANs           []string `json:"uri_sans,omitempty"` // URI SANs (e.g. SPIFFE IDs)
	IssuerCN          string   `json:"issuer_cn"`
	IssuerDN          string   `json:"issuer_dn"`
	CAID              string   `json:"ca_id"`
	TemplateID        string   `json:"template_id"`
	// TemplateRevision is the revision of the template in force when this
	// certificate was issued (W23-44); 0 = none recorded.
	TemplateRevision   int    `json:"template_revision,omitempty"`
	TeamID             string `json:"team_id"`
	ValidFrom          string `json:"valid_from"`
	ValidUntil         string `json:"valid_until"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	KeySizeBits        int    `json:"key_size_bits"`
	// KeyAlgorithmDisplay is the ML-DSA parameter set (e.g. "ML-DSA-65")
	// derived from the certificate; empty for other keys. Display only --
	// public_key_algorithm keeps the stored "ML-DSA" family value.
	KeyAlgorithmDisplay string   `json:"key_algorithm_display,omitempty"`
	SignatureAlgorithm  string   `json:"signature_algorithm"`
	ExtendedKeyUsage    []string `json:"extended_key_usage"`
	KeyUsage            []string `json:"key_usage"`
	// ChainComplete/ChainTrusted describe the chain the hub itself issued or
	// ingested. For a discovered certificate they are nil (absent in JSON):
	// what an endpoint served is an endpoint fact -- the same certificate can
	// be complete on one endpoint and missing its intermediate on another --
	// and lives on discovery's mapped_certs. The certificates-table column is a
	// stale default for those rows, so it must not be presented.
	ChainComplete *bool `json:"chain_complete,omitempty"`
	ChainTrusted  *bool `json:"chain_trusted,omitempty"`
	// TrustClass answers whose certificate this is: managed (this hub's CAs),
	// public, private_other, self_signed or unknown. Only classified for
	// discovery-found certs; empty on others. Derived by effectiveTrustClass.
	TrustClass    string   `json:"trust_class,omitempty"`
	PQCVulnerable bool     `json:"pqc_vulnerable"`
	PQCReadiness  string   `json:"pqc_readiness"` // not_applicable, vulnerable, migration_ready, quantum_safe
	RiskScore     int      `json:"risk_score"`
	RiskFlags     []string `json:"risk_flags"`
	Grade         string   `json:"grade"`
	RenewalMethod string   `json:"renewal_method"`
	RenewalStatus string   `json:"renewal_status"`
	Source        string   `json:"source"`
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
	// OwnershipSource records who assigned OwnerTeam (W22-24); "" = unowned.
	OwnershipSource string `json:"ownership_source,omitempty"`
}

func boolRef(b bool) *bool { return &b }

func boolVal(p *bool) bool { return p != nil && *p }

// chainFact is the certificate-level chain verdict to present: the stored one,
// except for discovered certificates, whose chain is judged per endpoint.
func chainFact(origin string, v bool) *bool {
	if origin == "discovered" {
		return nil
	}
	return &v
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
	// Owner "unassigned" keeps active certificates with no owner team
	// (W22-24); the dashboard unowned count uses the same predicate.
	Owner string
	// TrustClass keeps certificates of one class (see CertificateItem.TrustClass).
	TrustClass string
	// SunsetGroup keeps the active certificates of one Algorithm Sunset group
	// (sunsetRules ids), the set that group's report count is taken over.
	SunsetGroup string
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
	// RevocationScope says whether the revocation reached a CRL/OCSP
	// responder ("ca") or only the hub inventory ("inventory_only": a
	// certificate with no issuing CA in this hub, so revoking at the real
	// issuer is still the operator's job).
	RevocationScope string `json:"revocation_scope"`
}

// Revocation scopes reported by CertificateRevokeResult.
const (
	RevocationScopeCA            = "ca"
	RevocationScopeInventoryOnly = "inventory_only"
)

type CertificateIssueRequest struct {
	CAID       string                 `json:"ca_id"`
	TemplateID string                 `json:"template_id"`
	CSRPEM     string                 `json:"csr_pem"`
	TeamID     string                 `json:"team_id"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type CertificateIssueResult struct {
	CertificateItem
	// Reused is set when an existing certificate answered the request
	// (W26-32); the handler returns 200 instead of 201.
	Reused bool `json:"-"`
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
	// Source is set by the server, never by a client: a PATCH body must not
	// be able to claim a cmdb/agent provenance it did not have.
	Source string `json:"-"`
}

// Ownership sources (W22-24). Must match the ownership_source column values.
const (
	OwnershipSourceManual = "manual"
	OwnershipSourceCMDB   = "cmdb"
	OwnershipSourceImport = "import"
	OwnershipSourceAgent  = "agent"
)

func validOwnershipSource(s string) bool {
	switch s {
	case OwnershipSourceManual, OwnershipSourceCMDB, OwnershipSourceImport, OwnershipSourceAgent:
		return true
	}
	return false
}

// resolveOwnershipSource validates the request's source and returns the value
// to store: "" when the assignment clears the owner (the cert is unowned again).
func resolveOwnershipSource(req CertificateOwnershipRequest) (string, error) {
	src := req.Source
	if src == "" {
		src = OwnershipSourceManual
	}
	if !validOwnershipSource(src) {
		return "", errCertificateInvalid
	}
	if strings.TrimSpace(req.OwnerTeam) == "" {
		return "", nil
	}
	return src, nil
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
	// ClearRenewalConnector empties RenewalConnectorID (an empty string above
	// means "leave alone"); estate revert uses it to undo a takeover's connector.
	ClearRenewalConnector bool `json:"-"`
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
