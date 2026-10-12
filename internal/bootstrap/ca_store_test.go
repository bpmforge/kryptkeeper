// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type stubCertSummaryForCA struct{}

func (stubCertSummaryForCA) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	return CertSummarySnapshot{Total: 0, Expiring30Days: 0, Expired: 0, Source: "file-store-default"}, nil
}

type stubAuditProviderForCA struct{}

func (stubAuditProviderForCA) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: []AuditEntry{}, Total: 0, Limit: 25}, nil
}

func (stubAuditProviderForCA) AppendEntry(context.Context, AuditEntry) error { return nil }

type stubTemplateProviderForCA struct{}

func (stubTemplateProviderForCA) ListTemplates(context.Context, TemplateListQuery) (TemplateListResult, error) {
	return TemplateListResult{Items: []TemplateItem{}, Total: 0, Limit: 25}, nil
}

func (stubTemplateProviderForCA) GetTemplate(context.Context, string) (TemplateItem, bool, error) {
	return TemplateItem{}, false, nil
}

func (stubTemplateProviderForCA) CreateTemplate(context.Context, TemplateUpsertRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateInvalidCreate
}

func (stubTemplateProviderForCA) ReplaceTemplate(context.Context, string, TemplateUpsertRequest, int) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProviderForCA) CloneTemplate(context.Context, string, TemplateCloneRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProviderForCA) PatchTemplate(context.Context, string, TemplatePatchRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProviderForCA) DeleteTemplate(context.Context, string) error {
	return errTemplateNotFound
}

func (p *fileCAProvider) mustGetChainForTest(ctx context.Context, id string, t *testing.T) []CAListItem {
	t.Helper()
	chain, found, err := p.GetCAChain(ctx, id)
	if err != nil {
		t.Fatalf("unexpected chain error: %v", err)
	}
	if !found {
		t.Fatalf("expected chain for id=%s", id)
	}
	return chain
}

func TestFileCAProviderFiltersAndPagination(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
{"id":"ca-iss-1","name":"iss-1","display_name":"Issuing 1","type":"issuing","parent_ca_id":"ca-root-1","status":"suspended","key_storage_type":"software","certificate_fingerprint_sha256":"fp-iss-1","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	provider := NewFileCAProviderFromEnv()
	result, err := provider.ListCAs(context.Background(), CAListQuery{Limit: 1, Offset: 0, Type: "root", Status: "active"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 || len(result.Items) != 1 || result.Items[0].ID != "ca-root-1" {
		t.Fatalf("unexpected CA result: %+v", result)
	}
}

func TestCAHandlerReturnsContractShape(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-handler.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), stubTemplateProviderForCA{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cas?type=root&status=active&limit=1&cursor=0", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", rec.Code)
	}

	var payload struct {
		Data []CAListItem `json:"data"`
		Meta struct {
			Total int `json:"total"`
			Limit int `json:"limit"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode CA payload: %v", err)
	}
	if payload.Meta.Total != 1 || payload.Meta.Limit != 1 || len(payload.Data) != 1 {
		t.Fatalf("unexpected CA payload: %+v", payload)
	}
}

func TestFileCAProviderGetCAByID(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-get.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	provider := NewFileCAProviderFromEnv()
	item, found, err := provider.GetCA(context.Background(), "ca-root-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || item.ID != "ca-root-1" {
		t.Fatalf("expected to find ca-root-1, got found=%v item=%+v", found, item)
	}
}

func TestFileCAProviderGetCAChain(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-chain.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","certificate":{"fingerprint_sha256":"fp-root-1","subject_dn":"CN=Root 1","valid_from":"2026-04-01T00:00:00Z","valid_until":"2036-04-01T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":4096},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
{"id":"ca-iss-1","name":"iss-1","display_name":"Issuing 1","type":"issuing","parent_ca_id":"ca-root-1","status":"active","key_storage_type":"software","certificate_fingerprint_sha256":"fp-iss-1","certificate":{"fingerprint_sha256":"fp-iss-1","subject_dn":"CN=Issuing 1","valid_from":"2026-04-02T00:00:00Z","valid_until":"2031-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	provider := NewFileCAProviderFromEnv().(*fileCAProvider)
	chain := provider.mustGetChainForTest(context.Background(), "ca-iss-1", t)
	if len(chain) != 2 || chain[0].ID != "ca-iss-1" || chain[1].ID != "ca-root-1" {
		t.Fatalf("unexpected chain: %+v", chain)
	}
}

func TestCAHandlerGetByID(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-get-handler.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","certificate":{"fingerprint_sha256":"fp-root-1","subject_dn":"CN=Root 1","valid_from":"2026-04-01T00:00:00Z","valid_until":"2036-04-01T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":4096},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), stubTemplateProviderForCA{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cas/ca-root-1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", rec.Code)
	}

	var payload struct {
		Data CAListItem `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode CA payload: %v", err)
	}
	if payload.Data.ID != "ca-root-1" || payload.Data.Certificate == nil {
		t.Fatalf("unexpected CA payload: %+v", payload)
	}
}

func TestCAHandlerGetByIDReturns404WhenMissing(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_CA_FILE", filepath.Join(t.TempDir(), "missing.json"))

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), stubTemplateProviderForCA{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cas/not-there", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 status, got %d", rec.Code)
	}
}

// TestCAHandlerGetChainJSONAndPEM proves the format=pem export serves a real,
// parseable certificate (W19-01: it used to wrap the SHA-256 fingerprint HEX
// STRING in BEGIN/END CERTIFICATE markers -- a value no x509 parser could
// ever decode -- and nothing caught it because the old assertion only
// checked for the marker substring, never that the body actually parsed).
// The fixture embeds real self-signed test certificates (throwaway keys,
// generated here, never written to disk) rather than a placeholder string.
func TestCAHandlerGetChainJSONAndPEM(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	rootPEM := generateSelfSignedTestCertPEM(t, "Root 1")
	issPEM := generateSelfSignedTestCertPEM(t, "Issuing 1")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-chain-handler.json")
	fixture := []map[string]any{
		{
			"id": "ca-root-1", "name": "root-1", "display_name": "Root 1", "type": "root",
			"parent_ca_id": nil, "status": "active", "key_storage_type": "pkcs11",
			"certificate_fingerprint_sha256": "fp-root-1", "certificate_pem": rootPEM,
			"certificate": map[string]any{
				"fingerprint_sha256": "fp-root-1", "subject_dn": "CN=Root 1",
				"valid_from": "2026-04-01T00:00:00Z", "valid_until": "2036-04-01T00:00:00Z",
				"public_key_algorithm": "RSA", "key_size_bits": 4096,
			},
			"crl_distribution_points": []string{}, "ocsp_service_url": nil,
			"created_at": "2026-04-01T00:00:00Z", "updated_at": "2026-04-01T00:00:00Z",
		},
		{
			"id": "ca-iss-1", "name": "iss-1", "display_name": "Issuing 1", "type": "issuing",
			"parent_ca_id": "ca-root-1", "status": "active", "key_storage_type": "software",
			"certificate_fingerprint_sha256": "fp-iss-1", "certificate_pem": issPEM,
			"certificate": map[string]any{
				"fingerprint_sha256": "fp-iss-1", "subject_dn": "CN=Issuing 1",
				"valid_from": "2026-04-02T00:00:00Z", "valid_until": "2031-04-02T00:00:00Z",
				"public_key_algorithm": "RSA", "key_size_bits": 2048,
			},
			"crl_distribution_points": []string{}, "ocsp_service_url": nil,
			"created_at": "2026-04-02T00:00:00Z", "updated_at": "2026-04-02T00:00:00Z",
		},
	}
	body, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("failed to marshal CA fixture: %v", err)
	}
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), stubTemplateProviderForCA{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	jsonReq := httptest.NewRequest(http.MethodGet, "/api/v1/cas/ca-iss-1/chain", nil)
	jsonReq.Header.Set("Authorization", "Bearer test-token")
	jsonRec := httptest.NewRecorder()
	mux.ServeHTTP(jsonRec, jsonReq)
	if jsonRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for json chain, got %d", jsonRec.Code)
	}
	if got := jsonRec.Header().Get("Content-Type"); got == "" || got[:16] != "application/json" {
		t.Fatalf("expected json content type, got %q", got)
	}
	if !strings.Contains(jsonRec.Body.String(), `"ca_id":"ca-iss-1"`) {
		t.Fatalf("expected ca_id in json chain payload: %s", jsonRec.Body.String())
	}

	pemReq := httptest.NewRequest(http.MethodGet, "/api/v1/cas/ca-iss-1/chain?format=pem", nil)
	pemReq.Header.Set("Authorization", "Bearer test-token")
	pemRec := httptest.NewRecorder()
	mux.ServeHTTP(pemRec, pemReq)
	if pemRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for pem chain, got %d", pemRec.Code)
	}
	if got := pemRec.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Fatalf("expected pem content type, got %q", got)
	}
	// The real assertion: every PEM block in the response must be a
	// certificate x509 can actually parse, not just text that looks like one.
	rest := pemRec.Body.Bytes()
	parsed := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatalf("chain PEM block %d did not parse as a certificate: %v", parsed, err)
		}
		parsed++
	}
	if parsed != 2 {
		t.Fatalf("expected 2 parseable certificates in chain PEM, got %d: %s", parsed, pemRec.Body.String())
	}
}

// generateSelfSignedTestCertPEM returns a throwaway self-signed certificate
// (ECDSA P-256, discarded key) PEM-encoded for use as CA fixture data --
// never a real CA key, per CLAUDE.md's private-key-boundary rule.
func generateSelfSignedTestCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestFileCAProviderSuspendAndActivate(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-status.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	provider := NewFileCAProviderFromEnv()
	change, err := provider.SuspendCA(context.Background(), "ca-root-1")
	if err != nil || change.Status != "suspended" {
		t.Fatalf("unexpected suspend result: change=%+v err=%v", change, err)
	}
	change, err = provider.ActivateCA(context.Background(), "ca-root-1")
	if err != nil || change.Status != "active" {
		t.Fatalf("unexpected activate result: change=%+v err=%v", change, err)
	}
}

func TestCAHandlerSuspendActivateAndConflict(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-status-handler.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), stubTemplateProviderForCA{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	suspendReq := httptest.NewRequest(http.MethodPost, "/api/v1/cas/ca-root-1/suspend", nil)
	suspendReq.Header.Set("Authorization", "Bearer test-token")
	suspendRec := httptest.NewRecorder()
	mux.ServeHTTP(suspendRec, suspendReq)
	if suspendRec.Code != http.StatusOK || !strings.Contains(suspendRec.Body.String(), `"status":"suspended"`) {
		t.Fatalf("unexpected suspend response: code=%d body=%s", suspendRec.Code, suspendRec.Body.String())
	}

	conflictReq := httptest.NewRequest(http.MethodPost, "/api/v1/cas/ca-root-1/suspend", nil)
	conflictReq.Header.Set("Authorization", "Bearer test-token")
	conflictRec := httptest.NewRecorder()
	mux.ServeHTTP(conflictRec, conflictReq)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for second suspend, got %d", conflictRec.Code)
	}

	activateReq := httptest.NewRequest(http.MethodPost, "/api/v1/cas/ca-root-1/activate", nil)
	activateReq.Header.Set("Authorization", "Bearer test-token")
	activateRec := httptest.NewRecorder()
	mux.ServeHTTP(activateRec, activateReq)
	if activateRec.Code != http.StatusOK || !strings.Contains(activateRec.Body.String(), `"status":"active"`) {
		t.Fatalf("unexpected activate response: code=%d body=%s", activateRec.Code, activateRec.Body.String())
	}
}

func TestFileCAProviderUpdateCA(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-update.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","crl_distribution_points":["http://crl.old"],"ocsp_service_url":"http://ocsp.old","created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	provider := NewFileCAProviderFromEnv()
	display := "Root 1 Updated"
	crl := []string{"http://crl.new"}
	ocsp := "http://ocsp.new"
	updated, err := provider.UpdateCA(context.Background(), "ca-root-1", CAUpdateRequest{
		DisplayName:           &display,
		CRLDistributionPoints: &crl,
		OCSPServiceURL:        &ocsp,
	})
	if err != nil {
		t.Fatalf("unexpected update error: %v", err)
	}
	if updated.DisplayName != display || len(updated.CRLDistributionPoints) != 1 || updated.CRLDistributionPoints[0] != "http://crl.new" {
		t.Fatalf("unexpected updated item: %+v", updated)
	}
}

func TestCAHandlerPatchSuccessAndValidation(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-patch-handler.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","crl_distribution_points":["http://crl.old"],"ocsp_service_url":"http://ocsp.old","created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), stubTemplateProviderForCA{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/cas/ca-root-1", bytes.NewBufferString(`{"display_name":"Root 1 Updated"}`))
	patchReq.Header.Set("Authorization", "Bearer test-token")
	patchRec := httptest.NewRecorder()
	mux.ServeHTTP(patchRec, patchReq)
	if patchRec.Code != http.StatusOK || !strings.Contains(patchRec.Body.String(), `"display_name":"Root 1 Updated"`) {
		t.Fatalf("unexpected patch response: code=%d body=%s", patchRec.Code, patchRec.Body.String())
	}

	immutableReq := httptest.NewRequest(http.MethodPatch, "/api/v1/cas/ca-root-1", bytes.NewBufferString(`{"name":"nope"}`))
	immutableReq.Header.Set("Authorization", "Bearer test-token")
	immutableRec := httptest.NewRecorder()
	mux.ServeHTTP(immutableRec, immutableReq)
	if immutableRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for immutable patch field, got %d", immutableRec.Code)
	}

	invalidReq := httptest.NewRequest(http.MethodPatch, "/api/v1/cas/ca-root-1", bytes.NewBufferString(`{"unknown":"x"}`))
	invalidReq.Header.Set("Authorization", "Bearer test-token")
	invalidRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid patch field, got %d", invalidRec.Code)
	}
}

func TestFileCAProviderDeleteCA(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-delete.json")
	body := []byte(`[
{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"revoked","active_issued_certificates":0,"key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	provider := NewFileCAProviderFromEnv()
	if err := provider.DeleteCA(context.Background(), "ca-root-1"); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}
	_, found, err := provider.GetCA(context.Background(), "ca-root-1")
	if err != nil {
		t.Fatalf("unexpected get error after delete: %v", err)
	}
	if found {
		t.Fatalf("expected CA to be deleted")
	}
}

func TestCAHandlerDeleteValidation(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-delete-handler.json")
	body := []byte(`[
{"id":"ca-active","name":"active","display_name":"Active","type":"root","parent_ca_id":null,"status":"active","active_issued_certificates":0,"key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-a","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
{"id":"ca-revoked-busy","name":"busy","display_name":"Busy","type":"root","parent_ca_id":null,"status":"revoked","active_issued_certificates":2,"key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-b","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
{"id":"ca-revoked-empty","name":"empty","display_name":"Empty","type":"root","parent_ca_id":null,"status":"revoked","active_issued_certificates":0,"key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-c","crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), stubTemplateProviderForCA{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	activeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/cas/ca-active", nil)
	activeReq.Header.Set("Authorization", "Bearer test-token")
	activeRec := httptest.NewRecorder()
	mux.ServeHTTP(activeRec, activeReq)
	if activeRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for active CA delete, got %d", activeRec.Code)
	}

	busyReq := httptest.NewRequest(http.MethodDelete, "/api/v1/cas/ca-revoked-busy", nil)
	busyReq.Header.Set("Authorization", "Bearer test-token")
	busyRec := httptest.NewRecorder()
	mux.ServeHTTP(busyRec, busyReq)
	if busyRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for busy CA delete, got %d", busyRec.Code)
	}

	okReq := httptest.NewRequest(http.MethodDelete, "/api/v1/cas/ca-revoked-empty", nil)
	okReq.Header.Set("Authorization", "Bearer test-token")
	okRec := httptest.NewRecorder()
	mux.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for delete, got %d", okRec.Code)
	}
}
