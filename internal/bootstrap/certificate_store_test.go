// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stubCertSummaryForCertificate struct{}

func (stubCertSummaryForCertificate) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	return CertSummarySnapshot{Total: 0, Expiring30Days: 0, Expired: 0, Source: "file-store-default"}, nil
}

type stubAuditProviderForCertificate struct{}

func (stubAuditProviderForCertificate) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: []AuditEntry{}, Total: 0, Limit: 25}, nil
}
func (stubAuditProviderForCertificate) AppendEntry(context.Context, AuditEntry) error { return nil }

type stubCAProviderForCertificate struct{}

func (stubCAProviderForCertificate) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{Items: []CAListItem{}, Total: 0, Limit: 25}, nil
}
func (stubCAProviderForCertificate) GetCA(context.Context, string) (CAListItem, bool, error) {
	return CAListItem{}, false, nil
}
func (stubCAProviderForCertificate) GetCAChain(context.Context, string) ([]CAListItem, bool, error) {
	return nil, false, nil
}
func (stubCAProviderForCertificate) UpdateCA(context.Context, string, CAUpdateRequest) (CAListItem, error) {
	return CAListItem{}, errCANotFound
}
func (stubCAProviderForCertificate) DeleteCA(context.Context, string) error { return errCANotFound }
func (stubCAProviderForCertificate) SuspendCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}
func (stubCAProviderForCertificate) ActivateCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}

func (stubCAProviderForCertificate) CreateCA(context.Context, CACreateRequest) (CAListItem, error) {
	return CAListItem{}, errCACreateUnsupported
}

type stubTemplateProviderForCertificate struct{}

func (stubTemplateProviderForCertificate) ListTemplates(context.Context, TemplateListQuery) (TemplateListResult, error) {
	return TemplateListResult{Items: []TemplateItem{}, Total: 0, Limit: 25}, nil
}
func (stubTemplateProviderForCertificate) GetTemplate(context.Context, string) (TemplateItem, bool, error) {
	return TemplateItem{}, false, nil
}
func (stubTemplateProviderForCertificate) CreateTemplate(context.Context, TemplateUpsertRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateInvalidCreate
}
func (stubTemplateProviderForCertificate) ReplaceTemplate(context.Context, string, TemplateUpsertRequest, int) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}
func (stubTemplateProviderForCertificate) PatchTemplate(context.Context, string, TemplatePatchRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}
func (stubTemplateProviderForCertificate) CloneTemplate(context.Context, string, TemplateCloneRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}
func (stubTemplateProviderForCertificate) DeleteTemplate(context.Context, string) error {
	return errTemplateNotFound
}

func TestFileCertificateProviderListGetAndRevoke(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "certificates.json")
	body := []byte(`[
{"fingerprint_sha256":"fp-a","serial_number":"01","common_name":"api.example.com","subject_dn":"CN=api.example.com","subject_alt_names":["api.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-1","template_id":"tpl-1","team_id":"team-1","valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-06-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":true,"risk_score":35,"risk_flags":["EXPIRING_7_DAYS"],"grade":"C","renewal_method":"acme","renewal_status":"active","source":"acme","etag":2,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
{"fingerprint_sha256":"fp-b","serial_number":"02","common_name":"web.example.com","subject_dn":"CN=web.example.com","subject_alt_names":["web.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-1","template_id":"tpl-2","team_id":"team-2","valid_from":"2026-02-01T00:00:00Z","valid_until":"2026-07-01T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048,"signature_algorithm":"sha256WithRSAEncryption","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"api","renewal_status":"active","source":"api","etag":1,"created_at":"2026-02-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write certificate fixture: %v", err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", filePath)

	provider := NewFileCertificateProviderFromEnv()
	list, err := provider.ListCertificates(context.Background(), CertificateListQuery{Limit: 25, Q: "api", CAID: "ca-1", Status: "active", Grades: []string{"C"}})
	if err != nil {
		t.Fatalf("unexpected list error: %v", err)
	}
	if list.Total != 1 || len(list.Items) != 1 || list.Items[0].FingerprintSHA256 != "fp-a" {
		t.Fatalf("unexpected list result: %+v", list)
	}

	_, found, err := provider.GetCertificate(context.Background(), "fp-a")
	if err != nil || !found {
		t.Fatalf("expected certificate get success, found=%v err=%v", found, err)
	}

	revoked, err := provider.RevokeCertificate(context.Background(), "fp-a", CertificateRevokeRequest{ReasonCode: 1, ReasonText: "test"})
	if err != nil {
		t.Fatalf("unexpected revoke error: %v", err)
	}
	if revoked.RenewalStatus != "revoked" || revoked.RevocationReason != 1 {
		t.Fatalf("unexpected revoke result: %+v", revoked)
	}
}

func TestCertificateHandlersListGetChainAndRevoke(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "certificates-handler.json")
	body := []byte(`[
{"fingerprint_sha256":"fp-prev","serial_number":"00","common_name":"api.example.com","subject_dn":"CN=api.example.com","subject_alt_names":["api.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-1","template_id":"tpl-1","team_id":"team-1","valid_from":"2025-10-01T00:00:00Z","valid_until":"2026-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":true,"risk_score":55,"risk_flags":["EXPIRING_7_DAYS"],"grade":"D","renewal_method":"acme","renewal_status":"renewed","source":"acme","successor_fingerprint":"fp-cur","etag":1,"created_at":"2025-10-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
{"fingerprint_sha256":"fp-cur","serial_number":"01","common_name":"api.example.com","subject_dn":"CN=api.example.com","subject_alt_names":["api.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-1","template_id":"tpl-1","team_id":"team-1","valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-04-11T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":true,"risk_score":35,"risk_flags":["EXPIRING_7_DAYS"],"grade":"C","renewal_method":"acme","renewal_status":"active","source":"acme","predecessor_fingerprint":"fp-prev","successor_fingerprint":"fp-next","etag":2,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
{"fingerprint_sha256":"fp-next","serial_number":"02","common_name":"api.example.com","subject_dn":"CN=api.example.com","subject_alt_names":["api.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-1","template_id":"tpl-1","team_id":"team-1","valid_from":"2026-04-11T00:00:00Z","valid_until":"2026-07-11T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"api","renewal_status":"active","source":"api","predecessor_fingerprint":"fp-cur","etag":1,"created_at":"2026-04-11T00:00:00Z","updated_at":"2026-04-11T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write certificate fixture: %v", err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCertificate{}, stubAuditProviderForCertificate{}, stubCAProviderForCertificate{}, stubTemplateProviderForCertificate{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?status=active&grade=C&ca_id=ca-1&limit=1&cursor=0", nil)
	listReq.Header.Set("Authorization", "Bearer test-token")
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 list, got %d", listRec.Code)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/fp-cur", nil)
	getReq.Header.Set("Authorization", "Bearer test-token")
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 get, got %d", getRec.Code)
	}

	notModifiedReq := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/fp-cur", nil)
	notModifiedReq.Header.Set("Authorization", "Bearer test-token")
	notModifiedReq.Header.Set("If-None-Match", "2")
	notModifiedRec := httptest.NewRecorder()
	mux.ServeHTTP(notModifiedRec, notModifiedReq)
	if notModifiedRec.Code != http.StatusNotModified {
		t.Fatalf("expected 304 not modified, got %d", notModifiedRec.Code)
	}

	chainReq := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/fp-cur/chain", nil)
	chainReq.Header.Set("Authorization", "Bearer test-token")
	chainRec := httptest.NewRecorder()
	mux.ServeHTTP(chainRec, chainReq)
	if chainRec.Code != http.StatusOK {
		t.Fatalf("expected 200 chain, got %d", chainRec.Code)
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/fp-cur/revoke", strings.NewReader(`{"reason_code":1,"reason_text":"test"}`))
	revokeReq.Header.Set("Authorization", "Bearer test-token")
	revokeRec := httptest.NewRecorder()
	mux.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("expected 200 revoke, got %d (%s)", revokeRec.Code, revokeRec.Body.String())
	}

	conflictReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/fp-cur/revoke", strings.NewReader(`{"reason_code":1,"reason_text":"test"}`))
	conflictReq.Header.Set("Authorization", "Bearer test-token")
	conflictRec := httptest.NewRecorder()
	mux.ServeHTTP(conflictRec, conflictReq)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 revoke conflict, got %d", conflictRec.Code)
	}

	issueReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(`{"ca_id":"ca-1","template_id":"tpl-1","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nissue\n-----END CERTIFICATE REQUEST-----"}`))
	issueReq.Header.Set("Authorization", "Bearer test-token")
	issueRec := httptest.NewRecorder()
	mux.ServeHTTP(issueRec, issueReq)
	if issueRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 issue, got %d (%s)", issueRec.Code, issueRec.Body.String())
	}

	renewReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/fp-next/renew", strings.NewReader(`{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nrenew\n-----END CERTIFICATE REQUEST-----"}`))
	renewReq.Header.Set("Authorization", "Bearer test-token")
	renewRec := httptest.NewRecorder()
	mux.ServeHTTP(renewRec, renewReq)
	if renewRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 renew, got %d (%s)", renewRec.Code, renewRec.Body.String())
	}

	downloadReq := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/fp-next/download?format=pem", nil)
	downloadReq.Header.Set("Authorization", "Bearer test-token")
	downloadRec := httptest.NewRecorder()
	mux.ServeHTTP(downloadRec, downloadReq)
	if downloadRec.Code != http.StatusOK {
		t.Fatalf("expected 200 download, got %d", downloadRec.Code)
	}

	importReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/import", strings.NewReader(`{"certificate_pem":"-----BEGIN CERTIFICATE-----\nimport\n-----END CERTIFICATE-----"}`))
	importReq.Header.Set("Authorization", "Bearer test-token")
	importRec := httptest.NewRecorder()
	mux.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 import, got %d (%s)", importRec.Code, importRec.Body.String())
	}

	var payload struct {
		Data CertificateDetail `json:"data"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode get payload: %v", err)
	}
	if payload.Data.FingerprintSHA256 != "fp-cur" {
		t.Fatalf("unexpected get payload: %+v", payload)
	}
}
