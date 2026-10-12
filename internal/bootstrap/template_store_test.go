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

type stubCertSummaryForTemplate struct{}

func (stubCertSummaryForTemplate) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	return CertSummarySnapshot{Total: 0, Expiring30Days: 0, Expired: 0, Source: "file-store-default"}, nil
}

type stubAuditProviderForTemplate struct{}

func (stubAuditProviderForTemplate) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: []AuditEntry{}, Total: 0, Limit: 25}, nil
}
func (stubAuditProviderForTemplate) AppendEntry(context.Context, AuditEntry) error { return nil }

type stubCAProviderForTemplate struct{}

func (stubCAProviderForTemplate) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{Items: []CAListItem{}, Total: 0, Limit: 25}, nil
}
func (stubCAProviderForTemplate) GetCA(context.Context, string) (CAListItem, bool, error) {
	return CAListItem{}, false, nil
}
func (stubCAProviderForTemplate) GetCAChain(context.Context, string) ([]CAListItem, bool, error) {
	return nil, false, nil
}
func (stubCAProviderForTemplate) UpdateCA(context.Context, string, CAUpdateRequest) (CAListItem, error) {
	return CAListItem{}, errCANotFound
}
func (stubCAProviderForTemplate) DeleteCA(context.Context, string) error { return errCANotFound }
func (stubCAProviderForTemplate) SuspendCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}
func (stubCAProviderForTemplate) ActivateCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}

func (stubCAProviderForTemplate) CreateCA(context.Context, CACreateRequest) (CAListItem, error) {
	return CAListItem{}, errCACreateUnsupported
}

type stubTemplateProviderUnavailable struct{}

func (stubTemplateProviderUnavailable) ListTemplates(context.Context, TemplateListQuery) (TemplateListResult, error) {
	return TemplateListResult{}, os.ErrNotExist
}
func (stubTemplateProviderUnavailable) GetTemplate(context.Context, string) (TemplateItem, bool, error) {
	return TemplateItem{}, false, os.ErrNotExist
}
func (stubTemplateProviderUnavailable) CreateTemplate(context.Context, TemplateUpsertRequest) (TemplateItem, error) {
	return TemplateItem{}, os.ErrNotExist
}
func (stubTemplateProviderUnavailable) ReplaceTemplate(context.Context, string, TemplateUpsertRequest, int) (TemplateItem, error) {
	return TemplateItem{}, os.ErrNotExist
}
func (stubTemplateProviderUnavailable) CloneTemplate(context.Context, string, TemplateCloneRequest) (TemplateItem, error) {
	return TemplateItem{}, os.ErrNotExist
}
func (stubTemplateProviderUnavailable) PatchTemplate(context.Context, string, TemplatePatchRequest) (TemplateItem, error) {
	return TemplateItem{}, os.ErrNotExist
}
func (stubTemplateProviderUnavailable) DeleteTemplate(context.Context, string) error {
	return os.ErrNotExist
}

func TestFileTemplateProviderListAndGet(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates.json")
	body := []byte(`[
{"id":"tpl-tls-90d","name":"tls-server-90d","display_name":"TLS Server Certificate (90 days)","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":412,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"},
{"id":"tpl-code-1y","name":"code-signing-1y","display_name":"Code Signing Certificate (1 year)","oid":"1.3.6.1.4.1.99999.1.4","key_usage":["digitalSignature"],"extended_key_usage":["codeSigning"],"allowed_algorithms":["RSA"],"min_key_size":3072,"validity_period":"P1Y","renewal_overlap":"P30D","auto_enroll":false,"active":false,"revision":1,"schema_version":1,"issued_count":3,"created_at":"2026-02-01T08:00:00Z","updated_at":"2026-02-01T08:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	provider := NewFileTemplateProviderFromEnv()
	list, err := provider.ListTemplates(context.Background(), TemplateListQuery{Limit: 1, Offset: 0, Q: "tls", Active: parseTemplateActive("true")})
	if err != nil {
		t.Fatalf("unexpected list error: %v", err)
	}
	if list.Total != 1 || len(list.Items) != 1 || list.Items[0].ID != "tpl-tls-90d" {
		t.Fatalf("unexpected template list: %+v", list)
	}

	item, found, err := provider.GetTemplate(context.Background(), "tpl-tls-90d")
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if !found || item.Name != "tls-server-90d" {
		t.Fatalf("unexpected template get result: found=%v item=%+v", found, item)
	}
}

func TestFileTemplateProviderPatch(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates.json")
	body := []byte(`[
{"id":"tpl-tls-90d","name":"tls-server-90d","display_name":"TLS Server Certificate (90 days)","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":412,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	provider := NewFileTemplateProviderFromEnv()
	updated, err := provider.PatchTemplate(context.Background(), "tpl-tls-90d", TemplatePatchRequest{DisplayName: ptrString("TLS Updated"), AutoEnroll: ptrBool(false), Active: ptrBool(false)})
	if err != nil {
		t.Fatalf("unexpected patch error: %v", err)
	}
	if updated.DisplayName != "TLS Updated" || updated.AutoEnroll || updated.Active {
		t.Fatalf("unexpected patched template: %+v", updated)
	}
	if updated.Revision != 4 {
		t.Fatalf("expected revision increment to 4, got %d", updated.Revision)
	}

	_, err = provider.PatchTemplate(context.Background(), "missing", TemplatePatchRequest{DisplayName: ptrString("x")})
	if err != errTemplateNotFound {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestFileTemplateProviderDelete(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates-delete.json")
	body := []byte(`[
{"id":"tpl-used","name":"used","display_name":"Used","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":2,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"},
{"id":"tpl-unused","name":"unused","display_name":"Unused","oid":"1.3.6.1.4.1.99999.1.2","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"min_key_size":256,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":false,"active":true,"revision":1,"schema_version":1,"issued_count":0,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	provider := NewFileTemplateProviderFromEnv()
	if err := provider.DeleteTemplate(context.Background(), "tpl-used"); err != errTemplateConflict {
		t.Fatalf("expected conflict deleting issued template, got %v", err)
	}
	if err := provider.DeleteTemplate(context.Background(), "tpl-unused"); err != nil {
		t.Fatalf("expected delete to succeed, got %v", err)
	}
	if _, found, err := provider.GetTemplate(context.Background(), "tpl-unused"); err != nil || found {
		t.Fatalf("expected template to be deleted; found=%v err=%v", found, err)
	}
}

func TestFileTemplateProviderClone(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates-clone.json")
	body := []byte(`[
{"id":"tpl-src","name":"source","display_name":"Source","oid":"1.3.6.1.4.1.99999.1.5","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":9,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	provider := NewFileTemplateProviderFromEnv()
	cloned, err := provider.CloneTemplate(context.Background(), "tpl-src", TemplateCloneRequest{Name: "source-clone", DisplayName: "Source Clone"})
	if err != nil {
		t.Fatalf("expected clone to succeed, got %v", err)
	}
	if cloned.Name != "source-clone" || cloned.DisplayName != "Source Clone" || cloned.Active || cloned.AutoEnroll || cloned.Revision != 1 || cloned.IssuedCount != 0 {
		t.Fatalf("unexpected cloned template: %+v", cloned)
	}
}

func TestTemplateHandlersListAndGet(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates-handler.json")
	body := []byte(`[
{"id":"tpl-tls-90d","name":"tls-server-90d","display_name":"TLS Server Certificate (90 days)","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":412,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, NewFileTemplateProviderFromEnv(), NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/templates?active=true&q=tls&limit=1&cursor=0", nil)
	listReq.Header.Set("Authorization", "Bearer test-token")
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for template list, got %d", listRec.Code)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/templates/tpl-tls-90d", nil)
	getReq.Header.Set("Authorization", "Bearer test-token")
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for template get, got %d", getRec.Code)
	}

	missingReq := httptest.NewRequest(http.MethodGet, "/api/v1/templates/missing", nil)
	missingReq.Header.Set("Authorization", "Bearer test-token")
	missingRec := httptest.NewRecorder()
	mux.ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing template, got %d", missingRec.Code)
	}

	var payload struct {
		Data TemplateItem `json:"data"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode template get payload: %v", err)
	}
	if payload.Data.ID != "tpl-tls-90d" {
		t.Fatalf("unexpected template get payload: %+v", payload)
	}
}

func TestTemplateHandlersCreateAndReplace(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates-handler-create-replace.json")
	body := []byte(`[
{"id":"tpl-existing","name":"existing","display_name":"Existing","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":false,"active":true,"revision":2,"schema_version":1,"issued_count":0,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, NewFileTemplateProviderFromEnv(), NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(`{"name":"new-template","display_name":"New Template","oid":"1.3.6.1.4.1.99999.1.2","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"min_key_size":256,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true}`))
	createReq.Header.Set("Authorization", "Bearer test-token")
	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for template create, got %d (%s)", createRec.Code, createRec.Body.String())
	}

	conflictReq := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(`{"name":"existing","display_name":"Duplicate","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D"}`))
	conflictReq.Header.Set("Authorization", "Bearer test-token")
	conflictRec := httptest.NewRecorder()
	mux.ServeHTTP(conflictRec, conflictReq)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for template create conflict, got %d", conflictRec.Code)
	}

	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(`{"name":""}`))
	badReq.Header.Set("Authorization", "Bearer test-token")
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid template create, got %d", badRec.Code)
	}

	replaceReq := httptest.NewRequest(http.MethodPut, "/api/v1/templates/tpl-existing", strings.NewReader(`{"name":"existing","display_name":"Existing Replaced","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["RSA"],"min_key_size":4096,"validity_period":"P180D","renewal_overlap":"P30D","auto_enroll":true,"active":false}`))
	replaceReq.Header.Set("Authorization", "Bearer test-token")
	replaceReq.Header.Set("If-Match", "2")
	replaceRec := httptest.NewRecorder()
	mux.ServeHTTP(replaceRec, replaceReq)
	if replaceRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for template replace, got %d (%s)", replaceRec.Code, replaceRec.Body.String())
	}

	preconditionReq := httptest.NewRequest(http.MethodPut, "/api/v1/templates/tpl-existing", strings.NewReader(`{"name":"existing","display_name":"Existing Replaced","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["RSA"],"validity_period":"P180D"}`))
	preconditionReq.Header.Set("Authorization", "Bearer test-token")
	preconditionReq.Header.Set("If-Match", "1")
	preconditionRec := httptest.NewRecorder()
	mux.ServeHTTP(preconditionRec, preconditionReq)
	if preconditionRec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 for template replace precondition mismatch, got %d", preconditionRec.Code)
	}
}

func TestTemplateHandlersPatch(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates-handler-patch.json")
	body := []byte(`[
{"id":"tpl-tls-90d","name":"tls-server-90d","display_name":"TLS Server Certificate (90 days)","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":412,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, NewFileTemplateProviderFromEnv(), NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tpl-tls-90d", strings.NewReader(`{"display_name":"TLS Updated","auto_enroll":false}`))
	patchReq.Header.Set("Authorization", "Bearer test-token")
	patchRec := httptest.NewRecorder()
	mux.ServeHTTP(patchRec, patchReq)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for template patch, got %d (%s)", patchRec.Code, patchRec.Body.String())
	}

	immutableReq := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tpl-tls-90d", strings.NewReader(`{"name":"immutable"}`))
	immutableReq.Header.Set("Authorization", "Bearer test-token")
	immutableRec := httptest.NewRecorder()
	mux.ServeHTTP(immutableRec, immutableReq)
	if immutableRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for immutable template patch, got %d", immutableRec.Code)
	}

	badReq := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tpl-tls-90d", strings.NewReader(`{"unknown_field":"x"}`))
	badReq.Header.Set("Authorization", "Bearer test-token")
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid template patch, got %d", badRec.Code)
	}

	notFoundReq := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/missing", strings.NewReader(`{"display_name":"x"}`))
	notFoundReq.Header.Set("Authorization", "Bearer test-token")
	notFoundRec := httptest.NewRecorder()
	mux.ServeHTTP(notFoundRec, notFoundReq)
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing template patch, got %d", notFoundRec.Code)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/templates/tpl-tls-90d", nil)
	postReq.Header.Set("Authorization", "Bearer test-token")
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for non GET/PATCH/DELETE template detail method, got %d", postRec.Code)
	}
}

// TestTemplateHandlersPatchAllowedAlgorithms proves allowed_algorithms is a
// mutable policy knob, not identity (W18-15): PATCH must accept it, persist
// the new list, and bump revision — it must not raise errTemplateImmutableField.
func TestTemplateHandlersPatchAllowedAlgorithms(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates-handler-patch-algos.json")
	body := []byte(`[
{"id":"tpl-tls-90d","name":"tls-server-90d","display_name":"TLS Server Certificate (90 days)","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":412,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, NewFileTemplateProviderFromEnv(), NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tpl-tls-90d", strings.NewReader(`{"allowed_algorithms":["ECDSA-P256","RSA-2048"]}`))
	patchReq.Header.Set("Authorization", "Bearer test-token")
	patchRec := httptest.NewRecorder()
	mux.ServeHTTP(patchRec, patchReq)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowed_algorithms patch, got %d (%s)", patchRec.Code, patchRec.Body.String())
	}

	var patchResp struct {
		Data TemplateItem `json:"data"`
	}
	if err := json.Unmarshal(patchRec.Body.Bytes(), &patchResp); err != nil {
		t.Fatalf("failed to decode patch response: %v", err)
	}
	if patchResp.Data.Revision != 4 {
		t.Errorf("expected revision bumped to 4, got %d", patchResp.Data.Revision)
	}
	if len(patchResp.Data.AllowedAlgorithms) != 2 || patchResp.Data.AllowedAlgorithms[0] != "ECDSA-P256" || patchResp.Data.AllowedAlgorithms[1] != "RSA-2048" {
		t.Errorf("expected allowed_algorithms to persist new list, got %v", patchResp.Data.AllowedAlgorithms)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/templates/tpl-tls-90d", nil)
	getReq.Header.Set("Authorization", "Bearer test-token")
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	var getResp struct {
		Data TemplateItem `json:"data"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed to decode get response: %v", err)
	}
	if len(getResp.Data.AllowedAlgorithms) != 2 || getResp.Data.AllowedAlgorithms[0] != "ECDSA-P256" {
		t.Errorf("expected persisted allowed_algorithms on re-read, got %v", getResp.Data.AllowedAlgorithms)
	}

	emptyReq := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tpl-tls-90d", strings.NewReader(`{"allowed_algorithms":[]}`))
	emptyReq.Header.Set("Authorization", "Bearer test-token")
	emptyRec := httptest.NewRecorder()
	mux.ServeHTTP(emptyRec, emptyReq)
	if emptyRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty allowed_algorithms patch, got %d", emptyRec.Code)
	}
}

func TestTemplateHandlersDelete(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates-handler-delete.json")
	body := []byte(`[
{"id":"tpl-used","name":"used","display_name":"Used","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":2,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"},
{"id":"tpl-unused","name":"unused","display_name":"Unused","oid":"1.3.6.1.4.1.99999.1.2","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"min_key_size":256,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":false,"active":true,"revision":1,"schema_version":1,"issued_count":0,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, NewFileTemplateProviderFromEnv(), NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	conflictReq := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/tpl-used", nil)
	conflictReq.Header.Set("Authorization", "Bearer test-token")
	conflictRec := httptest.NewRecorder()
	mux.ServeHTTP(conflictRec, conflictReq)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for issued template delete, got %d", conflictRec.Code)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/tpl-unused", nil)
	deleteReq.Header.Set("Authorization", "Bearer test-token")
	deleteRec := httptest.NewRecorder()
	mux.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for template delete, got %d", deleteRec.Code)
	}

	notFoundReq := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/missing", nil)
	notFoundReq.Header.Set("Authorization", "Bearer test-token")
	notFoundRec := httptest.NewRecorder()
	mux.ServeHTTP(notFoundRec, notFoundReq)
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing template delete, got %d", notFoundRec.Code)
	}
}

func TestTemplateHandlersPatchServiceUnavailable(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, stubTemplateProviderUnavailable{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tpl-tls-90d", strings.NewReader(`{"display_name":"x"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for unavailable template patch provider, got %d", rec.Code)
	}
}

func TestTemplateHandlersClone(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "templates-handler-clone.json")
	body := []byte(`[
{"id":"tpl-src","name":"source","display_name":"Source","oid":"1.3.6.1.4.1.99999.1.5","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":9,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, NewFileTemplateProviderFromEnv(), NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	cloneReq := httptest.NewRequest(http.MethodPost, "/api/v1/templates/tpl-src/clone", strings.NewReader(`{"name":"source-clone","display_name":"Source Clone"}`))
	cloneReq.Header.Set("Authorization", "Bearer test-token")
	cloneRec := httptest.NewRecorder()
	mux.ServeHTTP(cloneRec, cloneReq)
	if cloneRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for template clone, got %d (%s)", cloneRec.Code, cloneRec.Body.String())
	}

	conflictReq := httptest.NewRequest(http.MethodPost, "/api/v1/templates/tpl-src/clone", strings.NewReader(`{"name":"source","display_name":"Conflict"}`))
	conflictReq.Header.Set("Authorization", "Bearer test-token")
	conflictRec := httptest.NewRecorder()
	mux.ServeHTTP(conflictRec, conflictReq)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for template clone conflict, got %d", conflictRec.Code)
	}
}

func ptrString(v string) *string { return &v }
func ptrBool(v bool) *bool       { return &v }

// require_approval/approval_roles used to be dropped on create AND update —
// the issuance gate (certificate_ca_provider.go) read a field nothing ever
// set, so approval-gated templates never gated anything.
func TestTemplatePersistsApprovalGating(t *testing.T) {
	t.Setenv("APP_TEMPLATE_FILE", filepath.Join(t.TempDir(), "templates.json"))
	p := NewTemplateProviderFromEnv()

	created, err := p.CreateTemplate(context.Background(), TemplateUpsertRequest{
		Name: "gated", DisplayName: "Gated", KeyUsage: []string{"digitalSignature"},
		ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"ECDSA"},
		ValidityPeriod: "P30D", Active: true,
		RequireApproval: true, ApprovalRoles: []string{"pki-admin"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !created.RequireApproval || len(created.ApprovalRoles) != 1 {
		t.Fatalf("approval gating not persisted on create: %+v", created)
	}
	got, found, err := p.GetTemplate(context.Background(), created.ID)
	if err != nil || !found {
		t.Fatalf("get: %v found=%v", err, found)
	}
	if !got.RequireApproval {
		t.Fatal("approval gating lost on reload")
	}

	updated, err := p.ReplaceTemplate(context.Background(), created.ID, TemplateUpsertRequest{
		Name: "gated", DisplayName: "Gated", KeyUsage: []string{"digitalSignature"},
		ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"ECDSA"},
		ValidityPeriod: "P30D", Active: true,
		RequireApproval: false,
	}, 0)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if updated.RequireApproval {
		t.Fatal("update must be able to clear the gate")
	}
}
