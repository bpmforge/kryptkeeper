// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tenantReqBody(mux *http.ServeMux, method, path, token, tenant, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant", tenant)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestLeakL06_BulkRevokeAndReissueSkipOtherTenantCerts(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	for _, path := range []string{"/api/v1/certificates/bulk-revoke", "/api/v1/certificates/bulk-reissue"} {
		code, body := tenantReqBody(mux, http.MethodPost, path, acmeToken, "acme", `{"fingerprints":["fp-globex-cert","fp-missing"]}`)
		if code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d: %s", path, code, body)
		}
		var resp struct {
			Succeeded []json.RawMessage `json:"succeeded"`
			Failed    []struct {
				Error string `json:"error"`
			} `json:"failed"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Succeeded) != 0 || len(resp.Failed) != 2 {
			t.Fatalf("%s: want 0 succeeded / 2 failed, got %s", path, body)
		}
		for _, f := range resp.Failed {
			if f.Error != bulkNotVisibleMessage {
				t.Fatalf("%s: existence leaked, error=%q", path, f.Error)
			}
		}
	}
	// The foreign cert must still be unrevoked.
	cert, _, _ := NewFileCertificateProviderFromEnv().GetCertificate(context.Background(), "fp-globex-cert")
	if cert.RevokedAt != nil {
		t.Fatal("globex cert was revoked by an acme caller")
	}
}

func TestLeakL07_CACreateRejectsInvisibleParent(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	for _, parent := range []string{"ca-globex", "ca-unmapped-default"} {
		code, body := tenantReqBody(mux, http.MethodPost, "/api/v1/cas", acmeToken, "acme",
			`{"name":"sub","type":"intermediate","algorithm":"ecdsaP256","subject_cn":"Sub","parent_ca_id":"`+parent+`"}`)
		if code != http.StatusForbidden {
			t.Fatalf("parent %s: want 403, got %d: %s", parent, code, body)
		}
	}
}

func TestLeakL20_ListTotalsAndCursorsCountOnlyCallerTenant(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	approvalStore, err := newApprovalStoreFromEnv()
	if err != nil || approvalStore == nil {
		t.Fatalf("approval store: %v", err)
	}
	for _, a := range []ApprovalRequest{
		{ID: "apr-a", TemplateID: "tpl-acme", CAID: "ca-acme", Requester: "svc-principal", Status: "pending", RequestedAt: time.Now().UTC().Format(time.RFC3339)},
		{ID: "apr-g", TemplateID: "tpl-globex", CAID: "ca-globex", Requester: "svc-principal", Status: "pending", RequestedAt: time.Now().UTC().Format(time.RFC3339)},
	} {
		if err := approvalStore.Create(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/api/v1/cas?limit=1", "/api/v1/templates?limit=1", "/api/v1/approvals"} {
		code, body := tenantReqBody(mux, http.MethodGet, path, acmeToken, "acme", "")
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		var resp struct {
			Data []json.RawMessage `json:"data"`
			Meta struct {
				Total      int     `json:"total"`
				NextCursor *string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Data) != 1 || resp.Meta.Total != 1 || resp.Meta.NextCursor != nil {
			t.Fatalf("%s: want 1 row, total 1, no cursor; got %s", path, body)
		}
	}
}

func TestLeakL21_CertsSummaryDeniedForTenantScoped(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	if code, body := tenantReqBody(mux, http.MethodGet, "/api/v1/protected/certs/summary", acmeToken, "acme", ""); code != http.StatusForbidden {
		t.Fatalf("tenant-scoped caller: want 403, got %d: %s", code, body)
	}
	if code, body := tenantReqBody(mux, http.MethodGet, "/api/v1/protected/certs/summary", "root-token", "", ""); code != http.StatusOK {
		t.Fatalf("super-admin: want 200, got %d: %s", code, body)
	}
}
