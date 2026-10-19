// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RC1: oversized bodies on the authenticated create/update routes answer 413,
// not the generic 400 (and templates, which had no cap at all, now have one).
func TestOversizedBodiesAnswer413(t *testing.T) {
	credMux, _ := credentialsTestMux(t)

	certFile := filepath.Join(t.TempDir(), "certificates.json")
	if err := os.WriteFile(certFile, []byte(`[{"fingerprint_sha256":"fp1","serial_number":"01","common_name":"a.example.com","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","renewal_status":"active","source":"api","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", certFile)
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerCertificateHandlers(mux, auth, NewFileCertificateProviderFromEnv(), stubAuditProviderForCertificate{}, nil)
	registerTemplateHandlers(mux, auth, stubTemplateProvider{}, stubAuditProvider{}, nil)

	pad := func(n int64) string { return strings.Repeat("a", int(n)) }
	cases := []struct {
		name, method, path, body string
		m                        *http.ServeMux
	}{
		{"credentials create", http.MethodPost, "/api/v1/credentials", `{"name":"x","credential_type":"ssh_key","payload":{"k":"` + pad(300*1024) + `"}}`, credMux},
		{"certificates issue", http.MethodPost, "/api/v1/certificates", `{"common_name":"` + pad(maxCertificateIssueBodyBytes) + `"}`, mux},
		{"certificates import", http.MethodPost, "/api/v1/certificates/import", `{"pem":"` + pad(maxCertificateImportBodyBytes) + `"}`, mux},
		{"certificates revoke", http.MethodPost, "/api/v1/certificates/fp1/revoke", `{"reason":"` + pad(maxCertificateRevokeBodyBytes) + `"}`, mux},
		{"certificates renew", http.MethodPost, "/api/v1/certificates/fp1/renew", `{"x":"` + pad(maxCertificateRenewBodyBytes) + `"}`, mux},
		{"certificates ownership", http.MethodPatch, "/api/v1/certificates/fp1/ownership", `{"owner":"` + pad(16*1024) + `"}`, mux},
		{"templates create", http.MethodPost, "/api/v1/templates", `{"name":"` + pad(maxTemplateBodyBytes) + `"}`, mux},
		{"templates patch", http.MethodPatch, "/api/v1/templates/t1", `{"name":"` + pad(maxTemplateBodyBytes) + `"}`, mux},
		{"templates replace", http.MethodPut, "/api/v1/templates/t1", `{"name":"` + pad(maxTemplateBodyBytes) + `"}`, mux},
		{"templates clone", http.MethodPost, "/api/v1/templates/t1/clone", `{"name":"` + pad(maxTemplateBodyBytes) + `"}`, mux},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := authedReq(tc.method, tc.path, []byte(tc.body))
			if tc.method == http.MethodPut {
				req.Header.Set("If-Match", "1")
			}
			tc.m.ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("want 413, got %d: %.200s", rec.Code, rec.Body.String())
			}
		})
	}
}
