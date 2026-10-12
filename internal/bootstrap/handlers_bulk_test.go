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
	"time"
)

// S-55: bulk revoke/reissue authorize on ROLE. Before S-36 they consulted
// principal == "bootstrap": any admin session named otherwise got 403,
// and only the literal name could bulk-mutate.

func newBulkTestMux(t *testing.T) (*http.ServeMux, string, string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "bulk-root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")

	certFile := filepath.Join(t.TempDir(), "certificates.json")
	certBody := []byte(`[
{"fingerprint_sha256":"fp-bulk-1","serial_number":"01","common_name":"a.example.com","subject_dn":"CN=a.example.com","subject_alt_names":[],"issuer_cn":"Root","issuer_dn":"CN=Root","ca_id":"ca-1","template_id":"tpl-1","team_id":"team-a","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"manual","renewal_status":"active","source":"api","etag":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
]`)
	if err := os.WriteFile(certFile, certBody, 0o600); err != nil {
		t.Fatalf("write cert fixture: %v", err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", certFile)

	auth := NewAuthenticatorFromEnv()
	// An admin whose principal string is decidedly NOT "bootstrap".
	_, adminToken, err := auth.CreateAPIKey("ops-admin", "casey-ops", "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("create admin key: %v", err)
	}
	_, viewerToken, err := auth.CreateAPIKey("plain-viewer", "team-a", "viewer", []string{}, "", "", time.Now())
	if err != nil {
		t.Fatalf("create viewer key: %v", err)
	}

	mux := http.NewServeMux()
	registerBulkHandlers(mux, auth, NewFileCertificateProviderFromEnv(), stubAuditProvider{})
	return mux, adminToken, viewerToken
}

func postBulk(t *testing.T, mux *http.ServeMux, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestBulkOpsAuthorizeOnRoleNotPrincipalString(t *testing.T) {
	mux, adminToken, _ := newBulkTestMux(t)

	// A pki-admin named "casey-ops" — not the old literal — bulk-revokes.
	rec := postBulk(t, mux, "/api/v1/certificates/bulk-revoke", adminToken,
		`{"fingerprints":["fp-bulk-1"],"reason_code":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin bulk-revoke: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "fp-bulk-1") {
		t.Fatalf("bulk-revoke result must carry the fingerprint: %s", rec.Body.String())
	}

	// Bulk-reissue: same privilege model.
	rec = postBulk(t, mux, "/api/v1/certificates/bulk-reissue", adminToken,
		`{"fingerprints":["fp-bulk-1"]}`)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("admin bulk-reissue must not be 403: %s", rec.Body.String())
	}
}

func TestBulkOpsRefuseNonPrivilegedOnBothRoutes(t *testing.T) {
	mux, _, viewerToken := newBulkTestMux(t)

	for _, path := range []string{"/api/v1/certificates/bulk-revoke", "/api/v1/certificates/bulk-reissue"} {
		rec := postBulk(t, mux, path, viewerToken, `{"fingerprints":["fp-bulk-1"],"reason_code":1}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: non-privileged principal must be 403, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}
