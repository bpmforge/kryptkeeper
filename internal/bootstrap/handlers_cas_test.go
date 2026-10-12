// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCASTestMux(t *testing.T) (*http.ServeMux, *Authenticator) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	fileProvider := NewFileCAProviderFromEnv()
	tenantStore := NewTenantStoreFromEnv()

	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, fileProvider, tenantStore, stubAuditProviderForCA{})
	return mux, auth
}

// TestCAListHandler_UnauthenticatedNonGetReturns401NotMethodNotAllowed is the
// S-31 decision test: /api/v1/cas authenticates before it looks at the
// method, so an unauthenticated caller sending any method gets the same 401
// an unauthenticated GET would get. It must NOT get a 405 with an Allow
// header -- that would let an unauthenticated prober enumerate which
// methods the route supports, which CLAUDE.md treats as the kind of
// disclosure a PKI product must not offer to a caller who hasn't proven who
// they are yet.
func TestCAListHandler_UnauthenticatedNonGetReturns401NotMethodNotAllowed(t *testing.T) {
	mux, _ := newCASTestMux(t)

	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodPut} {
		req := httptest.NewRequest(method, "/api/v1/cas", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", method, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "" {
			t.Errorf("%s: Allow header = %q, want unset -- unauthenticated caller must not learn supported methods", method, allow)
		}
		if !strings.Contains(rec.Body.String(), `"invalid or missing bearer token"`) {
			t.Errorf("%s: body = %s, want the unauthorized envelope", method, rec.Body.String())
		}
	}
}

// TestCAListHandler_AuthenticatedUnsupportedMethodReturns405 pairs with the
// unauthenticated case above: an authenticated caller sending a method the
// route genuinely doesn't support still gets a real 405 with an Allow
// header -- the S-31 decision is 401-before-405, not "CAS never 405s",
// which is what tests/smoke/run.sh's new lines 581/808 assert too.
func TestCAListHandler_AuthenticatedUnsupportedMethodReturns405(t *testing.T) {
	mux, _ := newCASTestMux(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/cas", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("Allow header = %q, want %q", allow, http.MethodGet)
	}
	if !strings.Contains(rec.Body.String(), "method not allowed") {
		t.Errorf("body = %s, want it to contain %q", rec.Body.String(), "method not allowed")
	}
}

// TestCADetailHandler_UnauthenticatedNonGetReturns401NotMethodNotAllowed is
// the same decision applied to /api/v1/cas/{id} and its sub-actions
// (suspend/activate/rotate-key/chain all share this handler's auth-first
// ordering) -- consistency within this file, not just the list route.
func TestCADetailHandler_UnauthenticatedNonGetReturns401NotMethodNotAllowed(t *testing.T) {
	mux, _ := newCASTestMux(t)

	paths := []string{
		"/api/v1/cas/ca-1",
		"/api/v1/cas/ca-1/suspend",
		"/api/v1/cas/ca-1/activate",
		"/api/v1/cas/ca-1/rotate-key",
	}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if strings.HasSuffix(path, "/rotate-key") || strings.HasSuffix(path, "/suspend") || strings.HasSuffix(path, "/activate") {
			req = httptest.NewRequest(http.MethodDelete, path, nil)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "" {
			t.Errorf("%s: Allow header = %q, want unset", path, allow)
		}
	}
}

// caListItemWithCert builds a CAListItem carrying a certificate whose
// validity window is defined by validFrom/validUntil (RFC3339), matching the
// anonymous struct shape ca_provider.go declares inline on CAListItem.
func caListItemWithCert(status, validFrom, validUntil string) CAListItem {
	return CAListItem{
		ID:     "ca-x",
		Name:   "ca-x",
		Status: status,
		Certificate: &struct {
			FingerprintSHA256 string `json:"fingerprint_sha256"`
			SubjectDN         string `json:"subject_dn"`
			ValidFrom         string `json:"valid_from"`
			ValidUntil        string `json:"valid_until"`
			PublicKeyAlg      string `json:"public_key_algorithm"`
			KeySizeBits       int    `json:"key_size_bits"`
		}{ValidFrom: validFrom, ValidUntil: validUntil},
	}
}

// TestCAEffectiveStatus is the S-43 decision test for the derivation rule
// itself: only a stored "active" CA whose certificate has actually expired
// is relabeled, everything else (other stored states, no certificate, an
// unparsable validity window) passes through unchanged.
func TestCAEffectiveStatus(t *testing.T) {
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		item CAListItem
		want string
	}{
		{
			name: "expired certificate, stored active -> expired",
			item: caListItemWithCert("active", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
			want: "expired",
		},
		{
			name: "valid certificate, stored active -> active",
			item: caListItemWithCert("active", "2026-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
			want: "active",
		},
		{
			name: "expired certificate, stored suspended -> unchanged",
			item: caListItemWithCert("suspended", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
			want: "suspended",
		},
		{
			name: "expired certificate, stored revoked -> unchanged",
			item: caListItemWithCert("revoked", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
			want: "revoked",
		},
		{
			name: "stored active, no certificate on file -> unchanged",
			item: CAListItem{ID: "ca-x", Status: "active"},
			want: "active",
		},
		{
			name: "stored active, unparsable validity -> unchanged",
			item: caListItemWithCert("active", "2020-01-01T00:00:00Z", "not-a-timestamp"),
			want: "active",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := caEffectiveStatus(tc.item, now)
			if got != tc.want {
				t.Errorf("caEffectiveStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

// caHealthFixturePath writes a CA fixture with one expired-but-stored-active
// CA (the ci-seed-root-ca shape from docs/ANALYST_REPORT_2026-07-31.md), one
// genuinely active CA, and one expired-but-suspended CA, and points
// APP_CA_FILE at it.
func caHealthFixturePath(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cas-expiry.json")
	body := []byte(`[
{"id":"ca-expired-active","name":"expired-active","display_name":"Expired Active","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"software","certificate_fingerprint_sha256":"fp-expired","crl_distribution_points":[],"ocsp_service_url":null,"certificate":{"fingerprint_sha256":"fp-expired","subject_dn":"CN=Expired","valid_from":"2020-01-01T00:00:00Z","valid_until":"2021-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256},"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
{"id":"ca-valid-active","name":"valid-active","display_name":"Valid Active","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"software","certificate_fingerprint_sha256":"fp-valid","crl_distribution_points":[],"ocsp_service_url":null,"certificate":{"fingerprint_sha256":"fp-valid","subject_dn":"CN=Valid","valid_from":"2026-01-01T00:00:00Z","valid_until":"2099-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256},"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
{"id":"ca-expired-suspended","name":"expired-suspended","display_name":"Expired Suspended","type":"root","parent_ca_id":null,"status":"suspended","key_storage_type":"software","certificate_fingerprint_sha256":"fp-susp","crl_distribution_points":[],"ocsp_service_url":null,"certificate":{"fingerprint_sha256":"fp-susp","subject_dn":"CN=Susp","valid_from":"2020-01-01T00:00:00Z","valid_until":"2021-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256},"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write CA fixture: %v", err)
	}
	return filePath
}

// TestCAListHandler_ExpiredActiveCADoesNotPresentAsActive is the S-43
// acceptance test: GET /api/v1/cas must not report status="active" for a CA
// whose certificate has expired, even though the stored column still says
// active. Suspended-but-expired is left alone -- it was never presenting as
// active in the first place.
func TestCAListHandler_ExpiredActiveCADoesNotPresentAsActive(t *testing.T) {
	t.Setenv("APP_CA_FILE", caHealthFixturePath(t))
	mux, _ := newCASTestMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cas?limit=10", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Data []CAListItem `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode CA payload: %v", err)
	}

	got := map[string]string{}
	for _, item := range payload.Data {
		got[item.ID] = item.Status
	}
	want := map[string]string{
		"ca-expired-active":    "expired",
		"ca-valid-active":      "active",
		"ca-expired-suspended": "suspended",
	}
	for id, wantStatus := range want {
		if got[id] != wantStatus {
			t.Errorf("id=%s status = %q, want %q (full payload: %+v)", id, got[id], wantStatus, payload.Data)
		}
	}
}

// TestCAListHandler_StatusFilterExcludesExpiredMislabeledActiveCAs proves
// the advisor-flagged gap: filtering by ?status=active must not return a CA
// that no longer presents as active once its status has been derived from
// validity, even though the provider's own stored-column filter matched it.
func TestCAListHandler_StatusFilterExcludesExpiredMislabeledActiveCAs(t *testing.T) {
	t.Setenv("APP_CA_FILE", caHealthFixturePath(t))
	mux, _ := newCASTestMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cas?status=active&limit=10", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Data []CAListItem `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode CA payload: %v", err)
	}

	if len(payload.Data) != 1 || payload.Data[0].ID != "ca-valid-active" {
		t.Fatalf("?status=active returned %+v, want exactly ca-valid-active", payload.Data)
	}
}

// TestCADetailHandler_ExpiredActiveCADoesNotPresentAsActive covers the same
// derivation on GET /api/v1/cas/{id}, a distinct response-construction site
// from the list handler.
func TestCADetailHandler_ExpiredActiveCADoesNotPresentAsActive(t *testing.T) {
	t.Setenv("APP_CA_FILE", caHealthFixturePath(t))
	mux, _ := newCASTestMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cas/ca-expired-active", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Data CAListItem `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode CA payload: %v", err)
	}
	if payload.Data.Status != "expired" {
		t.Errorf("status = %q, want %q", payload.Data.Status, "expired")
	}
}
