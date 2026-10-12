// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kryptkeeper/internal/keystore"
)

// TestRegisterHandlers_AcceptsRealKeystore is the W4-06 regression: keys
// keystore.Store is threaded through RegisterHandlers (a prerequisite for
// W4-03's PQC migrate-wave EXECUTE step, which will generate fresh keys
// during registration-scoped handler construction). Every other test in
// this package passes nil for keys (the common case: no crypto engine
// active) -- this test proves a real, non-nil store also works and doesn't
// change any existing handler's behavior.
func TestRegisterHandlers_AcceptsRealKeystore(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-not-for-production"))
	if err != nil {
		t.Fatalf("construct software keystore: %v", err)
	}

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryProvider{}, stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), keys)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from an unrelated handler (meta) with a real keystore passed through, got %d: %s", rec.Code, rec.Body.String())
	}
}
