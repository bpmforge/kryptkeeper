// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newFullTestMux builds the same handler surface RegisterHandlers wires in
// production, using the package's existing stub providers, so the
// getOnly-call-site table below exercises the real routing/registration path
// rather than a hand-rolled subset per route.
func newFullTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	mux := http.NewServeMux()
	RegisterHandlers(mux, auth,
		stubCertSummaryProvider{},
		stubAuditProvider{},
		stubCAProvider{},
		stubTemplateProvider{},
		NewFileCertificateProviderFromEnv(),
		NewProtocolProviderFromEnv(),
		stubDiscoveryProvider{},
		stubNotificationProvider{},
		stubDashboardActionProvider{},
		nil,
	)
	return mux
}

// getOnlyAuthenticatedRoutes lists every route acceptance criterion 1 names:
// the getOnly() call sites that used to check r.Method before auth ran. Each
// must now authenticate first, so an unauthenticated non-GET gets 401 (no
// Allow header, no "method not allowed" body) and an authenticated non-GET
// still gets a real 405 + Allow: GET.
var getOnlyAuthenticatedRoutes = []string{
	"/api/v1/audit",
	"/api/v1/authz-check",
	"/api/v1/dashboard/summary",
	"/api/v1/dashboard/actions",
	"/api/v1/dashboard/actions/history",
	"/api/v1/discovery/summary",
	"/api/v1/discovery/endpoints",
	"/api/v1/discovery/scan-jobs",
	"/api/v1/notifications/summary",
	"/api/v1/notifications/deliveries",
	"/api/v1/protected/certs/summary",
	"/api/v1/protected/config",
	"/api/v1/protected/ping",
	"/api/v1/protected/whoami",
	"/api/v1/protocols/status",
	"/api/v1/protocols/readiness",
	"/api/v1/protocols/conformance",
}

// TestGetOnlyAuthenticatedRoutes_UnauthenticatedNonGetReturns401NotMethodNotAllowed
// is the S-32 decision test (Class A of the S-31 finding): every route above
// must authenticate before it looks at the method, so an unauthenticated
// caller sending any non-GET method gets the same 401 an unauthenticated GET
// would get -- never a 405 with an Allow header, which would let an
// unauthenticated prober enumerate which methods the route supports before
// proving who it is.
func TestGetOnlyAuthenticatedRoutes_UnauthenticatedNonGetReturns401NotMethodNotAllowed(t *testing.T) {
	mux := newFullTestMux(t)

	for _, path := range getOnlyAuthenticatedRoutes {
		for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodPut} {
			req := httptest.NewRequest(method, path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: status = %d, want 401", method, path, rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != "" {
				t.Errorf("%s %s: Allow header = %q, want unset", method, path, allow)
			}
			if strings.Contains(rec.Body.String(), "method not allowed") {
				t.Errorf("%s %s: body = %s, must not disclose method-not-allowed to an unauthenticated caller", method, path, rec.Body.String())
			}
		}
	}
}

// TestGetOnlyAuthenticatedRoutes_AuthenticatedUnsupportedMethodReturns405
// pairs with the unauthenticated case above: an authenticated caller sending
// a method the route genuinely doesn't support still gets a real 405 with an
// Allow header -- the decision is 401-before-405, not "these routes never
// 405."
func TestGetOnlyAuthenticatedRoutes_AuthenticatedUnsupportedMethodReturns405(t *testing.T) {
	mux := newFullTestMux(t)

	for _, path := range getOnlyAuthenticatedRoutes {
		req := httptest.NewRequest(http.MethodDelete, path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405 (body: %s)", path, rec.Code, rec.Body.String())
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("%s: Allow header = %q, want %q", path, allow, http.MethodGet)
		}
		if !strings.Contains(rec.Body.String(), "method not allowed") {
			t.Errorf("%s: body = %s, want it to contain %q", path, rec.Body.String(), "method not allowed")
		}
	}
}

// TestGetOnlyUnauthenticatedMetaRoutesReturn405Directly pins acceptance
// criterion 2: the UNAUTHENTICATED getOnly() call sites in handlers_meta.go
// have no identity to check, so there is nothing to disclose by rejecting the
// method before any handler logic runs -- their 405-before-auth behaviour is
// intentional and must not change.
func TestGetOnlyUnauthenticatedMetaRoutesReturn405Directly(t *testing.T) {
	mux := http.NewServeMux()
	registerMetaHandlers(mux, nil)

	for _, path := range []string{"/", "/healthz", "/readyz", "/api/v1/meta"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("%s: Allow header = %q, want %q", path, allow, http.MethodGet)
		}
	}
}

func TestWriteUnauthorizedLegacyEnvelopeByDefault(t *testing.T) {
	t.Setenv("APP_ERROR_FORMAT", "")
	rec := httptest.NewRecorder()

	writeUnauthorized(rec)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected application/json, got %q", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"error":"unauthorized"`) || !strings.Contains(body, `"message":"invalid or missing bearer token"`) {
		t.Fatalf("unexpected legacy body: %s", body)
	}
}

func TestWriteUnauthorizedProblemEnvelopeWhenEnabled(t *testing.T) {
	t.Setenv("APP_ERROR_FORMAT", "problem")
	rec := httptest.NewRecorder()

	writeUnauthorized(rec)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("expected application/problem+json, got %q", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"title":"Unauthorized"`) || !strings.Contains(body, `"status":401`) || !strings.Contains(body, `"detail":"invalid or missing bearer token"`) {
		t.Fatalf("unexpected problem body: %s", body)
	}
}
