// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// classBAuthFirstRoute is one of the 9 routes named in this ticket's
// acceptance criterion 1 (S-31 Class B): each checked r.Method inline before
// calling AuthenticatePrincipalDetails, so an unauthenticated caller sending
// the wrong method got a 405 + Allow header disclosing which method the
// route supports before proving who it is. wrongMethod is any method other
// than correctMethod, used to probe both directions: unauthenticated ->
// 401 (no Allow, no disclosure), authenticated -> a real 405 + Allow for
// that same wrong method (401-before-405, not "never 405").
type classBAuthFirstRoute struct {
	path          string
	correctMethod string
	wrongMethod   string
}

// classBAuthFirstRoutes lists exactly the 9 routes named in acceptance
// criterion 1, spanning handlers_approvals.go, handlers_dashboard.go,
// handlers_discovery.go and handlers_notifications.go.
var classBAuthFirstRoutes = []classBAuthFirstRoute{
	{path: "/api/v1/approvals", correctMethod: http.MethodGet, wrongMethod: http.MethodPost},
	{path: "/api/v1/dashboard/actions/ack", correctMethod: http.MethodPost, wrongMethod: http.MethodGet},
	{path: "/api/v1/dashboard/actions/resolve", correctMethod: http.MethodPost, wrongMethod: http.MethodGet},
	{path: "/api/v1/discovery/scans", correctMethod: http.MethodPost, wrongMethod: http.MethodGet},
	{path: "/api/v1/discovery/scan-jobs/cancel", correctMethod: http.MethodPost, wrongMethod: http.MethodGet},
	{path: "/api/v1/discovery/scan-jobs/requeue", correctMethod: http.MethodPost, wrongMethod: http.MethodGet},
	{path: "/api/v1/notifications/test-delivery", correctMethod: http.MethodPost, wrongMethod: http.MethodGet},
	{path: "/api/v1/notifications/deliveries/retry", correctMethod: http.MethodPost, wrongMethod: http.MethodGet},
	{path: "/api/v1/notifications/deliveries/ack", correctMethod: http.MethodPost, wrongMethod: http.MethodGet},
}

// newClassBTestMux builds the same handler surface RegisterHandlers wires in
// production, using the package's existing stub providers and a fresh
// temp-dir-backed sqlite DB (needed because registerApprovalHandlers no-ops
// on a nil ApprovalStore), so the table below exercises the real
// routing/registration path rather than a hand-rolled subset per route.
func newClassBTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
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

// TestClassBRoutes_UnauthenticatedWrongMethodReturns401NotMethodNotAllowed is
// the S-33 decision test: every route above must authenticate before it
// looks at the method, so an unauthenticated caller sending the wrong
// method gets the same 401 an unauthenticated caller with the correct
// method would get -- never a 405 with an Allow header, which would let an
// unauthenticated prober enumerate which method the route supports before
// proving who it is.
func TestClassBRoutes_UnauthenticatedWrongMethodReturns401NotMethodNotAllowed(t *testing.T) {
	mux := newClassBTestMux(t)

	for _, rt := range classBAuthFirstRoutes {
		req := httptest.NewRequest(rt.wrongMethod, rt.path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401 (body: %s)", rt.wrongMethod, rt.path, rec.Code, rec.Body.String())
		}
		if allow := rec.Header().Get("Allow"); allow != "" {
			t.Errorf("%s %s: Allow header = %q, want unset", rt.wrongMethod, rt.path, allow)
		}
		if strings.Contains(rec.Body.String(), "method not allowed") {
			t.Errorf("%s %s: body = %s, must not disclose method-not-allowed to an unauthenticated caller", rt.wrongMethod, rt.path, rec.Body.String())
		}
	}
}

// TestClassBRoutes_AuthenticatedWrongMethodReturns405 pairs with the
// unauthenticated case above: an authenticated caller sending a method the
// route genuinely doesn't support still gets a real 405 with an Allow
// header naming the correct method -- the decision is 401-before-405, not
// "these routes never 405."
func TestClassBRoutes_AuthenticatedWrongMethodReturns405(t *testing.T) {
	mux := newClassBTestMux(t)

	for _, rt := range classBAuthFirstRoutes {
		req := httptest.NewRequest(rt.wrongMethod, rt.path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, want 405 (body: %s)", rt.wrongMethod, rt.path, rec.Code, rec.Body.String())
		}
		if allow := rec.Header().Get("Allow"); allow != rt.correctMethod {
			t.Errorf("%s %s: Allow header = %q, want %q", rt.wrongMethod, rt.path, allow, rt.correctMethod)
		}
		if !strings.Contains(rec.Body.String(), "method not allowed") {
			t.Errorf("%s %s: body = %s, want it to contain %q", rt.wrongMethod, rt.path, rec.Body.String(), "method not allowed")
		}
	}
}

// Proposer ≠ approver is a product law. The pending-actions handler always
// enforced it; the certificate-approval handler only checked role, so a
// pki-admin could raise a CSR and approve it themselves.
func TestApprovalApproveRefusesSelfApproval(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	approvalStore, err := newApprovalStoreFromEnv()
	if err != nil || approvalStore == nil {
		t.Fatalf("approval store: %v", err)
	}
	// acmeToken's principal ID is "svc-principal" (see setupTenantWritePathTest).
	self := ApprovalRequest{
		ID: "apr-self", TemplateID: "tpl-acme", CAID: "ca-acme", Requester: "svc-principal",
		Status: "pending", CSRPEM: "", RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := approvalStore.Create(context.Background(), self); err != nil {
		t.Fatalf("seed approval: %v", err)
	}

	rec := doTenantReq(mux, http.MethodPost, "/api/v1/approvals/apr-self/approve", acmeToken, "acme")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-approve: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "own action") {
		t.Fatalf("self-approve: expected the self-approval refusal, got: %s", rec.Body.String())
	}

	// The request must still be pending — the refusal happened before Decide.
	apr, err := approvalStore.Get(context.Background(), "apr-self")
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if apr.Status != "pending" {
		t.Fatalf("expected approval still pending after refused self-approve, got %q", apr.Status)
	}
}
