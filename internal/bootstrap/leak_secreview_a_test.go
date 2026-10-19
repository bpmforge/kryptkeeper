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

// Regression tests for the authz/tenant security review, lane A (F1, F3, F4,
// F5, F6). Same shape as the other leak_*_test.go files.

func secReviewEnv(t *testing.T, multiTenancy string) (auth *Authenticator, acme, globex string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", multiTenancy)
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth = NewAuthenticatorFromEnv()
	var err error
	if _, acme, err = auth.CreateAPIKey("acme-adm", "acme-adm", "pki-admin", []string{"*"}, "", "acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, globex, err = auth.CreateAPIKey("globex-adm", "globex-adm", "pki-admin", []string{"*"}, "", "globex", time.Now()); err != nil {
		t.Fatal(err)
	}
	return auth, acme, globex
}

// secReviewTenantStore installs a real tenant store with acme and globex and
// returns it; each CA ID in caOwners is mapped to its tenant.
func secReviewTenantStore(t *testing.T, caOwners map[string]string) TenantStore {
	t.Helper()
	ts := NewTenantStoreFromEnv()
	if ts == nil {
		t.Fatal("tenant store unavailable")
	}
	for _, id := range []string{"acme", "globex"} {
		if _, err := ts.CreateTenant(context.Background(), id, id); err != nil {
			t.Fatal(err)
		}
	}
	for ca, tenant := range caOwners {
		if err := ts.SetCATenant(context.Background(), ca, tenant); err != nil {
			t.Fatal(err)
		}
	}
	setActiveTenantStore(ts)
	t.Cleanup(func() { setActiveTenantStore(nil) })
	return ts
}

func codeSigningFixture() []CertificateItem {
	eku := []string{"codeSigning"}
	return []CertificateItem{
		{FingerprintSHA256: "fp-acme", CommonName: "acme-signer", CAID: "ca-acme", ExtendedKeyUsage: eku},
		{FingerprintSHA256: "fp-globex", CommonName: "globex-signer", CAID: "ca-globex", ExtendedKeyUsage: eku},
	}
}

// F1: the code-signing inventory and policy-check must be tenant-scoped.
func TestSecReviewF1_CodeSigningInventoryTenantScoped(t *testing.T) {
	auth, acme, _ := secReviewEnv(t, "on")
	secReviewTenantStore(t, map[string]string{"ca-acme": "acme", "ca-globex": "globex"})
	mux := http.NewServeMux()
	registerCodeSigningHandler(mux, auth, &reportCertProvider{items: codeSigningFixture()}, stubAuditProvider{})

	rec := doLeakJSON(mux, http.MethodGet, "/api/v1/inventory/code-signing", acme, "acme", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("inventory: %d %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "fp-globex") {
		t.Fatalf("acme sees globex code-signing cert: %s", body)
	}

	pol := doLeakJSON(mux, http.MethodPost, "/api/v1/inventory/code-signing/policy-check", acme, "acme", `{}`)
	if pol.Code != http.StatusOK {
		t.Fatalf("policy-check: %d %s", pol.Code, pol.Body.String())
	}
	if strings.Contains(pol.Body.String(), "fp-globex") || strings.Contains(pol.Body.String(), "globex-signer") {
		t.Fatalf("policy-check leaks globex cert: %s", pol.Body.String())
	}

	// The unscoped super-admin still sees the whole fleet.
	root := doLeakJSON(mux, http.MethodGet, "/api/v1/inventory/code-signing", "root-token", "", "")
	if !strings.Contains(root.Body.String(), "fp-globex") || !strings.Contains(root.Body.String(), "fp-acme") {
		t.Fatalf("super-admin should see both tenants: %s", root.Body.String())
	}
}

// F6: with multi-tenancy on and no tenant store, scoped principals see nothing;
// with it off nothing changes.
func TestSecReviewF6_TenantGatesFailClosedWithoutStore(t *testing.T) {
	setActiveTenantStore(nil)
	scoped := AuthPrincipal{ID: "u", Role: "pki-admin", Tenant: "acme"}
	t.Setenv("MULTI_TENANCY", "on")
	ctx := context.Background()

	if caVisibleToTenant(ctx, nil, scoped, "ca-1") {
		t.Error("caVisibleToTenant must fail closed")
	}
	if templateVisibleToTenant(ctx, nil, scoped, "t-1") {
		t.Error("templateVisibleToTenant must fail closed")
	}
	if got := filterCAsByTenant(ctx, nil, scoped, []CAListItem{{ID: "ca-1"}}); len(got) != 0 {
		t.Errorf("filterCAsByTenant leaked %v", got)
	}
	if got := filterCertificatesByTenant(ctx, nil, scoped, []CertificateItem{{CAID: "ca-1"}}); len(got) != 0 {
		t.Errorf("filterCertificatesByTenant leaked %v", got)
	}
	if got := filterTemplatesByTenant(ctx, nil, scoped, []TemplateItem{{ID: "t-1"}}); len(got) != 0 {
		t.Errorf("filterTemplatesByTenant leaked %v", got)
	}
	apprs := []ApprovalRequest{{CAID: "ca-1"}, {Kind: approvalKindSSH, Tenant: "acme"}, {Kind: approvalKindSSH, Tenant: "globex"}}
	if got := filterApprovalsByTenant(ctx, nil, scoped, apprs); len(got) != 1 || got[0].Tenant != "acme" {
		t.Errorf("filterApprovalsByTenant: want only the acme SSH row, got %v", got)
	}
	if err := checkPendingActionTargets(ctx, nil, nil, "acme", PendingAction{}); err == nil {
		t.Error("checkPendingActionTargets must refuse without a store")
	}

	certs := &reportCertProvider{items: buildTestCerts()}
	if got, err := searchCertificates(ctx, scoped, certs, "", 100); err != nil || len(got) != 0 {
		t.Errorf("searchCertificates must fail closed without a store: %d items, err=%v", len(got), err)
	}
	if got, err := searchCertificates(ctx, AuthPrincipal{ID: "root", SuperAdmin: true}, certs, "", 100); err != nil || len(got) == 0 {
		t.Errorf("super-admin search: %d items, err=%v", len(got), err)
	}

	// Unscoped super-admin is never gated by the store.
	root := AuthPrincipal{ID: "root", SuperAdmin: true}
	if !caVisibleToTenant(ctx, nil, root, "ca-1") || len(filterCAsByTenant(ctx, nil, root, []CAListItem{{ID: "ca-1"}})) != 1 {
		t.Error("super-admin must bypass")
	}

	t.Setenv("MULTI_TENANCY", "off")
	if !caVisibleToTenant(ctx, nil, scoped, "ca-1") || !templateVisibleToTenant(ctx, nil, scoped, "t-1") {
		t.Error("flag off: gates must pass")
	}
	if len(filterCertificatesByTenant(ctx, nil, scoped, []CertificateItem{{CAID: "ca-1"}})) != 1 ||
		len(filterApprovalsByTenant(ctx, nil, scoped, apprs)) != 3 {
		t.Error("flag off: filters must pass everything")
	}
	if err := checkPendingActionTargets(ctx, nil, nil, "acme", PendingAction{}); err != nil {
		t.Errorf("flag off: %v", err)
	}
}

// F3: the agent fleet API is global-admin-only under multi-tenancy.
func TestSecReviewF3_AgentFleetGlobalAdminOnly(t *testing.T) {
	for _, mt := range []string{"on", "off"} {
		t.Run("multi_tenancy_"+mt, func(t *testing.T) {
			auth, acme, _ := secReviewEnv(t, mt)
			store := NewAgentStore()
			id, _, err := store.register("host-b", AgentType("linux"))
			if err != nil {
				t.Fatal(err)
			}
			audit := &agentAuditLog{}
			mux := http.NewServeMux()
			registerAgentHandlers(mux, auth, store, audit)
			want := http.StatusForbidden
			if mt == "off" {
				want = http.StatusOK
			}
			for _, p := range []string{"/api/v1/agents", "/api/v1/agents/" + id + "/tasks"} {
				if rec := doLeakJSON(mux, http.MethodGet, p, acme, "acme", ""); rec.Code != want {
					t.Errorf("tenant admin GET %s: want %d, got %d %s", p, want, rec.Code, rec.Body.String())
				}
			}
			del := doLeakJSON(mux, http.MethodDelete, "/api/v1/agents/"+id, acme, "acme", "")
			if mt == "on" {
				if del.Code != http.StatusForbidden {
					t.Fatalf("tenant admin DELETE: want 403, got %d", del.Code)
				}
				if !audit.has("agent.remove", id, AuditOutcomeDenied) {
					t.Error("denied delete must be audited")
				}
				if !agentExists(store, id) {
					t.Fatal("agent was deleted despite the denial")
				}
				for _, p := range []string{"/api/v1/agents", "/api/v1/agents/" + id + "/tasks"} {
					if rec := doLeakJSON(mux, http.MethodGet, p, "root-token", "", ""); rec.Code != http.StatusOK {
						t.Errorf("super-admin GET %s: %d", p, rec.Code)
					}
				}
				if rec := doLeakJSON(mux, http.MethodDelete, "/api/v1/agents/"+id, "root-token", "", ""); rec.Code != http.StatusNoContent {
					t.Errorf("super-admin DELETE: %d", rec.Code)
				}
			} else if del.Code != http.StatusNoContent {
				t.Errorf("flag off: DELETE %d", del.Code)
			}
		})
	}
}

// F3: agent-credential endpoints keep working under multi-tenancy.
func TestSecReviewF3_AgentCredentialPathsUnaffected(t *testing.T) {
	auth, _, _ := secReviewEnv(t, "on")
	store := NewAgentStore()
	id, tok, err := store.register("host-a", AgentType("linux"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAgentHandlers(mux, auth, store, &agentAuditLog{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/tasks", nil)
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent task poll: %d %s", rec.Code, rec.Body.String())
	}
}

// F4: NHI identities and SPIFFE SVID minting are global-admin-only under
// multi-tenancy.
func TestSecReviewF4_NHIAndSPIFFEGlobalAdminOnly(t *testing.T) {
	auth, acme, _ := secReviewEnv(t, "on")
	store := NewNHIStoreFromEnv()
	if store == nil {
		t.Fatal("nhi store unavailable")
	}
	created, err := store.Create(context.Background(), NHIIdentity{
		Name: "payments", Kind: "service", SPIFFEID: "spiffe://example.org/nhi/service/payments",
		Scopes: []string{"read"}, CreatedBy: "globex-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerNHIHandlers(mux, auth, store, NewWorkloadRegistry(), stubAuditProvider{})
	registerSPIFFEHandlers(mux, auth, nil, stubAuditProvider{})

	if rec := doLeakJSON(mux, http.MethodGet, "/api/v1/nhi/identities", acme, "acme", ""); rec.Code != http.StatusForbidden {
		t.Errorf("tenant admin NHI list: want 403, got %d", rec.Code)
	}
	for _, verb := range []string{"approve", "reject", "revoke"} {
		rec := doLeakJSON(mux, http.MethodPost, "/api/v1/nhi/identities/"+created.ID+"/"+verb, acme, "acme", "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("tenant admin NHI %s: want 403, got %d", verb, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "join_token") {
			t.Errorf("join token leaked on %s", verb)
		}
	}
	if got, _, _ := store.Get(context.Background(), created.ID); got.Status != "pending" {
		t.Errorf("identity status changed to %q by a denied caller", got.Status)
	}
	if rec := doLeakJSON(mux, http.MethodPost, "/api/v1/spiffe/svid", acme, "acme", `{"spiffe_id":"spiffe://example.org/nhi/service/payments"}`); rec.Code != http.StatusForbidden {
		t.Errorf("tenant admin SVID mint: want 403, got %d", rec.Code)
	}

	// Unscoped super-admin passes the tenancy gate (SPIFFE is unconfigured
	// here, so it stops at 503 rather than 403).
	if rec := doLeakJSON(mux, http.MethodGet, "/api/v1/nhi/identities", "root-token", "", ""); rec.Code != http.StatusOK {
		t.Errorf("super-admin NHI list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doLeakJSON(mux, http.MethodPost, "/api/v1/spiffe/svid", "root-token", "", `{}`); rec.Code == http.StatusForbidden &&
		strings.Contains(rec.Body.String(), "instance-wide") {
		t.Errorf("super-admin must pass the tenancy gate: %s", rec.Body.String())
	}
}

// F5: change-audit needs audit.read and stays tenant-scoped.
func TestSecReviewF5_ChangeAuditRequiresAuditRead(t *testing.T) {
	auth, acme, _ := secReviewEnv(t, "on")
	_, viewer, err := auth.CreateAPIKey("viewer", "viewer", "viewer", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	audit := &changeAuditTestAuditProvider{entries: []AuditEntry{
		{Action: "ca.create", ResourceType: "ca", ResourceID: "ca-acme", Outcome: "success", Tenant: "acme", Timestamp: now, ActorID: "alice", SourceIP: "10.0.0.9"},
		{Action: "ca.create", ResourceType: "ca", ResourceID: "ca-globex", Outcome: "success", Tenant: "globex", Timestamp: now},
	}}
	mux := http.NewServeMux()
	registerReportsHandlers(mux, auth, &reportCertProvider{}, &reportCAProvider{}, stubTemplateProvider{}, nil, audit)

	rec := doLeakJSON(mux, http.MethodGet, "/api/v1/reports/change-audit", viewer, "acme", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer change-audit: want 403, got %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.0.0.9") {
		t.Fatal("audit data leaked in the denial")
	}
	rec = doLeakJSON(mux, http.MethodGet, "/api/v1/reports/change-audit", acme, "acme", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant admin change-audit: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data ChangeAuditReport `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil || resp.Data.TotalEvents != 1 {
		t.Fatalf("tenant admin should see exactly its own event: %v %+v", err, resp.Data)
	}
}

func TestSecReviewF4_WorkloadEntriesGlobalAdminOnly(t *testing.T) {
	auth, acme, _ := secReviewEnv(t, "on")
	mux := http.NewServeMux()
	registerSPIFFEWorkloadHandlers(mux, auth, NewWorkloadRegistry(), stubAuditProvider{})
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if rec := doLeakJSON(mux, m, "/api/v1/spiffe/workload-entries", acme, "acme", `{}`); rec.Code != http.StatusForbidden {
			t.Errorf("tenant admin %s workload-entries: want 403, got %d", m, rec.Code)
		}
	}
	if rec := doLeakJSON(mux, http.MethodGet, "/api/v1/spiffe/workload-entries", "root-token", "", ""); rec.Code != http.StatusOK {
		t.Errorf("super-admin list: %d %s", rec.Code, rec.Body.String())
	}
}
