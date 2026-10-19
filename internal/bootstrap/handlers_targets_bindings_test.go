// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// W27-02 binding routes.

var (
	bindFP1 = strings.Repeat("ab", 32)
	bindFP2 = strings.Repeat("cd", 32)
)

type bindingHandlerEnv struct {
	mux      *http.ServeMux
	auth     *Authenticator
	targets  *sqliteManagedTargetStore
	bindings *sqlCertTargetBindingStore
	tenants  *dbTenantStore
	audit    *recordingAuditProvider
	certs    map[string]CertificateDetail
}

type mapCertProvider struct {
	*reportCertProvider
	certs map[string]CertificateDetail
}

func (p mapCertProvider) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	d, ok := p.certs[fp]
	return d, ok, nil
}

func newBindingHandlerEnv(t *testing.T) *bindingHandlerEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "bindings-handler.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &bindingHandlerEnv{
		auth: auth, targets: &sqliteManagedTargetStore{db: db}, bindings: &sqlCertTargetBindingStore{db: db},
		tenants: &dbTenantStore{db: db, ph: sqlitePlaceholder}, audit: &recordingAuditProvider{},
		certs: map[string]CertificateDetail{},
	}
	ctx := context.Background()
	for _, ens := range []func(context.Context) error{e.targets.EnsureSchema, e.bindings.EnsureSchema, e.tenants.EnsureSchema} {
		if err := ens(ctx); err != nil {
			t.Fatal(err)
		}
	}
	prevTenant, prevBind := activeTenantStore, activeCertTargetBindingStore
	setActiveTenantStore(e.tenants)
	t.Cleanup(func() { setActiveTenantStore(prevTenant); setActiveCertTargetBindingStore(prevBind) })

	e.mux = http.NewServeMux()
	registerTargetHandlers(e.mux, auth, e.targets, e.tenants, e.audit, targetEgressDeps{})
	RegisterCertTargetBindingHandlers(e.mux, auth, e.targets, mapCertProvider{&reportCertProvider{}, e.certs}, e.bindings, e.audit)
	return e
}

func (e *bindingHandlerEnv) addTarget(t *testing.T, id, tenant string) {
	t.Helper()
	tg := mkTarget(id, id+".example.com")
	tg.Tenant = tenant
	if _, err := e.targets.Create(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
}

func (e *bindingHandlerEnv) addCert(fp, caID string) {
	e.certs[fp] = CertificateDetail{CertificateItem: CertificateItem{FingerprintSHA256: fp, CAID: caID}}
}

// lastTargetUpdate returns the newest target.update audit row.
func (e *bindingHandlerEnv) lastTargetUpdate(t *testing.T) AuditEntry {
	t.Helper()
	for i := len(e.audit.entries) - 1; i >= 0; i-- {
		if e.audit.entries[i].Action == "target.update" {
			return e.audit.entries[i]
		}
	}
	t.Fatalf("no target.update audit row in %+v", e.audit.entries)
	return AuditEntry{}
}

func bindBody(fp string) string { return `{"cert_fingerprint":"` + fp + `"}` }

func TestBindingHandlerCreateListDeleteAudited(t *testing.T) {
	e := newBindingHandlerEnv(t)
	e.addTarget(t, "t1", DefaultTenant)
	e.addCert(bindFP1, "ca-1")

	rec := doTargetsRequest(e.mux, http.MethodPost, "/api/v1/targets/t1/bindings", "test-token", bindBody(bindFP1))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data CertTargetBinding `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.TargetID != "t1" || created.Data.CertFingerprint != bindFP1 || created.Data.ServedFingerprint != bindFP1 || created.Data.Source != "operator" {
		t.Fatalf("binding = %+v", created.Data)
	}
	if row := e.lastTargetUpdate(t); row.Outcome != AuditOutcomeSuccess || row.ResourceType != "target" || row.ResourceID != "t1" || row.ChangeSummary != "binding.create cert="+bindFP1 {
		t.Fatalf("create audit row = %+v", row)
	}

	rec = doTargetsRequest(e.mux, http.MethodGet, "/api/v1/targets/t1/bindings", "test-token", "")
	var listed struct {
		Data []CertTargetBinding `json:"data"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &listed) != nil || len(listed.Data) != 1 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}

	rec = doTargetsRequest(e.mux, http.MethodDelete, "/api/v1/targets/t1/bindings/"+bindFP1, "test-token", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	if row := e.lastTargetUpdate(t); row.Outcome != AuditOutcomeSuccess || row.ChangeSummary != "binding.delete cert="+bindFP1 {
		t.Fatalf("delete audit row = %+v", row)
	}
	if left, _ := e.bindings.ListAll(context.Background()); len(left) != 0 {
		t.Fatalf("binding survived delete: %+v", left)
	}
}

func TestBindingHandlerRefusals(t *testing.T) {
	e := newBindingHandlerEnv(t)
	e.addTarget(t, "t1", DefaultTenant)
	e.addCert(bindFP1, "ca-1")
	post := func(path, token, body string) int {
		return doTargetsRequest(e.mux, http.MethodPost, path, token, body).Code
	}
	if post("/api/v1/targets/t1/bindings", "test-token", bindBody(bindFP1)) != http.StatusCreated {
		t.Fatal("setup create failed")
	}

	if got := post("/api/v1/targets/t1/bindings", "test-token", bindBody(bindFP1)); got != http.StatusConflict {
		t.Fatalf("duplicate = %d, want 409", got)
	}
	if got := post("/api/v1/targets/t1/bindings", "test-token", bindBody(bindFP2)); got != http.StatusNotFound {
		t.Fatalf("unknown certificate = %d, want 404", got)
	}
	if got := post("/api/v1/targets/nope/bindings", "test-token", bindBody(bindFP1)); got != http.StatusNotFound {
		t.Fatalf("unknown target = %d, want 404", got)
	}
	for _, body := range []string{`{}`, bindBody("short"), bindBody(strings.Repeat("zz", 32)), `not json`} {
		if got := post("/api/v1/targets/t1/bindings", "test-token", body); got != http.StatusBadRequest {
			t.Fatalf("body %q = %d, want 400", body, got)
		}
	}
	if got := doTargetsRequest(e.mux, http.MethodDelete, "/api/v1/targets/t1/bindings/"+bindFP2, "test-token", "").Code; got != http.StatusNotFound {
		t.Fatalf("delete unknown binding = %d, want 404", got)
	}
	if got := doTargetsRequest(e.mux, http.MethodDelete, "/api/v1/targets/t1/bindings/xyz", "test-token", "").Code; got != http.StatusBadRequest {
		t.Fatalf("delete malformed fingerprint = %d, want 400", got)
	}
	if got := post("/api/v1/targets/t1/bindings", "", bindBody(bindFP1)); got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", got)
	}

	// Every refusal above left an audit row (the route matrix demands it).
	failures := 0
	for _, row := range e.audit.entries {
		if row.Action == "target.update" && row.Outcome == AuditOutcomeFailure {
			failures++
		}
	}
	if failures < 8 {
		t.Fatalf("only %d failure audit rows for 9 refused requests: %+v", failures, e.audit.entries)
	}
}

func TestBindingHandlerNeedsCertificateRenew(t *testing.T) {
	e := newBindingHandlerEnv(t)
	e.addTarget(t, "t1", DefaultTenant)
	e.addCert(bindFP1, "ca-1")
	_, token, err := e.auth.CreateAPIKey("disc", "disc-1", "discovery-operator", []string{"discovery:write"}, "", DefaultTenant, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rec := doTargetsRequest(e.mux, http.MethodPost, "/api/v1/targets/t1/bindings", token, bindBody(bindFP1))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("discovery operator bound a cert (key egress) = %d: %s", rec.Code, rec.Body.String())
	}
	if row := e.lastTargetUpdate(t); row.Outcome != AuditOutcomeDenied {
		t.Fatalf("audit row = %+v", row)
	}
	if left, _ := e.bindings.ListAll(context.Background()); len(left) != 0 {
		t.Fatal("a refused request still created a binding")
	}
}

func TestBindingHandlerTenantChecks(t *testing.T) {
	e := newBindingHandlerEnv(t)
	t.Setenv("MULTI_TENANCY", "on")
	ctx := context.Background()
	for _, id := range []string{"tenant-a", "tenant-b"} {
		if _, err := e.tenants.CreateTenant(ctx, id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.tenants.SetCATenant(ctx, "ca-a", "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := e.tenants.SetCATenant(ctx, "ca-b", "tenant-b"); err != nil {
		t.Fatal(err)
	}
	e.addTarget(t, "ta", "tenant-a")
	e.addCert(bindFP1, "ca-a")
	e.addCert(bindFP2, "ca-b")
	_, tokenA, err := e.auth.CreateAPIKey("a", "user-a", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, tokenB, err := e.auth.CreateAPIKey("b", "user-b", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if got := doTargetsRequest(e.mux, http.MethodPost, "/api/v1/targets/ta/bindings", tokenA, bindBody(bindFP2)).Code; got != http.StatusForbidden {
		t.Fatalf("tenant A bound tenant B's certificate = %d, want 403", got)
	}
	if got := doTargetsRequest(e.mux, http.MethodPost, "/api/v1/targets/ta/bindings", tokenB, bindBody(bindFP2)).Code; got != http.StatusForbidden {
		t.Fatalf("tenant B reached tenant A's target = %d, want 403", got)
	}
	if got := doTargetsRequest(e.mux, http.MethodGet, "/api/v1/targets/ta/bindings", tokenB, "").Code; got != http.StatusForbidden {
		t.Fatalf("tenant B listed tenant A's bindings = %d, want 403", got)
	}
	if got := doTargetsRequest(e.mux, http.MethodPost, "/api/v1/targets/ta/bindings", tokenA, bindBody(bindFP1)).Code; got != http.StatusCreated {
		t.Fatalf("same-tenant bind = %d, want 201", got)
	}
	if got := doTargetsRequest(e.mux, http.MethodDelete, "/api/v1/targets/ta/bindings/"+bindFP1, tokenB, "").Code; got != http.StatusForbidden {
		t.Fatalf("tenant B deleted tenant A's binding = %d, want 403", got)
	}

	// The target-side check on its own (a principal that bypasses tenant scoping
	// would pass the caller check): tenant-a may not hold a tenant-b CA key.
	item := CertificateItem{CAID: "ca-b"}
	if targetMayReceiveCert(ctx, ManagedTarget{Tenant: "tenant-a"}, item) {
		t.Fatal("targetMayReceiveCert allowed tenant-a to receive a tenant-b CA's certificate")
	}
}

func TestTargetDeleteRemovesItsBindings(t *testing.T) {
	e := newBindingHandlerEnv(t)
	e.addTarget(t, "t1", DefaultTenant)
	e.addCert(bindFP1, "ca-1")
	if doTargetsRequest(e.mux, http.MethodPost, "/api/v1/targets/t1/bindings", "test-token", bindBody(bindFP1)).Code != http.StatusCreated {
		t.Fatal("setup create failed")
	}
	if got := doTargetsRequest(e.mux, http.MethodDelete, "/api/v1/targets/t1", "test-token", "").Code; got != http.StatusNoContent {
		t.Fatalf("delete target = %d", got)
	}
	if left, _ := e.bindings.ListAll(context.Background()); len(left) != 0 {
		t.Fatalf("bindings outlived their target: %+v", left)
	}
}

func TestBindingHandlerStoreUnavailable(t *testing.T) {
	e := newBindingHandlerEnv(t)
	mux := http.NewServeMux()
	RegisterCertTargetBindingHandlers(mux, e.auth, e.targets, nil, nil, e.audit)
	if got := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets/t1/bindings", "test-token", bindBody(bindFP1)).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("no store = %d, want 503", got)
	}
	if row := e.lastTargetUpdate(t); row.Outcome != AuditOutcomeFailure {
		t.Fatalf("audit row = %+v", row)
	}
}

// A manual renewal installs a successor on the target: its binding follows, or
// the sweep would renew the certificate it just replaced.
func TestManualRenewalExecuteAdvancesBindingServedFingerprint(t *testing.T) {
	bindings := newFreshBindingStore(t)
	prev := activeCertTargetBindingStore
	setActiveCertTargetBindingStore(bindings)
	t.Cleanup(func() { setActiveCertTargetBindingStore(prev) })

	runner := &slowRenewer{result: RenewalExecuteResult{NewFingerprint: "successor-fp", Renewed: true, InstallOutcome: "installed_verified"}}
	srv, fp, targetID := startRenewalServer(t, runner, time.Minute, time.Minute)
	ctx := context.Background()
	for _, b := range []CertTargetBinding{
		{CertFingerprint: fp, TargetID: targetID},
		{CertFingerprint: fp, TargetID: "other-target"},
	} {
		if _, err := bindings.Create(ctx, b); err != nil {
			t.Fatal(err)
		}
	}

	if code, body, err := postSlow(t, srv, fp, targetID); err != nil || code != http.StatusOK {
		t.Fatalf("execute = %d %s %v", code, body, err)
	}

	mine, _ := bindings.ListByTarget(ctx, targetID)
	other, _ := bindings.ListByTarget(ctx, "other-target")
	if mine[0].ServedFingerprint != "successor-fp" || other[0].ServedFingerprint != fp {
		t.Fatalf("served after manual renewal: target=%q other=%q", mine[0].ServedFingerprint, other[0].ServedFingerprint)
	}
}
