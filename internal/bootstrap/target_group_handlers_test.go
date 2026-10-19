// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// W27-04 group and effective-policy routes.

type groupHandlerEnv struct {
	mux     *http.ServeMux
	auth    *Authenticator
	targets *sqliteManagedTargetStore
	groups  *sqlTargetGroupStore
	tenants *dbTenantStore
	audit   *recordingAuditProvider
}

func newGroupHandlerEnv(t *testing.T) *groupHandlerEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "groups-handler.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &groupHandlerEnv{
		auth: auth, targets: &sqliteManagedTargetStore{db: db}, groups: &sqlTargetGroupStore{db: db},
		tenants: &dbTenantStore{db: db, ph: sqlitePlaceholder}, audit: &recordingAuditProvider{},
	}
	for _, ens := range []func(context.Context) error{e.targets.EnsureSchema, e.groups.EnsureSchema, e.tenants.EnsureSchema} {
		if err := ens(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	e.mux = http.NewServeMux()
	RegisterTargetGroupHandlers(e.mux, auth, e.targets, e.groups, e.audit)
	return e
}

func (e *groupHandlerEnv) addTarget(t *testing.T, id, tenant string, own int) {
	t.Helper()
	tg := mkTarget(id, id+".example.com")
	tg.Tenant, tg.RenewalThresholdDays = tenant, own
	if _, err := e.targets.Create(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
}

func (e *groupHandlerEnv) put(name, token, body string) *httptest.ResponseRecorder {
	return doTargetsRequest(e.mux, http.MethodPut, "/api/v1/target-groups/"+name, token, body)
}

func (e *groupHandlerEnv) lastAudit(t *testing.T) AuditEntry {
	t.Helper()
	if len(e.audit.entries) == 0 {
		t.Fatal("no audit rows")
	}
	return e.audit.entries[len(e.audit.entries)-1]
}

func TestTargetGroupHandlerPutListDeleteAudited(t *testing.T) {
	e := newGroupHandlerEnv(t)
	e.addTarget(t, "t1", DefaultTenant, 0)
	e.addTarget(t, "t2", DefaultTenant, 0)

	rec := e.put("prod", "test-token", `{"renewal_threshold_days":45,"target_ids":["t1","t2"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put = %d: %s", rec.Code, rec.Body.String())
	}
	if row := e.lastAudit(t); row.Action != "target.update" || row.ResourceType != "target_group" || row.ResourceID != "prod" || row.Outcome != AuditOutcomeSuccess {
		t.Fatalf("put audit row = %+v", row)
	}

	rec = doTargetsRequest(e.mux, http.MethodGet, "/api/v1/target-groups", "test-token", "")
	var listed struct {
		Data []TargetGroup `json:"data"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &listed) != nil || len(listed.Data) != 1 ||
		listed.Data[0].RenewalThresholdDays != 45 || len(listed.Data[0].TargetIDs) != 2 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}

	if got := doTargetsRequest(e.mux, http.MethodDelete, "/api/v1/target-groups/prod", "test-token", "").Code; got != http.StatusNoContent {
		t.Fatalf("delete = %d", got)
	}
	if row := e.lastAudit(t); row.Action != "target.update" || row.Outcome != AuditOutcomeSuccess {
		t.Fatalf("delete audit row = %+v", row)
	}
	if got := doTargetsRequest(e.mux, http.MethodDelete, "/api/v1/target-groups/prod", "test-token", "").Code; got != http.StatusNotFound {
		t.Fatalf("delete unknown = %d, want 404", got)
	}
	if row := e.lastAudit(t); row.Outcome != AuditOutcomeFailure {
		t.Fatalf("404 delete audit row = %+v", row)
	}
}

func TestTargetGroupHandlerValidation(t *testing.T) {
	e := newGroupHandlerEnv(t)
	e.addTarget(t, "t1", DefaultTenant, 0)
	for _, tc := range []struct{ name, path, body string }{
		{"399 days", "prod", `{"renewal_threshold_days":399}`},
		{"0 days", "prod", `{"renewal_threshold_days":0}`},
		{"negative days", "prod", `{"renewal_threshold_days":-5}`},
		{"unknown target", "prod", `{"renewal_threshold_days":30,"target_ids":["nope"]}`},
		{"bad name", "bad%20name", `{"renewal_threshold_days":30}`},
		{"bad body", "prod", `not json`},
	} {
		before := len(e.audit.entries)
		if got := e.put(tc.path, "test-token", tc.body).Code; got != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", tc.name, got)
		}
		if len(e.audit.entries) != before+1 || e.lastAudit(t).Outcome != AuditOutcomeFailure {
			t.Errorf("%s: refusal not audited as a failure", tc.name)
		}
	}
	for _, d := range []string{"1", "398"} {
		if got := e.put("edge"+d, "test-token", `{"renewal_threshold_days":`+d+`}`).Code; got != http.StatusOK {
			t.Errorf("%s days = %d, want 200", d, got)
		}
	}
	if got := e.put("prod", "", `{"renewal_threshold_days":30}`).Code; got != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d", got)
	}
}

func TestTargetGroupHandlerTenantScoping(t *testing.T) {
	e := newGroupHandlerEnv(t)
	t.Setenv("MULTI_TENANCY", "on")
	for _, id := range []string{"tenant-a", "tenant-b"} {
		if _, err := e.tenants.CreateTenant(context.Background(), id, id); err != nil {
			t.Fatal(err)
		}
	}
	e.addTarget(t, "ta", "tenant-a", 0)
	e.addTarget(t, "tb", "tenant-b", 0)
	_, tokenA, err := e.auth.CreateAPIKey("a", "user-a", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, tokenB, err := e.auth.CreateAPIKey("b", "user-b", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if got := e.put("prod", tokenA, `{"renewal_threshold_days":30,"target_ids":["tb"]}`).Code; got != http.StatusBadRequest {
		t.Fatalf("tenant A grouped tenant B's target = %d, want 400", got)
	}
	if got := e.put("prod", tokenA, `{"renewal_threshold_days":30,"target_ids":["ta"]}`).Code; got != http.StatusOK {
		t.Fatalf("own-tenant group = %d", got)
	}
	// The same name in tenant B is a different group.
	if got := e.put("prod", tokenB, `{"renewal_threshold_days":90,"target_ids":["tb"]}`).Code; got != http.StatusOK {
		t.Fatalf("tenant B same name = %d", got)
	}

	var listed struct {
		Data []TargetGroup `json:"data"`
	}
	rec := doTargetsRequest(e.mux, http.MethodGet, "/api/v1/target-groups", tokenA, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Data) != 1 || listed.Data[0].Tenant != "tenant-a" || listed.Data[0].RenewalThresholdDays != 30 {
		t.Fatalf("tenant A saw %+v (%v)", listed.Data, err)
	}
	if got := doTargetsRequest(e.mux, http.MethodDelete, "/api/v1/target-groups/prod", tokenB, "").Code; got != http.StatusNoContent {
		t.Fatalf("tenant B delete own = %d", got)
	}
	if groups, _ := e.groups.List(context.Background()); len(groups) != 1 || groups[0].Tenant != "tenant-a" {
		t.Fatalf("tenant B's delete touched tenant A: %+v", groups)
	}
}

func TestTargetPolicyShowsSource(t *testing.T) {
	e := newGroupHandlerEnv(t)
	e.addTarget(t, "member", DefaultTenant, 0)
	e.addTarget(t, "own", DefaultTenant, 10)
	e.addTarget(t, "loner", DefaultTenant, 0)
	if got := e.put("prod", "test-token", `{"renewal_threshold_days":45,"target_ids":["member","own"]}`).Code; got != http.StatusOK {
		t.Fatalf("setup put = %d", got)
	}

	rec := doTargetsRequest(e.mux, http.MethodGet, "/api/v1/target-policy", "test-token", "")
	var resp struct {
		Data []TargetPolicyRow `json:"data"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
		t.Fatalf("policy = %d %s", rec.Code, rec.Body.String())
	}
	byID := map[string]TargetPolicyRow{}
	for _, r := range resp.Data {
		byID[r.TargetID] = r
	}
	def := schedulerDefaultThreshold()
	if r := byID["member"]; r.Source != "group" || r.EffectiveDays != 45 || r.Group != "prod" || r.GroupDays != 45 || r.DefaultDays != def {
		t.Fatalf("member = %+v", r)
	}
	if r := byID["own"]; r.Source != "target" || r.EffectiveDays != 10 || r.OwnDays != 10 || r.GroupDays != 45 {
		t.Fatalf("own = %+v", r)
	}
	if r := byID["loner"]; r.Source != "default" || r.EffectiveDays != def || r.Group != "" {
		t.Fatalf("loner = %+v", r)
	}
}

func TestTargetGroupHandlerStoreUnavailable(t *testing.T) {
	e := newGroupHandlerEnv(t)
	mux := http.NewServeMux()
	RegisterTargetGroupHandlers(mux, e.auth, nil, nil, e.audit)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/target-groups", ""},
		{http.MethodPut, "/api/v1/target-groups/x", `{"renewal_threshold_days":30}`},
		{http.MethodDelete, "/api/v1/target-groups/x", ""},
		{http.MethodGet, "/api/v1/target-policy", ""},
	} {
		before := len(e.audit.entries)
		if got := doTargetsRequest(mux, tc.method, tc.path, "test-token", tc.body).Code; got != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d, want 503", tc.method, tc.path, got)
		}
		if len(e.audit.entries) != before+1 {
			t.Errorf("%s %s: 503 not audited", tc.method, tc.path)
		}
	}
}
