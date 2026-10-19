// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
)

type teamPolicyRig struct {
	mux     *http.ServeMux
	auth    *Authenticator
	audit   *recordingAuditProvider
	store   *dbTeamPolicyStore
	tenants *dbTenantStore
}

func newTeamPolicyRig(t *testing.T, multi bool) *teamPolicyRig {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	if multi {
		t.Setenv("MULTI_TENANCY", "on")
	} else {
		t.Setenv("MULTI_TENANCY", "off")
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	g := &teamPolicyRig{mux: http.NewServeMux(), auth: NewAuthenticatorFromEnv(), audit: &recordingAuditProvider{}}
	g.store = newDBTeamPolicyStore(db, false)
	opt := WithTeamPolicyAdmin(g.auth, db, false, g.audit)
	t.Cleanup(func() { activeTeamEnforcer = nil }) // W33-21: the option installs the global enforcer
	if opt == nil {
		t.Fatal("WithTeamPolicyAdmin returned nil for a live db")
	}
	cfg := &ServerConfig{Mux: g.mux}
	opt(cfg)
	if cfg.actionExecutors[ActionTeamPolicyLoosen] == nil {
		t.Fatal("executor not registered")
	}
	pending := NewPendingActionStoreFromEnv()
	if pending == nil {
		t.Fatal("pending store unavailable")
	}
	registerPendingActionHandlers(g.mux, g.auth, nil, pending, g.audit, cfg.actionExecutors)
	if multi {
		g.tenants = &dbTenantStore{db: db, ph: sqlitePlaceholder}
		ctx := context.Background()
		if err := g.tenants.EnsureSchema(ctx); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"acme", "beta"} {
			if _, err := g.tenants.CreateTenant(ctx, id, id); err != nil {
				t.Fatal(err)
			}
		}
		prev := activeTenantStore
		setActiveTenantStore(g.tenants)
		t.Cleanup(func() { setActiveTenantStore(prev) })
	}
	return g
}

func (g *teamPolicyRig) token(t *testing.T, id, role, tenant string) string {
	t.Helper()
	_, tok, err := g.auth.CreateAPIKey(id+"-key", id, role, []string{"*"}, "", tenant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (g *teamPolicyRig) do(method, path, tok, body string) (int, string) {
	rec := doLeakJSON(g.mux, method, path, tok, "", body)
	return rec.Code, rec.Body.String()
}

func (g *teamPolicyRig) actions() string {
	g.audit.mu.Lock()
	defer g.audit.mu.Unlock()
	var out []string
	for _, e := range g.audit.entries {
		out = append(out, e.Action+":"+string(e.Outcome))
	}
	return strings.Join(out, " ")
}

func (g *teamPolicyRig) get(t *testing.T, tenant, team string) TeamPolicy {
	t.Helper()
	p, found, err := g.store.Get(context.Background(), tenant, team)
	if err != nil || !found {
		t.Fatalf("get %s/%s: %v %v", tenant, team, found, err)
	}
	return p
}

func (g *teamPolicyRig) exists(tenant, team string) bool {
	_, found, _ := g.store.Get(context.Background(), tenant, team)
	return found
}

const denyStub = `{"team":"payments","max_validity_days":1,"monthly_quota":0}`

// seed creates the baseline policy (a create is a tightening and applies at
// once). The proposer/approver arguments are kept for call-site symmetry.
func (g *teamPolicyRig) seed(t *testing.T, proposer, _ string) {
	t.Helper()
	code, body := g.do(http.MethodPost, "/api/v1/team-policies", proposer, `{"team":"payments","allowed_cas":["ca-1"],"max_validity_days":90,"monthly_quota":10}`)
	if code != http.StatusCreated {
		t.Fatalf("seed create: %d %s", code, body)
	}
}

func actionIDFrom(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		Status   string   `json:"status"`
		ActionID string   `json:"pending_action_id"`
		Reasons  []string `json:"reasons"`
	}
	policyData(t, body, &out)
	if out.Status != "pending_approval" || out.ActionID == "" || len(out.Reasons) == 0 {
		t.Fatalf("not a pending response: %s", body)
	}
	return out.ActionID
}

func TestCreateAppliesAtOnce(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	admin := mintAdminToken(t, g.auth, "admin-1", "")
	code, body := g.do(http.MethodPost, "/api/v1/team-policies", admin, denyStub)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	p := g.get(t, DefaultTenant, "payments")
	if p.Version != 1 || p.MonthlyQuota != 0 || len(p.AllowedCAs) != 0 || p.UpdatedBy != "admin-1" {
		t.Fatalf("stored = %+v", p)
	}
	if !strings.Contains(body, `"allowed_cas":[]`) {
		t.Fatalf("lists must serialize as []: %s", body)
	}
	if !strings.Contains(g.actions(), "team_policy.create:success") {
		t.Fatalf("audit = %s", g.actions())
	}
}

func TestCreateWithGrantsAppliesAtOnce(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	admin := mintAdminToken(t, g.auth, "admin-1", "")
	code, body := g.do(http.MethodPost, "/api/v1/team-policies", admin, `{"team":"payments","allowed_dns_names":["a.example.com"],"max_validity_days":30,"monthly_quota":0}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	if !g.exists(DefaultTenant, "payments") {
		t.Fatal("create did not apply")
	}
}

func TestRaiseQuotaReturns202(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	a, b := mintAdminToken(t, g.auth, "admin-1", ""), mintAdminToken(t, g.auth, "admin-2", "")
	g.seed(t, a, b)
	code, body := g.do(http.MethodPatch, "/api/v1/team-policies/payments", a, `{"monthly_quota":11}`)
	if code != http.StatusAccepted {
		t.Fatalf("raise quota: %d %s", code, body)
	}
	if got := g.get(t, DefaultTenant, "payments").MonthlyQuota; got != 10 {
		t.Fatalf("quota applied without approval: %d", got)
	}
}

func TestSecondApproverApplies(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	a, b := mintAdminToken(t, g.auth, "admin-1", ""), mintAdminToken(t, g.auth, "admin-2", "")
	g.seed(t, a, b)
	if v := g.get(t, DefaultTenant, "payments").Version; v != 1 {
		t.Fatalf("seed version = %d", v)
	}
	_, body := g.do(http.MethodPatch, "/api/v1/team-policies/payments", a, `{"monthly_quota":50}`)
	id := actionIDFrom(t, body)
	if code, _ := g.do(http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", a, ""); code != http.StatusForbidden {
		t.Fatalf("self approval: %d", code)
	}
	if g.get(t, DefaultTenant, "payments").MonthlyQuota != 10 {
		t.Fatal("self-approval applied the change")
	}
	if code, out := g.do(http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", b, ""); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, out)
	}
	p := g.get(t, DefaultTenant, "payments")
	if p.MonthlyQuota != 50 || p.Version != 2 || p.UpdatedBy != "admin-2" {
		t.Fatalf("after approval = %+v", p)
	}
	if !strings.Contains(g.actions(), "team_policy.update:success") {
		t.Fatalf("audit = %s", g.actions())
	}
}

func TestTightenAppliesAtOnce(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	a, b := mintAdminToken(t, g.auth, "admin-1", ""), mintAdminToken(t, g.auth, "admin-2", "")
	g.seed(t, a, b)
	code, body := g.do(http.MethodPatch, "/api/v1/team-policies/payments", a, `{"monthly_quota":3,"max_validity_days":30}`)
	if code != http.StatusOK {
		t.Fatalf("tighten: %d %s", code, body)
	}
	p := g.get(t, DefaultTenant, "payments")
	if len(p.AllowedCAs) != 1 || p.MonthlyQuota != 3 || p.MaxValidityDays != 30 || p.Version != 2 {
		t.Fatalf("stored = %+v", p)
	}
}

func TestDeleteIsApprovalGated(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	a, b := mintAdminToken(t, g.auth, "admin-1", ""), mintAdminToken(t, g.auth, "admin-2", "")
	g.seed(t, a, b)
	code, body := g.do(http.MethodDelete, "/api/v1/team-policies/payments", a, "")
	if code != http.StatusAccepted {
		t.Fatalf("delete: %d %s", code, body)
	}
	id := actionIDFrom(t, body)
	if !g.exists(DefaultTenant, "payments") {
		t.Fatal("row removed without approval")
	}
	if code, _ := g.do(http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", a, ""); code != http.StatusForbidden {
		t.Fatalf("self approval: %d", code)
	}
	if !g.exists(DefaultTenant, "payments") {
		t.Fatal("self-approval removed the row")
	}
	if code, out := g.do(http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", b, ""); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, out)
	}
	if g.exists(DefaultTenant, "payments") {
		t.Fatal("row survived approved delete")
	}
	if code, _ := g.do(http.MethodDelete, "/api/v1/team-policies/payments", a, ""); code != http.StatusNotFound {
		t.Fatalf("delete of absent policy: %d", code)
	}
	for _, want := range []string{"team_policy.delete:pending_approval", "team_policy.delete:success", "team_policy.delete:failure"} {
		if !strings.Contains(g.actions(), want) {
			t.Fatalf("missing %s in %s", want, g.actions())
		}
	}
}

func TestClearListIsApprovalGated(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	a := mintAdminToken(t, g.auth, "admin-1", "")
	g.seed(t, a, "")
	if code, body := g.do(http.MethodPatch, "/api/v1/team-policies/payments", a, `{"allowed_cas":[]}`); code != http.StatusAccepted {
		t.Fatalf("clear list: %d %s", code, body)
	}
	if code, body := g.do(http.MethodPatch, "/api/v1/team-policies/payments", a, `{"monthly_quota":0}`); code != http.StatusAccepted {
		t.Fatalf("quota to 0: %d %s", code, body)
	}
	p := g.get(t, DefaultTenant, "payments")
	if len(p.AllowedCAs) != 1 || p.MonthlyQuota != 10 || p.Version != 1 {
		t.Fatalf("loosening applied: %+v", p)
	}
}

func TestStaleProposalRejected(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	a, b := mintAdminToken(t, g.auth, "admin-1", ""), mintAdminToken(t, g.auth, "admin-2", "")
	g.seed(t, a, b)
	_, body := g.do(http.MethodPatch, "/api/v1/team-policies/payments", a, `{"monthly_quota":50}`)
	id := actionIDFrom(t, body)
	// A tightening lands in between and bumps the version.
	if code, out := g.do(http.MethodPatch, "/api/v1/team-policies/payments", a, `{"monthly_quota":5}`); code != http.StatusOK {
		t.Fatalf("interleaved tighten: %d %s", code, out)
	}
	code, out := g.do(http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", b, "")
	if code == http.StatusOK || !strings.Contains(out, "team policy changed since proposal") {
		t.Fatalf("stale approve: %d %s", code, out)
	}
	if got := g.get(t, DefaultTenant, "payments").MonthlyQuota; got != 5 {
		t.Fatalf("stale proposal applied: quota %d", got)
	}
}

func TestViewerCannotWrite(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	viewer := g.token(t, "viewer-1", "viewer", "")
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/team-policies", denyStub},
		{http.MethodPatch, "/api/v1/team-policies/payments", `{"monthly_quota":1}`},
		{http.MethodDelete, "/api/v1/team-policies/payments", ""},
	} {
		if code, _ := g.do(c.method, c.path, viewer, c.body); code != http.StatusForbidden {
			t.Fatalf("%s %s: %d", c.method, c.path, code)
		}
	}
	for _, want := range []string{"team_policy.create:denied", "team_policy.update:denied", "team_policy.delete:denied"} {
		if !strings.Contains(g.actions(), want) {
			t.Fatalf("missing %s in %s", want, g.actions())
		}
	}
	if code, _ := g.do(http.MethodGet, "/api/v1/team-policies", viewer, ""); code != http.StatusForbidden {
		t.Fatalf("viewer list must be refused: %d", code)
	}
}

func TestPolicyReadScopedToOwnTeam(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	admin := g.token(t, "admin-1", "pki-admin", "")
	for _, team := range []string{"payments", "requester-1"} {
		body := `{"team":"` + team + `","monthly_quota":5}`
		if code, out := g.do(http.MethodPost, "/api/v1/team-policies", admin, body); code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("seed %s: %d %s", team, code, out)
		}
	}
	req := g.token(t, "requester-1", "requester", "")
	if code, _ := g.do(http.MethodGet, "/api/v1/team-policies/requester-1", req, ""); code != http.StatusOK {
		t.Fatalf("own team read: %d", code)
	}
	if code, _ := g.do(http.MethodGet, "/api/v1/team-policies/payments", req, ""); code != http.StatusForbidden {
		t.Fatalf("other team read must be refused: %d", code)
	}
	if !strings.Contains(g.actions(), "team_policy.get:denied") {
		t.Fatalf("refused read not audited: %s", g.actions())
	}
	auditor := g.token(t, "aud-1", "auditor", "")
	if code, _ := g.do(http.MethodGet, "/api/v1/team-policies/payments", auditor, ""); code != http.StatusOK {
		t.Fatalf("auditor read: %d", code)
	}
	if code, _ := g.do(http.MethodGet, "/api/v1/team-policies", auditor, ""); code != http.StatusOK {
		t.Fatalf("auditor list: %d", code)
	}
}

func TestDuplicateCreate409(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	admin := mintAdminToken(t, g.auth, "admin-1", "")
	if code, _ := g.do(http.MethodPost, "/api/v1/team-policies", admin, denyStub); code != http.StatusCreated {
		t.Fatal("first create failed")
	}
	if code, body := g.do(http.MethodPost, "/api/v1/team-policies", admin, denyStub); code != http.StatusConflict {
		t.Fatalf("duplicate: %d %s", code, body)
	}
}

func TestCreateValidationFailuresAreAudited(t *testing.T) {
	g := newTeamPolicyRig(t, false)
	admin := mintAdminToken(t, g.auth, "admin-1", "")
	for _, body := range []string{`{}`, `{"team":"a/b","max_validity_days":5}`, `{"team":"x","max_validity_days":5,"bogus":1}`, `{"team":"x","max_validity_days":5,"allowed_dns_suffixes":["*.x"]}`} {
		if code, out := g.do(http.MethodPost, "/api/v1/team-policies", admin, body); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", body, code, out)
		}
	}
	if got := strings.Count(g.actions(), "team_policy.create:failure"); got != 4 {
		t.Fatalf("failure rows = %d in %s", got, g.actions())
	}
}

func TestTenantScopingHidesOtherTenant(t *testing.T) {
	g := newTeamPolicyRig(t, true)
	acme1, acme2 := g.token(t, "acme-1", "pki-admin", "acme"), g.token(t, "acme-2", "pki-admin", "acme")
	beta := g.token(t, "beta-1", "pki-admin", "beta")
	if err := g.tenants.SetCATenant(context.Background(), "ca-1", "acme"); err != nil {
		t.Fatal(err)
	}
	g.seed(t, acme1, acme2)
	if p := g.get(t, "acme", "payments"); p.Tenant != "acme" {
		t.Fatalf("tenant = %s", p.Tenant)
	}
	if code, _ := g.do(http.MethodGet, "/api/v1/team-policies/payments", beta, ""); code != http.StatusNotFound {
		t.Fatalf("beta GET: %d", code)
	}
	for _, m := range []string{http.MethodPatch, http.MethodDelete} {
		if code, _ := g.do(m, "/api/v1/team-policies/payments", beta, `{"monthly_quota":0}`); code != http.StatusNotFound {
			t.Fatalf("beta %s: %d", m, code)
		}
	}
	// ?tenant= is ignored for a scoped admin.
	if code, _ := g.do(http.MethodGet, "/api/v1/team-policies/payments?tenant=acme", beta, ""); code != http.StatusNotFound {
		t.Fatalf("beta GET ?tenant=acme: %d", code)
	}
	code, body := g.do(http.MethodGet, "/api/v1/team-policies?tenant=acme", beta, "")
	var list []TeamPolicy
	policyData(t, body, &list)
	if code != http.StatusOK || len(list) != 0 {
		t.Fatalf("beta list: %d %s", code, body)
	}
	if !g.exists("acme", "payments") {
		t.Fatal("acme row damaged by beta")
	}
	_, body = g.do(http.MethodGet, "/api/v1/team-policies", acme1, "")
	policyData(t, body, &list)
	if len(list) != 1 || list[0].Team != "payments" {
		t.Fatalf("acme list: %s", body)
	}
	// A tenant-scoped approver of another tenant cannot approve acme's proposal.
	_, pbody := g.do(http.MethodPatch, "/api/v1/team-policies/payments", acme1, `{"monthly_quota":99}`)
	id := actionIDFrom(t, pbody)
	if code, _ := g.do(http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", beta, ""); code == http.StatusOK {
		t.Fatal("beta approved acme's proposal")
	}
	if g.get(t, "acme", "payments").MonthlyQuota != 10 {
		t.Fatal("cross-tenant approval applied the change")
	}
}

func TestPolicyCAFromOtherTenantRejected(t *testing.T) {
	g := newTeamPolicyRig(t, true)
	ctx := context.Background()
	if err := g.tenants.SetCATenant(ctx, "ca-acme", "acme"); err != nil {
		t.Fatal(err)
	}
	if err := g.tenants.SetCATenant(ctx, "ca-beta", "beta"); err != nil {
		t.Fatal(err)
	}
	if err := g.tenants.SetTemplateTenant(ctx, "tpl-beta", "beta"); err != nil {
		t.Fatal(err)
	}
	acme := g.token(t, "acme-1", "pki-admin", "acme")
	code, body := g.do(http.MethodPost, "/api/v1/team-policies", acme, `{"team":"t","allowed_cas":["ca-beta"],"max_validity_days":5}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "ca not in tenant") {
		t.Fatalf("foreign CA: %d %s", code, body)
	}
	code, body = g.do(http.MethodPost, "/api/v1/team-policies", acme, `{"team":"t","allowed_templates":["tpl-beta"],"max_validity_days":5}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "template not in tenant") {
		t.Fatalf("foreign template: %d %s", code, body)
	}
	if code, body = g.do(http.MethodPost, "/api/v1/team-policies", acme, `{"team":"t","allowed_cas":["ca-acme"],"max_validity_days":5}`); code != http.StatusCreated {
		t.Fatalf("own CA: %d %s", code, body)
	}
}
