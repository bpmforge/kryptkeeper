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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type expiryAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *expiryAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (a *expiryAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
	return nil
}
func (a *expiryAudit) count(action string, outcome AuditOutcome) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			n++
		}
	}
	return n
}
func (a *expiryAudit) find(action string) (AuditEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action {
			return e, true
		}
	}
	return AuditEntry{}, false
}

type fakeExpiryNotifier struct {
	mu  sync.Mutex
	got []ApprovalExpiredEvent
}

func (f *fakeExpiryNotifier) NotifyApprovalExpired(_ context.Context, ev ApprovalExpiredEvent) error {
	f.mu.Lock()
	f.got = append(f.got, ev)
	f.mu.Unlock()
	return nil
}

func newTestApprovalStore(t *testing.T) *sqliteApprovalStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "apr.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteApprovalStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func seedAction(t *testing.T, s PendingActionStore, proposer string) PendingAction {
	t.Helper()
	a, err := s.Create(context.Background(), PendingAction{ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1"}`), ProposedBy: proposer, Tenant: "acme"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return a
}

func TestApprovalTTLDefault72(t *testing.T) {
	t.Setenv(approvalTTLEnv, "")
	if got := ApprovalTTL(); got != 72*time.Hour {
		t.Fatalf("unset: %v", got)
	}
	t.Setenv(approvalTTLEnv, "24")
	if got := ApprovalTTL(); got != 24*time.Hour {
		t.Fatalf("24: %v", got)
	}
	for _, bad := range []string{"abc", "-1", "0"} {
		t.Setenv(approvalTTLEnv, bad)
		if got := ApprovalTTL(); got != 72*time.Hour {
			t.Fatalf("%q: %v", bad, got)
		}
	}
}

func TestExpiryRejectsOldPendingAction(t *testing.T) {
	store := newTestPendingStore(t)
	audit := &expiryAudit{}
	a := seedAction(t, store, "mcp:agent")
	created, _ := time.Parse(time.RFC3339, a.CreatedAt)
	now := created.Add(72*time.Hour + time.Minute)
	job := &ApprovalExpiryJob{Actions: store, Audit: audit, TTL: 72 * time.Hour, Now: func() time.Time { return now }}
	n, err := job.RunOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("RunOnce = %d, %v", n, err)
	}
	got, _, _ := store.Get(context.Background(), a.ID)
	if got.Status != "rejected" || got.ApprovedBy != expirySweeper {
		t.Fatalf("row = %+v", got)
	}
	var res map[string]any
	_ = json.Unmarshal(got.Result, &res)
	if res["expired"] != true {
		t.Fatalf("result = %s", got.Result)
	}
	if audit.count("action.expire", AuditOutcomeSuccess) != 1 {
		t.Fatalf("missing action.expire: %+v", audit.entries)
	}
	if e, _ := audit.find("action.expire"); e.Tenant != "acme" || e.ActorType != "system" {
		t.Fatalf("audit entry = %+v", e)
	}
}

func TestExpiryLeavesFreshAndDecided(t *testing.T) {
	store := newTestPendingStore(t)
	audit := &expiryAudit{}
	fresh := seedAction(t, store, "p1")
	approved := seedAction(t, store, "p2")
	rejected := seedAction(t, store, "p3")
	ctx := context.Background()
	_ = store.Decide(ctx, approved.ID, "approved", "someone", nil)
	_ = store.Decide(ctx, rejected.ID, "rejected", "someone", nil)
	created, _ := time.Parse(time.RFC3339, fresh.CreatedAt)
	now := created.Add(71 * time.Hour)
	job := &ApprovalExpiryJob{Actions: store, Audit: audit, TTL: 72 * time.Hour, Now: func() time.Time { return now }}
	// Move the decided rows far into the past: they must still be untouched.
	later := &ApprovalExpiryJob{Actions: store, Audit: audit, TTL: time.Hour, Now: func() time.Time { return created.Add(200 * time.Hour) }}
	if n, _ := job.RunOnce(ctx); n != 0 {
		t.Fatalf("71h-old expired: %d", n)
	}
	if n, _ := later.RunOnce(ctx); n != 1 { // only the still-pending fresh row
		t.Fatalf("expected only the pending row to expire, got %d", n)
	}
	if audit.count("action.expire", AuditOutcomeSuccess) != 1 {
		t.Fatalf("decided rows re-audited: %+v", audit.entries)
	}
	if g, _, _ := store.Get(ctx, approved.ID); g.Status != "approved" {
		t.Fatalf("approved changed: %s", g.Status)
	}
	if g, _, _ := store.Get(ctx, rejected.ID); g.ApprovedBy != "someone" {
		t.Fatalf("rejected re-decided: %s", g.ApprovedBy)
	}
}

func TestExpiryNotifiesProposerAndApprovers(t *testing.T) {
	store := newTestPendingStore(t)
	audit := &expiryAudit{}
	n := &fakeExpiryNotifier{}
	a := seedAction(t, store, "proposer-x")
	created, _ := time.Parse(time.RFC3339, a.CreatedAt)
	job := &ApprovalExpiryJob{Actions: store, Audit: audit, Notifier: n, TTL: time.Hour, Now: func() time.Time { return created.Add(2 * time.Hour) }}
	if _, err := job.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(n.got) != 1 {
		t.Fatalf("notifications = %d", len(n.got))
	}
	ev := n.got[0]
	if ev.Proposer != "proposer-x" || ev.Tenant != "acme" || ev.ID != a.ID || ev.Kind != "pending_action" {
		t.Fatalf("event = %+v", ev)
	}
	roles := map[string]bool{}
	for _, r := range ev.ApproverRoles {
		roles[r] = true
	}
	if !roles["pki-admin"] || !roles["pki-operator"] {
		t.Fatalf("roles = %v", ev.ApproverRoles)
	}
	if audit.count("approval.expired", AuditOutcomeSuccess) != 1 {
		t.Fatalf("missing approval.expired: %+v", audit.entries)
	}
}

func TestExpiryWithinOneMinute(t *testing.T) {
	if approvalExpiryInterval > 30*time.Second {
		t.Fatalf("interval %v exceeds 30s", approvalExpiryInterval)
	}
	store := newTestPendingStore(t)
	a := seedAction(t, store, "p")
	created, _ := time.Parse(time.RFC3339, a.CreatedAt)
	var past atomic.Bool
	now := func() time.Time {
		if past.Load() {
			return created.Add(2 * time.Hour)
		}
		return created
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	job := &ApprovalExpiryJob{Actions: store, Audit: &expiryAudit{}, TTL: time.Hour, Now: now, Interval: 10 * time.Millisecond}
	job.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	if g, _, _ := store.Get(ctx, a.ID); g.Status != "pending" {
		t.Fatalf("expired early: %s", g.Status)
	}
	past.Store(true)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if g, _, _ := store.Get(ctx, a.ID); g.Status == "rejected" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("not expired within 1s")
}

func expiryActionMux(t *testing.T, store PendingActionStore, ran *atomic.Bool) (*http.ServeMux, *Authenticator) {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	execs := map[string]ActionExecutor{"revoke": func(context.Context, PendingAction, AuthPrincipal) (json.RawMessage, error) {
		ran.Store(true)
		return json.RawMessage(`{}`), nil
	}}
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, store, stubAuditProvider{}, execs)
	return mux, auth
}

func TestExpiredActionCannotBeApproved(t *testing.T) {
	store := newTestPendingStore(t)
	var ran atomic.Bool
	mux, auth := expiryActionMux(t, store, &ran)
	a := seedAction(t, store, "mcp:agent")
	created, _ := time.Parse(time.RFC3339, a.CreatedAt)
	job := &ApprovalExpiryJob{Actions: store, TTL: time.Hour, Now: func() time.Time { return created.Add(2 * time.Hour) }}
	if n, _ := job.RunOnce(context.Background()); n != 1 {
		t.Fatalf("expired %d", n)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, auth, "approver-one", ""), http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ran.Load() {
		t.Fatal("executor ran for an expired action")
	}
}

type foundTemplateProvider struct{ stubTemplateProvider }

func (foundTemplateProvider) GetTemplate(context.Context, string) (TemplateItem, bool, error) {
	return TemplateItem{ID: "tpl"}, true, nil
}

func TestExpiredApprovalRequestCannotBeApproved(t *testing.T) {
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	store := newTestApprovalStore(t)
	mux := http.NewServeMux()
	registerApprovalHandlers(mux, auth, store, &reportCertProvider{}, foundTemplateProvider{}, stubAuditProvider{})
	reqAt := time.Now().UTC().Add(-100 * time.Hour)
	if err := store.Create(context.Background(), ApprovalRequest{ID: "apr-old", TemplateID: "tpl", CAID: "ca", Requester: "requester", RequestedAt: reqAt.Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	audit := &expiryAudit{}
	job := &ApprovalExpiryJob{Actions: nil, Approvals: store, Audit: audit, TTL: 72 * time.Hour}
	if n, err := job.RunOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("RunOnce = %d, %v", n, err)
	}
	if audit.count("approval.expire", AuditOutcomeSuccess) != 1 {
		t.Fatalf("audit: %+v", audit.entries)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, auth, "approver-one", ""), http.MethodPost, "/api/v1/approvals/apr-old/approve", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got, _ := store.Get(context.Background(), "apr-old")
	if got.Status != "rejected" || got.DecidedBy == nil || *got.DecidedBy != expirySweeper {
		t.Fatalf("row = %+v", got)
	}
}

func TestExpiryRacesApproverClaim(t *testing.T) {
	store := newTestPendingStore(t)
	audit := &expiryAudit{}
	a := seedAction(t, store, "p")
	if err := store.Decide(context.Background(), a.ID, statusExecuting, "approver", nil); err != nil {
		t.Fatal(err)
	}
	created, _ := time.Parse(time.RFC3339, a.CreatedAt)
	job := &ApprovalExpiryJob{Actions: store, Audit: audit, TTL: time.Hour, Now: func() time.Time { return created.Add(5 * time.Hour) }}
	// The executing row is no longer listed as pending, and Decide(rejected)
	// is pending-guarded, so the expiry cannot steal it.
	if n, _ := job.RunOnce(context.Background()); n != 0 {
		t.Fatalf("expired a claimed row: %d", n)
	}
	if g, _, _ := store.Get(context.Background(), a.ID); g.Status != statusExecuting {
		t.Fatalf("status = %s", g.Status)
	}
	if len(audit.entries) != 0 {
		t.Fatalf("audit rows written: %+v", audit.entries)
	}
}

func TestExpiryApprovalsStoreNil(t *testing.T) {
	job := &ApprovalExpiryJob{Actions: newTestPendingStore(t), Approvals: nil, TTL: time.Hour}
	if _, err := job.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestExpiryAuditCarriesCATenant: the certificate-approval expiry rows must be
// stamped with the CA's tenant, not the default tenant, including when the
// sweeper is built the way production builds it (before any handler has
// registered a tenant store).
func TestExpiryAuditCarriesCATenant(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv(dbModeEnv, dbModeSQLite)
	t.Setenv("APP_AUDIT_DB_DSN", "")
	ctx := context.Background()
	tenants := NewTenantStoreFromEnv()
	if tenants == nil {
		t.Fatal("tenant store unavailable")
	}
	if _, err := tenants.CreateTenant(ctx, "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	if err := tenants.SetCATenant(ctx, "ca-acme", "acme"); err != nil {
		t.Fatal(err)
	}
	approvals, err := newApprovalStoreFromEnv()
	if err != nil || approvals == nil {
		t.Fatalf("approval store: %v", err)
	}
	old := time.Now().UTC().Add(-100 * time.Hour).Format(time.RFC3339)
	for _, r := range []ApprovalRequest{
		{ID: "apr-acme", TemplateID: "tpl", CAID: "ca-acme", Requester: "r", RequestedAt: old},
		{ID: "apr-unmapped", TemplateID: "tpl", CAID: "ca-none", Requester: "r", RequestedAt: old},
	} {
		if err := approvals.Create(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	audit := &expiryAudit{}
	job := newApprovalExpiryJob(audit)
	if job == nil || job.Tenants == nil {
		t.Fatalf("job must carry a tenant store: %+v", job)
	}
	if n, err := job.RunOnce(ctx); err != nil || n != 2 {
		t.Fatalf("RunOnce = %d, %v", n, err)
	}
	for _, e := range audit.entries {
		want := DefaultTenant
		if e.ResourceID == "apr-acme" {
			want = "acme"
		}
		if e.Tenant != want {
			t.Errorf("%s on %s: tenant %q, want %q", e.Action, e.ResourceID, e.Tenant, want)
		}
	}
}
