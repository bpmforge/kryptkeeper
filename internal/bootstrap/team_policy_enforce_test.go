// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
)

// enforceTemplates is a one-map TemplateProvider.
type enforceTemplates struct {
	TemplateProvider
	mu   sync.Mutex
	tpls map[string]TemplateItem
	err  error
}

func (p *enforceTemplates) GetTemplate(_ context.Context, id string) (TemplateItem, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return TemplateItem{}, false, p.err
	}
	t, ok := p.tpls[id]
	return t, ok, nil
}

func (p *enforceTemplates) set(t TemplateItem) {
	p.mu.Lock()
	p.tpls[t.ID] = t
	p.mu.Unlock()
}

// enforceCerts counts issuance attempts and can fail or demand approval.
type enforceCerts struct {
	CertificateProvider
	calls     atomic.Int64
	failWith  error
	needsAppr bool
}

func (c *enforceCerts) IssueCertificate(ctx context.Context, req CertificateIssueRequest) (CertificateIssueResult, error) {
	c.calls.Add(1)
	if c.needsAppr && ctx.Value(approvalBypassKey{}) == nil {
		return CertificateIssueResult{}, errApprovalRequired
	}
	if c.failWith != nil {
		return CertificateIssueResult{}, c.failWith
	}
	var r CertificateIssueResult
	r.FingerprintSHA256 = "fp-" + req.TeamID
	r.CommonName = "issued"
	return r, nil
}

type enforceRig struct {
	mux       *http.ServeMux
	auth      *Authenticator
	audit     *recordingAuditProvider
	policies  *dbTeamPolicyStore
	enf       *teamPolicyEnforcer
	templates *enforceTemplates
	certs     *enforceCerts
	approvals *sqliteApprovalStore
	now       atomic.Int64
}

func newEnforceRig(t *testing.T) *enforceRig {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("MULTI_TENANCY", "off")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "enf.db")+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	g := &enforceRig{
		mux: http.NewServeMux(), auth: NewAuthenticatorFromEnv(), audit: &recordingAuditProvider{},
		policies:  newDBTeamPolicyStore(db, false),
		templates: &enforceTemplates{tpls: map[string]TemplateItem{"tpl": {ID: "tpl", ValidityPeriod: "P30D"}}},
		certs:     &enforceCerts{},
	}
	g.now.Store(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC).UnixNano())
	g.enf = &teamPolicyEnforcer{
		policies: g.policies, templates: g.templates, counters: newTeamCounterStore(db, false),
		now: func() time.Time { return time.Unix(0, g.now.Load()).UTC() },
	}
	if err := g.enf.counters.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.approvals = &sqliteApprovalStore{db: db}
	if err := g.approvals.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	activeTeamEnforcer = g.enf
	t.Cleanup(func() { activeTeamEnforcer = nil })
	registerCertificateHandlers(g.mux, g.auth, g.certs, g.audit, g.approvals)
	return g
}

func (g *enforceRig) setNow(ts time.Time) { g.now.Store(ts.UnixNano()) }

func (g *enforceRig) policy(t *testing.T, mut func(*TeamPolicy)) {
	t.Helper()
	p := TeamPolicy{
		Tenant: DefaultTenant, Team: "team-a", AllowedCAs: []string{"ca-1"}, AllowedTemplates: []string{"tpl"},
		AllowedDNSSuffixes: []string{"corp.example"}, MaxValidityDays: 90, MonthlyQuota: 10,
	}
	if mut != nil {
		mut(&p)
	}
	if _, err := g.policies.Put(context.Background(), p, 0, "test"); err != nil {
		t.Fatal(err)
	}
}

func testCSR(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func (g *enforceRig) issueBody(t *testing.T, ca, tpl string, csr string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"ca_id": ca, "template_id": tpl, "csr_pem": csr, "team_id": "team-a"})
	return string(b)
}

func (g *enforceRig) post(body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	g.mux.ServeHTTP(rec, req)
	return rec
}

func (g *enforceRig) goodIssue(t *testing.T) *httptest.ResponseRecorder {
	return g.post(g.issueBody(t, "ca-1", "tpl", testCSR(t, "a.corp.example", "a.corp.example")))
}

// wantDenied asserts a 403 carrying code, a specific message, and a denied audit row.
func (g *enforceRig) wantDenied(t *testing.T, rec *httptest.ResponseRecorder, code, msgPart string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", rec.Code, rec.Body.String())
	}
	var b struct{ Error, ErrorCode, Message string }
	var raw map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	b.Error, b.ErrorCode, b.Message = raw["error"], raw["error_code"], raw["message"]
	if b.Error != "forbidden" || b.ErrorCode != code || !strings.Contains(b.Message, msgPart) {
		t.Fatalf("body %v, want error_code %q and message containing %q", raw, code, msgPart)
	}
	g.audit.mu.Lock()
	defer g.audit.mu.Unlock()
	for _, e := range g.audit.entries {
		if e.Outcome == AuditOutcomeDenied && strings.Contains(e.ChangeSummary, code) {
			return
		}
	}
	t.Fatalf("no denied audit row mentioning %q: %+v", code, g.audit.entries)
}

func TestEnforce_CANotInAllowList_403WithCode(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, nil)
	g.wantDenied(t, g.post(g.issueBody(t, "ca-other", "tpl", testCSR(t, "a.corp.example"))), CodeTeamCANotAllowed, "does not allow requests from this CA")
	if g.certs.calls.Load() != 0 {
		t.Fatal("provider must not run on a refusal")
	}
}

func TestEnforce_TemplateNotAllowed(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, nil)
	g.wantDenied(t, g.post(g.issueBody(t, "ca-1", "tpl-x", testCSR(t, "a.corp.example"))), CodeTeamTemplateNotAllowed, "does not allow this template")
}

func TestEnforce_NameOutsideSuffixes(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, nil)
	g.wantDenied(t, g.post(g.issueBody(t, "ca-1", "tpl", testCSR(t, "a.corp.example", "evil.example.org"))), CodeTeamNameNotAllowed, `"evil.example.org" is outside your team's allowed domains`)
}

func TestEnforce_UnparseableCSRRefused(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, nil)
	g.wantDenied(t, g.post(g.issueBody(t, "ca-1", "tpl", "not a csr")), CodeTeamNameNotAllowed, "could not be read")
}

func TestEnforce_ValidityExceeded(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MaxValidityDays = 7 })
	g.wantDenied(t, g.goodIssue(t), CodeTeamValidityExceeded, "maximum of 7 days")
}

func TestEnforce_NoPolicy_Unrestricted(t *testing.T) {
	g := newEnforceRig(t) // D-195: an absent policy means unrestricted
	for i := 0; i < 3; i++ {
		if rec := g.goodIssue(t); rec.Code != http.StatusCreated {
			t.Fatalf("no policy must issue: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestEnforce_EmptyListsAndZeroCap_Unrestricted(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) {
		p.AllowedCAs, p.AllowedTemplates, p.AllowedDNSSuffixes, p.AllowedDNSNames = nil, nil, nil, nil
		p.MaxValidityDays, p.MonthlyQuota = 0, 0
	})
	if rec := g.post(g.issueBody(t, "any-ca", "tpl", testCSR(t, "x.anywhere.example", "y.other.org"))); rec.Code != http.StatusCreated {
		t.Fatalf("empty axes must not restrict: %d %s", rec.Code, rec.Body.String())
	}
}

func TestEnforce_AllowedIssues(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, nil)
	if rec := g.goodIssue(t); rec.Code != http.StatusCreated {
		t.Fatalf("allowed request: %d %s", rec.Code, rec.Body.String())
	}
}

func TestEnforce_FailClosed(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, nil)
	g.templates.err = errors.New("template backend down")
	if rec := g.goodIssue(t); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("template lookup error must refuse: %d %s", rec.Code, rec.Body.String())
	}
	g.templates.err = nil
	g.enf.counters.db.Close() // counter and policy store now error
	if rec := g.goodIssue(t); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("store error must refuse: %d %s", rec.Code, rec.Body.String())
	}
	if g.certs.calls.Load() != 0 {
		t.Fatal("issuance ran despite an enforcement error")
	}
	// A DB-backed server whose policy store failed to initialise refuses too.
	activeTeamEnforcer = &teamPolicyEnforcer{}
	if rec := g.goodIssue(t); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil stores must refuse: %d %s", rec.Code, rec.Body.String())
	}
}

func TestQuota_NPlus1Blocked(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MonthlyQuota = 3 })
	for i := 0; i < 3; i++ {
		if rec := g.goodIssue(t); rec.Code != http.StatusCreated {
			t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := g.goodIssue(t)
	g.wantDenied(t, rec, CodeTeamQuotaExceeded, "monthly certificate quota of 3 reached; resets 2026-11-01")
	g.audit.mu.Lock()
	defer g.audit.mu.Unlock()
	for _, e := range g.audit.entries {
		if e.Action == "request.quota_exceeded" && e.ResourceType == "team" && e.ResourceID == "team-a" && e.Outcome == AuditOutcomeDenied &&
			strings.Contains(e.ChangeSummary, `"limit":3`) && strings.Contains(e.ChangeSummary, `"period":"2026-10"`) {
			return
		}
	}
	t.Fatalf("no request.quota_exceeded audit row: %+v", g.audit.entries)
}

func TestQuota_ZeroMeansUnlimited(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MonthlyQuota = 0 })
	for i := 0; i < 5; i++ {
		if rec := g.goodIssue(t); rec.Code != http.StatusCreated {
			t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	used, limit, _, err := g.enf.Usage(context.Background(), DefaultTenant, "team-a")
	if err != nil || used != 0 || limit != 0 {
		t.Fatalf("unlimited must not count: used=%d limit=%d err=%v", used, limit, err)
	}
}

func TestQuota_UTCMonthBoundary(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MonthlyQuota = 1 })
	g.setNow(time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC))
	if rec := g.goodIssue(t); rec.Code != http.StatusCreated {
		t.Fatalf("first: %d", rec.Code)
	}
	g.wantDenied(t, g.goodIssue(t), CodeTeamQuotaExceeded, "resets 2026-11-01")
	g.setNow(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if rec := g.goodIssue(t); rec.Code != http.StatusCreated {
		t.Fatalf("new month must reset: %d %s", rec.Code, rec.Body.String())
	}
}

func TestQuota_ReleasedOnIssueFailure(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MonthlyQuota = 1 })
	g.certs.failWith = errors.New("ca unavailable")
	if rec := g.goodIssue(t); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("provider failure: %d", rec.Code)
	}
	used, _, _, _ := g.enf.Usage(context.Background(), DefaultTenant, "team-a")
	if used != 0 {
		t.Fatalf("slot not released after failure: used=%d", used)
	}
	g.certs.failWith = nil
	if rec := g.goodIssue(t); rec.Code != http.StatusCreated {
		t.Fatalf("slot should be free: %d", rec.Code)
	}

	// Approval-pending keeps its reservation.
	g2 := newEnforceRig(t)
	g2.policy(t, func(p *TeamPolicy) { p.MonthlyQuota = 1 })
	g2.certs.needsAppr = true
	if rec := g2.goodIssue(t); rec.Code != http.StatusAccepted {
		t.Fatalf("approval-required: %d %s", rec.Code, rec.Body.String())
	}
	if used, _, _, _ := g2.enf.Usage(context.Background(), DefaultTenant, "team-a"); used != 1 {
		t.Fatalf("pending approval must hold the slot: used=%d", used)
	}
	g2.wantDenied(t, g2.post(g2.issueBody(t, "ca-1", "tpl", testCSR(t, "b.corp.example", "b.corp.example"))), CodeTeamQuotaExceeded, "quota")
}

func TestQuota_ConcurrentReserve(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MonthlyQuota = 5 })
	var wg sync.WaitGroup
	var ok, denied, errs atomic.Int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, d, err := g.enf.Reserve(context.Background(), DefaultTenant, "team-a")
			switch {
			case err != nil:
				errs.Add(1)
			case d != nil && d.Code == CodeTeamQuotaExceeded:
				denied.Add(1)
			case res != nil:
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 5 || denied.Load() != 15 || errs.Load() != 0 {
		t.Fatalf("ok=%d denied=%d errs=%d, want 5/15/0", ok.Load(), denied.Load(), errs.Load())
	}
	if used, _, _, _ := g.enf.Usage(context.Background(), DefaultTenant, "team-a"); used != 5 {
		t.Fatalf("used=%d, want 5", used)
	}
}

func TestQuotaEndpoint_ShapeAndWarn(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MonthlyQuota = 10 })
	get := func() map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/quota?team_id=team-a", nil)
		req.Header.Set("Authorization", "Bearer root-token")
		rec := httptest.NewRecorder()
		g.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("quota: %d %s", rec.Code, rec.Body.String())
		}
		var out struct{ Data map[string]any }
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	for i := 0; i < 7; i++ {
		g.goodIssue(t)
	}
	if d := get(); d["warn"] != false || d["used"] != float64(7) || d["remaining"] != float64(3) || d["limit"] != float64(10) || d["period"] != "2026-10" || d["resets_at"] != "2026-11-01T00:00:00Z" {
		t.Fatalf("at 70%%: %v", d)
	}
	g.goodIssue(t)
	if d := get(); d["warn"] != true || d["used"] != float64(8) {
		t.Fatalf("at 80%% warn must be true: %v", d)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/quota?team_id=team-a", nil)
	rec := httptest.NewRecorder()
	g.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
}

func TestApprove_ReevaluatesPolicy_TemplateChanged(t *testing.T) {
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MaxValidityDays = 90 })
	g.templates.set(TemplateItem{ID: "tpl", ValidityPeriod: "P30D", ApprovalRoles: []string{"pki-admin"}})
	g.certs.needsAppr = true
	if rec := g.goodIssue(t); rec.Code != http.StatusAccepted {
		t.Fatalf("file request: %d %s", rec.Code, rec.Body.String())
	}
	list, _, err := g.approvals.List(context.Background(), "pending", 10, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("pending list: %v %v", list, err)
	}
	id := list[0].ID
	// The template grows past the team cap between request and approval.
	g.templates.set(TemplateItem{ID: "tpl", ValidityPeriod: "P365D", ApprovalRoles: []string{"pki-admin"}})

	approve := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+id+"/approve", nil)
		rec := httptest.NewRecorder()
		handleApprove(rec, req, g.auth, AuthPrincipal{ID: "approver-1", Role: "pki-admin"}, id, g.approvals, g.certs, g.templates, g.audit)
		return rec
	}
	before := g.certs.calls.Load()
	g.wantDenied(t, approve(), CodeTeamValidityExceeded, "maximum of 90 days")
	if got, _ := g.approvals.Get(context.Background(), id); got.Status != "pending" {
		t.Fatalf("denied approval must stay pending, got %q", got.Status)
	}
	if g.certs.calls.Load() != before {
		t.Fatal("issuance ran for a refused approval")
	}
	// Restored: the same approval now goes through.
	g.templates.set(TemplateItem{ID: "tpl", ValidityPeriod: "P30D", ApprovalRoles: []string{"pki-admin"}})
	if rec := approve(); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("approve after restore: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIssue_100AutoApproved_P95Under60s(t *testing.T) {
	if os.Getenv("KRYPTKEEPER_SCALE_TESTS") != "1" {
		t.Skip("nightly-only: set KRYPTKEEPER_SCALE_TESTS=1")
	}
	g := newEnforceRig(t)
	g.policy(t, func(p *TeamPolicy) { p.MonthlyQuota = 1000 })
	csr := testCSR(t, "a.corp.example", "a.corp.example")
	var lat []time.Duration
	issued := 0
	for i := 0; i < 100; i++ {
		start := time.Now()
		if rec := g.post(g.issueBody(t, "ca-1", "tpl", csr)); rec.Code == http.StatusCreated {
			issued++
		}
		lat = append(lat, time.Since(start))
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	if p95 := lat[94]; issued != 100 || p95 >= 60*time.Second {
		t.Fatalf("issued=%d p95=%s", issued, p95)
	}
}
