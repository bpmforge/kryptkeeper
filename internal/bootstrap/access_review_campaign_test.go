// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// recUserProvider records mutating calls so tests can prove a decision did (or
// did not) reach the provider.
type recUserProvider struct {
	stubUserProvider
	mu    sync.Mutex
	calls []string
}

func (p *recUserProvider) UpdateUser(ctx context.Context, id, role, status string) (UserRecord, error) {
	p.mu.Lock()
	p.calls = append(p.calls, id+"|"+role+"|"+status)
	p.mu.Unlock()
	return p.stubUserProvider.UpdateUser(ctx, id, role, status)
}

func (p *recUserProvider) callList() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

type campaignEnv struct {
	t       *testing.T
	mux     *http.ServeMux
	auth    *Authenticator
	users   *recUserProvider
	audit   *memAuditProvider
	store   accessReviewStore
	alice   string // tokens of two distinct named admins
	bob     string
	kid     string // a minted viewer key
	keyTok  string
	clock   *time.Time
	handler *accessReviewCampaignAPI
}

func newCampaignEnv(t *testing.T, store accessReviewStore) *campaignEnv {
	t.Helper()
	auth := newARAuth(t)
	e := &campaignEnv{t: t, auth: auth, audit: &memAuditProvider{}, store: store}
	e.alice = mintAdminToken(t, auth, "alice", "alice")
	e.bob = mintAdminToken(t, auth, "bob", "bob")
	rec, tok, err := auth.CreateAPIKeyAs("alice", "svc", "svc-p", "viewer", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.kid, e.keyTok = rec.Kid, tok
	e.users = &recUserProvider{stubUserProvider: stubUserProvider{users: []UserRecord{
		{ID: "op1", Email: "op@x", Role: "pki-operator", Status: "active", CreatedAt: "2026-01-01T00:00:00Z"},
		{ID: "v1", Email: "v@x", Role: "viewer", Status: "active", CreatedAt: "2026-01-01T00:00:00Z"},
		{ID: "scim1", Email: "s@x", Role: "viewer", Status: "active", CreatedAt: "2026-01-01T00:00:00Z"},
	}}}
	e.audit.entries = append(e.audit.entries, AuditEntry{Timestamp: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), Action: "scim.users.create", ResourceID: "scim1", Outcome: AuditOutcomeSuccess})
	now := time.Now().UTC()
	e.clock = &now
	e.handler = &accessReviewCampaignAPI{auth: auth, users: e.users, roles: nil, store: store, audit: e.audit, now: func() time.Time { return *e.clock }}
	e.mux = http.NewServeMux()
	registerAccessReviewCampaignHandlersAt(e.mux, e.handler)
	return e
}

func (e *campaignEnv) do(tok, method, path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(tok, method, accessReviewCampaignsPath+path, raw))
	return rec
}

func (e *campaignEnv) open(tok string) AccessReviewCampaign {
	e.t.Helper()
	rec := e.do(tok, http.MethodPost, "", map[string]any{"name": "Q4 recert"})
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("open = %d %s", rec.Code, rec.Body)
	}
	return decodeCampaign(e.t, rec)
}

func decodeCampaign(t *testing.T, rec *httptest.ResponseRecorder) AccessReviewCampaign {
	t.Helper()
	var resp struct {
		Data AccessReviewCampaign `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v: %s", err, rec.Body)
	}
	return resp.Data
}

func (e *campaignEnv) decide(tok, camp, entry, decision, role string) *httptest.ResponseRecorder {
	return e.do(tok, http.MethodPost, "/"+camp+"/decisions", map[string]any{"entry_id": entry, "decision": decision, "new_role": role})
}

func (e *campaignEnv) decideAll(tok string, c AccessReviewCampaign) {
	e.t.Helper()
	for _, en := range c.Entries {
		if rec := e.decide(tok, c.ID, en.EntryID, "keep", ""); rec.Code != 200 {
			e.t.Fatalf("keep %s = %d %s", en.EntryID, rec.Code, rec.Body)
		}
	}
}

func TestCampaignOpenSnapshotsPrincipals(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	// 3 users + alice-key, bob-key, svc-key.
	if len(c.Entries) != 6 || c.Status != campaignOpen {
		t.Fatalf("entries=%d status=%s", len(c.Entries), c.Status)
	}
	for _, en := range c.Entries {
		if en.EntryID != en.Kind+":"+en.ID || en.DecisionStatus != "undecided" {
			t.Errorf("entry %+v", en)
		}
	}
	if len(e.audit.actions("access_review.open")) != 1 {
		t.Error("access_review.open not audited")
	}
	if rec := e.do(e.keyTok, http.MethodPost, "", map[string]any{"name": "x"}); rec.Code != http.StatusForbidden {
		t.Errorf("viewer open = %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodPost, "", map[string]any{"name": " "}); rec.Code != http.StatusBadRequest {
		t.Errorf("blank name = %d", rec.Code)
	}
}

func TestCampaignRevokeKeyCallsRevoke(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	if _, err := e.auth.AuthenticatePrincipalDetails(bearerReq(e.keyTok, "GET", "/", nil), time.Now()); err != nil {
		t.Fatalf("key should authenticate before revoke: %v", err)
	}
	rec := e.decide(e.alice, c.ID, "api_key:"+e.kid, "revoke", "")
	if rec.Code != 200 {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if _, err := e.auth.AuthenticatePrincipalDetails(bearerReq(e.keyTok, "GET", "/", nil), time.Now()); err == nil {
		t.Fatal("revoked key still authenticates")
	}
	got := decodeCampaign(t, e.do(e.alice, http.MethodGet, "/"+c.ID, nil))
	for _, en := range got.Entries {
		if en.EntryID == "api_key:"+e.kid && (!en.Executed || en.DecisionStatus != "decided") {
			t.Errorf("entry not executed: %+v", en)
		}
	}
	if len(e.audit.actions("api-key.delete")) != 1 {
		t.Error("side-effect row api-key.delete missing")
	}
	// Keys cannot be modified.
	if rec := e.decide(e.alice, c.ID, "api_key:"+e.kid, "modify", "viewer"); rec.Code != 400 {
		t.Errorf("modify key = %d", rec.Code)
	}
}

func TestCampaignModifyUserRole(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	if rec := e.decide(e.alice, c.ID, "user:v1", "modify", ""); rec.Code != 400 {
		t.Fatalf("modify without role = %d", rec.Code)
	}
	if rec := e.decide(e.alice, c.ID, "user:v1", "modify", "no-such-role"); rec.Code != 400 {
		t.Fatalf("modify unknown role = %d %s", rec.Code, rec.Body)
	}
	if len(e.users.callList()) != 0 {
		t.Fatalf("rejected decision reached the provider: %v", e.users.callList())
	}
	if rec := e.decide(e.alice, c.ID, "user:v1", "modify", "auditor"); rec.Code != 200 {
		t.Fatalf("modify = %d %s", rec.Code, rec.Body)
	}
	if calls := e.users.callList(); len(calls) != 1 || calls[0] != "v1|auditor|" {
		t.Fatalf("calls = %v", calls)
	}
	var ok int
	for _, a := range e.audit.actions("users.update") {
		if a.Outcome == AuditOutcomeSuccess {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("users.update success rows = %d, want 1", ok)
	}
}

func TestCampaignRevokeUserDeactivates(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	if rec := e.decide(e.alice, c.ID, "user:v1", "revoke", ""); rec.Code != 200 {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if calls := e.users.callList(); len(calls) != 1 || calls[0] != "v1||deactivated" {
		t.Fatalf("calls = %v", calls)
	}
	// Executed entries cannot be re-decided.
	if rec := e.decide(e.alice, c.ID, "user:v1", "keep", ""); rec.Code != 409 {
		t.Errorf("re-decide = %d", rec.Code)
	}
	if rec := e.decide(e.alice, c.ID, "user:nobody", "keep", ""); rec.Code != 404 {
		t.Errorf("unknown entry = %d", rec.Code)
	}
	if rec := e.decide(e.alice, c.ID, "user:op1", "bogus", ""); rec.Code != 400 {
		t.Errorf("bad decision = %d", rec.Code)
	}
}

func TestCampaignRevokeApproverNeedsSecondReviewer(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	rec := e.decide(e.alice, c.ID, "user:op1", "revoke", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first revoke = %d %s", rec.Code, rec.Body)
	}
	if len(e.users.callList()) != 0 {
		t.Fatal("first reviewer executed an approver revoke alone")
	}
	if rec := e.decide(e.alice, c.ID, "user:op1", "revoke", ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgSelfApproval) {
		t.Fatalf("same human = %d %s", rec.Code, rec.Body)
	}
	// A key minted by alice is still alice.
	if rec := e.decide(e.keyTok, c.ID, "user:op1", "revoke", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer key = %d", rec.Code)
	}
	aliceKey2 := mintAdminToken(t, e.auth, "alice-ci", "alice")
	if rec := e.decide(aliceKey2, c.ID, "user:op1", "revoke", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("alice's other key as second reviewer = %d %s", rec.Code, rec.Body)
	}
	if rec := e.decide("reports-test-token", c.ID, "user:op1", "revoke", ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "bootstrap") {
		t.Fatalf("bootstrap second reviewer = %d %s", rec.Code, rec.Body)
	}
	if len(e.users.callList()) != 0 {
		t.Fatal("refused second reviews still executed")
	}
	rec = e.decide(e.bob, c.ID, "user:op1", "revoke", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("second reviewer = %d %s", rec.Code, rec.Body)
	}
	if calls := e.users.callList(); len(calls) != 1 || calls[0] != "op1||deactivated" {
		t.Fatalf("calls = %v", calls)
	}
	got := decodeCampaign(t, e.do(e.alice, http.MethodGet, "/"+c.ID, nil))
	for _, en := range got.Entries {
		if en.EntryID == "user:op1" && (!en.Executed || en.SecondReviewer != "bob" || en.DecidedBy != "alice") {
			t.Errorf("entry = %+v", en)
		}
	}
}

func TestCampaignHeldRevokeCountsUndecidedAndCanBeWithdrawn(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	e.decide(e.alice, c.ID, "user:op1", "revoke", "")
	// Everything else decided; the held revoke still blocks close.
	for _, en := range c.Entries {
		if en.EntryID != "user:op1" {
			e.decide(e.alice, c.ID, en.EntryID, "keep", "")
		}
	}
	if rec := e.do(e.alice, http.MethodPost, "/"+c.ID+"/close", map[string]any{}); rec.Code != 409 || !strings.Contains(rec.Body.String(), "1 entries undecided") {
		t.Fatalf("close with held revoke = %d %s", rec.Code, rec.Body)
	}
	// Bob disagrees: keep replaces the held revoke and nothing is executed.
	if rec := e.decide(e.bob, c.ID, "user:op1", "keep", ""); rec.Code != 200 {
		t.Fatalf("keep over held = %d %s", rec.Code, rec.Body)
	}
	if len(e.users.callList()) != 0 {
		t.Fatal("withdrawn revoke executed")
	}
	if rec := e.do(e.alice, http.MethodPost, "/"+c.ID+"/close", map[string]any{}); rec.Code != 200 {
		t.Fatalf("close = %d %s", rec.Code, rec.Body)
	}
}

func TestCampaignScimUsersReadOnly(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	for _, d := range []string{"revoke", "modify"} {
		if rec := e.decide(e.alice, c.ID, "user:scim1", d, "auditor"); rec.Code != 409 {
			t.Errorf("%s scim user = %d %s", d, rec.Code, rec.Body)
		}
	}
	if len(e.users.callList()) != 0 {
		t.Fatalf("provider touched: %v", e.users.callList())
	}
	if rec := e.decide(e.alice, c.ID, "user:scim1", "keep", ""); rec.Code != 200 {
		t.Fatalf("keep scim = %d %s", rec.Code, rec.Body)
	}
}

func TestCampaignCloseRecordsExportHash(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	e.decideAll(e.alice, c)
	rec := e.do(e.alice, http.MethodPost, "/"+c.ID+"/close", map[string]any{})
	if rec.Code != 200 {
		t.Fatalf("close = %d %s", rec.Code, rec.Body)
	}
	closed := decodeCampaign(t, rec)
	rows := e.audit.actions("access_review.close")
	if len(rows) != 1 || closed.Status != campaignClosed {
		t.Fatalf("close rows=%d status=%s", len(rows), closed.Status)
	}
	exp1 := e.do(e.alice, http.MethodGet, "/"+c.ID+"/export?format=csv", nil)
	exp2 := e.do(e.alice, http.MethodGet, "/"+c.ID+"/export?format=csv", nil)
	if exp1.Code != 200 || !strings.HasPrefix(exp1.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export = %d %s", exp1.Code, exp1.Header())
	}
	if !bytes.Equal(exp1.Body.Bytes(), exp2.Body.Bytes()) {
		t.Fatal("export is not byte-stable")
	}
	sum := sha256.Sum256(exp1.Body.Bytes())
	want := hex.EncodeToString(sum[:])
	if !strings.Contains(rows[0].ChangeSummary, "sha256="+want) || closed.ReportSHA256 != want {
		t.Fatalf("audit %q / report %q do not carry sha256=%s", rows[0].ChangeSummary, closed.ReportSHA256, want)
	}
	if !strings.HasPrefix(exp1.Body.String(), strings.Join(accessReviewCSVHeader, ",")+"\n") {
		t.Fatalf("csv header: %q", strings.SplitN(exp1.Body.String(), "\n", 2)[0])
	}
	if rec := e.do(e.alice, http.MethodGet, "/"+c.ID+"/export?format=pdf", nil); rec.Code != 400 {
		t.Errorf("pdf export = %d", rec.Code)
	}
}

func TestCampaignCloseRefusesUndecided(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	e.decide(e.alice, c.ID, "user:v1", "keep", "")
	rec := e.do(e.alice, http.MethodPost, "/"+c.ID+"/close", map[string]any{})
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "5 entries undecided") {
		t.Fatalf("close = %d %s", rec.Code, rec.Body)
	}
	// The refusal must leave the campaign open for more decisions.
	if rec := e.decide(e.alice, c.ID, "user:scim1", "keep", ""); rec.Code != 200 {
		t.Fatalf("decide after refused close = %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(e.alice, http.MethodPost, "/"+c.ID+"/close", map[string]any{"allow_undecided": true}); rec.Code != 200 {
		t.Fatalf("close allow_undecided = %d %s", rec.Code, rec.Body)
	}
}

func TestCampaignDecideOnClosed409(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	e.do(e.alice, http.MethodPost, "/"+c.ID+"/close", map[string]any{"allow_undecided": true})
	if rec := e.decide(e.alice, c.ID, "user:v1", "keep", ""); rec.Code != 409 {
		t.Fatalf("decide on closed = %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodPost, "/"+c.ID+"/close", map[string]any{"allow_undecided": true}); rec.Code != 409 {
		t.Fatalf("second close = %d", rec.Code)
	}
}

func TestCampaignFailedSideEffectIsRetryable(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	// The key vanished between snapshot and decision.
	if found, _ := e.auth.RevokeAPIKey(e.kid); !found {
		t.Fatal("setup")
	}
	if rec := e.decide(e.alice, c.ID, "api_key:"+e.kid, "revoke", ""); rec.Code != 404 {
		t.Fatalf("revoke gone key = %d", rec.Code)
	}
	if rec := e.decide(e.alice, c.ID, "api_key:"+e.kid, "keep", ""); rec.Code != 200 {
		t.Fatalf("entry should be decidable again, got %d %s", rec.Code, rec.Body)
	}
}

func TestCampaignTenantScoped(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	e := newCampaignEnv(t, newMemAccessReviewStore())
	acmeAdmin := func(name string) string {
		_, tok, err := e.auth.CreateAPIKeyAs(name, name+"-key", name, "pki-admin", []string{"*"}, "", "acme", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	globexAdmin := func(name string) string {
		_, tok, err := e.auth.CreateAPIKeyAs(name, name+"-key", name, "pki-admin", []string{"*"}, "", "globex", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	a, g := acmeAdmin("acme-admin"), globexAdmin("globex-admin")
	e.users.users = append(e.users.users,
		UserRecord{ID: "ua", Email: "ua@acme", Role: "viewer", Status: "active", Tenant: "acme", CreatedAt: "2026-01-01T00:00:00Z"})

	acme := e.open(a)
	for _, en := range acme.Entries {
		if en.Tenant != "acme" {
			t.Fatalf("acme campaign holds %+v", en)
		}
	}
	if acme.Tenant != "acme" {
		t.Fatalf("tenant = %s", acme.Tenant)
	}
	// globex can neither read, list, decide, close nor export acme's campaign.
	for _, tc := range []struct{ method, path string }{
		{"GET", "/" + acme.ID}, {"GET", "/" + acme.ID + "/export"},
		{"POST", "/" + acme.ID + "/close"}, {"POST", "/" + acme.ID + "/decisions"},
	} {
		if rec := e.do(g, tc.method, tc.path, map[string]any{"entry_id": "user:ua", "decision": "revoke"}); rec.Code != 404 {
			t.Errorf("globex %s %s = %d", tc.method, tc.path, rec.Code)
		}
	}
	if len(e.users.callList()) != 0 {
		t.Fatalf("cross-tenant decision reached the provider: %v", e.users.callList())
	}
	list := e.do(g, http.MethodGet, "", nil)
	if strings.Contains(list.Body.String(), acme.ID) {
		t.Fatalf("globex list leaks acme campaign: %s", list.Body)
	}
	// An unscoped super-admin's campaign spans tenants and is global: scoped
	// admins never see it.
	global := e.open("reports-test-token")
	if global.Tenant != campaignGlobalTenant {
		t.Fatalf("global campaign tenant = %s", global.Tenant)
	}
	if rec := e.do(a, http.MethodGet, "/"+global.ID, nil); rec.Code != 404 {
		t.Fatalf("acme read of global campaign = %d", rec.Code)
	}
	if strings.Contains(e.do(a, http.MethodGet, "", nil).Body.String(), global.ID) {
		t.Fatal("acme list leaks global campaign")
	}
	// The super-admin sees both.
	if !strings.Contains(e.do("reports-test-token", http.MethodGet, "", nil).Body.String(), acme.ID) {
		t.Fatal("super-admin cannot list tenant campaign")
	}
}

func TestCampaignUnauthenticatedAndReadGate(t *testing.T) {
	e := newCampaignEnv(t, newMemAccessReviewStore())
	c := e.open(e.alice)
	if rec := e.do("", http.MethodGet, "", nil); rec.Code != 401 {
		t.Errorf("no token = %d", rec.Code)
	}
	if rec := e.do(e.keyTok, http.MethodGet, "/"+c.ID, nil); rec.Code != 403 {
		t.Errorf("viewer read = %d", rec.Code)
	}
}

func TestCampaignStoreRoundTripSQLite(t *testing.T) {
	db := openMigratedKeyDB(t, filepath.Join(t.TempDir(), "k.db"))
	store := &dbAccessReviewStore{db: db, ph: sqlitePlaceholder}
	if err := store.EnsureSchema(context.Background()); err != nil { // coexists with the migration
		t.Fatal(err)
	}
	e := newCampaignEnv(t, store)
	c := e.open(e.alice)
	if rec := e.decide(e.alice, c.ID, "user:v1", "keep", ""); rec.Code != 200 {
		t.Fatalf("keep = %d %s", rec.Code, rec.Body)
	}
	if rec := e.decide(e.alice, c.ID, "user:op1", "revoke", ""); rec.Code != 202 {
		t.Fatalf("hold = %d %s", rec.Code, rec.Body)
	}
	if rec := e.decide(e.bob, c.ID, "user:op1", "revoke", ""); rec.Code != 200 {
		t.Fatalf("second = %d %s", rec.Code, rec.Body)
	}
	// Re-open the store on the same DB: state is durable.
	reopened := &dbAccessReviewStore{db: db, ph: sqlitePlaceholder}
	got, ok, err := reopened.Get(context.Background(), c.ID)
	if err != nil || !ok {
		t.Fatalf("get: %v %v", ok, err)
	}
	if len(got.Snapshot.Principals) != 6 || got.Decisions["user:v1"].Decision != "keep" ||
		got.Decisions["user:op1"].SecondReviewer != "bob" || !got.Decisions["user:op1"].Executed {
		t.Fatalf("round trip lost data: %+v", got.Decisions)
	}
	e.handler.store = reopened
	for _, en := range decodeCampaign(t, e.do(e.alice, http.MethodGet, "/"+c.ID, nil)).Entries {
		if en.DecisionStatus == "undecided" {
			e.decide(e.alice, c.ID, en.EntryID, "keep", "")
		}
	}
	rec := e.do(e.alice, http.MethodPost, "/"+c.ID+"/close", map[string]any{"allow_undecided": true})
	if rec.Code != 200 {
		t.Fatalf("close = %d %s", rec.Code, rec.Body)
	}
	closed, _, _ := reopened.Get(context.Background(), c.ID)
	if closed.Status != campaignClosed || closed.ReportSHA256 == "" {
		t.Fatalf("closed state: %+v", closed.AccessReviewCampaign)
	}
	// Decisions are rejected by the store itself once closed.
	if ok, _ := reopened.InsertDecision(context.Background(), AccessReviewDecision{CampaignID: c.ID, EntryID: "user:zzz", Decision: "keep", DecidedBy: "x"}); ok {
		t.Fatal("store accepted a decision on a closed campaign")
	}
}
