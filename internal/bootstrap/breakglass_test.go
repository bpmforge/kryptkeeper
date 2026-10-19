// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const bgBootstrapToken = "bootstrap-token-0123456789abcdef0123456789"

// bgEnv wires a break-glass manager over real session tokens (the code under
// test refuses API keys and the bootstrap token, so those paths are real too).
type bgEnv struct {
	t      *testing.T
	auth   *Authenticator
	b      *BreakGlass
	mux    *http.ServeMux
	audit  *memAuditProvider
	clock  time.Time
	mu     sync.Mutex
	alerts []BreakGlassAlert
}

func newBGEnv(t *testing.T, store breakGlassStore) *bgEnv {
	t.Helper()
	e := &bgEnv{t: t, audit: &memAuditProvider{}, clock: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)}
	e.auth = newLoginAuth(apiKeyVerifier("pw", "pepper"),
		UserRecord{ID: "holderA", Email: "a@x", Role: breakGlassRole, Status: "active"},
		UserRecord{ID: "holderB", Email: "b@x", Role: breakGlassRole, Status: "active"},
		UserRecord{ID: "gone", Email: "g@x", Role: breakGlassRole, Status: "deactivated"},
		UserRecord{ID: "adminC", Email: "c@x", Role: "pki-admin", Status: "active"},
		UserRecord{ID: "adminD", Email: "d@x", Role: "pki-admin", Status: "active"},
		UserRecord{ID: "viewerV", Email: "v@x", Role: "viewer", Status: "active"},
	)
	e.auth.config.apiKeyPepper = "test-pepper-32chars-minimum!!!!!"
	e.auth.config.apiKeyAuthEnabled = true
	e.auth.config.apiKeys = map[string]apiKeyRecord{}
	if store == nil {
		store = newMemBreakGlassStore()
	}
	users := e.auth.userProvider
	e.b = NewBreakGlass(store, users, e.auth, e.audit, func() time.Time { return e.clockNow() }, func(a BreakGlassAlert) {
		e.mu.Lock()
		e.alerts = append(e.alerts, a)
		e.mu.Unlock()
	})
	e.mux = http.NewServeMux()
	mountBreakGlass(e.mux, e.b, e.auth)
	return e
}

func (e *bgEnv) clockNow() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *bgEnv) advance(d time.Duration) {
	e.mu.Lock()
	e.clock = e.clock.Add(d)
	e.mu.Unlock()
}

func (e *bgEnv) alertCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.alerts)
}

// token mints a real session for a seeded user.
func (e *bgEnv) token(id string) string {
	e.t.Helper()
	role := ""
	users, _ := e.auth.userProvider.ListUsers(context.Background())
	for _, u := range users {
		if u.ID == id {
			role = u.Role
		}
	}
	tok, _, _, _, err := e.auth.mintSessionForUser(id, role, time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *bgEnv) do(tok, method, path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(tok, method, breakGlassBase+path, raw))
	return rec
}

func bgDecode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var resp struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return resp.Data
}

// activate drives request (holderA) + confirm (holderB) and returns the window.
func (e *bgEnv) activate() BreakGlassActivation {
	e.t.Helper()
	rec := e.do(e.token("holderA"), http.MethodPost, "/activations", map[string]string{"reason": "IdP outage, CA unreachable"})
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("request = %d %s", rec.Code, rec.Body)
	}
	a := bgDecode[BreakGlassActivation](e.t, rec)
	rec = e.do(e.token("holderB"), http.MethodPost, "/activations/"+a.ID+"/confirm", nil)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("confirm = %d %s", rec.Code, rec.Body)
	}
	return bgDecode[BreakGlassActivation](e.t, rec)
}

func useReq() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	return r
}

func TestBreakGlassNeedsTwoDistinctHolders(t *testing.T) {
	e := newBGEnv(t, nil)
	rec := e.do(e.token("holderA"), http.MethodPost, "/activations", map[string]string{"reason": "outage"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("request = %d %s", rec.Code, rec.Body)
	}
	a := bgDecode[BreakGlassActivation](t, rec)
	if a.Status != bgPending {
		t.Fatalf("status = %s", a.Status)
	}
	confirm := func(tok string) *httptest.ResponseRecorder {
		return e.do(tok, http.MethodPost, "/activations/"+a.ID+"/confirm", nil)
	}
	if rec := confirm(e.token("holderA")); rec.Code != 403 || !strings.Contains(rec.Body.String(), msgSelfApproval) {
		t.Fatalf("self confirm = %d %s", rec.Code, rec.Body)
	}
	if rec := confirm(e.token("adminC")); rec.Code != 403 {
		t.Fatalf("non-holder admin confirm = %d", rec.Code)
	}
	// A deactivated holder's still-valid token is refused by the auth layer
	// itself (fail closed), before the holder check even runs.
	if rec := confirm(e.token("gone")); rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("deactivated holder confirm = %d", rec.Code)
	}
	if rec := confirm(bgBootstrapToken); rec.Code != 403 || !strings.Contains(rec.Body.String(), "bootstrap") {
		t.Fatalf("bootstrap confirm = %d %s", rec.Code, rec.Body)
	}
	_, keyTok, err := e.auth.CreateAPIKeyAs("holderB", "bk", "holderB", breakGlassRole, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := confirm(keyTok); rec.Code != 403 {
		t.Fatalf("api-key confirm = %d", rec.Code)
	}
	if _, ok := e.b.Active(context.Background()); ok {
		t.Fatal("refused confirms activated the window")
	}
	rec = confirm(e.token("holderB"))
	if rec.Code != 200 {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body)
	}
	act := bgDecode[BreakGlassActivation](t, rec)
	if act.Status != bgActive || act.ConfirmedBy != "holderB" || act.ExpiresAt != e.clockNow().Add(breakGlassTTL).Format(time.RFC3339) {
		t.Fatalf("activation = %+v", act)
	}
	rows := e.audit.actions("breakglass.activate")
	var okRow *AuditEntry
	for i := range rows {
		if rows[i].Outcome == AuditOutcomeSuccess {
			okRow = &rows[i]
		}
	}
	if okRow == nil || !strings.Contains(okRow.ChangeSummary, "holders=holderA,holderB") {
		t.Fatalf("breakglass.activate success row = %+v", rows)
	}
	if len(e.audit.actions("breakglass.request")) == 0 {
		t.Error("breakglass.request not audited")
	}
	// Requesters must be holders too.
	for _, tok := range []string{e.token("adminC"), e.token("viewerV"), bgBootstrapToken, keyTok} {
		if rec := e.do(tok, http.MethodPost, "/activations", map[string]string{"reason": "x"}); rec.Code != 403 {
			t.Errorf("non-holder request = %d", rec.Code)
		}
	}
	// A second request while one is active is refused.
	if rec := e.do(e.token("holderA"), http.MethodPost, "/activations", map[string]string{"reason": "again"}); rec.Code != 409 {
		t.Errorf("request while active = %d", rec.Code)
	}
	if rec := e.do(e.token("holderA"), http.MethodPost, "/activations", map[string]string{"reason": " "}); rec.Code != 400 && rec.Code != 409 {
		t.Errorf("blank reason = %d", rec.Code)
	}
}

func TestBreakGlassBlankReasonRejected(t *testing.T) {
	e := newBGEnv(t, nil)
	if rec := e.do(e.token("holderA"), http.MethodPost, "/activations", map[string]string{"reason": "  "}); rec.Code != 400 {
		t.Fatalf("blank reason = %d", rec.Code)
	}
}

func TestBreakGlassExpiresAfterFourHours(t *testing.T) {
	e := newBGEnv(t, nil)
	act := e.activate()
	e.advance(4*time.Hour - time.Second)
	if _, ok := e.b.Active(context.Background()); !ok {
		t.Fatal("window closed early")
	}
	e.advance(time.Second)
	if _, ok := e.b.Active(context.Background()); ok {
		t.Fatal("window still open at +4h")
	}
	got, _, _ := e.b.store.GetActivation(context.Background(), act.ID)
	if got.Status != bgExpired {
		t.Fatalf("persisted status = %s", got.Status)
	}
	// An expired window frees the slot.
	if rec := e.do(e.token("holderA"), http.MethodPost, "/activations", map[string]string{"reason": "next"}); rec.Code != http.StatusCreated {
		t.Fatalf("new request after expiry = %d", rec.Code)
	}
}

func TestBreakGlassPendingLapses(t *testing.T) {
	e := newBGEnv(t, nil)
	rec := e.do(e.token("holderA"), http.MethodPost, "/activations", map[string]string{"reason": "outage"})
	a := bgDecode[BreakGlassActivation](t, rec)
	e.advance(breakGlassConfirmWindow + time.Minute)
	rec = e.do(e.token("holderB"), http.MethodPost, "/activations/"+a.ID+"/confirm", nil)
	if rec.Code != http.StatusGone {
		t.Fatalf("late confirm = %d %s", rec.Code, rec.Body)
	}
	got, _, _ := e.b.store.GetActivation(context.Background(), a.ID)
	if got.Status != bgExpired {
		t.Fatalf("status = %s", got.Status)
	}
	if rec := e.do(e.token("holderB"), http.MethodPost, "/activations/nope/confirm", nil); rec.Code != 404 {
		t.Errorf("unknown activation = %d", rec.Code)
	}
}

func TestBreakGlassUseRaisesAlertAndReview(t *testing.T) {
	e := newBGEnv(t, nil)
	act := e.activate()
	ctx := context.Background()
	rv, err := e.b.RecordUse(ctx, useReq(), "holderA", "approval.override", "action-1")
	if err != nil {
		t.Fatal(err)
	}
	if e.alertCount() != 1 || e.alerts[0].Event != "breakglass.used" || e.alerts[0].ActivationID != act.ID {
		t.Fatalf("alerts = %+v", e.alerts)
	}
	used := e.audit.actions("breakglass.used")
	if len(used) != 1 || used[0].ResourceID != act.ID || used[0].ActorID != "holderA" {
		t.Fatalf("breakglass.used rows = %+v", used)
	}
	if rv.Status != bgOpen || rv.DueAt != e.clockNow().Add(24*time.Hour).Format(time.RFC3339) || rv.UseCount != 1 {
		t.Fatalf("review = %+v", rv)
	}
	rv2, err := e.b.RecordUse(ctx, useReq(), "holderB", "approval.override", "action-2")
	if err != nil {
		t.Fatal(err)
	}
	if rv2.ID != rv.ID || rv2.UseCount != 2 || e.alertCount() != 2 {
		t.Fatalf("second use: review %+v alerts=%d", rv2, e.alertCount())
	}
	if open, _ := e.b.Reviews(ctx, bgOpen); len(open) != 1 {
		t.Fatalf("open reviews = %d", len(open))
	}
	e.advance(5 * time.Hour)
	if _, err := e.b.RecordUse(ctx, useReq(), "holderA", "x", "y"); err != errBreakGlassNotActive {
		t.Fatalf("use after expiry err = %v", err)
	}
	if e.alertCount() != 2 {
		t.Fatal("a refused use alerted")
	}
}

func TestBreakGlassLocalLoginScopeNeedsNoWindow(t *testing.T) {
	e := newBGEnv(t, nil)
	rv, err := e.b.recordUse(context.Background(), useReq(), breakGlassLocalLoginScope, "admin", "auth.breakglass_login", "10.0.0.1", false)
	if err != nil {
		t.Fatal(err)
	}
	if rv.ActivationID != breakGlassLocalLoginScope || e.alertCount() != 1 {
		t.Fatalf("review=%+v alerts=%d", rv, e.alertCount())
	}
	if used := e.audit.actions("breakglass.used"); len(used) != 1 || used[0].ResourceID != breakGlassLocalLoginScope {
		t.Fatalf("rows = %+v", used)
	}
}

func TestBreakGlassReviewComplete(t *testing.T) {
	e := newBGEnv(t, nil)
	e.activate()
	rv, err := e.b.RecordUse(context.Background(), useReq(), "holderA", "approval.override", "a1")
	if err != nil {
		t.Fatal(err)
	}
	path := "/reviews/" + rv.ID + "/complete"
	body := map[string]string{"outcome": "justified", "notes": "CA host was down"}
	if rec := e.do(e.token("holderA"), http.MethodPost, path, body); rec.Code != 403 {
		t.Fatalf("holder completes own review = %d", rec.Code)
	}
	if rec := e.do(e.token("holderB"), http.MethodPost, path, body); rec.Code != 403 {
		t.Fatalf("other holder completes = %d", rec.Code)
	}
	if rec := e.do(bgBootstrapToken, http.MethodPost, path, body); rec.Code != 403 {
		t.Fatalf("bootstrap completes = %d", rec.Code)
	}
	if rec := e.do(e.token("viewerV"), http.MethodPost, path, body); rec.Code != 403 {
		t.Fatalf("viewer completes = %d", rec.Code)
	}
	if rec := e.do(e.token("adminC"), http.MethodPost, path, map[string]string{"outcome": "meh"}); rec.Code != 400 {
		t.Fatalf("bad outcome = %d", rec.Code)
	}
	if rec := e.do(e.token("adminC"), http.MethodPost, path, body); rec.Code != 200 {
		t.Fatalf("admin completes = %d %s", rec.Code, rec.Body)
	}
	if rows := e.audit.actions("breakglass.review"); len(rows) == 0 || rows[len(rows)-1].Outcome != AuditOutcomeSuccess || !strings.Contains(rows[len(rows)-1].ChangeSummary, "justified") {
		t.Fatalf("breakglass.review rows = %+v", rows)
	}
	if rec := e.do(e.token("adminD"), http.MethodPost, path, body); rec.Code != 409 {
		t.Fatalf("complete twice = %d", rec.Code)
	}

	// Overdue is derived from the clock.
	rv2, err := e.b.recordUse(context.Background(), useReq(), breakGlassLocalLoginScope, "adminD", "auth.breakglass_login", "ip", false)
	if err != nil {
		t.Fatal(err)
	}
	list := func() BreakGlassReview {
		rec := e.do(e.token("adminC"), http.MethodGet, "/reviews?status=open", nil)
		if rec.Code != 200 {
			t.Fatalf("list = %d %s", rec.Code, rec.Body)
		}
		items := bgDecode[struct {
			Items []BreakGlassReview `json:"items"`
		}](t, rec).Items
		if len(items) != 1 || items[0].ID != rv2.ID {
			t.Fatalf("items = %+v", items)
		}
		return items[0]
	}
	if list().Overdue {
		t.Fatal("overdue too early")
	}
	e.advance(24*time.Hour + time.Second)
	if !list().Overdue {
		t.Fatal("not overdue after 24h+1s")
	}
	// The local-login user cannot review their own login.
	if rec := e.do(e.token("adminD"), http.MethodPost, "/reviews/"+rv2.ID+"/complete", body); rec.Code != 403 {
		t.Fatalf("login actor reviews own use = %d", rec.Code)
	}
	if rec := e.do(e.token("adminC"), http.MethodGet, "/reviews?status=bogus", nil); rec.Code != 400 {
		t.Fatalf("bad status filter = %d", rec.Code)
	}
}

func TestBreakGlassStatus(t *testing.T) {
	e := newBGEnv(t, nil)
	status := func(tok string) (int, map[string]any) {
		rec := e.do(tok, http.MethodGet, "/status", nil)
		return rec.Code, bgDecode[map[string]any](t, rec)
	}
	if c, d := status(e.token("adminC")); c != 200 || d["active"] != false {
		t.Fatalf("idle status = %d %v", c, d)
	}
	e.activate()
	if c, d := status(e.token("holderA")); c != 200 || d["active"] != true {
		t.Fatalf("active status = %d %v", c, d)
	}
	if c, _ := status(e.token("viewerV")); c != 403 {
		t.Fatalf("viewer status = %d", c)
	}
	if rec := e.do("", http.MethodGet, "/status", nil); rec.Code != 401 {
		t.Fatalf("anon status = %d", rec.Code)
	}
}

func TestBreakGlassTenantScopedAdminsCannotReview(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	e := newBGEnv(t, nil)
	rv, err := e.b.recordUse(context.Background(), useReq(), breakGlassLocalLoginScope, "someone", "u", "d", false)
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := e.auth.CreateAPIKeyAs("tenantadmin", "ta", "ta", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.do(tok, http.MethodGet, "/reviews", nil); rec.Code != 403 {
		t.Fatalf("tenant admin lists reviews = %d", rec.Code)
	}
	if rec := e.do(tok, http.MethodPost, "/reviews/"+rv.ID+"/complete", map[string]string{"outcome": "justified"}); rec.Code != 403 {
		t.Fatalf("tenant admin completes = %d", rec.Code)
	}
}

func TestBootstrapTokenStaysNonApproving(t *testing.T) {
	e := newBGEnv(t, nil)
	e.activate()
	bootstrap := AuthPrincipal{ID: "bootstrap", Role: "bootstrap", AuthType: AuthTypeBootstrap}
	if e.auth.mayDecide(bootstrap) {
		t.Fatal("bootstrap may decide while a break-glass window is active")
	}
	actions := newTestPendingStore(t)
	pa, err := actions.Create(context.Background(), PendingAction{ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp"}`), ProposedBy: "someone"})
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, e.auth, &reportCertProvider{}, actions, e.audit, map[string]ActionExecutor{"revoke": func(context.Context, PendingAction, AuthPrincipal) (json.RawMessage, error) {
		ran = true
		return json.RawMessage(`{}`), nil
	}})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(bgBootstrapToken, http.MethodPost, "/api/v1/pending-actions/"+pa.ID+"/approve", nil))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgBootstrapCannotApprove) || ran {
		t.Fatalf("bootstrap approve = %d %s ran=%v", rec.Code, rec.Body, ran)
	}
}

func TestBreakGlassStoreSQLite(t *testing.T) {
	db := openMigratedKeyDB(t, filepath.Join(t.TempDir(), "bg.db"))
	store := &dbBreakGlassStore{db: db, ph: sqlitePlaceholder}
	if err := store.EnsureSchema(context.Background()); err != nil { // coexists with the migration
		t.Fatal(err)
	}
	e := newBGEnv(t, store)
	act := e.activate()
	rv, err := e.b.RecordUse(context.Background(), useReq(), "holderA", "approval.override", "a1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.b.RecordUse(context.Background(), useReq(), "holderB", "approval.override", "a2"); err != nil {
		t.Fatal(err)
	}
	// A fresh store handle on the same database sees everything.
	reopened := &dbBreakGlassStore{db: db, ph: sqlitePlaceholder}
	got, ok, err := reopened.GetActivation(context.Background(), act.ID)
	if err != nil || !ok || got.Status != bgActive || got.ConfirmedBy != "holderB" {
		t.Fatalf("activation = %+v %v %v", got, ok, err)
	}
	cur, ok, _ := reopened.CurrentActive(context.Background())
	if !ok || cur.ID != act.ID {
		t.Fatal("CurrentActive lost the window")
	}
	r, ok, _ := reopened.GetReview(context.Background(), rv.ID)
	if !ok || r.UseCount != 2 || len(r.Actors) != 2 {
		t.Fatalf("review = %+v", r)
	}
	// One open review per scope is a database invariant.
	dup := BreakGlassReview{ID: "bgr-dup", ActivationID: r.ActivationID, Status: bgOpen, OpenedAt: r.OpenedAt, DueAt: r.DueAt}
	if rv3, created, err := reopened.UseReview(context.Background(), dup, "x"); err != nil || created || rv3.ID != rv.ID {
		t.Fatalf("UseReview should bump the existing open review: %+v created=%v err=%v", rv3, created, err)
	}
	// Busy predicate: a second pending request while active is refused.
	ok, err = reopened.CreateActivationIfFree(context.Background(), BreakGlassActivation{ID: "bga-x", Status: bgPending, RequestedBy: "z", RequestedAt: e.clockNow().Format(time.RFC3339)}, e.clockNow())
	if err != nil || ok {
		t.Fatalf("CreateActivationIfFree while active: %v %v", ok, err)
	}
	// Compare-and-set: completing twice only wins once.
	if won, _ := reopened.CompleteReview(context.Background(), rv.ID, "adminC", "now", "justified", ""); !won {
		t.Fatal("first completion lost")
	}
	if won, _ := reopened.CompleteReview(context.Background(), rv.ID, "adminD", "now", "justified", ""); won {
		t.Fatal("second completion won")
	}
}

func TestBreakGlassConcurrentConfirmWinsOnce(t *testing.T) {
	e := newBGEnv(t, nil)
	rec := e.do(e.token("holderA"), http.MethodPost, "/activations", map[string]string{"reason": "outage"})
	a := bgDecode[BreakGlassActivation](t, rec)
	tokB := e.token("holderB")
	var wg sync.WaitGroup
	codes := make(chan int, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- e.do(tokB, http.MethodPost, "/activations/"+a.ID+"/confirm", nil).Code
		}()
	}
	wg.Wait()
	close(codes)
	ok := 0
	for c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d confirms succeeded", ok)
	}
}

func TestBreakGlassHolderIsCheckedAgainstLiveRecord(t *testing.T) {
	e := newBGEnv(t, nil)
	// A token still claiming the role for a user who was demoted since.
	stale := AuthPrincipal{ID: "viewerV", Role: breakGlassRole, AuthType: AuthTypeLocal}
	if _, err := e.b.Request(context.Background(), stale, "outage"); err != errBreakGlassNotHolder {
		t.Fatalf("stale-role request err = %v", err)
	}
	unknown := AuthPrincipal{ID: "ghost", Role: breakGlassRole, AuthType: AuthTypeLocal}
	if _, err := e.b.Request(context.Background(), unknown, "outage"); err != errBreakGlassNotHolder {
		t.Fatalf("unknown-user request err = %v", err)
	}
}
