// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func (e *bgEnv) login(email, password string) *httptest.ResponseRecorder {
	e.t.Helper()
	raw, _ := json.Marshal(map[string]string{"email": email, "password": password})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, breakGlassBase+"/login", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:4000"
	e.mux.ServeHTTP(rec, req)
	return rec
}

func newBGLoginEnv(t *testing.T) *bgEnv {
	t.Helper()
	t.Setenv(envBreakGlassEmail, "admin@example.com")
	e := newBGEnv(t, nil)
	// The IdP is configured but nothing listens there: SSO is down.
	e.auth.config.mode = "oidc"
	e.auth.config.oidcIssuer = "http://127.0.0.1:1"
	mountBreakGlassLogin(e.mux, e.b, e.auth)
	return e
}

func TestBreakGlassLoginWorksWithDeadIdP(t *testing.T) {
	e := newBGLoginEnv(t)
	rec := e.login("admin@example.com", "pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d %s", rec.Code, rec.Body)
	}
	data := bgDecode[struct {
		AccessToken string `json:"access_token"`
		Principal   struct {
			UserID string `json:"user_id"`
		} `json:"principal"`
	}](t, rec)
	if data.AccessToken == "" || data.Principal.UserID == "" {
		t.Fatalf("no token in %s", rec.Body)
	}
	if rows := e.audit.actions("auth.breakglass_login"); len(rows) != 1 || rows[0].Outcome != AuditOutcomeSuccess || rows[0].ActorID != "team-1" {
		t.Fatalf("auth.breakglass_login rows = %+v", rows)
	}
	if e.alertCount() != 1 || e.alerts[0].Event != "breakglass.used" {
		t.Fatalf("alerts = %+v", e.alerts)
	}
	open, _ := e.b.Reviews(context.Background(), bgOpen)
	if len(open) != 1 || open[0].ActivationID != breakGlassLocalLoginScope {
		t.Fatalf("reviews = %+v", open)
	}
	// Every further login alerts again and extends the same review.
	if rec := e.login("ADMIN@example.com", "pw"); rec.Code != 200 {
		t.Fatalf("second login = %d", rec.Code)
	}
	if e.alertCount() != 2 {
		t.Fatalf("alerts after second login = %d", e.alertCount())
	}
	if open, _ := e.b.Reviews(context.Background(), bgOpen); len(open) != 1 || open[0].UseCount != 2 {
		t.Fatalf("reviews = %+v", open)
	}

	before := e.alertCount()
	if rec := e.login("admin@example.com", "wrong"); rec.Code != 401 {
		t.Fatalf("wrong password = %d", rec.Code)
	}
	if rec := e.login("someone@example.com", "pw"); rec.Code != 403 {
		t.Fatalf("non-flagged email = %d", rec.Code)
	}
	if e.alertCount() != before {
		t.Fatal("a failed login raised the break-glass alert")
	}
	var denied int
	for _, r := range e.audit.actions("auth.breakglass_login") {
		if r.Outcome == AuditOutcomeDenied {
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("denied rows = %d, want 2", denied)
	}
	if strings.Contains(strings.Join(func() []string {
		var s []string
		for _, r := range e.audit.entries {
			s = append(s, r.ChangeSummary)
		}
		return s
	}(), "|"), "pw") {
		t.Fatal("a password reached the audit trail")
	}
}

func TestBreakGlassLoginNotConfigured503(t *testing.T) {
	e := newBGEnv(t, nil)
	mountBreakGlassLogin(e.mux, e.b, e.auth)
	t.Setenv(envBreakGlassEmail, "")
	if rec := e.login("admin@example.com", "pw"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unset = %d", rec.Code)
	}
	// Flagging an account other than the local login user configures nothing.
	t.Setenv(envBreakGlassEmail, "someone-else@example.com")
	if rec := e.login("someone-else@example.com", "pw"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("mismatch = %d", rec.Code)
	}
	if e.alertCount() != 0 {
		t.Fatal("unconfigured route alerted")
	}
}

func TestBreakGlassLoginRateLimitedAlone(t *testing.T) {
	e := newBGLoginEnv(t)
	for i := 0; i < 5; i++ {
		if rec := e.login("admin@example.com", "wrong"); rec.Code != 401 {
			t.Fatalf("attempt %d = %d", i, rec.Code)
		}
	}
	if rec := e.login("admin@example.com", "pw"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt = %d", rec.Code)
	}
}

func TestBreakGlassLoginRouteIsHooked(t *testing.T) {
	found := false
	for range breakGlassRouteHooks {
		found = true
	}
	if !found {
		t.Fatal("login route hook not registered")
	}
}

// ---- override --------------------------------------------------------------

type overrideEnv struct {
	*bgEnv
	store *dbPendingActionStore
	ran   *atomic.Int32
}

func newOverrideEnv(t *testing.T) *overrideEnv {
	t.Helper()
	e := newBGEnv(t, nil)
	setActiveBreakGlass(e.b)
	t.Cleanup(func() { setActiveBreakGlass(nil) })
	store := newTestPendingStore(t)
	var ran atomic.Int32
	execs := map[string]ActionExecutor{"revoke": func(context.Context, PendingAction, AuthPrincipal) (json.RawMessage, error) {
		ran.Add(1)
		return json.RawMessage(`{"revoked":1}`), nil
	}}
	registerPendingActionHandlers(e.mux, e.auth, &reportCertProvider{}, store, e.audit, execs)
	return &overrideEnv{bgEnv: e, store: store, ran: &ran}
}

func (e *overrideEnv) propose(proposer string, n int, tenant string) PendingAction {
	e.t.Helper()
	a, err := e.store.Create(context.Background(), PendingAction{ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp"}`), ProposedBy: proposer, QuorumN: n, QuorumM: n, Tenant: tenant})
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *overrideEnv) override(tok, id string) *httptest.ResponseRecorder {
	return e.do0(tok, "/api/v1/pending-actions/"+id+"/override", map[string]string{"reason": "CA approvers unreachable"})
}

func (e *overrideEnv) do0(tok, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(tok, http.MethodPost, path, raw))
	return rec
}

func TestOverrideExecutesWhenQuorumUnreachable(t *testing.T) {
	e := newOverrideEnv(t)
	e.activate()
	// 2 approvals needed; the only eligible human besides the proposer is adminD.
	a := e.propose("adminC", 2, "")
	rec := e.override(e.token("holderA"), a.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("override = %d %s", rec.Code, rec.Body)
	}
	got := bgDecode[struct {
		Status     string `json:"status"`
		Overridden bool   `json:"overridden"`
	}](t, rec)
	if got.Status != "approved" || !got.Overridden || e.ran.Load() != 1 {
		t.Fatalf("response %+v ran=%d", got, e.ran.Load())
	}
	rows := e.audit.actions("approval.override")
	if len(rows) != 1 || rows[0].Outcome != AuditOutcomeSuccess || !strings.Contains(rows[0].ChangeSummary, "holders=holderA,holderB") || !strings.Contains(rows[0].ChangeSummary, "reason=CA approvers unreachable") {
		t.Fatalf("approval.override rows = %+v", rows)
	}
	if used := e.audit.actions("breakglass.used"); len(used) != 1 || used[0].ActorID != "holderA" {
		t.Fatalf("breakglass.used rows = %+v", used)
	}
	if e.alertCount() != 1 {
		t.Fatalf("alerts = %d", e.alertCount())
	}
	if open, _ := e.b.Reviews(context.Background(), bgOpen); len(open) != 1 || open[0].DueAt != e.clockNow().Add(24*time.Hour).Format(time.RFC3339) {
		t.Fatalf("review = %+v", open)
	}
	done, _, _ := e.store.Get(context.Background(), a.ID)
	if done.Status != "approved" {
		t.Fatalf("action status = %s", done.Status)
	}
	// A second override of the same action finds it already decided.
	if rec := e.override(e.token("holderB"), a.ID); rec.Code != http.StatusConflict {
		t.Fatalf("override of decided action = %d", rec.Code)
	}
}

func TestOverrideCountsApprovalsAlreadyGiven(t *testing.T) {
	e := newOverrideEnv(t)
	e.activate()
	a := e.propose("adminC", 2, "")
	// adminD already approved: one more is needed and nobody eligible is left.
	if _, err := e.store.RecordApproval(context.Background(), a.ID, "adminD", "adminD"); err != nil {
		t.Fatal(err)
	}
	if rec := e.override(e.token("holderA"), a.ID); rec.Code != http.StatusOK {
		t.Fatalf("override = %d %s", rec.Code, rec.Body)
	}
}

func TestOverrideRefusedWhenQuorumReachable(t *testing.T) {
	e := newOverrideEnv(t)
	e.activate()
	a := e.propose("adminC", 1, "") // adminD can still approve
	rec := e.override(e.token("holderA"), a.ID)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "quorum is still reachable") {
		t.Fatalf("override = %d %s", rec.Code, rec.Body)
	}
	if e.ran.Load() != 0 || e.alertCount() != 0 {
		t.Fatalf("refused override ran=%d alerts=%d", e.ran.Load(), e.alertCount())
	}
}

func TestOverrideRefusedWithoutActiveWindow(t *testing.T) {
	e := newOverrideEnv(t)
	a := e.propose("adminC", 2, "")
	if rec := e.override(e.token("holderA"), a.ID); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "no active break-glass window") {
		t.Fatalf("no window = %d %s", rec.Code, rec.Body)
	}
	if e.ran.Load() != 0 {
		t.Fatal("executed without a window")
	}
}

func TestOverrideRefusedForExpiredWindow(t *testing.T) {
	e := newOverrideEnv(t)
	e.activate()
	a := e.propose("adminC", 2, "")
	e.advance(breakGlassTTL)
	if rec := e.override(e.token("holderA"), a.ID); rec.Code != http.StatusForbidden {
		t.Fatalf("expired window = %d %s", rec.Code, rec.Body)
	}
	if e.ran.Load() != 0 {
		t.Fatal("executed after the window expired")
	}
}

func TestOverrideRefusedForNonHolderAndBootstrap(t *testing.T) {
	e := newOverrideEnv(t)
	e.activate()
	a := e.propose("adminC", 2, "")
	_, keyTok, err := e.auth.CreateAPIKeyAs("holderA", "bk", "holderA", breakGlassRole, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{
		"admin (non-holder)":    e.token("adminD"),
		"viewer":                e.token("viewerV"),
		"bootstrap":             bgBootstrapToken,
		"api key of the holder": keyTok,
	} {
		rec := e.override(tok, a.ID)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := e.override(bgBootstrapToken, a.ID); !strings.Contains(rec.Body.String(), msgBootstrapCannotApprove) {
		t.Errorf("bootstrap message = %s", rec.Body)
	}
	if rec := e.do0("", "/api/v1/pending-actions/"+a.ID+"/override", map[string]string{"reason": "x"}); rec.Code != 401 {
		t.Errorf("anonymous = %d", rec.Code)
	}
	if e.ran.Load() != 0 {
		t.Fatal("a refused caller executed the action")
	}
}

func TestOverrideRefusedOnOwnProposal(t *testing.T) {
	e := newOverrideEnv(t)
	e.activate()
	a := e.propose("holderA", 3, "")
	rec := e.override(e.token("holderA"), a.ID)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgSelfApproval) {
		t.Fatalf("own proposal = %d %s", rec.Code, rec.Body)
	}
	// The other holder may override it: proposer != approver still holds.
	if rec := e.override(e.token("holderB"), a.ID); rec.Code != http.StatusOK {
		t.Fatalf("other holder = %d %s", rec.Code, rec.Body)
	}
}

func TestOverrideNeedsReason(t *testing.T) {
	e := newOverrideEnv(t)
	e.activate()
	a := e.propose("adminC", 2, "")
	rec := e.do0(e.token("holderA"), "/api/v1/pending-actions/"+a.ID+"/override", map[string]string{"reason": "  "})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("blank reason = %d", rec.Code)
	}
}

func TestOverrideDoesNotCrossTenants(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	e := newOverrideEnv(t)
	e.activate()
	a := e.propose("someone", 2, "acme") // holders are in the default tenant
	if rec := e.override(e.token("holderA"), a.ID); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant override = %d %s", rec.Code, rec.Body)
	}
	if e.ran.Load() != 0 || e.alertCount() != 0 {
		t.Fatalf("cross-tenant override ran=%d alerts=%d", e.ran.Load(), e.alertCount())
	}
}

func TestOverrideDoubleExecuteRace(t *testing.T) {
	e := newOverrideEnv(t)
	// The bare test DB has no busy_timeout (production DSNs set one), so
	// concurrent writers get SQLITE_BUSY and answer 503; serialise the pool
	// so the test measures the CAS, not the test harness.
	e.store.db.SetMaxOpenConns(1)
	e.activate()
	a := e.propose("adminC", 2, "")
	toks := []string{e.token("holderA"), e.token("holderB")}
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(tok string) {
			defer wg.Done()
			codes <- e.override(tok, a.ID).Code
		}(toks[i%2])
	}
	wg.Wait()
	close(codes)
	ok := 0
	for c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 || e.ran.Load() != 1 {
		t.Fatalf("succeeded=%d ran=%d, want exactly one", ok, e.ran.Load())
	}
}

func TestQuorumUnreachableCountsOnlyEligibleHumansInTenant(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newLoginAuth(apiKeyVerifier("pw", "pepper"))
	users := &stubUserProvider{users: []UserRecord{
		{ID: "acme-op", Role: "pki-operator", Status: "active", Tenant: "acme"},
		{ID: "globex-op", Role: "pki-operator", Status: "active", Tenant: "globex"},
		{ID: "acme-off", Role: "pki-operator", Status: "deactivated", Tenant: "acme"},
		{ID: "acme-viewer", Role: "viewer", Status: "active", Tenant: "acme"},
	}}
	store := newTestPendingStore(t)
	a := PendingAction{ID: "x", ProposedBy: "someone", Tenant: "acme", QuorumN: 2}
	un, err := quorumUnreachable(context.Background(), auth, users, nil, store, a)
	if err != nil || !un {
		t.Fatalf("1 eligible of 2 needed: unreachable=%v err=%v", un, err)
	}
	users.users = append(users.users, UserRecord{ID: "acme-op2", Role: "approver", Status: "active", Tenant: "acme"})
	un, err = quorumUnreachable(context.Background(), auth, users, nil, store, a)
	if err != nil || un {
		t.Fatalf("2 eligible of 2 needed: unreachable=%v err=%v", un, err)
	}
	// The proposer's own account never counts.
	a.ProposedBy = "acme-op2"
	if un, _ := quorumUnreachable(context.Background(), auth, users, nil, store, a); !un {
		t.Fatal("proposer was counted as an eligible approver")
	}
}

func TestOverrideRouteBypassesWriteGateOnlyForSelfAuth(t *testing.T) {
	rt, ok := matchWriteRoute("/api/v1/pending-actions/abc/override")
	if !ok || rt.perm != permSelf {
		t.Fatalf("override route = %+v ok=%v", rt, ok)
	}
	// approve/reject keep their permission.
	if rt, _ := matchWriteRoute("/api/v1/pending-actions/abc/approve"); rt.perm != "action.approve" {
		t.Fatalf("approve route = %+v", rt)
	}
}

type reviewDownStore struct{ breakGlassStore }

func (reviewDownStore) UseReview(context.Context, BreakGlassReview, string) (BreakGlassReview, bool, error) {
	return BreakGlassReview{}, false, errors.New("break-glass db down")
}

// R-04 (accepted): with the break-glass DB down the login still succeeds, the
// audit row and alert fire, and the lost review row is logged at error level
// naming the elevation.
func TestBreakGlassLoginSurvivesReviewStoreDownAndLogsError(t *testing.T) {
	e := newBGLoginEnv(t)
	e.b.store = reviewDownStore{e.b.store}
	buf := captureLogs(t, slog.LevelInfo)
	if rec := e.login("admin@example.com", "pw"); rec.Code != http.StatusOK {
		t.Fatalf("login = %d %s", rec.Code, rec.Body)
	}
	if len(e.audit.actions("breakglass.used")) != 1 || e.alertCount() != 1 {
		t.Fatalf("audit/alert must fire without the store: alerts=%d", e.alertCount())
	}
	var found bool
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "review row not written") {
			found = true
			if !strings.Contains(line, `"level":"error"`) || !strings.Contains(line, breakGlassLocalLoginScope) {
				t.Fatalf("log line must be ERROR and name the elevation: %s", line)
			}
		}
	}
	if !found {
		t.Fatalf("lost review row was not logged: %s", buf)
	}
}
