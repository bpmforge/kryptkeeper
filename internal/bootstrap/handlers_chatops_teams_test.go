// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/chatops"
	"kryptkeeper/internal/notifications/chatops/teams"
)

const (
	teamsTestApp = "teams-app-1"
	teamsTestSvc = "https://smba.trafficmanager.net/amer/"
	teamsTestTID = "11111111-1111-1111-1111-111111111111"
)

var teamsActSeq atomic.Int64

type teamsEnv struct {
	chatopsEnv
	key *rsa.PrivateKey
}

func teamsRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTeamsEnv(t *testing.T) teamsEnv {
	t.Helper()
	t.Setenv(teamsAppIDEnv, teamsTestApp)
	ce := newChatopsEnv(t)
	key := teamsRSA(t)
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	doc, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1",
		"n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
	val := &teams.Validator{JWKS: func(context.Context) (string, error) { return string(doc), nil }}
	RegisterChatopsTeamsHandlers(ce.mux, ce.users, ce.audit, ce.store, val, nil)
	e := teamsEnv{ce, key}
	for oid, user := range map[string]string{"oid-appr": "appr-a", "oid-prop": "proposer-x", "oid-view": "viewer-v", "oid-gone": "gone-g"} {
		err := ce.store.Upsert(t.Context(), chatops.Mapping{Identity: chatops.Identity{Platform: "teams", Workspace: teamsTestTID, ExternalID: oid},
			KryptkeeperUser: user, Tenant: DefaultTenant, CreatedAt: "t"})
		if err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e teamsEnv) token(t *testing.T, key *rsa.PrivateKey, alg string, mod func(c map[string]any)) string {
	t.Helper()
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	claims := map[string]any{"iss": teams.BotFrameworkIssuer, "aud": teamsTestApp, "serviceurl": teamsTestSvc,
		"exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix()}
	if mod != nil {
		mod(claims)
	}
	h, _ := json.Marshal(map[string]any{"alg": alg, "kid": "k1"})
	c, _ := json.Marshal(claims)
	in := enc(h) + "." + enc(c)
	if alg != "RS256" {
		return in + "."
	}
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + enc(sig)
}

type teamsAct struct {
	id, oid, tenant, typ string
	value                map[string]any
	ts                   time.Time
}

func (e teamsEnv) act(oid, verb, kind, target string) teamsAct {
	return teamsAct{id: "act-" + strconv.FormatInt(teamsActSeq.Add(1), 10), oid: oid, tenant: teamsTestTID, typ: "message", ts: time.Now(),
		value: map[string]any{"kk_action": verb, "kind": kind, "id": target}}
}

func teamsReq(a teamsAct, auth string) *http.Request {
	body, _ := json.Marshal(map[string]any{"id": a.id, "type": a.typ, "serviceUrl": teamsTestSvc,
		"timestamp":    a.ts.UTC().Format(time.RFC3339Nano),
		"from":         map[string]string{"id": "29:opaque", "aadObjectId": a.oid, "name": "Ann"},
		"conversation": map[string]string{"id": "c1"}, "channelData": map[string]any{"tenant": map[string]string{"id": a.tenant}},
		"value": a.value})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chatops/teams/activities", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

func (e teamsEnv) send(t *testing.T, a teamsAct) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, teamsReq(a, "Bearer "+e.token(t, e.key, "RS256", nil)))
	return rec
}

func TestTeamsForgedOrReplayedRejected10of10(t *testing.T) {
	e := newTeamsEnv(t)
	a := e.chatopsEnv.propose(t, "someone-else", "")
	mk := func() teamsAct { return e.act("oid-appr", "approve", "action", a.ID) }
	good := "Bearer " + e.token(t, e.key, "RS256", nil)
	stale, future := mk(), mk()
	stale.ts, future.ts = time.Now().Add(-6*time.Minute), time.Now().Add(6*time.Minute)
	cases := []struct {
		name string
		act  teamsAct
		auth string
	}{
		{"bad signature", mk(), "Bearer " + e.token(t, teamsRSA(t), "RS256", nil)},
		{"wrong aud", mk(), "Bearer " + e.token(t, e.key, "RS256", func(c map[string]any) { c["aud"] = "other-app" })},
		{"expired", mk(), "Bearer " + e.token(t, e.key, "RS256", func(c map[string]any) { c["exp"] = time.Now().Add(-10 * time.Minute).Unix() })},
		{"wrong serviceurl", mk(), "Bearer " + e.token(t, e.key, "RS256", func(c map[string]any) { c["serviceurl"] = "https://evil.example/" })},
		{"alg none", mk(), "Bearer " + e.token(t, e.key, "none", nil)},
		{"no header", mk(), ""},
		{"stale activity -6m", stale, good},
		{"future activity +6m", future, good},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, teamsReq(c.act, c.auth))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
	}
	// A valid activity from an unmapped user changes nothing (403); the same activity id replayed is 401.
	replay := e.act("oid-nobody", "approve", "action", a.ID)
	if rec := e.send(t, replay); rec.Code != http.StatusForbidden {
		t.Fatalf("first use: %d", rec.Code)
	}
	if rec := e.send(t, replay); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay: %d", rec.Code)
	}
	t.Setenv(teamsAppIDEnv, "")
	if rec := e.send(t, mk()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty app id: %d", rec.Code)
	}
	if got := e.actionStatus(t, a.ID); got != "pending" {
		t.Fatalf("state changed: %s", got)
	}
	if e.ran.Load() != 0 {
		t.Fatal("executor ran")
	}
	rows := e.audit.all("chatops.signature_failed", AuditOutcomeDenied)
	if len(rows) != 10 {
		t.Fatalf("signature_failed rows = %d, want 10", len(rows))
	}
	for _, row := range rows {
		if strings.Contains(row.ChangeSummary, "Bearer") || strings.Contains(row.ChangeSummary, "eyJ") || strings.Contains(row.ChangeSummary, "serviceUrl") {
			t.Errorf("audit leaks request data: %q", row.ChangeSummary)
		}
	}
}

func TestTeamsUnmappedUser403(t *testing.T) {
	e := newTeamsEnv(t)
	a := e.chatopsEnv.propose(t, "someone-else", "")
	rec := e.send(t, e.act("oid-nobody", "approve", "action", a.ID))
	if rec.Code != http.StatusForbidden || e.actionStatus(t, a.ID) != "pending" || e.ran.Load() != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(e.audit.all("chatops.interaction", AuditOutcomeDenied)) != 1 {
		t.Fatalf("audit: %+v", e.audit.entries)
	}
}

func TestTeamsUnmappedAADTenant403(t *testing.T) {
	e := newTeamsEnv(t)
	a := e.chatopsEnv.propose(t, "someone-else", "")
	// Same object id as a mapped approver, but from an AAD tenant with no mappings.
	act := e.act("oid-appr", "approve", "action", a.ID)
	act.tenant = "22222222-2222-2222-2222-222222222222"
	if rec := e.send(t, act); rec.Code != http.StatusForbidden || e.actionStatus(t, a.ID) != "pending" || e.ran.Load() != 0 {
		t.Fatalf("%d", rec.Code)
	}
	noTenant := e.act("oid-appr", "approve", "action", a.ID)
	noTenant.tenant = ""
	if rec := e.send(t, noTenant); rec.Code != http.StatusForbidden {
		t.Fatalf("no tenant: %d", rec.Code)
	}
}

func TestTeamsRefusalsLeaveStatePending(t *testing.T) {
	e := newTeamsEnv(t)
	for _, c := range []struct{ name, oid, proposer string }{
		{"proposer refused", "oid-prop", "proposer-x"},
		{"deprovisioned user", "oid-gone", "someone-else"},
		{"no approve role", "oid-view", "someone-else"},
	} {
		a := e.chatopsEnv.propose(t, c.proposer, "")
		if rec := e.send(t, e.act(c.oid, "approve", "action", a.ID)); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
		if e.actionStatus(t, a.ID) != "pending" {
			t.Errorf("%s: state changed", c.name)
		}
	}
	if e.ran.Load() != 0 {
		t.Fatal("executor ran")
	}
}

func TestTeamsApproveAuditsBothIdentities(t *testing.T) {
	e := newTeamsEnv(t)
	a := e.chatopsEnv.propose(t, "someone-else", "")
	rec := e.send(t, e.act("oid-appr", "approve", "action", a.ID))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"approved"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if e.ran.Load() != 1 || e.actionStatus(t, a.ID) != "approved" {
		t.Fatalf("ran=%d status=%s", e.ran.Load(), e.actionStatus(t, a.ID))
	}
	rows := e.audit.all("action.approve", AuditOutcomeSuccess)
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, "channel=chatops") ||
		!strings.Contains(rows[0].ChangeSummary, "external_id=teams:"+teamsTestTID+"/oid-appr") || rows[0].ActorID != "appr-a" {
		t.Fatalf("rows: %+v", rows)
	}
	// Retried delivery of the same decision by a new activity is refused as already decided.
	if rec := e.send(t, e.act("oid-appr", "approve", "action", a.ID)); rec.Code != http.StatusConflict || e.ran.Load() != 1 {
		t.Fatalf("second: %d ran=%d", rec.Code, e.ran.Load())
	}
}

func TestTeamsRejectFromTeams(t *testing.T) {
	e := newTeamsEnv(t)
	a := e.chatopsEnv.propose(t, "someone-else", "")
	rec := e.send(t, e.act("oid-appr", "reject", "action", a.ID))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"rejected"`) || e.actionStatus(t, a.ID) != "rejected" || e.ran.Load() != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rows := e.audit.all("action.reject", AuditOutcomeSuccess)
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, "channel=chatops") {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestTeamsNonMessageActivityIgnored200(t *testing.T) {
	e := newTeamsEnv(t)
	a := e.chatopsEnv.propose(t, "someone-else", "")
	act := e.act("oid-appr", "approve", "action", a.ID)
	act.typ = "conversationUpdate"
	if rec := e.send(t, act); rec.Code != http.StatusOK {
		t.Fatalf("%d", rec.Code)
	}
	// Ignored only after authentication: an unauthenticated one is still 401.
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, teamsReq(act, ""))
	if rec.Code != http.StatusUnauthorized || e.actionStatus(t, a.ID) != "pending" || e.ran.Load() != 0 {
		t.Fatalf("%d", rec.Code)
	}
}

func TestTeamsBadActionAndMethod(t *testing.T) {
	e := newTeamsEnv(t)
	for _, act := range []teamsAct{
		e.act("oid-appr", "delete", "action", "x"),
		e.act("oid-appr", "approve", "action", "../etc"),
		e.act("oid-appr", "approve", "secret", "x"),
	} {
		if rec := e.send(t, act); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", act.value, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/chatops/teams/activities", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
}

func TestTeamsIdentityMapAcceptsTeamsPlatform(t *testing.T) {
	e := newChatopsEnv(t)
	admin := mintAdminToken(t, e.auth, "admin-1", "")
	put := `{"platform":"teams","workspace":"` + teamsTestTID + `","external_id":"33333333-3333-3333-3333-333333333333","kryptkeeper_user":"appr-a"}`
	if rec := e.do(admin, http.MethodPut, "/api/v1/chatops/identity-map", put); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
}
