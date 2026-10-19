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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseQuorumPolicy(t *testing.T) {
	got, err := parseQuorumPolicy("revoke=2/3, bulk_revoke=3/9")
	if err != nil || got["revoke"] != [2]int{2, 3} || got["bulk_revoke"] != [2]int{3, 9} {
		t.Fatalf("valid: %v %v", got, err)
	}
	for _, bad := range []string{"revoke=0/3", "revoke=3/2", "revoke=10/10", "garbage", "revoke=a/b", "=2/3", "revoke=2"} {
		if _, err := parseQuorumPolicy(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestQuorumDefaultsOneOfOne(t *testing.T) {
	t.Setenv(approvalQuorumPolicyEnv, "")
	if n, m := quorumFor("revoke"); n != 1 || m != 1 {
		t.Fatalf("unset: %d/%d", n, m)
	}
	t.Setenv(approvalQuorumPolicyEnv, "revoke=2/3")
	if n, m := quorumFor("bulk_revoke"); n != 1 || m != 1 {
		t.Fatalf("unlisted: %d/%d", n, m)
	}
	t.Setenv(approvalQuorumPolicyEnv, "revoke=banana")
	if n, m := quorumFor("revoke"); n != 1 || m != 1 {
		t.Fatalf("bad policy must fail safe to 1-of-1: %d/%d", n, m)
	}
}

type quorumEnv struct {
	mux  *http.ServeMux
	auth *Authenticator
	st   *dbPendingActionStore
	ran  *atomic.Int32
}

func newQuorumEnv(t *testing.T, policy string) quorumEnv {
	t.Helper()
	t.Setenv(approvalQuorumPolicyEnv, policy)
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	store := newTestPendingStore(t)
	var ran atomic.Int32
	execs := map[string]ActionExecutor{"revoke": func(context.Context, PendingAction, AuthPrincipal) (json.RawMessage, error) {
		ran.Add(1)
		return json.RawMessage(`{}`), nil
	}}
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, store, stubAuditProvider{}, execs)
	return quorumEnv{mux, auth, store, &ran}
}

func (e quorumEnv) propose(t *testing.T, proposer string) PendingAction {
	t.Helper()
	a, err := e.st.Create(context.Background(), PendingAction{ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp"}`), ProposedBy: proposer})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e quorumEnv) approve(token, id string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(token, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil))
	return rec
}

func TestTwoOfThreeNeedsSecondDistinctApprover(t *testing.T) {
	e := newQuorumEnv(t, "revoke=2/3")
	a := e.propose(t, "mcp:agent")
	if a.QuorumN != 2 || a.QuorumM != 3 {
		t.Fatalf("stored quorum %d/%d", a.QuorumN, a.QuorumM)
	}
	rec := e.approve(mintAdminToken(t, e.auth, "appr-a", ""), a.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first approver: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Status              string
			Approvals, Required int
		}
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Data.Approvals != 1 || body.Data.Required != 2 || body.Data.Status != "pending" {
		t.Fatalf("partial body: %s", rec.Body.String())
	}
	if e.ran.Load() != 0 {
		t.Fatal("executed after one approval")
	}
	if g, _, _ := e.st.Get(context.Background(), a.ID); g.Status != "pending" || g.ApprovalsCount != 1 {
		t.Fatalf("row: %+v", g)
	}
	rec = e.approve(mintAdminToken(t, e.auth, "appr-b", ""), a.ID)
	if rec.Code != http.StatusOK || e.ran.Load() != 1 {
		t.Fatalf("second approver: %d %s ran=%d", rec.Code, rec.Body.String(), e.ran.Load())
	}
	if g, _, _ := e.st.Get(context.Background(), a.ID); g.Status != "approved" {
		t.Fatalf("status %s", g.Status)
	}
}

func TestSameHumanTwiceCountsOnce(t *testing.T) {
	e := newQuorumEnv(t, "revoke=2/3")
	a := e.propose(t, "mcp:agent")
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	if rec := e.approve(tokA, a.ID); rec.Code != http.StatusAccepted {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := e.approve(tokA, a.ID); rec.Code != http.StatusConflict {
		t.Fatalf("same key again: %d %s", rec.Code, rec.Body.String())
	}
	// A key minted by A resolves to the same human.
	tokA2 := mintAdminToken(t, e.auth, "a2", "appr-a")
	if rec := e.approve(tokA2, a.ID); rec.Code != http.StatusConflict {
		t.Fatalf("chained key: %d %s", rec.Code, rec.Body.String())
	}
	if e.ran.Load() != 0 {
		t.Fatal("executed with one distinct human")
	}
	if g, _, _ := e.st.Get(context.Background(), a.ID); g.Status != "pending" || g.ApprovalsCount != 1 {
		t.Fatalf("row: %+v", g)
	}
}

func TestQuorumStoredAtProposal(t *testing.T) {
	e := newQuorumEnv(t, "revoke=2/3")
	a := e.propose(t, "mcp:agent")
	t.Setenv(approvalQuorumPolicyEnv, "")
	if rec := e.approve(mintAdminToken(t, e.auth, "appr-a", ""), a.ID); rec.Code != http.StatusAccepted {
		t.Fatalf("policy relaxed after proposal must not weaken the row: %d", rec.Code)
	}
	if g, _, _ := e.st.Get(context.Background(), a.ID); g.QuorumN != 2 || g.QuorumM != 3 {
		t.Fatalf("row quorum %d/%d", g.QuorumN, g.QuorumM)
	}
}

func TestDefaultStaysOneOfOne(t *testing.T) {
	e := newQuorumEnv(t, "")
	a := e.propose(t, "mcp:agent")
	if a.QuorumN != 1 || a.QuorumM != 1 {
		t.Fatalf("quorum %d/%d", a.QuorumN, a.QuorumM)
	}
	if rec := e.approve(mintAdminToken(t, e.auth, "appr-a", ""), a.ID); rec.Code != http.StatusOK || e.ran.Load() != 1 {
		t.Fatalf("%d ran=%d", rec.Code, e.ran.Load())
	}
}

func TestConcurrentFinalApprovalsExecuteOnce(t *testing.T) {
	e := newQuorumEnv(t, "revoke=2/3")
	// The bare test DB has no busy_timeout (production DSNs set one), so
	// serialise connections; the CAS under test is still what picks the winner.
	e.st.db.SetMaxOpenConns(1)
	a := e.propose(t, "mcp:agent")
	if rec := e.approve(mintAdminToken(t, e.auth, "appr-a", ""), a.ID); rec.Code != http.StatusAccepted {
		t.Fatalf("first: %d", rec.Code)
	}
	tokB := mintAdminToken(t, e.auth, "appr-b", "")
	tokC := mintAdminToken(t, e.auth, "appr-c", "")
	var wg sync.WaitGroup
	codes := make([]int, 2)
	bodies := make([]string, 2)
	for i, tok := range []string{tokB, tokC} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := e.approve(tok, a.ID)
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}()
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		}
	}
	if e.ran.Load() != 1 || ok != 1 || conflict != 1 {
		t.Fatalf("ran=%d codes=%v bodies=%v", e.ran.Load(), codes, bodies)
	}
}

func TestSelfApprovalStill403(t *testing.T) {
	e := newQuorumEnv(t, "revoke=2/3")
	a := e.propose(t, "appr-a")
	if rec := e.approve(mintAdminToken(t, e.auth, "appr-a", ""), a.ID); rec.Code != http.StatusForbidden {
		t.Fatalf("self approval: %d", rec.Code)
	}
	// A key minted by the proposer is the proposer too.
	if rec := e.approve(mintAdminToken(t, e.auth, "appr-a2", "appr-a"), a.ID); rec.Code != http.StatusForbidden {
		t.Fatalf("chained self approval: %d", rec.Code)
	}
	if g, _, _ := e.st.Get(context.Background(), a.ID); g.ApprovalsCount != 0 {
		t.Fatalf("approval recorded for refused caller: %+v", g)
	}
}

func TestMCPApproveStill403(t *testing.T) {
	e := newQuorumEnv(t, "revoke=2/3")
	a := e.propose(t, "someone")
	_, tok, err := e.auth.CreateAPIKey("mcp-int", "mcp-server", RoleMCPAgent, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.approve(tok, a.ID); rec.Code != http.StatusForbidden {
		t.Fatalf("mcp approve: %d", rec.Code)
	}
	if g, _, _ := e.st.Get(context.Background(), a.ID); g.ApprovalsCount != 0 {
		t.Fatalf("approval recorded: %+v", g)
	}
}

func TestValidateApprovalQuorumPolicyFromEnv(t *testing.T) {
	t.Setenv(approvalQuorumPolicyEnv, "")
	if err := ValidateApprovalQuorumPolicyFromEnv(); err != nil {
		t.Fatalf("unset policy must be valid: %v", err)
	}
	t.Setenv(approvalQuorumPolicyEnv, "revoke=2/3, bulk_revoke=3/9")
	if err := ValidateApprovalQuorumPolicyFromEnv(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	t.Setenv(approvalQuorumPolicyEnv, "revoke=2/3,bulk_revoke=3/2")
	err := ValidateApprovalQuorumPolicyFromEnv()
	if err == nil {
		t.Fatal("invalid policy accepted: startup would silently drop classes to 1-of-1")
	}
	if !strings.Contains(err.Error(), "bulk_revoke=3/2") || !strings.Contains(err.Error(), approvalQuorumPolicyEnv) {
		t.Fatalf("error must name the env var and the bad entry: %v", err)
	}
}
