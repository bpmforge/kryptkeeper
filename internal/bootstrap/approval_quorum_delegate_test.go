// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// F2: a delegate must contribute one quorum vote per action, whether it votes
// as itself, as its delegator, or both.
func TestQuorum_DelegateCannotVoteTwice(t *testing.T) {
	e := newDelegEnv(t, "revoke=2/3")
	tokD := mintAdminToken(t, e.auth, "appr-d", "")
	tokE := mintAdminToken(t, e.auth, "appr-e", "")
	now := time.Now()
	if rec := e.do(tokD, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-e", now.Add(-time.Minute), now.Add(time.Hour))); rec.Code != http.StatusOK {
		t.Fatalf("delegation: %d %s", rec.Code, rec.Body.String())
	}
	obo := `{"on_behalf_of":"appr-d"}`

	// Self first, then on behalf of D: second vote refused, quorum not met.
	a := e.propose(t, "mcp:agent", "")
	if rec := e.do(tokE, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("self vote: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(tokE, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", obo); rec.Code != http.StatusConflict {
		t.Fatalf("self then on-behalf: %d %s", rec.Code, rec.Body.String())
	}
	if e.ran.Load() != 0 {
		t.Fatal("executed on one physical approver")
	}

	// On behalf of D first, then self.
	b := e.propose(t, "mcp:agent", "")
	if rec := e.do(tokE, http.MethodPost, "/api/v1/pending-actions/"+b.ID+"/approve", obo); rec.Code != http.StatusAccepted {
		t.Fatalf("on-behalf vote: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(tokE, http.MethodPost, "/api/v1/pending-actions/"+b.ID+"/approve", ""); rec.Code != http.StatusConflict {
		t.Fatalf("on-behalf then self: %d %s", rec.Code, rec.Body.String())
	}
	// A key minted by E is the same physical approver.
	tokE2 := mintAdminToken(t, e.auth, "appr-e2", "appr-e")
	if rec := e.do(tokE2, http.MethodPost, "/api/v1/pending-actions/"+b.ID+"/approve", ""); rec.Code != http.StatusConflict {
		t.Fatalf("E's chained key: %d %s", rec.Code, rec.Body.String())
	}
	if e.ran.Load() != 0 {
		t.Fatal("executed on one physical approver")
	}

	// Existing guarantee: delegator direct + delegate on behalf counts once.
	c := e.propose(t, "mcp:agent", "")
	if rec := e.do(tokD, http.MethodPost, "/api/v1/pending-actions/"+c.ID+"/approve", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("D direct: %d", rec.Code)
	}
	if rec := e.do(tokE, http.MethodPost, "/api/v1/pending-actions/"+c.ID+"/approve", obo); rec.Code != http.StatusConflict {
		t.Fatalf("D direct then E for D: %d %s", rec.Code, rec.Body.String())
	}
	// A genuinely second human still completes the quorum.
	tokF := mintAdminToken(t, e.auth, "appr-f", "")
	if rec := e.do(tokF, http.MethodPost, "/api/v1/pending-actions/"+c.ID+"/approve", ""); rec.Code != http.StatusOK || e.ran.Load() != 1 {
		t.Fatalf("second human: %d %s ran=%d", rec.Code, rec.Body.String(), e.ran.Load())
	}
}

// Proposer != approver must hold when acting on behalf of a delegator, in
// both directions.
func TestQuorum_OnBehalfRespectsProposer(t *testing.T) {
	e := newDelegEnv(t, "revoke=2/3")
	tokD := mintAdminToken(t, e.auth, "appr-d", "")
	tokE := mintAdminToken(t, e.auth, "appr-e", "")
	now := time.Now()
	if rec := e.do(tokD, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-e", now.Add(-time.Minute), now.Add(time.Hour))); rec.Code != http.StatusOK {
		t.Fatalf("delegation: %d", rec.Code)
	}
	obo := `{"on_behalf_of":"appr-d"}`
	// D proposed: E may not approve as D.
	a := e.propose(t, "appr-d", "")
	if rec := e.do(tokE, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", obo); rec.Code != http.StatusForbidden {
		t.Fatalf("delegate approving delegator's own proposal: %d %s", rec.Code, rec.Body.String())
	}
	// E proposed: E may not approve at all.
	b := e.propose(t, "appr-e", "")
	if rec := e.do(tokE, http.MethodPost, "/api/v1/pending-actions/"+b.ID+"/approve", obo); rec.Code != http.StatusForbidden {
		t.Fatalf("proposer approving on behalf: %d %s", rec.Code, rec.Body.String())
	}
	if g, _, _ := e.st.Get(context.Background(), a.ID); g.ApprovalsCount != 0 {
		t.Fatalf("approval recorded: %+v", g)
	}
}
