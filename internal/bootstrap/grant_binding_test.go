// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// RC1-B-02: an approved egress grant is bound to the proposing credential,
// not to a free-text principal id.

// TestSoD_APIKeyPrincipalIDMayNotImpersonateAPerson covers the second layer of
// RC1-B-02: no key may carry the bootstrap id.
func TestSoD_APIKeyPrincipalIDMayNotImpersonateAPerson(t *testing.T) {
	e := newEgressEnv(t, "false")
	rec := e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": "bootstrap", "role": "pki-admin", "scopes": []string{"*"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("minting a key as principal_id=bootstrap: want 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestGrantRedemptionBoundToProposingCredential: another admin who mints a
// key under the proposer's free-text principal id cannot redeem the
// proposer's approved grant, on any egress route; the proposer still can,
// once.
func TestGrantRedemptionBoundToProposingCredential(t *testing.T) {
	e := newEgressEnv(t, "unset")
	carol := mintAdminToken(t, e.auth, "carol", "")
	// carol mints a key that claims to be "alice" (free-text principal id).
	imposter := mintViaAPI(t, e, carol, "alice")
	// alice mints a second key for herself: same human, different credential.
	aliceSecond := mintViaAPI(t, e, e.alice, "alice")

	for _, c := range egressCases(t, e.keys) {
		t.Run(c.name, func(t *testing.T) {
			rec := e.post(t, e.alice, c.path, c.body)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("propose: want 202, got %d: %s", rec.Code, rec.Body.String())
			}
			id := actionID(t, rec)
			if rec := e.post(t, e.bob, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusOK {
				t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
			}
			withGrant := map[string]any{}
			for k, v := range c.body {
				withGrant[k] = v
			}
			withGrant["approved_action_id"] = id

			for name, tok := range map[string]string{"imposter key with alice's principal id": imposter, "alice's other key": aliceSecond, "third admin": carol} {
				if rec := e.post(t, tok, c.path, withGrant); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "different principal") {
					t.Fatalf("%s: want 403, got %d: %s", name, rec.Code, rec.Body.String())
				}
			}
			// Refused attempts do not burn the grant: the proposer redeems it...
			if rec := e.post(t, e.alice, c.path, withGrant); rec.Code != c.afterGate {
				t.Fatalf("proposer redeem: want %d, got %d: %s", c.afterGate, rec.Code, rec.Body.String())
			}
			// ...exactly once.
			if rec := e.post(t, e.alice, c.path, withGrant); rec.Code != http.StatusForbidden {
				t.Fatalf("second redeem: want 403, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestGrantWithoutBindingIsNotRedeemable(t *testing.T) {
	_, _, queue := newDualControlMux(t, true)
	ctx := context.Background()
	dc := NewKeyDualControlFromEnv(queue)
	auth := newReportsTestAuth(t)
	// A grant queued before the binding existed: no proposer_* fields.
	a, err := queue.Create(ctx, PendingAction{
		ActionType: keyActionExport, Params: json.RawMessage(`{"key_id":"k1"}`), ProposedBy: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Decide(ctx, a.ID, "approved", "bob", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	err = dc.AuthorizeGrant(ctx, auth, keyActionExport, "k1", "", AuthPrincipal{ID: "alice", AuthType: "local"}, a.ID)
	if err == nil {
		t.Fatal("an unbound grant must not be redeemable")
	}
}
