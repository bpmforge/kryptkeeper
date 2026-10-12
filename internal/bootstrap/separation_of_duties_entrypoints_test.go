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
	"testing"
	"time"
)

// RC1-B-01: the bootstrap token and every key minted with it share ONE
// canonical identity ("bootstrap") that may propose but never decide. One
// person can hold the bootstrap token and a named account, so a
// bootstrap-minted key must be refused on EVERY approval entry point.
// RC1-B-02: an approved egress grant is bound to the proposing credential,
// not to a free-text principal id.

const bootstrapTestToken = "test-token" // APP_BOOTSTRAP_TOKEN in newEgressEnv

func TestSoD_BootstrapIdentityCanonicalizesToOne(t *testing.T) {
	e := newEgressEnv(t, "false")
	boot := mintViaAPI(t, e, bootstrapTestToken, "svc-boot")
	hop2 := mintViaAPI(t, e, boot, "svc-boot-2")
	for _, r := range e.auth.ListAPIKeys() {
		if (r.PrincipalID == "svc-boot" || r.PrincipalID == "svc-boot-2") && r.CreatedBy != bootstrapHuman {
			t.Errorf("key %s CreatedBy = %q, want %q", r.PrincipalID, r.CreatedBy, bootstrapHuman)
		}
	}
	for name, pd := range map[string]AuthPrincipal{
		"bootstrap token":        {ID: "bootstrap", Role: "pki-admin", AuthType: "bootstrap"},
		"bootstrap-minted key":   keyPrincipal(t, e, "svc-boot"),
		"key minted by that key": keyPrincipal(t, e, "svc-boot-2"),
	} {
		if got := e.auth.canonicalHuman(pd); got != bootstrapHuman {
			t.Errorf("%s: canonicalHuman = %q, want %q", name, got, bootstrapHuman)
		}
		if e.auth.mayDecide(pd) {
			t.Errorf("%s: mayDecide = true, want false", name)
		}
	}
	_ = hop2
	if pd := keyPrincipal(t, e, "alice"); !e.auth.mayDecide(pd) {
		t.Error("a named admin's key must be able to decide")
	}
}

func keyPrincipal(t *testing.T, e *egressEnv, principalID string) AuthPrincipal {
	t.Helper()
	for _, r := range e.auth.ListAPIKeys() {
		if r.PrincipalID == principalID {
			return AuthPrincipal{ID: r.PrincipalID, Role: r.Role, AuthType: "api-key", Kid: r.Kid}
		}
	}
	t.Fatalf("no key for principal %q", principalID)
	return AuthPrincipal{}
}

// TestSoD_BootstrapMintedKeyRefusedAtEveryDecisionEntryPoint is the table over
// the approval entry points reachable through the pending-actions queue:
// generic approve and reject, every egress grant type, delete/rotate, and the
// plugin-enable action.
func TestSoD_BootstrapMintedKeyRefusedAtEveryDecisionEntryPoint(t *testing.T) {
	e := newEgressEnv(t, "unset")
	store := NewPendingActionStoreFromEnv()
	bootKey := mintViaAPI(t, e, bootstrapTestToken, "svc-boot")

	actionTypes := []string{
		"revoke", ActionEnableDeliveryPlugin,
		keyActionDelete, keyActionRotate,
		keyActionExport, keyActionBackup, keyActionEscrow, keyActionEscrowRecover,
		keyActionLeafEscrow, keyActionLeafEscrowRecover, keyActionBYOKExport,
	}
	// A proposal by a named human AND by the bootstrap token itself: the
	// bootstrap identity is refused either way.
	for _, proposer := range []string{"alice", "bootstrap"} {
		for _, typ := range actionTypes {
			for _, verb := range []string{"approve", "reject"} {
				t.Run(proposer+"/"+typ+"/"+verb, func(t *testing.T) {
					a, err := store.Create(context.Background(), PendingAction{
						ActionType: typ, Params: json.RawMessage(`{"key_id":"k1","fingerprint":"fp"}`),
						ProposedBy: proposer,
					})
					if err != nil {
						t.Fatal(err)
					}
					rec := e.post(t, bootKey, "/api/v1/pending-actions/"+a.ID+"/"+verb, nil)
					if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "bootstrap") {
						t.Fatalf("bootstrap-minted key %s: want 403 naming bootstrap, got %d: %s", verb, rec.Code, rec.Body.String())
					}
					got, _, _ := store.Get(context.Background(), a.ID)
					if got.Status != "pending" {
						t.Fatalf("action must stay pending, got %s", got.Status)
					}
				})
			}
		}
	}

	// Control: a genuinely different named admin is NOT refused.
	a, _ := store.Create(context.Background(), PendingAction{ActionType: keyActionBackup, Params: json.RawMessage(`{"key_id":"all-keys"}`), ProposedBy: "bootstrap"})
	if rec := e.post(t, e.bob, "/api/v1/pending-actions/"+a.ID+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("named admin approving the bootstrap holder's proposal: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSoD_BootstrapMintedKeyRefusedOnNHIApproval(t *testing.T) {
	mux, store, auth := nhiTestSetup(t)
	created := proposeNHI(t, mux, "agent-b01")
	if err := seedNHICreator(store, created.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	_, bootKey, err := auth.CreateAPIKeyAs(bootstrapHuman, "boot", "svc-boot", "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(bootKey, http.MethodPost, "/api/v1/nhi/identities/"+created.ID+"/approve", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bootstrap-minted key approving an NHI identity: want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if got, _, _ := store.Get(context.Background(), created.ID); got.Status != "pending" {
		t.Fatalf("identity must stay pending, got %q", got.Status)
	}
	// A named admin can.
	named := mintAdminToken(t, auth, "bob", "")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(named, http.MethodPost, "/api/v1/nhi/identities/"+created.ID+"/approve", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("named admin approving: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSoD_BootstrapMintedKeyRefusedOnCertificateApproval(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	approvalStore, err := newApprovalStoreFromEnv()
	if err != nil || approvalStore == nil {
		t.Fatalf("approval store: %v", err)
	}
	req := ApprovalRequest{
		ID: "apr-b01", TemplateID: "tpl-acme", CAID: "ca-acme", Requester: "alice",
		Status: "pending", RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := approvalStore.Create(context.Background(), req); err != nil {
		t.Fatalf("seed approval: %v", err)
	}
	// Mint a key WITH THE BOOTSTRAP TOKEN (root-token) for tenant acme.
	body := `{"name":"b","principal_id":"svc-boot","role":"pki-admin","scopes":["*"],"tenant":"acme"}`
	mrec := httptest.NewRecorder()
	mreq := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(body))
	mreq.Header.Set("Authorization", "Bearer root-token")
	mreq.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(mrec, mreq)
	var mp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mrec.Body.Bytes(), &mp); err != nil || mp.Data.Token == "" {
		t.Fatalf("mint: %d %s", mrec.Code, mrec.Body.String())
	}
	rec := doTenantReq(mux, http.MethodPost, "/api/v1/approvals/apr-b01/approve", mp.Data.Token, "acme")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "bootstrap") {
		t.Fatalf("bootstrap-minted key approving a CSR: want 403 naming bootstrap, got %d: %s", rec.Code, rec.Body.String())
	}
	_ = acmeToken
}
