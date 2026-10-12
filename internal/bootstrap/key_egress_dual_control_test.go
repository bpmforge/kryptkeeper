// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// FG-2 (A2A7-001, A07-4/LLM-006, A01-003): every private-key egress rides
// the same propose -> different-human approve -> one-time redeem flow, dual
// control is ON unless explicitly "false", approval separation of duties
// follows the human behind a key, and an approved action executes once.

type egressEnv struct {
	mux   *http.ServeMux
	auth  *Authenticator
	keys  keystore.Store
	alice string // bearer tokens of two genuinely different admins
	bob   string
}

// newEgressEnv builds a mux with every egress route plus the approval queue.
// dualControl is the raw KRYPTKEEPER_KEY_DUAL_CONTROL value; "unset" removes
// the variable so the default applies.
func newEgressEnv(t *testing.T, dualControl string) *egressEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", dualControl)
	if dualControl == "unset" {
		if err := os.Unsetenv("KRYPTKEEPER_KEY_DUAL_CONTROL"); err != nil {
			t.Fatal(err)
		}
	}
	auth := NewAuthenticatorFromEnv()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("egress-test-passphrase-32chars!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })
	if _, err := keys.GenerateKey("k1", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}

	queue := NewPendingActionStoreFromEnv()
	if queue == nil {
		t.Fatal("pending action store unavailable")
	}
	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProvider{}, "")
	registerKeyEscrowHandlers(mux, auth, keys, stubAuditProvider{})
	registerBackupHandlers(mux, auth, keys, stubAuditProvider{})
	registerKeyCustodyOpsHandlers(mux, auth, keys, stubAuditProvider{})
	registerBYOKHandlers(mux, auth, stubAuditProvider{})
	registerAuthHandlers(mux, auth, stubAuditProvider{})
	registerPendingActionHandlers(mux, auth, NewFileCertificateProviderFromEnv(), queue, stubAuditProvider{}, nil, keys)
	return &egressEnv{
		mux: mux, auth: auth, keys: keys,
		alice: mintAdminToken(t, auth, "alice", ""),
		bob:   mintAdminToken(t, auth, "bob", ""),
	}
}

func (e *egressEnv) post(t *testing.T, token, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(token, http.MethodPost, path, raw))
	return rec
}

func actionID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Data struct {
			ActionID string `json:"action_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Data.ActionID == "" {
		t.Fatalf("no action_id in %d: %s", rec.Code, rec.Body.String())
	}
	return p.Data.ActionID
}

// egressCases are the routes that carry private key material out.
func egressCases(t *testing.T, keys keystore.Store) []struct {
	name, path string
	body       map[string]any
	// afterGate is the status a redeemed request reaches once past the
	// dual-control gate (the operation's own result, not 202/dual-control 403).
	afterGate int
} {
	t.Helper()
	bundle, err := keystore.EscrowKey(keys, "k1", []byte("custodian-a-passphrase!"), []byte("custodian-b-passphrase!"))
	if err != nil {
		t.Fatalf("escrow fixture: %v", err)
	}
	return []struct {
		name, path string
		body       map[string]any
		afterGate  int
	}{
		{"backup", "/api/v1/admin/backup", map[string]any{"backup_passphrase": "backup-passphrase-1"}, http.StatusOK},
		{"escrow", "/api/v1/keys/escrow", map[string]any{"key_id": "k1", "custodian_a_passphrase": "custodian-a-passphrase!", "custodian_b_passphrase": "custodian-b-passphrase!"}, http.StatusOK},
		{"escrow-recover", "/api/v1/keys/escrow/recover", map[string]any{"bundle": json.RawMessage(bundle), "custodian_a_passphrase": "custodian-a-passphrase!", "custodian_b_passphrase": "custodian-b-passphrase!"}, http.StatusConflict},
		{"leaf-escrow", "/api/v1/keys/leaf-escrow", map[string]any{"key_id": "k1", "custodian_a_passphrase": "custodian-a-passphrase!", "custodian_b_passphrase": "custodian-b-passphrase!"}, http.StatusForbidden},
		{"leaf-escrow-recover", "/api/v1/keys/leaf-escrow/recover", map[string]any{"bundle": json.RawMessage(bundle), "custodian_a_passphrase": "custodian-a-passphrase!", "custodian_b_passphrase": "custodian-b-passphrase!"}, http.StatusBadRequest},
		{"byok-export", "/api/v1/keys/byok/export", map[string]any{"bundle": json.RawMessage(bundle), "key_id": "kms-1", "provider": "nope", "custodian_a_passphrase": "custodian-a-passphrase!", "custodian_b_passphrase": "custodian-b-passphrase!"}, http.StatusBadRequest},
	}
}

func TestEgressRoutesRequireDifferentAdminApproval_DefaultOn(t *testing.T) {
	e := newEgressEnv(t, "unset") // default: no env var at all
	for _, c := range egressCases(t, e.keys) {
		t.Run(c.name, func(t *testing.T) {
			// Single admin: proposal only, no material.
			rec := e.post(t, e.alice, c.path, c.body)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("propose: want 202, got %d: %s", rec.Code, rec.Body.String())
			}
			id := actionID(t, rec)
			if strings.Contains(rec.Body.String(), "BEGIN") || strings.Contains(rec.Body.String(), "wrapped_key") {
				t.Fatal("proposal must not carry key material")
			}
			withGrant := map[string]any{"approved_action_id": id}
			for k, v := range c.body {
				withGrant[k] = v
			}

			// Unapproved grant is refused.
			if rec := e.post(t, e.alice, c.path, withGrant); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "not approved") {
				t.Fatalf("unapproved grant: want 403 not approved, got %d: %s", rec.Code, rec.Body.String())
			}
			// The proposer cannot approve; a different admin can.
			if rec := e.post(t, e.alice, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusForbidden {
				t.Fatalf("self-approval: want 403, got %d", rec.Code)
			}
			if rec := e.post(t, e.bob, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusOK {
				t.Fatalf("approve by other admin: want 200, got %d: %s", rec.Code, rec.Body.String())
			}
			// Only the proposer redeems.
			if rec := e.post(t, e.bob, c.path, withGrant); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "different principal") {
				t.Fatalf("redeem by non-proposer: want 403, got %d: %s", rec.Code, rec.Body.String())
			}
			rec = e.post(t, e.alice, c.path, withGrant)
			if rec.Code != c.afterGate {
				t.Fatalf("redeem: want %d (past the gate), got %d: %s", c.afterGate, rec.Code, rec.Body.String())
			}
			// One-time: the same grant never works again.
			if rec := e.post(t, e.alice, c.path, withGrant); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "already redeemed") {
				t.Fatalf("second redeem: want 403 already redeemed, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestEgressRoutesRunDirectlyWhenExplicitlyDisabled(t *testing.T) {
	e := newEgressEnv(t, "FALSE") // case-insensitive
	for _, c := range egressCases(t, e.keys) {
		t.Run(c.name, func(t *testing.T) {
			rec := e.post(t, e.alice, c.path, c.body)
			if rec.Code == http.StatusAccepted {
				t.Fatalf("dual control is off: got a 202 proposal: %s", rec.Body.String())
			}
			if rec.Code != c.afterGate {
				t.Fatalf("direct path: want %d, got %d: %s", c.afterGate, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestKeyDualControlDefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		val   string
		unset bool
		want  bool
	}{
		{unset: true, want: true},
		{val: "", want: true},
		{val: "true", want: true},
		{val: "TRUE", want: true},
		{val: "garbage", want: true},
		{val: "false", want: false},
		{val: " False ", want: false},
	} {
		t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", tc.val)
		if tc.unset {
			if err := os.Unsetenv("KRYPTKEEPER_KEY_DUAL_CONTROL"); err != nil {
				t.Fatal(err)
			}
		}
		if got := NewKeyDualControlFromEnv(newTestPendingStore(t)).Enabled(); got != tc.want {
			t.Errorf("KRYPTKEEPER_KEY_DUAL_CONTROL=%q unset=%v: Enabled()=%v, want %v", tc.val, tc.unset, got, tc.want)
		}
	}
}

func TestDualControlFailsClosedWithoutQueue(t *testing.T) {
	dc := &KeyDualControl{enabled: true, redeemed: map[string]bool{}} // no store
	if !dc.Enabled() {
		t.Fatal("guard must stay on when the queue is unreachable")
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if dc.gate(rec, r, nil, stubAuditProvider{}, AuthPrincipal{ID: "alice"}, egressGate{actionType: keyActionBackup, keyID: backupScope}) {
		t.Fatal("gate must not let an egress through without a queue")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestEgressGrantExpires(t *testing.T) {
	store := newTestPendingStore(t)
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "true")
	dc := NewKeyDualControlFromEnv(store)
	ctx := context.Background()
	auth := newReportsTestAuth(t)
	alice := AuthPrincipal{ID: "alice", AuthType: "local"}
	a, err := dc.ProposeGrant(ctx, auth, keyActionBackup, backupScope, "", alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Decide(ctx, a.ID, "approved", "bob", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-grantTTL - time.Minute).UTC().Format(time.RFC3339)
	if _, err := store.db.ExecContext(ctx, `UPDATE pending_actions SET decided_at = ? WHERE id = ?`, old, a.ID); err != nil {
		t.Fatal(err)
	}
	err = dc.AuthorizeGrant(ctx, auth, keyActionBackup, backupScope, "", alice, a.ID)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired grant must be refused, got %v", err)
	}
}

// --- separation of duties by human identity (A07-4 / LLM-006) ---

// proposeAs files a revoke proposal as proposedBy straight on the queue.
func proposeAs(t *testing.T, store PendingActionStore, proposedBy string) string {
	t.Helper()
	a, err := store.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp-sod"}`), ProposedBy: proposedBy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func mintViaAPI(t *testing.T, e *egressEnv, minterToken, principalID string) string {
	t.Helper()
	rec := e.post(t, minterToken, "/api/v1/api-keys", map[string]any{"name": "minted", "principal_id": principalID, "role": "pki-admin", "scopes": []string{"*"}})
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	var p struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Data.Token == "" {
		t.Fatalf("mint response: %s", rec.Body.String())
	}
	return p.Data.Token
}

func TestSoD_MintedKeyCannotApproveMintersProposal(t *testing.T) {
	e := newEgressEnv(t, "false")
	store := NewPendingActionStoreFromEnv()
	// alice mints a pki-admin key under an unrelated, free-text principal id.
	evil := mintViaAPI(t, e, e.alice, "totally-different-person")

	// Direction 1: alice proposes, her minted key approves -> refused.
	id := proposeAs(t, store, "alice")
	rec := e.post(t, evil, "/api/v1/pending-actions/"+id+"/approve", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("minted key approving its minter's proposal: want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// A genuinely different admin still can.
	if rec := e.post(t, e.bob, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code == http.StatusForbidden {
		t.Fatalf("a different admin must be able to approve, got 403: %s", rec.Body.String())
	}

	// Direction 2: the proposal is made WITH the minted key; its minter
	// approving it is the same person on both sides -> refused.
	id2 := proposeAs(t, store, "totally-different-person")
	if rec := e.post(t, e.alice, "/api/v1/pending-actions/"+id2+"/approve", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("minter approving a proposal made with its own key: want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := e.post(t, e.bob, "/api/v1/pending-actions/"+id2+"/approve", nil); rec.Code == http.StatusForbidden {
		t.Fatalf("a different admin must be able to approve, got 403: %s", rec.Body.String())
	}
}

func TestSoD_KeyMintedByMintedKeyResolvesToFirstHuman(t *testing.T) {
	e := newEgressEnv(t, "false")
	store := NewPendingActionStoreFromEnv()
	k1 := mintViaAPI(t, e, e.alice, "hop-one")
	k2 := mintViaAPI(t, e, k1, "hop-two") // minted BY a minted key

	rec := e.post(t, k2, "/api/v1/pending-actions/"+proposeAs(t, store, "alice")+"/approve", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("two-hop key approving alice's proposal: want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// The creator recorded on each key is the canonical human, not the key.
	for _, r := range e.auth.ListAPIKeys() {
		if (r.PrincipalID == "hop-one" || r.PrincipalID == "hop-two") && r.CreatedBy != "alice" {
			t.Errorf("key %s CreatedBy = %q, want alice", r.PrincipalID, r.CreatedBy)
		}
	}
}

func TestSoD_BootstrapTokenCannotApproveOrReject(t *testing.T) {
	e := newEgressEnv(t, "false")
	store := NewPendingActionStoreFromEnv()
	id := proposeAs(t, store, "alice")
	for _, verb := range []string{"approve", "reject"} {
		rec := e.post(t, "test-token", "/api/v1/pending-actions/"+id+"/"+verb, nil)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "bootstrap") {
			t.Fatalf("bootstrap %s: want 403 naming the bootstrap token, got %d: %s", verb, rec.Code, rec.Body.String())
		}
	}
	got, _, _ := store.Get(context.Background(), id)
	if got.Status != "pending" {
		t.Fatalf("action must stay pending, got %s", got.Status)
	}
}

// --- execute exactly once (A01-003) ---

func TestApproveRaceExecutesOnce(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	store := newTestPendingStore(t)
	store.db.SetMaxOpenConns(1) // one in-process connection: no SQLITE_BUSY noise, the CAS is what's under test

	var runs atomic.Int32
	exec := func(ctx context.Context, a PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		runs.Add(1)
		time.Sleep(20 * time.Millisecond) // widen the window the old order lost
		return json.RawMessage(`{"ok":true}`), nil
	}
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, store, stubAuditProvider{},
		map[string]ActionExecutor{"count_once": exec})
	created, err := store.Create(context.Background(), PendingAction{ActionType: "count_once", ProposedBy: "proposer"})
	if err != nil {
		t.Fatal(err)
	}

	const approvers = 5
	tokens := make([]string, approvers)
	for i := range tokens {
		tokens[i] = mintAdminToken(t, auth, "approver-"+string(rune('a'+i)), "")
	}
	codes := make([]int, approvers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < approvers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, bearerReq(tokens[i], http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/approve", nil))
			codes[i] = rec.Code
		}()
	}
	close(start)
	wg.Wait()

	if n := runs.Load(); n != 1 {
		t.Fatalf("executor ran %d times, want exactly 1", n)
	}
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if ok != 1 || conflict != approvers-1 {
		t.Fatalf("want 1x200 + %dx409, got codes %v", approvers-1, codes)
	}
	got, _, _ := store.Get(context.Background(), created.ID)
	if got.Status != "approved" {
		t.Fatalf("final status = %s, want approved", got.Status)
	}
}

func TestApproveFailedExecutorRecordsFailure(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	store := newTestPendingStore(t)
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, store, stubAuditProvider{},
		map[string]ActionExecutor{"boom": func(context.Context, PendingAction, AuthPrincipal) (json.RawMessage, error) {
			return nil, context.DeadlineExceeded
		}})
	created, _ := store.Create(context.Background(), PendingAction{ActionType: "boom", ProposedBy: "proposer"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, auth, "approver", ""), http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/approve", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", rec.Code, rec.Body.String())
	}
	got, _, _ := store.Get(context.Background(), created.ID)
	if got.Status != "failed" {
		t.Fatalf("status = %s, want failed", got.Status)
	}
	// A failed action cannot be approved again.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, auth, "approver-2", ""), http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/approve", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-approve of failed action: want 409, got %d", rec.Code)
	}
}
