// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W9-05: the keys API enforces the generation policy — the exact surface
// that previously passed any algorithm straight through (G-42).

func newKeysTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	return newKeysTestMuxWithBackend(t, "")
}

// newKeysTestMuxWithBackend lets W19-19's PQC-on-HSM tests inject a backend
// label ("pkcs11") without any package-level state -- keyBackend is a plain
// constructor argument all the way down to registerKeyHandlers.
func newKeysTestMuxWithBackend(t *testing.T, keyBackend string) *http.ServeMux {
	t.Helper()
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("keys-policy-test-passphrase-32b!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProvider{}, keyBackend)
	return mux
}

func postKeyGenerate(t *testing.T, mux *http.ServeMux, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestKeyGenerateRefusesBelowFloorWithCitedRule(t *testing.T) {
	mux := newKeysTestMux(t)

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "weak-ca-key", "algorithm": "RSA-2048", "purpose": "ca",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 policy refusal, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "min_rsa_bits") {
		t.Fatalf("refusal must cite the rule, got: %s", rec.Body.String())
	}
}

func TestKeyGenerateAllowsPolicyCompliantRequest(t *testing.T) {
	mux := newKeysTestMux(t)

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "good-key", "algorithm": "ECDSA-P256",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKeyGenerateRefusesUnknownAlgorithmAtThePolicy(t *testing.T) {
	mux := newKeysTestMux(t)

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "des-key", "algorithm": "DES",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "allowed_algorithms") {
		t.Fatalf("refusal must cite the rule, got: %s", rec.Body.String())
	}
}

// TestKeyGenerateRefusesPQCOnHSMBackendWithADRReference covers W19-19: the
// UAT (W19-08) observed a bare 503 with no explanation and, worse, no way to
// tell it apart from a real backend outage. The refusal must be a 422 that
// names the ADR and creates no token object.
func TestKeyGenerateRefusesPQCOnHSMBackendWithADRReference(t *testing.T) {
	mux := newKeysTestMuxWithBackend(t, "pkcs11")

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "pqc-key", "algorithm": string(keystore.MLDSA65),
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md") {
		t.Fatalf("refusal must cite the ADR, got: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "software-keystore-only") {
		t.Fatalf("refusal must say PQC keys are software-keystore-only, got: %s", rec.Body.String())
	}

	// No token object: the key must not exist in the underlying store.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/keys/pqc-key", nil)
	getReq.Header.Set("Authorization", "Bearer test-token")
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("expected the refused key to not exist, got %d: %s", getRec.Code, getRec.Body.String())
	}
}

// TestKeyGenerateAllowsPQCOnSoftwareBackend proves the refusal is
// backend-scoped, not algorithm-scoped: PQC on the software backend
// (the default/empty activeKeyBackend) still succeeds.
func TestKeyGenerateAllowsPQCOnSoftwareBackend(t *testing.T) {
	mux := newKeysTestMux(t)

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "pqc-software-key", "algorithm": string(keystore.MLDSA65),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- W23-22: cancel scheduled key deletion under dual control ---

// cancellableStore is a software store that also reports a scheduled deletion
// window, standing in for a cloud KMS key in PendingDeletion. It records calls
// so tests can prove the provider was (or was not) touched.
type cancellableStore struct {
	keystore.Store
	can        bool
	cancels    int
	deletes    int
	cancelErr  error
	canceledID string
	pending    []keystore.KeyMetadata
}

func (c *cancellableStore) PendingDeletions(time.Time) []keystore.KeyMetadata { return c.pending }

func (c *cancellableStore) CanCancelDeletion(string, time.Time) (bool, error) { return c.can, nil }

func (c *cancellableStore) CancelDeletion(_ context.Context, id string) error {
	c.cancels++
	c.canceledID = id
	return c.cancelErr
}

func (c *cancellableStore) Delete(id string) error {
	c.deletes++
	return c.Store.Delete(id)
}

// cancelRecordingAudit keeps appended entries for assertions.
type cancelRecordingAudit struct {
	stubAuditProvider
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *cancelRecordingAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *cancelRecordingAudit) outcomes(action string) []AuditOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditOutcome
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e.Outcome)
		}
	}
	return out
}

type cancelHarness struct {
	mux   *http.ServeMux
	auth  *Authenticator
	queue PendingActionStore
	audit *cancelRecordingAudit
	soft  keystore.Store
	store *cancellableStore
}

func newCancelHarness(t *testing.T, dualControlOn bool) *cancelHarness {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", map[bool]string{true: "true", false: "false"}[dualControlOn])
	auth := NewAuthenticatorFromEnv()
	soft, err := keystore.NewSoftwareStore(t.TempDir(), []byte("cancel-deletion-test-pass-32byt!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { soft.Close() })
	store := &cancellableStore{Store: soft, can: true}
	queue := NewPendingActionStoreFromEnv()
	if err := queue.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	audit := &cancelRecordingAudit{}
	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, store, audit, "")
	registerPendingActionHandlers(mux, auth, NewFileCertificateProviderFromEnv(), queue, audit, nil, store)
	return &cancelHarness{mux: mux, auth: auth, queue: queue, audit: audit, soft: soft, store: store}
}

func (h *cancelHarness) do(token, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, bearerReq(token, method, path, nil))
	return rec
}

func (h *cancelHarness) propose(t *testing.T, id string) string {
	t.Helper()
	rec := h.do("test-token", http.MethodPost, "/api/v1/keys/"+id+"/cancel-deletion")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data struct {
			ActionID string `json:"action_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Data.ActionID == "" {
		t.Fatalf("no action_id in %s", rec.Body.String())
	}
	return out.Data.ActionID
}

func TestCancelDeletion_Returns202WithActionID(t *testing.T) {
	h := newCancelHarness(t, true)
	id := h.propose(t, "cloud-k")
	a, ok, err := h.queue.Get(context.Background(), id)
	if err != nil || !ok || a.ActionType != keyActionCancelDelete || a.Status != "pending" {
		t.Fatalf("queued action = %+v ok=%v err=%v", a, ok, err)
	}
	if h.store.cancels != 0 {
		t.Fatal("a proposal must not touch the provider")
	}
}

func TestCancelDeletion_AfterApprovalKeyEnabled(t *testing.T) {
	h := newCancelHarness(t, true)
	id := h.propose(t, "cloud-k")

	// Proposer cannot approve their own proposal.
	if rec := h.do("test-token", http.MethodPost, "/api/v1/pending-actions/"+id+"/approve"); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval = %d, want 403", rec.Code)
	}
	rec := h.do(mintAdminToken(t, h.auth, "approver-two", ""), http.MethodPost, "/api/v1/pending-actions/"+id+"/approve")
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	if h.store.cancels != 1 || h.store.canceledID != "cloud-k" {
		t.Fatalf("CancelDeletion calls = %d for %q, want exactly 1 for cloud-k", h.store.cancels, h.store.canceledID)
	}
	a, _, _ := h.queue.Get(context.Background(), id)
	if a.Status != "approved" || !strings.Contains(string(a.Result), "cloud-k") {
		t.Fatalf("action after approval = %+v", a)
	}
}

func TestCancelDeletion_ApprovalFailsWhenWindowClosedMeanwhile(t *testing.T) {
	h := newCancelHarness(t, true)
	id := h.propose(t, "cloud-k")
	h.store.can = false // window passed while the proposal waited
	rec := h.do(mintAdminToken(t, h.auth, "approver-two", ""), http.MethodPost, "/api/v1/pending-actions/"+id+"/approve")
	if rec.Code != http.StatusServiceUnavailable || h.store.cancels != 0 {
		t.Fatalf("approve = %d, cancels = %d; want 503 and no provider call", rec.Code, h.store.cancels)
	}
	if a, _, _ := h.queue.Get(context.Background(), id); a.Status != "failed" {
		t.Fatalf("status = %s, want failed", a.Status)
	}
}

func TestCancelDeletion_SoftwareKeyIs409(t *testing.T) {
	h := newCancelHarness(t, true)
	// A plain software store is not a DeletionCanceller at all.
	mux := http.NewServeMux()
	registerKeyHandlers(mux, h.auth, h.soft, h.audit, "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq("test-token", http.MethodPost, "/api/v1/keys/some-key/cancel-deletion", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("software key = %d %s, want 409", rec.Code, rec.Body.String())
	}
	pending, _ := h.queue.List(context.Background(), "pending")
	if len(pending) != 0 {
		t.Fatal("a refused cancel must not queue anything")
	}
}

func TestCancelDeletion_OutsideWindowIs409(t *testing.T) {
	h := newCancelHarness(t, true)
	h.store.can = false
	rec := h.do("test-token", http.MethodPost, "/api/v1/keys/cloud-k/cancel-deletion")
	if rec.Code != http.StatusConflict {
		t.Fatalf("outside window = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if pending, _ := h.queue.List(context.Background(), "pending"); len(pending) != 0 {
		t.Fatal("a refused cancel must not queue anything")
	}
}

func TestCancelDeletion_RouteIsPostOnly(t *testing.T) {
	h := newCancelHarness(t, true)
	if rec := h.do("test-token", http.MethodGet, "/api/v1/keys/cloud-k/cancel-deletion"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", rec.Code)
	}
}

func TestCancelDeletion_DirectWhenDualControlOff(t *testing.T) {
	h := newCancelHarness(t, false)
	rec := h.do("test-token", http.MethodPost, "/api/v1/keys/cloud-k/cancel-deletion")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cancelled"`) || h.store.cancels != 1 {
		t.Fatalf("direct cancel = %d %s cancels=%d", rec.Code, rec.Body.String(), h.store.cancels)
	}
	if got := h.audit.outcomes("key.destroy_cancel"); len(got) != 1 || got[0] != AuditOutcomeSuccess {
		t.Fatalf("audit = %v, want [success]", got)
	}
}

func TestCancelDeletion_EmitsKeyDestroyCancelAudit(t *testing.T) {
	h := newCancelHarness(t, true)
	h.propose(t, "cloud-k")
	h.store.can = false
	h.do("test-token", http.MethodPost, "/api/v1/keys/cloud-k/cancel-deletion")
	got := h.audit.outcomes("key.destroy_cancel")
	if len(got) != 2 || got[0] != AuditOutcomeProposed || got[1] != AuditOutcomeDenied {
		t.Fatalf("key.destroy_cancel outcomes = %v, want [proposed denied]", got)
	}
}

// --- delete guard for a key that backs an active CA (propose AND execute) ---

func caBackedHarness(t *testing.T, dualControlOn bool) (*cancelHarness, string, ca.Store) {
	t.Helper()
	h := newCancelHarness(t, dualControlOn)
	caStore := ca.NewMemStore()
	engine := ca.NewEngine(h.store, caStore)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return h, root.KeyID, caStore
}

func TestDeleteRefusedAtProposeWhenKeyBacksActiveCA(t *testing.T) {
	h, keyID, caStore := caBackedHarness(t, true)
	SetActiveCAStore(caStore)
	t.Cleanup(func() { SetActiveCAStore(nil) })

	rec := h.do("test-token", http.MethodDelete, "/api/v1/keys/"+keyID)
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete of CA-backed key = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if pending, _ := h.queue.List(context.Background(), "pending"); len(pending) != 0 {
		t.Fatalf("a refused delete must not create a pending row, got %d", len(pending))
	}
	if h.store.deletes != 0 {
		t.Fatal("keys.Delete must not run")
	}
}

func TestDeleteRefusedAtExecuteWhenKeyBecameCABacked(t *testing.T) {
	h, keyID, caStore := caBackedHarness(t, true)
	// Proposed while no CA store is registered, i.e. while the guard cannot
	// see the CA; the CA becomes visible before approval.
	rec := h.do("test-token", http.MethodDelete, "/api/v1/keys/"+keyID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose = %d %s", rec.Code, rec.Body.String())
	}
	pending, _ := h.queue.List(context.Background(), "pending")
	if len(pending) != 1 {
		t.Fatalf("pending = %d", len(pending))
	}
	SetActiveCAStore(caStore)
	t.Cleanup(func() { SetActiveCAStore(nil) })

	rec = h.do(mintAdminToken(t, h.auth, "approver-two", ""), http.MethodPost, "/api/v1/pending-actions/"+pending[0].ID+"/approve")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "refusing to delete") {
		t.Fatalf("approve = %d %s, want 503 refusing to delete", rec.Code, rec.Body.String())
	}
	if h.store.deletes != 0 {
		t.Fatal("keys.Delete must never be called for a CA-backed key")
	}
	if _, err := h.soft.PublicKey(keyID); err != nil {
		t.Fatalf("CA key must be untouched: %v", err)
	}
}

// W23-23: GET /keys lists pending-deletion keys with state and purge date.
func TestKeyList_IncludesPendingDeletionKeys(t *testing.T) {
	h := newCancelHarness(t, false)
	h.store.pending = []keystore.KeyMetadata{{
		ID: "cloud-gone", Algorithm: keystore.ECDSAP256, CreatedAt: "2026-01-01T00:00:00Z",
		State: "pending_deletion", DeletionScheduledAt: "2026-11-01T00:00:00Z",
	}}
	rec := h.do("test-token", http.MethodGet, "/api/v1/keys")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data []keystore.KeyMetadata `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Data) != 1 || out.Data[0].ID != "cloud-gone" || out.Data[0].State != "pending_deletion" ||
		out.Data[0].DeletionScheduledAt != "2026-11-01T00:00:00Z" {
		t.Fatalf("list = %+v, want the pending-deletion key with state and date", out.Data)
	}
}
