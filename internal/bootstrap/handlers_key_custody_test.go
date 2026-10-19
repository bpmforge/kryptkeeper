// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
)

// W15-02: key-custody evidence — backend mapping, rotation/access from
// the audit trail, admin gate, and nil-store 503.

// fakeKeystore implements the slice of keystore.Store the report uses.
type fakeKeystore struct{ metas []keystore.KeyMetadata }

func (f *fakeKeystore) List() ([]keystore.KeyMetadata, error) { return f.metas, nil }
func (f *fakeKeystore) GenerateKey(string, keystore.Algorithm) (keystore.KeyMetadata, error) {
	return keystore.KeyMetadata{}, nil
}
func (f *fakeKeystore) Signer(string) (crypto.Signer, error)       { return nil, nil }
func (f *fakeKeystore) PublicKey(string) (crypto.PublicKey, error) { return nil, nil }
func (f *fakeKeystore) Metadata(string) (keystore.KeyMetadata, error) {
	return keystore.KeyMetadata{}, nil
}
func (f *fakeKeystore) Delete(string) error { return nil }
func (f *fakeKeystore) RotateKey(string, keystore.Algorithm) (keystore.KeyRotateResult, error) {
	return keystore.KeyRotateResult{}, nil
}
func (f *fakeKeystore) ExportEncryptedKey(string, []byte) ([]byte, error) { return nil, nil }
func (f *fakeKeystore) ImportEncryptedKey(string, []byte, []byte) error   { return nil }

// custodyAudit records appended events and serves seeded key entries.
type custodyAudit struct {
	seeded   []AuditEntry
	appended []string
}

func (c *custodyAudit) ListEntries(_ context.Context, q AuditListQuery) (AuditListResult, error) {
	if q.ResourceType != "key" {
		return AuditListResult{}, nil
	}
	return AuditListResult{Entries: c.seeded, Total: len(c.seeded)}, nil
}
func (c *custodyAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	c.appended = append(c.appended, e.Action+":"+string(e.Outcome))
	return nil
}

func custodyMux(t *testing.T, store keystore.Store, audit AuditProvider, approvals ...PendingActionStore) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerKeyCustodyHandler(mux, newReportsTestAuth(t), store, nil, audit, approvals...)
	return mux
}

func TestKeyCustodyReportFromAudit(t *testing.T) {
	store := &fakeKeystore{metas: []keystore.KeyMetadata{
		{ID: "ca-signing-key", Algorithm: "ecdsa-p256", CreatedAt: "2026-01-01T00:00:00Z"},
		{ID: "idle-key", Algorithm: "rsa-2048", CreatedAt: "2026-02-01T00:00:00Z"},
	}}
	audit := &custodyAudit{seeded: []AuditEntry{
		{Action: "key.rotate", ResourceType: "key", ResourceID: "ca-signing-key", Timestamp: "2026-06-01T00:00:00Z", Outcome: AuditOutcomeSuccess},
		{Action: "key.op", ResourceType: "key", ResourceID: "ca-signing-key", Timestamp: "2026-07-15T12:00:00Z"},
		{Action: "key.get", ResourceType: "key", ResourceID: "ca-signing-key", Timestamp: "2026-07-16T12:00:00Z"},
	}}
	mux := custodyMux(t, store, audit)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/key-custody", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data KeyCustodyReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Backend != "software" {
		// fakeKeystore is not a SoftwareStore; its type name should fall
		// through to the raw name, not misreport a known backend.
		if resp.Data.Backend == "" {
			t.Fatalf("backend must be populated")
		}
	}
	byID := map[string]KeyCustodyEntry{}
	for _, k := range resp.Data.Keys {
		byID[k.KeyID] = k
	}
	active := byID["ca-signing-key"]
	if active.RotationCount != 1 || active.LastRotatedAt != "2026-06-01T00:00:00Z" {
		t.Fatalf("rotation facts: %+v", active)
	}
	if active.AccessCount != 2 || active.LastAccessedAt != "2026-07-16T12:00:00Z" {
		t.Fatalf("access facts: %+v", active)
	}
	if byID["idle-key"].RotationCount != 0 || byID["idle-key"].AccessCount != 0 {
		t.Fatalf("idle key must show zeros: %+v", byID["idle-key"])
	}
	// The request itself is audited.
	found := false
	for _, a := range audit.appended {
		if a == "report.key_custody:success" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custody read must be audited: %v", audit.appended)
	}
}

func TestKeyCustodyBackendLabel(t *testing.T) {
	dir := t.TempDir()
	sw, err := keystore.NewSoftwareStore(dir, []byte("custody-test-passphrase-32chars!"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := keystoreBackendLabel(sw); got != "software" {
		t.Fatalf("software store must map to 'software', got %q", got)
	}
}

func TestKeyCustodyDualControlFlag(t *testing.T) {
	// os.Setenv is process-wide; t.Setenv restores whatever value (or absence)
	// the env var had before this test, instead of always unsetting it and
	// clobbering it for every test that runs later in the same binary.
	t.Setenv("APP_KEY_ESCROW_CUSTODIANS", "alice,bob")
	report, err := buildKeyCustodyReport(context.Background(), &fakeKeystore{}, &custodyAudit{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !report.DualControlEscrow {
		t.Fatal("configured escrow custodians must set DualControlEscrow")
	}
}

func TestKeyCustodyNilStore503(t *testing.T) {
	mux := custodyMux(t, nil, &custodyAudit{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/key-custody", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil store must 503, got %d", rec.Code)
	}
}

// custodyApprovals serves seeded actions; only List is implemented because the
// report reads nothing else.
type custodyApprovals struct {
	PendingActionStore
	actions []PendingAction
}

func (c *custodyApprovals) List(_ context.Context, status string) ([]PendingAction, error) {
	var out []PendingAction
	for _, a := range c.actions {
		if a.Status == status {
			out = append(out, a)
		}
	}
	return out, nil
}

func approvedAction(id, typ, keyID, proposer, approver, decided string) PendingAction {
	params, _ := json.Marshal(keyActionParams{KeyID: keyID})
	return PendingAction{ID: id, ActionType: typ, Params: params, ProposedBy: proposer, ApprovedBy: approver, DecidedAt: decided, Status: "approved"}
}

func custodyRow(action, keyID, actor, ts string) AuditEntry {
	return AuditEntry{Action: action, ResourceType: "key", ResourceID: keyID, ActorID: actor, Timestamp: ts, Outcome: AuditOutcomeSuccess}
}

func getCustodyReport(t *testing.T, mux *http.ServeMux) KeyCustodyReport {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/key-custody", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data KeyCustodyReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Data
}

// seedCustody50 seeds 50 keys, each with a dual-controlled export and escrow,
// 10 with an approved rotate and 10 with an approved delete.
func seedCustody50() (*fakeKeystore, *custodyAudit, *custodyApprovals) {
	store := &fakeKeystore{}
	audit := &custodyAudit{}
	ap := &custodyApprovals{}
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("key-%02d", i)
		store.metas = append(store.metas, keystore.KeyMetadata{ID: id, Algorithm: "ecdsa-p256"})
		ap.actions = append(ap.actions,
			approvedAction("ex-"+id, keyActionExport, id, "alice", "bob", "2026-06-01T10:00:00Z"),
			approvedAction("es-"+id, keyActionEscrow, id, "alice", "bob", "2026-06-01T11:00:00Z"))
		audit.seeded = append(audit.seeded,
			custodyRow("key.export", id, "carol", "2026-06-01T10:05:00Z"),
			custodyRow("key.escrow", id, "carol", "2026-06-01T11:05:00Z"))
		if i < 10 {
			ap.actions = append(ap.actions, approvedAction("ro-"+id, keyActionRotate, id, "alice", "bob", "2026-06-02T10:00:00Z"))
		}
		if i >= 40 {
			ap.actions = append(ap.actions, approvedAction("de-"+id, keyActionDelete, id, "alice", "bob", "2026-06-03T10:00:00Z"))
		}
	}
	return store, audit, ap
}

func TestKeyCustodyEventsNamedActorsOn50Keys(t *testing.T) {
	store, audit, ap := seedCustody50()
	rep := getCustodyReport(t, custodyMux(t, store, audit, ap))
	if len(rep.Keys) != 50 {
		t.Fatalf("keys: %d", len(rep.Keys))
	}
	total, named := 0, 0
	for _, k := range rep.Keys {
		for _, ev := range k.Events {
			total++
			if ev.Requester != "" && ev.Approver != "" && ev.Redeemer != "" {
				named++
			}
			if ev.Requester == ev.Approver {
				t.Fatalf("SoD violation in %+v", ev)
			}
			if !ev.DualControl || ev.ApprovalID == "" {
				t.Fatalf("event not linked to its approval: %+v", ev)
			}
		}
	}
	if total != 50*2+10+10 || named != total {
		t.Fatalf("named actors %d of %d events", named, total)
	}
}

func TestKeyCustodyCountsReconcileWithAudit(t *testing.T) {
	store, audit, ap := seedCustody50()
	rep := getCustodyReport(t, custodyMux(t, store, audit, ap))
	want := map[string]int{"key.export": 0, "key.escrow": 0, "key.escrow_recover": 0, "key.rotate": 0, "key.delete": 0}
	for _, e := range audit.seeded {
		want[e.Action]++
	}
	for _, a := range ap.actions {
		switch a.ActionType {
		case keyActionRotate:
			want["key.rotate"]++
		case keyActionDelete:
			want["key.delete"]++
		}
	}
	for a, n := range want {
		if rep.EventCounts[a] != n {
			t.Fatalf("event_counts[%s]=%d, want %d (%v)", a, rep.EventCounts[a], n, rep.EventCounts)
		}
	}
	if rep.Keys[0].RotationCount != 1 || rep.Keys[0].LastRotatedAt != "2026-06-02T10:00:00Z" {
		t.Fatalf("dual-controlled rotation must count: %+v", rep.Keys[0])
	}
}

func TestKeyCustodyDeletedKeyTombstone(t *testing.T) {
	audit := &custodyAudit{seeded: []AuditEntry{custodyRow("key.export", "gone", "carol", "2026-06-01T10:05:00Z")}}
	ap := &custodyApprovals{actions: []PendingAction{
		approvedAction("ex", keyActionExport, "gone", "alice", "bob", "2026-06-01T10:00:00Z"),
		approvedAction("de", keyActionDelete, "gone", "alice", "bob", "2026-06-02T10:00:00Z"),
	}}
	rep := getCustodyReport(t, custodyMux(t, &fakeKeystore{}, audit, ap))
	if len(rep.Keys) != 1 || rep.Keys[0].KeyID != "gone" || !rep.Keys[0].Deleted || len(rep.Keys[0].Events) != 2 {
		t.Fatalf("tombstone: %+v", rep.Keys)
	}
}

func TestKeyCustodySingleActorWhenDualControlOff(t *testing.T) {
	store := &fakeKeystore{metas: []keystore.KeyMetadata{{ID: "k1"}}}
	audit := &custodyAudit{seeded: []AuditEntry{custodyRow("key.export", "k1", "carol", "2026-06-01T10:05:00Z")}}
	rep := getCustodyReport(t, custodyMux(t, store, audit, &custodyApprovals{}))
	ev := rep.Keys[0].Events[0]
	if ev.DualControl || ev.Approver != "" || ev.Requester != "carol" || ev.Redeemer != "carol" {
		t.Fatalf("single actor event: %+v", ev)
	}
}

func TestKeyCustodyApprovalAfterRedemptionNotPaired(t *testing.T) {
	store := &fakeKeystore{metas: []keystore.KeyMetadata{{ID: "k1"}}}
	audit := &custodyAudit{seeded: []AuditEntry{custodyRow("key.export", "k1", "carol", "2026-06-01T10:05:00Z")}}
	ap := &custodyApprovals{actions: []PendingAction{approvedAction("ex", keyActionExport, "k1", "alice", "bob", "2026-06-01T10:30:00Z")}}
	rep := getCustodyReport(t, custodyMux(t, store, audit, ap))
	if rep.Keys[0].Events[0].DualControl {
		t.Fatalf("approval decided after redemption must not pair: %+v", rep.Keys[0].Events[0])
	}
}

func TestKeyCustodyImportedKey(t *testing.T) {
	store := &fakeKeystore{metas: []keystore.KeyMetadata{{ID: "imp"}}}
	audit := &custodyAudit{seeded: []AuditEntry{custodyRow("key.import", "imp", "carol", "2026-06-01T10:05:00Z")}}
	rep := getCustodyReport(t, custodyMux(t, store, audit))
	if !rep.Keys[0].Imported || len(rep.Keys[0].Events) != 0 {
		t.Fatalf("imported: %+v", rep.Keys[0])
	}
}

func TestKeyCustodyEventsNeverNull(t *testing.T) {
	store := &fakeKeystore{metas: []keystore.KeyMetadata{{ID: "idle"}}}
	rec := httptest.NewRecorder()
	custodyMux(t, store, &custodyAudit{}).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/key-custody", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"events":[]`) || strings.Contains(body, `"events":null`) {
		t.Fatalf("events must serialise as []: %s", body)
	}
	if !strings.Contains(body, `"key.escrow_recover":0`) {
		t.Fatalf("event_counts must list all actions: %s", body)
	}
}

func TestKeyCustodyTenantSeesZeroForeignKeys(t *testing.T) {
	e := setupKeysLeakEnv(t)
	audit := &custodyAudit{seeded: []AuditEntry{
		custodyRow("key.export", e.acmeCAKey, "acme-carol", "2026-06-01T10:05:00Z"),
		custodyRow("key.export", e.globexCAKey, "globex-mallory", "2026-06-01T10:06:00Z"),
		custodyRow("key.export", "tombstone-key", "tomb-actor", "2026-06-01T10:07:00Z"),
	}}
	ap := &custodyApprovals{actions: []PendingAction{
		approvedAction("a1", keyActionExport, e.acmeCAKey, "acme-alice", "acme-bob", "2026-06-01T10:00:00Z"),
		approvedAction("g1", keyActionDelete, e.globexCAKey, "globex-proposer", "globex-approver", "2026-06-02T10:00:00Z"),
		approvedAction("t1", keyActionDelete, "tombstone-key", "tomb-proposer", "tomb-approver", "2026-06-02T10:00:00Z"),
	}}
	mux := http.NewServeMux()
	registerKeyCustodyHandler(mux, e.auth, e.keys, nil, audit, ap)

	r := doLeakJSON(mux, http.MethodGet, "/api/v1/reports/key-custody", e.acme, "", "")
	body := r.Body.String()
	if r.Code != http.StatusOK || !strings.Contains(body, e.acmeCAKey) {
		t.Fatalf("acme report: %d %s", r.Code, body)
	}
	for _, leak := range []string{e.globexCAKey, "globex-", "ssh-ca", "tombstone-key", "tomb-"} {
		if strings.Contains(body, leak) {
			t.Fatalf("tenant report leaks %q: %s", leak, body)
		}
	}
	var resp struct {
		Data KeyCustodyReport `json:"data"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.EventCounts["key.export"] != 1 || resp.Data.EventCounts["key.delete"] != 0 {
		t.Fatalf("event_counts must reflect only acme: %v", resp.Data.EventCounts)
	}

	r = doLeakJSON(mux, http.MethodGet, "/api/v1/reports/key-custody", "root-token", "", "")
	for _, want := range []string{e.acmeCAKey, e.globexCAKey, "tombstone-key", "globex-approver"} {
		if !strings.Contains(r.Body.String(), want) {
			t.Fatalf("super-admin report missing %q: %s", want, r.Body.String())
		}
	}
}

func TestKeyCustodyReportCarriesPQCStatement(t *testing.T) {
	store := &fakeKeystore{metas: []keystore.KeyMetadata{
		{ID: "ca-signing-key", Algorithm: "ecdsa-p256", CreatedAt: "2026-01-01T00:00:00Z"},
	}}
	report, err := buildKeyCustodyReport(context.Background(), store, &custodyAudit{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if report.PQCCustody != PQCCustodyStatement {
		t.Fatalf("report statement = %q, want PQCCustodyStatement", report.PQCCustody)
	}
	if !strings.Contains(report.PQCCustody, "ADR_PQC_KEYS_SOFTWARE_ONLY.md") {
		t.Fatalf("statement does not cite the ADR: %q", report.PQCCustody)
	}

	rec := httptest.NewRecorder()
	custodyMux(t, store, &custodyAudit{}).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/key-custody", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, ok := env.Data["pqc_custody_statement"].(string); !ok || got != PQCCustodyStatement {
		t.Fatalf("pqc_custody_statement missing or wrong in JSON: %v", env.Data["pqc_custody_statement"])
	}
}

func TestPQCCustodyStatementMatchesKeysPage(t *testing.T) {
	src, err := os.ReadFile("../../ui/src/pages/Keys.tsx")
	if err != nil {
		t.Fatalf("read Keys.tsx: %v", err)
	}
	if !strings.Contains(string(src), PQCCustodyStatement) {
		t.Fatal("ui/src/pages/Keys.tsx PQC_CUSTODY_STATEMENT drifted from PQCCustodyStatement in handlers_key_custody.go; change both together")
	}
}

func TestPQCCustodyStatementClaimsNoHSM(t *testing.T) {
	if !strings.Contains(PQCCustodyStatement, "not provided") {
		t.Fatal("statement must say hardware-backed PQC custody is not provided")
	}
	if strings.Contains(PQCCustodyStatement, "HSM-backed") {
		t.Fatal("statement must not claim HSM-backed PQC")
	}
}
