// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func custodyMux(t *testing.T, store keystore.Store, audit AuditProvider) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerKeyCustodyHandler(mux, newReportsTestAuth(t), store, audit)
	return mux
}

func TestKeyCustodyReportFromAudit(t *testing.T) {
	store := &fakeKeystore{metas: []keystore.KeyMetadata{
		{ID: "ca-signing-key", Algorithm: "ecdsa-p256", CreatedAt: "2026-01-01T00:00:00Z"},
		{ID: "idle-key", Algorithm: "rsa-2048", CreatedAt: "2026-02-01T00:00:00Z"},
	}}
	audit := &custodyAudit{seeded: []AuditEntry{
		{Action: "key.rotate", ResourceType: "key", ResourceID: "ca-signing-key", Timestamp: "2026-06-01T00:00:00Z"},
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
