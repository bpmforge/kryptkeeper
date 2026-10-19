// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kryptkeeper/internal/audittrust"
)

// W17-04: the transparency surface. The tests act as the AUDITOR —
// verifying proofs with the standalone verifiers, never trusting the
// handler's own claims.

type fixedAudit struct {
	entries   []AuditEntry
	lastOrder string
}

// ListEntries HONOURS Order the way the real DB provider does, so a
// handler that asks for the wrong direction is caught: leaf indexes are
// only stable as the log grows if the tree is built oldest-first.
func (f *fixedAudit) ListEntries(_ context.Context, q AuditListQuery) (AuditListResult, error) {
	f.lastOrder = q.Order
	out := append([]AuditEntry(nil), f.entries...)
	if q.Order != "asc" { // the provider's default is newest-first
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return AuditListResult{Entries: out, Total: len(out)}, nil
}
func (f *fixedAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

func auditTrustFixture(n int) *fixedAudit {
	f := &fixedAudit{}
	for i := 0; i < n; i++ {
		f.entries = append(f.entries, AuditEntry{
			ID: int64(i + 1), Timestamp: "2026-08-20T00:00:00Z",
			Action: "cert.issue", ActorType: "user", ActorID: "alice",
			ResourceType: "certificate", ResourceID: "fp-" + string(rune('a'+i)),
			Outcome: "success", Tenant: "default",
		})
	}
	return f
}

func auditTrustMux(t *testing.T, provider AuditProvider) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerAuditTrustHandlers(mux, newReportsTestAuth(t), nil, provider)
	return mux
}

func getJSONData(t *testing.T, mux *http.ServeMux, url string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, url, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: expected 200, got %d: %s", url, rec.Code, rec.Body.String())
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return resp.Data
}

func decodeProof(t *testing.T, raw any) [][32]byte {
	t.Helper()
	items, _ := raw.([]any)
	out := make([][32]byte, 0, len(items))
	for _, it := range items {
		b, err := base64.StdEncoding.DecodeString(it.(string))
		if err != nil || len(b) != 32 {
			t.Fatalf("bad proof node %v", it)
		}
		var h [32]byte
		copy(h[:], b)
		out = append(out, h)
	}
	return out
}

func decodeRoot(t *testing.T, s any) [32]byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s.(string))
	if err != nil || len(b) != 32 {
		t.Fatalf("bad root %v", s)
	}
	var h [32]byte
	copy(h[:], b)
	return h
}

// The auditor verifies an inclusion proof independently.
func TestAuditInclusionProofVerifiesIndependently(t *testing.T) {
	provider := auditTrustFixture(7)
	mux := auditTrustMux(t, provider)

	data := getJSONData(t, mux, "/api/v1/audit/transparency/inclusion?index=3")
	root := decodeRoot(t, data["root"])
	proof := decodeProof(t, data["audit_path"])
	size := int(data["tree_size"].(float64))

	if provider.lastOrder != "asc" {
		t.Fatalf("the tree must be built oldest-first or leaf indexes shift as the log grows; asked for %q", provider.lastOrder)
	}
	leaf := audittrust.HashLeaf(canonicalAuditLeaf(provider.entries[3]))
	if !audittrust.VerifyInclusion(3, size, leaf, root, proof) {
		t.Fatal("the served inclusion proof must verify against the served root")
	}
	// A different record must NOT verify at that position — otherwise the
	// proof proves nothing.
	other := audittrust.HashLeaf(canonicalAuditLeaf(provider.entries[4]))
	if audittrust.VerifyInclusion(3, size, other, root, proof) {
		t.Fatal("a proof must not verify for a record that is not at that index")
	}
}

// The headline property: a tampered historical record breaks consistency.
func TestAuditTamperBreaksConsistency(t *testing.T) {
	provider := auditTrustFixture(8)
	mux := auditTrustMux(t, provider)

	// Auditor records the tree head at size 5.
	before := getJSONData(t, mux, "/api/v1/audit/transparency/consistency?from=5")
	oldTree := &audittrust.MerkleLog{}
	for _, e := range provider.entries[:5] {
		oldTree.Append(canonicalAuditLeaf(e))
	}
	oldRoot := oldTree.Root()
	if !audittrust.VerifyConsistency(5, int(before["tree_size"].(float64)), oldRoot, decodeRoot(t, before["root"]), decodeProof(t, before["proof"])) {
		t.Fatal("an untampered log must be consistent with its own earlier head")
	}

	// Someone edits history: entry 2's outcome flips.
	provider.entries[2].Outcome = "denied"

	after := getJSONData(t, mux, "/api/v1/audit/transparency/consistency?from=5")
	if audittrust.VerifyConsistency(5, int(after["tree_size"].(float64)), oldRoot, decodeRoot(t, after["root"]), decodeProof(t, after["proof"])) {
		t.Fatal("a retro-edited record MUST break consistency against the earlier head")
	}
}

func TestAuditCheckpointIsSignedAndVerifiable(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	t.Setenv("AUDIT_TRANSPARENCY_SIGNING_SEED", base64.StdEncoding.EncodeToString(seed))

	mux := auditTrustMux(t, auditTrustFixture(4))
	data := getJSONData(t, mux, "/api/v1/audit/transparency/checkpoint")

	pub, err := base64.StdEncoding.DecodeString(data["public_key"].(string))
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	cp := audittrust.SignedCheckpoint{
		Size:      int(data["size"].(float64)),
		RootB64:   data["root"].(string),
		Signature: data["signature"].(string),
	}
	if _, err := audittrust.VerifyCheckpoint(ed25519.PublicKey(pub), cp); err != nil {
		t.Fatalf("the served checkpoint must verify: %v", err)
	}
}

// W22-04: with no env seed the hub generates and persists one, so the
// checkpoint endpoint works out of the box and stays verifiable across
// restarts (second call = same key).
func TestAuditCheckpointAutoProvisionsSeed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUDIT_TRANSPARENCY_SIGNING_SEED", "")
	t.Setenv("KRYPTKEEPER_DATA_DIR", dir)
	mux := auditTrustMux(t, auditTrustFixture(3))
	pubOf := func() string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/transparency/checkpoint", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				PublicKey string `json:"public_key"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		return env.Data.PublicKey
	}
	first := pubOf()
	info, err := os.Stat(filepath.Join(dir, "audit-transparency.seed"))
	if err != nil {
		t.Fatalf("seed file not persisted: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("seed file mode %v, want 0600", info.Mode().Perm())
	}
	if second := pubOf(); second != first {
		t.Fatal("second call must reuse the persisted seed")
	}
}

// The persisted-key rule has no ephemeral escape hatch: an unwritable
// data dir refuses rather than minting a key nobody can verify later.
func TestAuditCheckpointRefusesWhenSeedUnwritable(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_TRANSPARENCY_SIGNING_SEED", "")
	t.Setenv("KRYPTKEEPER_DATA_DIR", blocker)
	rec := httptest.NewRecorder()
	auditTrustMux(t, auditTrustFixture(3)).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/transparency/checkpoint", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwritable seed dir must refuse, got %d", rec.Code)
	}
}

func TestAuditCheckpointInvalidEnvSeedStaysHardError(t *testing.T) {
	t.Setenv("AUDIT_TRANSPARENCY_SIGNING_SEED", "not-a-seed")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	rec := httptest.NewRecorder()
	auditTrustMux(t, auditTrustFixture(3)).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/transparency/checkpoint", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid seed must refuse, got %d", rec.Code)
	}
}

// Pins the verifier's leaf encoding to the server's: if they drift,
// every offline proof silently fails.
func TestCanonicalLeafMatchesBootstrap(t *testing.T) {
	for _, e := range auditTrustFixture(3).entries {
		raw, _ := json.Marshal(e)
		got, err := audittrust.CanonicalLeaf(raw)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(canonicalAuditLeaf(e)) {
			t.Fatalf("leaf drift:\n%s\n%s", got, canonicalAuditLeaf(e))
		}
	}
}

func TestAuditTransparencyRequiresAuth(t *testing.T) {
	rec := httptest.NewRecorder()
	auditTrustMux(t, auditTrustFixture(3)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit/transparency/inclusion?index=0", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
