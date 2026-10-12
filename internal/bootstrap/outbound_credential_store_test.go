// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func newFreshOutboundCredentialStore(t *testing.T, passphrase []byte) *sqliteOutboundCredentialStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "outbound-credentials-fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteOutboundCredentialStore{db: db, passphrase: passphrase}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}
	return s
}

func TestSealOpenEnvelope_RoundTrips(t *testing.T) {
	passphrase := []byte("correct-horse-battery-staple")
	plaintext := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-material\n-----END OPENSSH PRIVATE KEY-----") // secret-scan:allow fake fixture

	envelope, err := sealEnvelope(passphrase, plaintext)
	if err != nil {
		t.Fatalf("sealEnvelope: %v", err)
	}
	got, err := openEnvelope(passphrase, envelope)
	if err != nil {
		t.Fatalf("openEnvelope: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

// TestSealEnvelope_DifferentCallsProduceDifferentCiphertext is the
// discriminating test for fresh salt+nonce per call: a lazily-reused
// salt/nonce would produce byte-identical envelopes for identical
// plaintext, which breaks AES-GCM's confidentiality guarantee.
func TestSealEnvelope_DifferentCallsProduceDifferentCiphertext(t *testing.T) {
	passphrase := []byte("correct-horse-battery-staple")
	plaintext := []byte("identical-plaintext-both-times")

	envelope1, err := sealEnvelope(passphrase, plaintext)
	if err != nil {
		t.Fatalf("sealEnvelope 1: %v", err)
	}
	envelope2, err := sealEnvelope(passphrase, plaintext)
	if err != nil {
		t.Fatalf("sealEnvelope 2: %v", err)
	}
	if envelope1 == envelope2 {
		t.Fatal("two Create calls with identical plaintext produced byte-identical envelopes -- salt/nonce is being reused")
	}
}

func TestOpenEnvelope_WrongPassphraseFails(t *testing.T) {
	envelope, err := sealEnvelope([]byte("right-passphrase"), []byte("secret-payload"))
	if err != nil {
		t.Fatalf("sealEnvelope: %v", err)
	}
	if _, err := openEnvelope([]byte("wrong-passphrase"), envelope); err == nil {
		t.Fatal("expected an error decrypting with the wrong passphrase, got none")
	}
}

// TestOpenEnvelope_RejectsTruncatedEnvelope proves openEnvelope bounds-checks
// DB-sourced data before slicing it, rather than trusting its shape --
// distinct from the wrong-passphrase case above (that one reaches GCM's
// auth check; a too-short envelope must never get that far).
func TestOpenEnvelope_RejectsTruncatedEnvelope(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"not base64":        "!!!not-valid-base64!!!",
		"shorter than salt": "YWJj", // "abc"
		"salt but no nonce": strings.Repeat("A", 24),
	}
	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := openEnvelope([]byte("some-passphrase"), envelope); err == nil {
				t.Fatalf("expected an error for a truncated/garbage envelope (%s), got none", name)
			}
		})
	}
}

// TestOutboundCredentialStoreSelfHealsSchemaOnFreshDB is the G-33
// regression: a brand-new database with no pre-existing
// outbound_credentials table must still work, and EnsureSchema must be
// idempotent. Round-trips real plaintext through the full store, not just
// the envelope helpers.
func TestOutboundCredentialStoreSelfHealsSchemaOnFreshDB(t *testing.T) {
	s := newFreshOutboundCredentialStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	plaintext := []byte("super-secret-ssh-key")
	created, err := s.Create(ctx, "cred-1", "prod-ssh-key", CredentialTypeSSHKey, "default", plaintext)
	if err != nil {
		t.Fatalf("Create on fresh db: %v", err)
	}
	if created.ID != "cred-1" || created.CredentialType != CredentialTypeSSHKey {
		t.Fatalf("unexpected created meta: %+v", created)
	}

	resolved, err := s.Resolve(ctx, "cred-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(resolved) != string(plaintext) {
		t.Fatalf("Resolve round-trip mismatch: got %q, want %q", resolved, plaintext)
	}

	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema again: %v", err)
	}
}

// TestOutboundCredentialStore_GetAndListNeverExposeEnvelope is the
// DISCRIMINATING test for acceptance #2 ("never returned in plaintext over
// the API"): asserts the JSON-marshaled OutboundCredentialMeta from
// Get/List contains neither the plaintext NOR the envelope anywhere in the
// output -- proves the type system, not just convention, prevents the leak.
func TestOutboundCredentialStore_GetAndListNeverExposeEnvelope(t *testing.T) {
	s := newFreshOutboundCredentialStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	const plaintextMarker = "THIS-PLAINTEXT-MUST-NEVER-LEAK-abc123"
	if _, err := s.Create(ctx, "cred-1", "leak-check", CredentialTypeAPIToken, "default", []byte(plaintextMarker)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, "cred-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	getJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal Get result: %v", err)
	}
	if strings.Contains(string(getJSON), plaintextMarker) {
		t.Fatalf("Get's JSON output contains the plaintext: %s", getJSON)
	}
	if strings.Contains(string(getJSON), "envelope") {
		t.Fatalf("Get's JSON output contains an 'envelope' field: %s", getJSON)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	listJSON, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal List result: %v", err)
	}
	if strings.Contains(string(listJSON), plaintextMarker) {
		t.Fatalf("List's JSON output contains the plaintext: %s", listJSON)
	}
	if strings.Contains(string(listJSON), "envelope") {
		t.Fatalf("List's JSON output contains an 'envelope' field: %s", listJSON)
	}
}

// TestOutboundCredentialStore_RejectsInvalidCredentialType is the L-03
// CHECK-constraint-enforced test, mirrors
// TestManagedTargetStore_RejectsInvalidEnums.
func TestOutboundCredentialStore_RejectsInvalidCredentialType(t *testing.T) {
	s := newFreshOutboundCredentialStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	if _, err := s.Create(ctx, "cred-bad", "bad-type", "carrier-pigeon", "default", []byte("x")); err == nil {
		t.Error("expected an error for an invalid credential_type, got none")
	}
}

// TestNewOutboundCredentialStoreFromEnv_FailsClosedWithNoPassphrase is the
// regression for a fail-open bug caught in advisor review: with neither
// APP_CREDENTIAL_STORE_PASSPHRASE nor KRYPTKEEPER_KEYSTORE_PASSPHRASE set,
// the constructor must return nil, not a fully working store encrypting
// under an empty passphrase (which any DB reader could then decrypt with
// zero secret knowledge -- exactly what acceptance #1 exists to prevent).
func TestNewOutboundCredentialStoreFromEnv_FailsClosedWithNoPassphrase(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "")
	t.Setenv("KRYPTKEEPER_KEYSTORE_PASSPHRASE", "")

	if s := newOutboundCredentialStoreFromEnv(); s != nil {
		t.Fatal("expected newOutboundCredentialStoreFromEnv to return nil with no passphrase configured, got a store")
	}
}

func TestOutboundCredentialStore_Delete(t *testing.T) {
	s := newFreshOutboundCredentialStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	if _, err := s.Create(ctx, "cred-1", "to-delete", CredentialTypeCloudIAM, "default", []byte("x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(ctx, "cred-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "cred-1"); err == nil {
		t.Fatal("expected Get after Delete to error, got none")
	}
	if err := s.Delete(ctx, "cred-1"); err == nil {
		t.Fatal("expected double-delete to error, got none")
	}
}

// W18-01: WinRM authenticates with a username and password, so Windows
// targets could not resolve a credential at all — the store admitted
// only ssh_key, api_token and cloud_iam.
func TestWindowsPasswordCredentialRoundTrips(t *testing.T) {
	s := newFreshOutboundCredentialStore(t, []byte("windows-cred-test-passphrase!!"))
	ctx := context.Background()

	// The payload shape is the caller's; the store treats it as opaque.
	payload := []byte(`{"username":"CORP\\svc-pki","password":"s3cret","domain":"CORP"}`)
	meta, err := s.Create(ctx, "cred-win", "win host", CredentialTypeWindowsPassword, "", payload)
	if err != nil {
		t.Fatalf("a windows_password credential must be storable: %v", err)
	}
	if meta.CredentialType != CredentialTypeWindowsPassword {
		t.Fatalf("credential type round-trip: %q", meta.CredentialType)
	}

	got, err := s.Resolve(ctx, "cred-win")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatal("resolved payload must match what was stored")
	}

	// Metadata must never carry the secret — same guarantee as every
	// other credential type.
	if bytes.Contains([]byte(meta.Name+meta.ID+meta.CredentialType), []byte("s3cret")) {
		t.Fatal("metadata leaked credential material")
	}
}

// Widening the vocabulary must not turn it into no vocabulary.
func TestUnknownCredentialTypeStillRejected(t *testing.T) {
	s := newFreshOutboundCredentialStore(t, []byte("windows-cred-test-passphrase!!"))
	if _, err := s.Create(context.Background(), "cred-x", "x", "carrier_pigeon", "", []byte(`{}`)); err == nil {
		t.Fatal("an unknown credential type must still be refused")
	}
}
