// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "acme-test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := NewSQLiteStore(db, false)
	if err := s.EnsureSchema(); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func TestSQLiteStore_AccountRoundTrip(t *testing.T) {
	s := newTestSQLiteStore(t)
	acct := &Account{
		ID:        "acct-test-1",
		Contact:   []string{"mailto:test@example.com"},
		Status:    "valid",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.SaveAccount(acct); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok := s.LoadAccount(acct.ID)
	if !ok {
		t.Fatal("account not found after save")
	}
	if got.Status != "valid" || len(got.Contact) != 1 || got.Contact[0] != acct.Contact[0] {
		t.Fatalf("unexpected account: %+v", got)
	}
}

func TestSQLiteStore_OrderRoundTrip(t *testing.T) {
	s := newTestSQLiteStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	order := &Order{
		ID:             "order-test-1",
		AccountID:      "acct-1",
		Status:         "pending",
		Identifiers:    []Identifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/authz-1"},
		Finalize:       "https://acme.example.com/acme/finalize/order-test-1",
		Expires:        now.Add(7 * 24 * time.Hour),
		CreatedAt:      now,
	}
	if err := s.SaveOrder(order); err != nil {
		t.Fatalf("save order: %v", err)
	}

	// Update status (simulates finalize completing).
	order.Status = "valid"
	order.Certificate = "https://acme.example.com/acme/cert/cert-1"
	if err := s.SaveOrder(order); err != nil {
		t.Fatalf("update order: %v", err)
	}

	got, ok := s.LoadOrder("order-test-1")
	if !ok {
		t.Fatal("order not found")
	}
	if got.Status != "valid" {
		t.Fatalf("expected valid, got %q", got.Status)
	}
	if got.Certificate != order.Certificate {
		t.Fatalf("certificate URL mismatch: %q", got.Certificate)
	}
	if len(got.Identifiers) != 1 || got.Identifiers[0].Value != "example.com" {
		t.Fatalf("identifier mismatch: %+v", got.Identifiers)
	}
}

func TestSQLiteStore_AuthzRoundTrip(t *testing.T) {
	s := newTestSQLiteStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	validated := now
	authz := &Authorization{
		ID:         "authz-test-1",
		Identifier: Identifier{Type: "dns", Value: "example.com"},
		Status:     "pending",
		Challenges: []Challenge{
			{Type: "http-01", Token: "tok123", Status: "valid", Validated: &validated},
		},
		Expires: now.Add(7 * 24 * time.Hour),
	}
	if err := s.SaveAuthz(authz); err != nil {
		t.Fatalf("save authz: %v", err)
	}

	authz.Status = "valid"
	if err := s.SaveAuthz(authz); err != nil {
		t.Fatalf("update authz: %v", err)
	}

	got, ok := s.LoadAuthz("authz-test-1")
	if !ok {
		t.Fatal("authz not found")
	}
	if got.Status != "valid" {
		t.Fatalf("expected valid, got %q", got.Status)
	}
	if len(got.Challenges) != 1 || got.Challenges[0].Token != "tok123" {
		t.Fatalf("challenge mismatch: %+v", got.Challenges)
	}
}

func TestSQLiteStore_CertRoundTrip(t *testing.T) {
	s := newTestSQLiteStore(t)
	pem := []byte("-----BEGIN CERTIFICATE-----\nfakepem\n-----END CERTIFICATE-----\n")
	if err := s.SaveCert("cert-test-1", pem); err != nil {
		t.Fatalf("save cert: %v", err)
	}
	got, ok := s.LoadCert("cert-test-1")
	if !ok {
		t.Fatal("cert not found")
	}
	if string(got) != string(pem) {
		t.Fatalf("pem mismatch")
	}
}

func TestSQLiteStore_EABKeyRoundTrip(t *testing.T) {
	s := newTestSQLiteStore(t)
	key := &EABKey{KID: "kid-1", MACKey: []byte("mac-secret-bytes"), CreatedAt: time.Now().UTC()}
	if err := s.SaveEABKey(key); err != nil {
		t.Fatalf("save eab key: %v", err)
	}
	got, ok := s.LoadEABKey("kid-1")
	if !ok {
		t.Fatal("eab key not found")
	}
	if string(got.MACKey) != string(key.MACKey) {
		t.Fatalf("mac key mismatch: got %q want %q", got.MACKey, key.MACKey)
	}
	if got.Disabled {
		t.Fatal("expected Disabled=false")
	}

	// Upsert with disabled=true.
	key.Disabled = true
	if err := s.SaveEABKey(key); err != nil {
		t.Fatalf("update eab key: %v", err)
	}
	got2, ok := s.LoadEABKey("kid-1")
	if !ok {
		t.Fatal("eab key not found after update")
	}
	if !got2.Disabled {
		t.Fatal("expected Disabled=true after update")
	}
}

func TestSQLiteStore_LoadEABKeyMissing(t *testing.T) {
	s := newTestSQLiteStore(t)
	if _, ok := s.LoadEABKey("no-such-kid"); ok {
		t.Fatal("expected not found for missing kid")
	}
}

func TestSQLiteStore_BindAccountEAB(t *testing.T) {
	s := newTestSQLiteStore(t)
	if err := s.BindAccountEAB("acct-1", "kid-1"); err != nil {
		t.Fatalf("bind account eab: %v", err)
	}
	// Re-bind (upsert) to a different kid should not error.
	if err := s.BindAccountEAB("acct-1", "kid-2"); err != nil {
		t.Fatalf("rebind account eab: %v", err)
	}
}

func TestSQLiteStore_ListOrdersSurvivesReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "acme-persist.db")

	// First process: create and save an order.
	func() {
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open db1: %v", err)
		}
		defer db.Close()
		s := NewSQLiteStore(db, false)
		if err := s.EnsureSchema(); err != nil {
			t.Fatalf("schema: %v", err)
		}
		now := time.Now().UTC()
		if err := s.SaveOrder(&Order{
			ID:          "persist-order-1",
			Status:      "ready",
			Identifiers: []Identifier{{Type: "dns", Value: "persist.example.com"}},
			Finalize:    "https://acme.example.com/acme/finalize/persist-order-1",
			Expires:     now.Add(7 * 24 * time.Hour),
			CreatedAt:   now,
		}); err != nil {
			t.Fatalf("save: %v", err)
		}
	}()

	// Second process: reopen same DB and verify order is present.
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db2: %v", err)
	}
	defer db2.Close()
	s2 := NewSQLiteStore(db2, false)
	if err := s2.EnsureSchema(); err != nil {
		t.Fatalf("schema2: %v", err)
	}
	orders := s2.ListOrders()
	if len(orders) != 1 || orders[0].ID != "persist-order-1" {
		t.Fatalf("expected 1 persisted order, got %d", len(orders))
	}
	if orders[0].Status != "ready" {
		t.Fatalf("expected ready, got %q", orders[0].Status)
	}
}

// TestSQLiteStore_AccountKeyResolvesAfterReopen is G-90's core proof: an
// account created before a restart must still authenticate by kid after one.
// It persists an account with a real ECDSA account key, reopens the store
// against the same database file (a second, independent *sql.DB simulating
// a process restart, matching TestSQLiteStore_ListOrdersSurvivesReopen's
// pattern), and resolves the account key through the exact path
// verifyJWS uses for every kid-authenticated ACME request.
func TestSQLiteStore_AccountKeyResolvesAfterReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "acme-account-persist.db")
	baseURL := "https://acme.example.com"

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, err := publicKeyToJWK(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToJWK: %v", err)
	}
	thumbprint, err := jwkThumbprint(jwk)
	if err != nil {
		t.Fatalf("jwkThumbprint: %v", err)
	}

	// First process: create the account and persist it.
	func() {
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open db1: %v", err)
		}
		defer db.Close()
		s := NewSQLiteStore(db, false)
		if err := s.EnsureSchema(); err != nil {
			t.Fatalf("schema: %v", err)
		}
		acct := &Account{
			ID:            "acct-restart-1",
			Key:           &priv.PublicKey,
			KeyThumbprint: thumbprint,
			Status:        "valid",
			CreatedAt:     time.Now().UTC().Truncate(time.Second),
		}
		if err := s.SaveAccount(acct); err != nil {
			t.Fatalf("save account: %v", err)
		}
	}()

	// Second process: reopen the same database file (simulating a restart).
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db2: %v", err)
	}
	defer db2.Close()
	s2 := NewSQLiteStore(db2, false)
	if err := s2.EnsureSchema(); err != nil {
		t.Fatalf("schema2: %v", err)
	}

	got, ok := s2.LoadAccount("acct-restart-1")
	if !ok {
		t.Fatal("account not found after reopen")
	}
	if got.KeyThumbprint != thumbprint {
		t.Fatalf("thumbprint changed across restart: got %q want %q", got.KeyThumbprint, thumbprint)
	}
	if got.Key == nil {
		t.Fatal("account key is nil after restart -- kid authentication is impossible")
	}
	gotECDSA, ok := got.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("reconstructed key has type %T, want *ecdsa.PublicKey", got.Key)
	}

	// The persisted JWK must round-trip to the SAME thumbprint newAccount
	// deduped on, not just a key that happens to verify -- this is what
	// catches a truncated/misencoded coordinate (e.g. a stripped leading
	// zero byte) that signature verification alone would not.
	gotJWK, err := publicKeyToJWK(gotECDSA)
	if err != nil {
		t.Fatalf("publicKeyToJWK(reconstructed): %v", err)
	}
	gotThumbprint, err := jwkThumbprint(gotJWK)
	if err != nil {
		t.Fatalf("jwkThumbprint(reconstructed): %v", err)
	}
	if gotThumbprint != got.KeyThumbprint {
		t.Fatalf("reconstructed key's own thumbprint %q != stored thumbprint %q -- persisted JWK is not the key the thumbprint was derived from", gotThumbprint, got.KeyThumbprint)
	}

	// Prove the key is actually usable for verification, not just structurally present.
	sum := sha256.Sum256([]byte("POST /acme/order/order-1"))
	r, sVal, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.Verify(gotECDSA, sum[:], r, sVal) {
		t.Fatal("signature verification failed against the key reconstructed after restart")
	}

	// End-to-end through the same call verifyJWS makes for a kid-authenticated
	// request, not just LoadAccount directly.
	srv := NewServerWithStore(baseURL, nil, "ca-1", s2, nil)
	kid := baseURL + "/acme/account/acct-restart-1"
	resolved, err := srv.resolveAccountKey(kid)
	if err != nil {
		t.Fatalf("resolveAccountKey after restart: %v", err)
	}
	resolvedECDSA, ok := resolved.(*ecdsa.PublicKey)
	if !ok || resolvedECDSA.X.Cmp(priv.PublicKey.X) != 0 || resolvedECDSA.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("resolveAccountKey returned a different key than was saved")
	}
}

// saveAndLoadAccountKey saves acct's key via SaveAccount, reloads it via
// LoadAccount on the same store, and returns the reconstructed key -- the
// scanAccount round trip every TestSQLiteStore_AccountKey_* algorithm test
// exercises.
func saveAndLoadAccountKey(t *testing.T, s *SQLiteStore, id string, pub crypto.PublicKey) crypto.PublicKey {
	t.Helper()
	acct := &Account{
		ID:        id,
		Key:       pub,
		Status:    "valid",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.SaveAccount(acct); err != nil {
		t.Fatalf("save account: %v", err)
	}
	got, ok := s.LoadAccount(id)
	if !ok {
		t.Fatal("account not found after save")
	}
	if got.Key == nil {
		t.Fatal("reconstructed key is nil")
	}
	return got.Key
}

// TestSQLiteStore_AccountKey_ES256 covers acceptance criterion 3 for the
// ECDSA P-256 account keys verifyJWSSignature accepts as "ES256".
func TestSQLiteStore_AccountKey_ES256(t *testing.T) {
	s := newTestSQLiteStore(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, ok := saveAndLoadAccountKey(t, s, "acct-es256", &priv.PublicKey).(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", pub)
	}
	sum := sha256.Sum256([]byte("es256 payload"))
	r, sVal, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.Verify(pub, sum[:], r, sVal) {
		t.Fatal("ES256 signature did not verify against the reconstructed key")
	}
}

// TestSQLiteStore_AccountKey_RS256 covers acceptance criterion 3 for the RSA
// account keys verifyJWSSignature accepts as "RS256". 2048 bits: jwk.publicKey
// (jws.go) rejects anything smaller.
func TestSQLiteStore_AccountKey_RS256(t *testing.T) {
	s := newTestSQLiteStore(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, ok := saveAndLoadAccountKey(t, s, "acct-rs256", &priv.PublicKey).(*rsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *rsa.PublicKey", pub)
	}
	sum := sha256.Sum256([]byte("rs256 payload"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("RS256 signature did not verify against the reconstructed key: %v", err)
	}
}

// TestSQLiteStore_AccountKey_EdDSA covers acceptance criterion 3 for the
// Ed25519 account keys verifyJWSSignature accepts as "EdDSA".
func TestSQLiteStore_AccountKey_EdDSA(t *testing.T) {
	s := newTestSQLiteStore(t)
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, ok := saveAndLoadAccountKey(t, s, "acct-eddsa", pubKey).(ed25519.PublicKey)
	if !ok {
		t.Fatalf("got %T, want ed25519.PublicKey", pub)
	}
	msg := []byte("eddsa payload")
	sig := ed25519.Sign(privKey, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("EdDSA signature did not verify against the reconstructed key")
	}
}

// TestSQLiteStore_PreUpgradeAccountFailsClosed covers acceptance criterion 4:
// a row written before G-90 (no jwk value -- SQL NULL, exactly what an
// existing acme_accounts row gets once EnsureSchema's best-effort ALTER TABLE
// widens the table) must fail closed, not be treated as authenticated.
func TestSQLiteStore_PreUpgradeAccountFailsClosed(t *testing.T) {
	s := newTestSQLiteStore(t)
	baseURL := "https://acme.example.com"

	// Insert exactly what a pre-G-90 row looks like: the old 5-column INSERT,
	// omitting jwk entirely so the column is SQL NULL rather than an empty
	// string.
	_, err := s.db.Exec(
		`INSERT INTO acme_accounts (id, contact, thumbprint, status, created_at) VALUES (?,?,?,?,?)`,
		"acct-pre-upgrade", "[]", "some-thumbprint-with-no-recoverable-key", "valid",
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("seed pre-upgrade row: %v", err)
	}

	got, ok := s.LoadAccount("acct-pre-upgrade")
	if !ok {
		t.Fatal("expected pre-upgrade account to load")
	}
	if got.Key != nil {
		t.Fatalf("expected nil Key for a pre-upgrade row, got %T", got.Key)
	}

	// The actual authorization consequence: resolveAccountKey, what every
	// kid-authenticated ACME request calls, must reject it -- never fall back
	// to treating KeyThumbprint (or anything else) as sufficient to
	// authenticate an unverifiable key.
	srv := NewServerWithStore(baseURL, nil, "ca-1", s, nil)
	kid := baseURL + "/acme/account/acct-pre-upgrade"
	if _, err := srv.resolveAccountKey(kid); !errors.Is(err, errAccountNotFound) {
		t.Fatalf("resolveAccountKey for a pre-upgrade account = %v, want errAccountNotFound (unauthorized)", err)
	}
}
