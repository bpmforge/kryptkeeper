// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
)

const testKeyPepper = "test-pepper-not-a-secret"

func openMigratedKeyDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newKeyAuth builds the Authenticator a process start would: config keys from
// env, then the persisted store attached on top of the (re)opened DB.
func newKeyAuth(t *testing.T, db *sql.DB, configKeys map[string]apiKeyRecord) *Authenticator {
	t.Helper()
	if configKeys == nil {
		configKeys = map[string]apiKeyRecord{}
	}
	a := &Authenticator{config: authValidatorConfig{
		mode: "bootstrap", apiKeyAuthEnabled: true, apiKeyPepper: testKeyPepper, apiKeys: configKeys,
	}}
	if db != nil {
		if err := a.SetAPIKeyStore(t.Context(), NewAPIKeyStore(db, false)); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func authStatus(a *Authenticator, token string) (AuthPrincipal, error) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	pd, err := a.AuthenticatePrincipalDetails(req, time.Now())
	a.touchWG.Wait() // let the async last_used_at write finish before the test reopens the DB
	return pd, err
}

func TestMintedAPIKeySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kk.db")
	db := openMigratedKeyDB(t, path)
	a1 := newKeyAuth(t, db, nil)
	expires := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	rec, token, err := a1.CreateAPIKeyAs("alice@example.test", "ci", "svc-ci", "service-account", []string{"read:certs"}, expires, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authStatus(a1, token); err != nil {
		t.Fatalf("fresh key must authenticate: %v", err)
	}

	// "Restart": a brand-new Authenticator over a freshly opened DB handle.
	db2 := openMigratedKeyDB(t, path)
	a2 := newKeyAuth(t, db2, nil)
	pd, err := authStatus(a2, token)
	if err != nil {
		t.Fatalf("minted key lost across restart: %v", err)
	}
	if pd.ID != "svc-ci" || pd.Role != "service-account" || pd.Kid != rec.Kid {
		t.Errorf("principal after restart = %+v", pd)
	}
	var got apiKeyRecord
	for _, k := range a2.ListAPIKeys() {
		if k.Kid == rec.Kid {
			got = k
		}
	}
	if got.CreatedBy != "alice@example.test" || got.ExpiresAt != expires || got.Name != "ci" || !got.Active {
		t.Errorf("metadata not preserved (FG-2 created_by must survive): %+v", got)
	}
}

func TestRevokedAPIKeyStaysRevokedAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kk.db")
	db := openMigratedKeyDB(t, path)
	a1 := newKeyAuth(t, db, nil)
	rec, token, err := a1.CreateAPIKeyAs("alice@example.test", "ci", "svc-ci", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if found, err := a1.RevokeAPIKey(rec.Kid); !found || err != nil {
		t.Fatalf("revoke failed: found=%v err=%v", found, err)
	}
	if _, err := authStatus(a1, token); err == nil {
		t.Fatal("revoked key still authenticates in-process")
	}

	a2 := newKeyAuth(t, openMigratedKeyDB(t, path), nil)
	if _, err := authStatus(a2, token); err == nil {
		t.Fatal("revoked key authenticates again after restart")
	}
	if len(a2.ListAPIKeys()) != 0 {
		t.Errorf("revoked key reloaded: %+v", a2.ListAPIKeys())
	}
}

func TestMintedAPIKeySecretIsNeverStored(t *testing.T) {
	db := openMigratedKeyDB(t, filepath.Join(t.TempDir(), "kk.db"))
	a := newKeyAuth(t, db, nil)
	_, token, err := a.CreateAPIKeyAs("alice@example.test", "ci", "svc-ci", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secret := token[strings.LastIndex(token, "_")+1:]
	rows, err := db.Query(`SELECT * FROM minted_api_keys`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	n := 0
	for rows.Next() {
		n++
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, v := range vals {
			s, _ := v.(string)
			if strings.Contains(s, secret) || strings.Contains(s, token) {
				t.Errorf("column %s holds the secret/token", cols[i])
			}
		}
	}
	if n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	var verifier string
	if err := db.QueryRow(`SELECT secret_verifier FROM minted_api_keys`).Scan(&verifier); err != nil || verifier != apiKeyVerifier(secret, testKeyPepper) {
		t.Errorf("secret_verifier must be the HMAC verifier, got %q (%v)", verifier, err)
	}
}

func TestConfiguredAPIKeyWinsKidCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kk.db")
	db := openMigratedKeyDB(t, path)
	a1 := newKeyAuth(t, db, nil)
	rec, minted, err := a1.CreateAPIKeyAs("alice@example.test", "ci", "svc-minted", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	configured := map[string]apiKeyRecord{rec.Kid: {
		Kid: rec.Kid, SecretVerifier: apiKeyVerifier("config-secret", testKeyPepper),
		PrincipalID: "svc-config", Role: "service-account", Active: true,
	}}
	a2 := newKeyAuth(t, openMigratedKeyDB(t, path), configured)
	if pd, err := authStatus(a2, "kk_"+rec.Kid+"_config-secret"); err != nil || pd.ID != "svc-config" {
		t.Fatalf("configured key must win: %+v, %v", pd, err)
	}
	if _, err := authStatus(a2, minted); err == nil {
		t.Fatal("shadowed persisted key must not authenticate")
	}
}

func TestAPIKeyLastUsedIsThrottled(t *testing.T) {
	db := openMigratedKeyDB(t, filepath.Join(t.TempDir(), "kk.db"))
	a := newKeyAuth(t, db, nil)
	rec, _, err := a.CreateAPIKeyAs("alice@example.test", "ci", "svc", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Truncate(time.Second)
	a.touchAPIKey(rec.Kid, t0)
	a.touchAPIKey(rec.Kid, t0.Add(10*time.Second)) // inside the interval: no write
	var got string
	if err := db.QueryRow(`SELECT last_used_at FROM minted_api_keys WHERE kid = ?`, rec.Kid).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != t0.Format(time.RFC3339) {
		t.Errorf("last_used_at = %q, want %q", got, t0.Format(time.RFC3339))
	}
	a.touchAPIKey(rec.Kid, t0.Add(2*time.Minute))
	_ = db.QueryRow(`SELECT last_used_at FROM minted_api_keys WHERE kid = ?`, rec.Kid).Scan(&got)
	if got != t0.Add(2*time.Minute).Format(time.RFC3339) {
		t.Errorf("after interval last_used_at = %q", got)
	}
}

func TestMintFailsClosedWhenPersistenceFails(t *testing.T) {
	db := openMigratedKeyDB(t, filepath.Join(t.TempDir(), "kk.db"))
	a := newKeyAuth(t, db, nil)
	if _, err := db.Exec(`DROP TABLE minted_api_keys`); err != nil {
		t.Fatal(err)
	}
	_, token, err := a.CreateAPIKeyAs("alice@example.test", "ci", "svc", "service-account", nil, "", "", time.Now())
	if err == nil || token != "" {
		t.Fatalf("a key that cannot be persisted must not be issued (token=%q err=%v)", token, err)
	}
	if len(a.ListAPIKeys()) != 0 {
		t.Error("unpersisted key left in memory")
	}
}

func TestMintWithoutStoreStaysInMemory(t *testing.T) {
	a := newKeyAuth(t, nil, nil)
	_, token, err := a.CreateAPIKeyAs("alice@example.test", "ci", "svc", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authStatus(a, token); err != nil {
		t.Fatalf("in-memory key must keep working: %v", err)
	}
	if !a.APIKeyMintingAvailable() {
		t.Error("APIKeyMintingAvailable must be true with pepper + auth enabled")
	}
}

func TestRevokeFailsClosedWhenPersistenceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kk.db")
	db := openMigratedKeyDB(t, path)
	a := newKeyAuth(t, db, nil)
	rec, token, err := a.CreateAPIKeyAs("alice@example.test", "ci", "svc", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE minted_api_keys RENAME TO minted_api_keys_off`); err != nil {
		t.Fatal(err)
	}
	found, perr := a.RevokeAPIKey(rec.Kid)
	if !found || perr == nil {
		t.Fatalf("want found with persist error, got found=%v err=%v", found, perr)
	}
	if _, err := authStatus(a, token); err == nil {
		t.Fatal("key must be rejected in-process even though revocation was not persisted")
	}
	// DB recovers: a repeated revoke retries the write instead of 404.
	if _, err := db.Exec(`ALTER TABLE minted_api_keys_off RENAME TO minted_api_keys`); err != nil {
		t.Fatal(err)
	}
	if found, perr := a.RevokeAPIKey(rec.Kid); !found || perr != nil {
		t.Fatalf("retry: found=%v err=%v", found, perr)
	}
	a2 := newKeyAuth(t, openMigratedKeyDB(t, path), nil)
	if _, err := authStatus(a2, token); err == nil {
		t.Fatal("key authenticates after restart following a successful retry")
	}
}

func TestDeleteAPIKeyHandlerReturns503WhenRevocationNotDurable(t *testing.T) {
	db := openMigratedKeyDB(t, filepath.Join(t.TempDir(), "kk.db"))
	a := newKeyAuth(t, db, nil)
	a.config.bootstrapToken = "admin-token-for-test"
	rec, _, err := a.CreateAPIKeyAs("alice@example.test", "ci", "svc", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE minted_api_keys RENAME TO minted_api_keys_off`); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAuthHandlers(mux, a, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+rec.Kid, nil)
	req.Header.Set("Authorization", "Bearer admin-token-for-test")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("DELETE = %d, want 503 (body %s)", rr.Code, rr.Body.String())
	}
}

// countingKeyStore counts last_used_at writes reaching the store.
type countingKeyStore struct {
	apiKeyStore
	n atomic.Int32
}

func (c *countingKeyStore) TouchLastUsed(ctx context.Context, kid string, at time.Time) error {
	c.n.Add(1)
	return c.apiKeyStore.TouchLastUsed(ctx, kid, at)
}

// W22-33 acceptance 1: real authentication stamps last_used_at, at most once
// a minute, and the write reaches the DB.
func TestAPIKeyAuthStampsLastUsedOncePerMinute(t *testing.T) {
	db := openMigratedKeyDB(t, filepath.Join(t.TempDir(), "kk.db"))
	a := newKeyAuth(t, nil, nil)
	store := &countingKeyStore{apiKeyStore: NewAPIKeyStore(db, false)}
	if err := a.SetAPIKeyStore(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	rec, token, err := a.CreateAPIKeyAs("alice@example.test", "ci", "svc", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := authStatus(a, token); err != nil {
			t.Fatalf("auth %d: %v", i, err)
		}
	}
	if n := store.n.Load(); n != 1 {
		t.Fatalf("store writes = %d, want 1 (second auth is inside the interval)", n)
	}
	var got string
	if err := db.QueryRow(`SELECT last_used_at FROM minted_api_keys WHERE kid = ?`, rec.Kid).Scan(&got); err != nil || got == "" {
		t.Fatalf("db last_used_at = %q, err=%v", got, err)
	}
}

// Config keys (APP_API_KEYS_JSON) never touch the store but still report use.
func TestAPIKeyConfigKeyLastUsedInMemory(t *testing.T) {
	configured := map[string]apiKeyRecord{"cfgkid": {
		Kid: "cfgkid", SecretVerifier: apiKeyVerifier("config-secret", testKeyPepper),
		PrincipalID: "svc-config", Role: "service-account", Active: true,
	}}
	a := newKeyAuth(t, nil, configured)
	if _, err := authStatus(a, "kk_cfgkid_config-secret"); err != nil {
		t.Fatal(err)
	}
	keys := a.ListAPIKeys()
	if len(keys) != 1 || keys[0].LastUsedAt == "" {
		t.Fatalf("config key must carry an in-memory last_used_at, got %+v", keys)
	}
	if _, err := time.Parse(time.RFC3339, keys[0].LastUsedAt); err != nil {
		t.Fatalf("last_used_at not RFC3339: %v", err)
	}
}

func TestAPIKeyListResponseIncludesLastUsedAt(t *testing.T) {
	mux, auth := newAPIKeyTestMux(t)
	used, usedToken, err := auth.CreateAPIKey("used", "svc-used", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	unused, _, err := auth.CreateAPIKey("unused", "svc-unused", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authStatus(auth, usedToken); err != nil {
		t.Fatal(err)
	}
	rec := doLeakJSON(mux, http.MethodGet, "/api/v1/api-keys", "admin-token", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	seen := map[string]any{}
	for _, row := range out.Data {
		seen[row["kid"].(string)] = row["last_used_at"]
	}
	ts, ok := seen[used.Kid].(string)
	if !ok {
		t.Fatalf("used key must report last_used_at, got %v", seen[used.Kid])
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Fatalf("last_used_at %q: %v", ts, err)
	}
	if v, present := seen[unused.Kid]; present && v != nil {
		t.Fatalf("never-used key must omit last_used_at, got %v", v)
	}
}

// W22-33 acceptance 2: the column exists in both engines' migration.
func TestAPIKeyLastUsedColumnBothEngines(t *testing.T) {
	for _, engine := range []string{"postgres", "sqlite"} {
		b, err := os.ReadFile("../db/migrations/" + engine + "/000074_minted_api_keys.up.sql")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "last_used_at") {
			t.Errorf("%s migration 000074 lacks last_used_at", engine)
		}
	}
}
