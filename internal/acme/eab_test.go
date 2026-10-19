// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
)

// testJWK is a fixed, syntactically-valid EC JWK used by the direct
// verifyExternalAccountBinding unit tests below. Its coordinates don't need
// to be a real on-curve point: verifyExternalAccountBinding only computes
// its RFC 7638 thumbprint from the JSON fields, it never reconstructs a
// crypto.PublicKey from them.
func testJWK(x string) *JSONWebKey {
	return &JSONWebKey{Kty: "EC", Crv: "P-256", X: x, Y: "dummy-y-value"}
}

func buildEAB(t *testing.T, kid string, macKey []byte, url string, jwk *JSONWebKey) *ExternalAccountBinding {
	t.Helper()
	protectedJSON, _ := json.Marshal(eabProtectedHeader{Alg: "HS256", KID: kid, URL: url})
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(jwkJSON)

	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(protectedB64 + "." + payloadB64))

	return &ExternalAccountBinding{
		Protected: protectedB64,
		Payload:   payloadB64,
		Signature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}
}

func TestVerifyExternalAccountBinding_Valid(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	if err := store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("save eab key: %v", err)
	}
	jwk := testJWK("account-key-x")
	thumbprint, err := jwkThumbprint(jwk)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	eab := buildEAB(t, "kid-1", macKey, "https://hub.example.com/acme/new-account", jwk)

	if err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint); err != nil {
		t.Fatalf("expected valid EAB to verify, got: %v", err)
	}
}

func TestVerifyExternalAccountBinding_BadMAC(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()})

	jwk := testJWK("account-key-x")
	thumbprint, _ := jwkThumbprint(jwk)
	eab := buildEAB(t, "kid-1", []byte("wrong-key-entirely"), "https://hub.example.com/acme/new-account", jwk)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint)
	if err == nil {
		t.Fatal("expected verification failure for wrong MAC key")
	}
}

func TestVerifyExternalAccountBinding_UnknownKID(t *testing.T) {
	store := NewMemStore()
	jwk := testJWK("account-key-x")
	thumbprint, _ := jwkThumbprint(jwk)
	eab := buildEAB(t, "no-such-kid", []byte("whatever"), "https://hub.example.com/acme/new-account", jwk)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint)
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestVerifyExternalAccountBinding_DisabledKey(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, Disabled: true, CreatedAt: time.Now().UTC()})

	jwk := testJWK("account-key-x")
	thumbprint, _ := jwkThumbprint(jwk)
	eab := buildEAB(t, "kid-1", macKey, "https://hub.example.com/acme/new-account", jwk)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint)
	if err == nil {
		t.Fatal("expected error for disabled key")
	}
}

func TestVerifyExternalAccountBinding_WrongURL(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()})

	jwk := testJWK("account-key-x")
	thumbprint, _ := jwkThumbprint(jwk)
	eab := buildEAB(t, "kid-1", macKey, "https://attacker.example.com/acme/new-account", jwk)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint)
	if err == nil {
		t.Fatal("expected error for url mismatch (replay to a different endpoint)")
	}
}

func TestVerifyExternalAccountBinding_WrongAlg(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()})

	protectedJSON, _ := json.Marshal(eabProtectedHeader{Alg: "none", KID: "kid-1", URL: "https://hub.example.com/acme/new-account"})
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	eab := &ExternalAccountBinding{Protected: protectedB64, Payload: payloadB64, Signature: base64.RawURLEncoding.EncodeToString([]byte("x"))}

	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", "irrelevant-thumbprint")
	if err == nil {
		t.Fatal("expected error for unsupported alg")
	}
}

func TestVerifyExternalAccountBinding_Missing(t *testing.T) {
	store := NewMemStore()
	if err := verifyExternalAccountBinding(store, nil, "https://hub.example.com/acme/new-account", "irrelevant-thumbprint"); err == nil {
		t.Fatal("expected error for missing EAB")
	}
}

// TestVerifyExternalAccountBinding_PayloadKeyMismatch proves the G-44
// anti-replay fix: an externalAccountBinding value that is otherwise
// perfectly valid (right kid, right url, right MAC) must still be rejected
// if its payload JWK isn't the key of the account actually presenting it.
func TestVerifyExternalAccountBinding_PayloadKeyMismatch(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()})

	victimJWK := testJWK("victim-key-x")
	attackerJWK := testJWK("attacker-key-x")
	attackerThumbprint, _ := jwkThumbprint(attackerJWK)

	// eab is validly HMAC-signed and bound (in payload) to victimJWK, but the
	// caller presenting it (per its outer account JWS) is attackerJWK.
	eab := buildEAB(t, "kid-1", macKey, "https://hub.example.com/acme/new-account", victimJWK)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", attackerThumbprint)
	if err == nil {
		t.Fatal("expected error: eab payload is bound to a different account key")
	}
}

func TestEABConfigFromEnv(t *testing.T) {
	t.Setenv("APP_ACME_EAB_REQUIRED", "true")
	macKeyB64 := base64.RawURLEncoding.EncodeToString([]byte("some-mac-key"))
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `{"kid-1":"`+macKeyB64+`"}`)

	cfg, err := eabConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.required {
		t.Error("expected required=true")
	}
	if len(cfg.seedKeys) != 1 || cfg.seedKeys[0].KID != "kid-1" {
		t.Fatalf("expected 1 seed key kid-1, got %+v", cfg.seedKeys)
	}
}

func TestEABConfigFromEnv_InvalidJSON(t *testing.T) {
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `not-json`)
	if _, err := eabConfigFromEnv(); err == nil {
		t.Fatal("expected error for invalid APP_ACME_EAB_KEYS_JSON")
	}
}

func TestACMENewAccountEABRequired(t *testing.T) {
	macKey := []byte("super-secret-mac-key-material-32")
	macKeyB64 := base64.RawURLEncoding.EncodeToString(macKey)
	t.Setenv("APP_ACME_EAB_REQUIRED", "true")
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `{"kid-1":"`+macKeyB64+`"}`)

	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMETestClient(t)

	// Without EAB: rejected.
	payload, _ := json.Marshal(map[string]any{"contact": []string{"mailto:a@example.com"}, "termsOfServiceAgreed": true})
	resp := client.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without EAB, got %d", resp.StatusCode)
	}

	// With a valid EAB bound to this account's own key: accepted, and the
	// binding is recorded.
	eab := buildEAB(t, "kid-1", macKey, srv.baseURL+"/acme/new-account", client.jwk)
	payload2, _ := json.Marshal(map[string]any{
		"contact":                []string{"mailto:a@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eab,
	})
	resp2 := client.postJWS(t, ts, ts.URL+"/acme/new-account", payload2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 201 with valid EAB, got %d: %s", resp2.StatusCode, b)
	}

	var acct Account
	if err := json.NewDecoder(resp2.Body).Decode(&acct); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	mem, ok := srv.store.(*MemStore)
	if !ok {
		t.Fatal("expected MemStore")
	}
	if kid := mem.accountEAB[acct.ID]; kid != "kid-1" {
		t.Fatalf("expected account bound to kid-1, got %q", kid)
	}
}

// TestACMENewAccountEABReplayRejected proves acceptance criterion 2's
// closed replay gap end-to-end: an externalAccountBinding value captured
// for one account's key cannot be replayed by a different account key.
func TestACMENewAccountEABReplayRejected(t *testing.T) {
	macKey := []byte("super-secret-mac-key-material-32")
	macKeyB64 := base64.RawURLEncoding.EncodeToString(macKey)
	t.Setenv("APP_ACME_EAB_REQUIRED", "true")
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `{"kid-1":"`+macKeyB64+`"}`)

	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	victim := newACMETestClient(t)
	eab := buildEAB(t, "kid-1", macKey, srv.baseURL+"/acme/new-account", victim.jwk) // bound to victim's key

	attacker := newACMETestClient(t) // a different keypair entirely
	payload, _ := json.Marshal(map[string]any{
		"contact":                []string{"mailto:attacker@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eab, // replayed, still bound to victim.jwk
	})
	resp := attacker.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected replayed EAB (bound to a different account key) to be rejected, got %d", resp.StatusCode)
	}
}

func TestACMENewAccountEABOptionalByDefault(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMETestClient(t)
	payload, _ := json.Marshal(map[string]any{"contact": []string{"mailto:a@example.com"}, "termsOfServiceAgreed": true})
	resp := client.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 when EAB is not required, got %d", resp.StatusCode)
	}
}

// --- W26-01: admin-minted keys, reject audit, alerts, reuse ---

type eabAuditRec struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *eabAuditRec) fn(_ context.Context, ev AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

func (a *eabAuditRec) rejects() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditEvent(nil), a.events...)
}

// eabAdminServer is a test ACME server with a minted (or revoked) admin key.
func eabAdminServer(t *testing.T, revoke bool) (srv *Server, ts *httptest.Server, rec *eabAuditRec, mac []byte, admin *MemEABAdmin) {
	t.Helper()
	srv, ts = newTestACMEServer(t)
	t.Cleanup(ts.Close)
	admin = NewMemEABAdmin()
	mac = []byte("admin-minted-mac-key-32-bytes!!!")
	if err := admin.Create(context.Background(), EABAdminKey{KID: "kk-eab-1", CreatedAt: time.Now().UTC()}, string(mac)); err != nil {
		t.Fatal(err)
	}
	if revoke {
		if err := admin.Revoke(context.Background(), "kk-eab-1", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	rec = &eabAuditRec{}
	srv.WithEABAdmin(admin).WithAuditFunc(rec.fn)
	return srv, ts, rec, mac, admin
}

func postNewAccountEAB(t *testing.T, srv *Server, ts *httptest.Server, c *acmeTestClient, kid string, mac []byte) *http.Response {
	t.Helper()
	eab := buildEAB(t, kid, mac, srv.baseURL+"/acme/new-account", c.jwk)
	payload, _ := json.Marshal(map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": eab})
	return c.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
}

func TestNewAccountRevokedKeyIs401AndAudited(t *testing.T) {
	srv, ts, rec, mac, _ := eabAdminServer(t, true)
	resp := postNewAccountEAB(t, srv, ts, newACMETestClient(t), "kk-eab-1", mac)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked key: got %d, want 401", resp.StatusCode)
	}
	ev := rec.rejects()
	if len(ev) != 1 || ev[0].Action != "acme.eab.reject" || ev[0].Outcome != "denied" || ev[0].Actor != "kk-eab-1" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestNewAccountWrongHMACIs401AndAudited(t *testing.T) {
	srv, ts, rec, mac, _ := eabAdminServer(t, false)
	resp := postNewAccountEAB(t, srv, ts, newACMETestClient(t), "kk-eab-1", append([]byte("x"), mac...))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong hmac: got %d, want 401", resp.StatusCode)
	}
	ev := rec.rejects()
	if len(ev) != 1 || ev[0].Action != "acme.eab.reject" {
		t.Fatalf("audit = %+v", ev)
	}
	if strings.Contains(ev[0].Detail, string(mac)) {
		t.Fatal("audit detail leaks key material")
	}
}

func TestNewAccountMissingBindingAudited(t *testing.T) {
	t.Setenv("APP_ACME_EAB_REQUIRED", "true")
	srv, ts, rec, _, _ := eabAdminServer(t, false)
	_ = srv
	payload, _ := json.Marshal(map[string]any{"termsOfServiceAgreed": true})
	resp := newACMETestClient(t).postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	if ev := rec.rejects(); len(ev) != 1 || ev[0].Detail != "missing binding" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestEABFailuresAlertAfterTen(t *testing.T) {
	rt := newEABRuntime()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rt.now = func() time.Time { return now }

	alerts := func(src string, n int) (fired int) {
		for i := 0; i < n; i++ {
			if _, fire := rt.recordFailure(src); fire {
				fired++
			}
		}
		return fired
	}
	if got := alerts("10.0.0.1", 10); got != 0 {
		t.Fatalf("10 failures alerted %d times", got)
	}
	if got := alerts("10.0.0.1", 5); got != 1 {
		t.Fatalf("11th+ failures alerted %d times, want exactly 1", got)
	}
	if got := alerts("10.0.0.2", 10); got != 0 {
		t.Fatal("second source must count independently")
	}
	now = now.Add(eabFailureWindow)
	if got := alerts("10.0.0.1", 11); got != 1 {
		t.Fatalf("window rollover re-arm: alerted %d times, want 1", got)
	}
}

func TestEABFailureAlertEndToEnd(t *testing.T) {
	srv, ts, _, mac, _ := eabAdminServer(t, false)
	var alerts []map[string]string
	srv.WithAlertFunc(func(_ context.Context, kind string, d map[string]string) {
		if kind != "acme.eab.failures" {
			t.Errorf("kind = %s", kind)
		}
		alerts = append(alerts, d)
	})
	for i := 0; i < 11; i++ {
		resp := postNewAccountEAB(t, srv, ts, newACMETestClient(t), "kk-eab-1", []byte("wrong-"+string(mac)))
		resp.Body.Close()
	}
	if len(alerts) != 1 || alerts[0]["count"] != "11" || alerts[0]["source"] == "" {
		t.Fatalf("alerts = %v", alerts)
	}
}

func TestSeedKeysStillLoad(t *testing.T) {
	macKey := []byte("seed-mac-key-material-32-bytes!!")
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `{"seed-1":"`+base64.RawURLEncoding.EncodeToString(macKey)+`"}`)
	srv, ts, _, _, admin := eabAdminServer(t, false)
	c := newACMETestClient(t)
	resp := postNewAccountEAB(t, srv, ts, c, "seed-1", macKey)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("seed key: got %d, want 201", resp.StatusCode)
	}
	list, _ := admin.List(context.Background())
	for _, k := range list {
		if k.KID == "seed-1" {
			t.Fatal("seed keys must not be listable")
		}
	}
}

func TestEABKeyReusedBySecondAccountKeyRefused(t *testing.T) {
	srv, ts, rec, mac, _ := eabAdminServer(t, false)
	first, second := newACMETestClient(t), newACMETestClient(t)
	for i, c := range []*acmeTestClient{first, second, first} {
		resp := postNewAccountEAB(t, srv, ts, c, "kk-eab-1", mac)
		resp.Body.Close()
		want := http.StatusCreated
		if i == 1 {
			want = http.StatusUnauthorized
		}
		if resp.StatusCode != want {
			t.Fatalf("attempt %d: got %d, want %d", i, resp.StatusCode, want)
		}
	}
	ev := rec.rejects()
	if len(ev) != 1 || ev[0].Detail != "kid already bound to another account key" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestDBEABAdminRealNewAccountSetsLastUsed(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "eab.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	store := NewDBEABAdmin(db, false, func(s string) ([]byte, error) { return []byte(s), nil })
	mac := []byte("db-minted-mac-key-32-bytes-long!")
	if err := store.Create(context.Background(), EABAdminKey{KID: "kk-eab-db", Label: "ci", CreatedBy: "u1", CreatedAt: time.Now().UTC()}, string(mac)); err != nil {
		t.Fatal(err)
	}
	srv.WithEABAdmin(store)

	before, _ := store.List(context.Background())
	if len(before) != 1 || before[0].LastUsedAt != nil || before[0].Uses != 0 {
		t.Fatalf("before = %+v", before)
	}
	resp := postNewAccountEAB(t, srv, ts, newACMETestClient(t), "kk-eab-db", mac)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newAccount: %d", resp.StatusCode)
	}
	after, _ := store.List(context.Background())
	if after[0].LastUsedAt == nil || after[0].Uses != 1 {
		t.Fatalf("after = %+v", after)
	}
	if err := store.Revoke(context.Background(), "kk-eab-db", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(context.Background(), "kk-eab-db", time.Now()); !errors.Is(err, ErrEABAlreadyRevoked) {
		t.Fatalf("second revoke = %v", err)
	}
	if err := store.Revoke(context.Background(), "nope", time.Now()); !errors.Is(err, ErrEABNotFound) {
		t.Fatalf("unknown revoke = %v", err)
	}
	resp = postNewAccountEAB(t, srv, ts, newACMETestClient(t), "kk-eab-db", mac)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after revoke: %d", resp.StatusCode)
	}
}
