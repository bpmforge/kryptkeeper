// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/acme"
	kkdb "kryptkeeper/internal/db"
)

var eabTestPassphrase = []byte("eab-test-passphrase")

func newACMEEABMux(t *testing.T, passphrase []byte) (*http.ServeMux, *Authenticator, *acme.DBEABAdmin, *scepRecordingAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "eab.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := acme.NewDBEABAdmin(db, false, func(s string) ([]byte, error) { return OpenSecret(passphrase, s) })
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	RegisterACMEEABHandlers(mux, auth, store, ACMEEABOptions{Passphrase: passphrase}, audit)
	return mux, auth, store, audit
}

type eabMinted struct {
	Data struct {
		KID     string `json:"kid"`
		HMACKey string `json:"hmac_key"`
	} `json:"data"`
}

func TestEABCreateListRevoke(t *testing.T) {
	mux, _, store, audit := newACMEEABMux(t, eabTestPassphrase)

	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/acme/eab-keys", "test-token",
		map[string]any{"label": "ci", "provisioner": "prod-acme", "template_id": "tpl-1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response carrying the secret must not be cached")
	}
	var minted eabMinted
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(minted.Data.HMACKey)
	if err != nil || len(raw) != 32 || !strings.HasPrefix(minted.Data.KID, "kk-eab-") {
		t.Fatalf("minted %+v (%v)", minted, err)
	}
	// The stored key verifies: the sealed copy opens to the same bytes.
	if k, ok := store.LoadEABKey(minted.Data.KID); !ok || string(k.MACKey) != string(raw) || k.Disabled || k.Provisioner != "prod-acme" {
		t.Fatalf("stored key = %+v ok=%v", k, ok)
	}

	list := scepAPI(t, mux, http.MethodGet, "/api/v1/acme/eab-keys", "test-token", nil)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "hmac_key") || strings.Contains(list.Body.String(), minted.Data.HMACKey) ||
		!strings.Contains(list.Body.String(), minted.Data.KID) {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}

	if del := scepAPI(t, mux, http.MethodDelete, "/api/v1/acme/eab-keys/"+minted.Data.KID, "test-token", nil); del.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", del.Code)
	}
	list = scepAPI(t, mux, http.MethodGet, "/api/v1/acme/eab-keys", "test-token", nil)
	if !strings.Contains(list.Body.String(), `"revoked_at":"20`) {
		t.Fatalf("list after revoke has no revoked_at: %s", list.Body.String())
	}
	if k, _ := store.LoadEABKey(minted.Data.KID); k == nil || !k.Disabled {
		t.Fatal("revoked key must load as disabled")
	}
	if del := scepAPI(t, mux, http.MethodDelete, "/api/v1/acme/eab-keys/"+minted.Data.KID, "test-token", nil); del.Code != http.StatusConflict {
		t.Errorf("second revoke: %d, want 409", del.Code)
	}
	if del := scepAPI(t, mux, http.MethodDelete, "/api/v1/acme/eab-keys/kk-eab-nope", "test-token", nil); del.Code != http.StatusNotFound {
		t.Errorf("unknown kid: %d, want 404", del.Code)
	}
	if bad := scepAPI(t, mux, http.MethodPost, "/api/v1/acme/eab-keys", "test-token", map[string]any{"provisioner": "Bad Name"}); bad.Code != http.StatusBadRequest {
		t.Errorf("bad provisioner: %d, want 400", bad.Code)
	}
	for _, e := range audit.entries {
		if e.Action == "" || e.Outcome == "" {
			t.Fatalf("incomplete audit entry %+v", e)
		}
	}
}

func TestEABRequiresPKIAdmin(t *testing.T) {
	mux, auth, _, audit := newACMEEABMux(t, eabTestPassphrase)
	_, opKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if rec := scepAPI(t, mux, m, "/api/v1/acme/eab-keys", opKey, map[string]any{}); rec.Code != http.StatusForbidden {
			t.Errorf("%s as operator: %d, want 403", m, rec.Code)
		}
		if rec := scepAPI(t, mux, m, "/api/v1/acme/eab-keys", "", map[string]any{}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d, want 401", m, rec.Code)
		}
	}
	if rec := scepAPI(t, mux, http.MethodDelete, "/api/v1/acme/eab-keys/x", opKey, nil); rec.Code != http.StatusForbidden {
		t.Errorf("DELETE as operator: %d, want 403", rec.Code)
	}
	denied := 0
	for _, e := range audit.entries {
		if e.Outcome == AuditOutcomeDenied {
			denied++
		}
	}
	if denied != 5 {
		t.Errorf("denied audit rows = %d, want 5", denied)
	}
}

func TestEABMintNeedsPassphrase(t *testing.T) {
	mux, _, _, _ := newACMEEABMux(t, nil)
	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/acme/eab-keys", "test-token", map[string]any{"label": "x"})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "credential store passphrase") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestEABSecretNotInAudit(t *testing.T) {
	mux, _, _, audit := newACMEEABMux(t, eabTestPassphrase)
	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/acme/eab-keys", "test-token", map[string]any{"label": "ci"})
	var minted eabMinted
	_ = json.Unmarshal(rec.Body.Bytes(), &minted)
	if minted.Data.HMACKey == "" || len(audit.entries) == 0 {
		t.Fatal("setup failed")
	}
	for _, e := range audit.entries {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), minted.Data.HMACKey) {
			t.Fatalf("secret reached the audit log: %s", b)
		}
	}
}

func TestEABListShowsLastUsed(t *testing.T) {
	mux, _, store, _ := newACMEEABMux(t, eabTestPassphrase)
	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/acme/eab-keys", "test-token", map[string]any{"label": "ci"})
	var minted eabMinted
	_ = json.Unmarshal(rec.Body.Bytes(), &minted)
	// The ACME server calls RecordUse on a successful newAccount (covered
	// end to end in internal/acme TestDBEABAdminRealNewAccountSetsLastUsed).
	if ok, err := store.RecordUse(minted.Data.KID, "thumb", time.Now().UTC()); !ok || err != nil {
		t.Fatalf("record use: %v %v", ok, err)
	}
	list := scepAPI(t, mux, http.MethodGet, "/api/v1/acme/eab-keys", "test-token", nil)
	if !strings.Contains(list.Body.String(), `"last_used_at":"20`) || !strings.Contains(list.Body.String(), `"uses":1`) {
		t.Fatalf("list: %s", list.Body.String())
	}
}

func TestSealRoundTrip(t *testing.T) {
	sealed, err := SealSecret(eabTestPassphrase, []byte("mac-bytes"))
	if err != nil || strings.Contains(sealed, "mac-bytes") {
		t.Fatalf("seal: %v %q", err, sealed)
	}
	got, err := OpenSecret(eabTestPassphrase, sealed)
	if err != nil || string(got) != "mac-bytes" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := OpenSecret([]byte("wrong"), sealed); err == nil {
		t.Fatal("wrong passphrase must not open")
	}
}
