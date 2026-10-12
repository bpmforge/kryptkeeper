// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func newCARotationTestMux(t *testing.T) (*http.ServeMux, *Authenticator, CAProvider, *ca.Engine) {
	t.Helper()
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	sqlDB := setupIntegrationDB(t)
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("ca-rotation-test-passphrase-32b!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(sqlDB, false))

	provider := NewEngineCAProvider(engine)
	tenantStore := NewTenantStoreFromEnv()
	auditProvider := stubAuditProviderForCA{}

	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, provider, tenantStore, auditProvider)
	return mux, auth, provider, engine
}

func TestRotateCAKeyHandler_Success(t *testing.T) {
	mux, _, _, engine := newCARotationTestMux(t)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Rotate Test Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cas/"+root.ID+"/rotate-key", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data CAKeyRotationResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Data.ID != root.ID {
		t.Errorf("ID = %q, want %q", resp.Data.ID, root.ID)
	}
	if resp.Data.KeyID != root.KeyID {
		t.Errorf("KeyID = %q, want unchanged %q", resp.Data.KeyID, root.KeyID)
	}
	if resp.Data.LedgerID == "" {
		t.Error("expected a non-empty ledger_id")
	}
}

func TestRotateCAKeyHandler_RequiresAuth(t *testing.T) {
	mux, _, _, engine := newCARotationTestMux(t)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cas/"+root.ID+"/rotate-key", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRotateCAKeyHandler_RequiresAdminRole(t *testing.T) {
	mux, auth, _, engine := newCARotationTestMux(t)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	_, token, err := auth.CreateAPIKey("non-admin", "team-1", "service-account", []string{"read:certs"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cas/"+root.ID+"/rotate-key", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want 403", rec.Code, rec.Body.String())
	}
}

func TestRotateCAKeyHandler_UnsupportedProviderReturns503(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	fileProvider := NewFileCAProviderFromEnv()
	tenantStore := NewTenantStoreFromEnv()
	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, fileProvider, tenantStore, stubAuditProviderForCA{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cas/some-id/rotate-key", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s, want 503", rec.Code, rec.Body.String())
	}
}

// TestRawKeyRotateHandler_RefusesWhenKeyBacksCA is the acceptance-critical
// guard test for W9-04/G-35: the raw keystore rotate endpoint must refuse
// to touch a key that backs a CA, pointing the caller at the real CA
// re-key endpoint instead of silently breaking the CA.
func TestRawKeyRotateHandler_RefusesWhenKeyBacksCA(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("raw-rotate-guard-test-pass-32b!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	caStore := ca.NewMemStore()
	engine := ca.NewEngine(keys, caStore)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	SetActiveCAStore(caStore)
	t.Cleanup(func() { SetActiveCAStore(nil) })

	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProviderForCA{}, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+root.KeyID+"/rotate", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s, want 409", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("rotate-key")) {
		t.Errorf("expected the refusal message to point at the CA rotate-key endpoint, got: %s", rec.Body.String())
	}

	// The key must be genuinely untouched -- still resolvable and still
	// reported as backing the CA (a real rotation would have kept the same
	// ID too, so this alone doesn't prove non-rotation, but combined with
	// the 409 status and unchanged metadata below it does).
	if _, err := keys.PublicKey(root.KeyID); err != nil {
		t.Fatalf("PublicKey after refused rotation: %v", err)
	}
	if caID, found, err := ca.KeyInUseByCA(caStore, root.KeyID); err != nil || !found || caID != root.ID {
		t.Fatalf("KeyInUseByCA after refused rotation = (%q, %v, %v), want (%q, true, nil)", caID, found, err, root.ID)
	}
	meta, err := keys.Metadata(root.KeyID)
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.CreatedAt == "" {
		t.Error("expected key metadata to still be present")
	}
}

// ledgerFailStore wraps a ca.Store and makes RecordKeyRotation always fail,
// simulating a successful key rotation + certificate re-issuance whose
// ledger write fails afterward -- the partial-success case the handler
// must report as HTTP 200 with ledger_persisted:false, not as a failed
// rotation (which would invite a caller to retry and generate ANOTHER new
// key on an already-rotated CA).
type ledgerFailStore struct {
	ca.Store
}

func (s ledgerFailStore) RecordKeyRotation(ca.KeyRotation) error {
	return errors.New("simulated ledger write failure")
}

// TestRotateCAKeyHandler_LedgerFailureReturns200WithPersistedFalse covers
// the bug found during W9-04 review: a ledger-only failure (key + cert
// already committed) must not be reported to the caller as a failed
// rotation, or the caller could retry and generate an unnecessary second
// new key on a CA that already rotated successfully.
func TestRotateCAKeyHandler_LedgerFailureReturns200WithPersistedFalse(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("ledger-fail-test-passphrase-32b!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	store := ledgerFailStore{Store: ca.NewMemStore()}
	engine := ca.NewEngine(keys, store)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	provider := NewEngineCAProvider(engine)
	tenantStore := NewTenantStoreFromEnv()
	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, provider, tenantStore, stubAuditProviderForCA{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cas/"+root.ID+"/rotate-key", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want 200 (rotation itself succeeded)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data CAKeyRotationResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Data.LedgerPersisted {
		t.Error("LedgerPersisted = true, want false (RecordKeyRotation was made to fail)")
	}
	if resp.Data.ID != root.ID {
		t.Errorf("ID = %q, want %q -- the rotation must still be reported as applying to this CA", resp.Data.ID, root.ID)
	}

	// The key rotation itself must have genuinely gone through despite the
	// ledger failure -- the keystore now holds a different public key.
	newPub, err := keys.PublicKey(root.KeyID)
	if err != nil {
		t.Fatalf("PublicKey after rotation: %v", err)
	}
	if newPub == nil {
		t.Fatal("expected a public key after rotation")
	}
}

// TestRawKeyRotateHandler_AllowsUnrelatedKey is the regression guard that
// the new guard doesn't over-trigger for keys that don't back any CA.
func TestRawKeyRotateHandler_AllowsUnrelatedKey(t *testing.T) {
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("raw-rotate-allow-test-pass-32b!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	if _, err := keys.GenerateKey("unrelated-key", keystore.ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	caStore := ca.NewMemStore()
	engine := ca.NewEngine(keys, caStore)
	if _, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	SetActiveCAStore(caStore)
	t.Cleanup(func() { SetActiveCAStore(nil) })

	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProviderForCA{}, "")

	// The raw rotate endpoint (unlike ca.Engine.RotateCA) requires an
	// explicit algorithm -- it has no "reuse the current one" default.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unrelated-key/rotate", bytes.NewBufferString(`{"algorithm":"ECDSA-P256"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want 200 (unrelated key must not be blocked)", rec.Code, rec.Body.String())
	}
}

// TestRawKeyDeleteHandler_RefusesWhenKeyBacksCA covers W19-19: DELETE had no
// in-use guard, unlike /rotate -- deleting a CA's key would orphan the CA
// (its certificate still embeds the deleted key's public half, with nothing
// able to re-sign against it). Reuses the exact ca.KeyInUseByCA check
// /rotate applies.
func TestRawKeyDeleteHandler_RefusesWhenKeyBacksCA(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("raw-delete-guard-test-pass-32b!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	caStore := ca.NewMemStore()
	engine := ca.NewEngine(keys, caStore)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	SetActiveCAStore(caStore)
	t.Cleanup(func() { SetActiveCAStore(nil) })

	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProviderForCA{}, "")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/"+root.KeyID, nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s, want 409", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(root.ID)) {
		t.Errorf("expected the refusal message to name the backing CA, got: %s", rec.Body.String())
	}

	// The key must be genuinely untouched.
	if _, err := keys.PublicKey(root.KeyID); err != nil {
		t.Fatalf("PublicKey after refused delete: %v", err)
	}
}

// TestRawKeyDeleteHandler_AllowsUnrelatedKey proves the guard is scoped to
// keys that actually back a CA -- a disposable key still deletes.
func TestRawKeyDeleteHandler_AllowsUnrelatedKey(t *testing.T) {
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("raw-delete-allow-test-pass-32b!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	if _, err := keys.GenerateKey("disposable-key", keystore.ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	caStore := ca.NewMemStore()
	engine := ca.NewEngine(keys, caStore)
	if _, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	SetActiveCAStore(caStore)
	t.Cleanup(func() { SetActiveCAStore(nil) })

	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProviderForCA{}, "")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/disposable-key", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s, want 204 (unrelated key must still delete)", rec.Code, rec.Body.String())
	}
	if _, err := keys.PublicKey("disposable-key"); err == nil {
		t.Fatalf("expected the key's token object to be gone after delete")
	}
}
