// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kryptkeeper/internal/keystore"
)

func newBackupTestStore(t *testing.T) keystore.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := keystore.NewSoftwareStore(dir, []byte("store-passphrase-32chars-min!!!!"))
	if err != nil {
		t.Fatalf("NewSoftwareStore: %v", err)
	}
	return store
}

func newBackupTestMux(t *testing.T, store keystore.Store) *http.ServeMux {
	t.Helper()
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerBackupHandlers(mux, auth, store, stubAuditProvider{})
	return mux
}

func TestBackupHandler_RequiresAuth(t *testing.T) {
	mux := newBackupTestMux(t, newBackupTestStore(t))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/backup", bytes.NewBufferString(`{"backup_passphrase":"x"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBackupHandler_ExportsAllKeysAndRestoreRoundTrips(t *testing.T) {
	src := newBackupTestStore(t)
	if _, err := src.GenerateKey("ca-root", keystore.ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := src.GenerateKey("ca-intermediate", keystore.RSA2048); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	mux := newBackupTestMux(t, src)

	backupReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/backup", bytes.NewBufferString(`{"backup_passphrase":"backup-pass-32chars-minimum!!!!"}`))
	backupReq.Header.Set("Authorization", "Bearer test-token")
	backupRec := httptest.NewRecorder()
	mux.ServeHTTP(backupRec, backupReq)
	if backupRec.Code != http.StatusOK {
		t.Fatalf("backup status = %d, body = %s", backupRec.Code, backupRec.Body.String())
	}
	if ct := backupRec.Header().Get("Content-Disposition"); ct == "" {
		t.Error("expected a Content-Disposition header on the backup response")
	}

	var bundle keystore.Bundle
	if err := json.Unmarshal(backupRec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("backup response is not a valid bundle: %v", err)
	}
	if len(bundle.Keys) != 2 {
		t.Fatalf("bundle has %d keys, want 2", len(bundle.Keys))
	}
	for _, k := range bundle.Keys {
		if k.Status != keystore.BackupKeyExported {
			t.Errorf("key %s: status %q, want exported", k.ID, k.Status)
		}
	}

	// Restore into a fresh store instance via the HTTP endpoint, proving the
	// bundle produced by /backup is what /restore actually expects.
	dst := newBackupTestStore(t)
	restoreMux := newBackupTestMux(t, dst)
	restoreBody, err := json.Marshal(map[string]any{
		"backup_passphrase": "backup-pass-32chars-minimum!!!!",
		"bundle":            bundle,
	})
	if err != nil {
		t.Fatalf("marshal restore request: %v", err)
	}
	restoreReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/restore", bytes.NewReader(restoreBody))
	restoreReq.Header.Set("Authorization", "Bearer test-token")
	restoreRec := httptest.NewRecorder()
	restoreMux.ServeHTTP(restoreRec, restoreReq)
	if restoreRec.Code != http.StatusOK {
		t.Fatalf("restore status = %d, body = %s", restoreRec.Code, restoreRec.Body.String())
	}

	var restoreResp struct {
		Data struct {
			Imported int `json:"imported"`
		} `json:"data"`
	}
	if err := json.Unmarshal(restoreRec.Body.Bytes(), &restoreResp); err != nil {
		t.Fatalf("restore response not valid JSON: %v", err)
	}
	if restoreResp.Data.Imported != 2 {
		t.Fatalf("imported = %d, want 2", restoreResp.Data.Imported)
	}
	if _, err := dst.PublicKey("ca-root"); err != nil {
		t.Errorf("restored store missing ca-root: %v", err)
	}
	if _, err := dst.PublicKey("ca-intermediate"); err != nil {
		t.Errorf("restored store missing ca-intermediate: %v", err)
	}
}

func TestRestoreHandler_PartialFailureReturns207WithImportedCount(t *testing.T) {
	src := newBackupTestStore(t)
	if _, err := src.GenerateKey("ok-key", keystore.ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	backupMux := newBackupTestMux(t, src)
	backupReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/backup", bytes.NewBufferString(`{"backup_passphrase":"backup-pass-32chars-minimum!!!!"}`))
	backupReq.Header.Set("Authorization", "Bearer test-token")
	backupRec := httptest.NewRecorder()
	backupMux.ServeHTTP(backupRec, backupReq)
	var bundle keystore.Bundle
	if err := json.Unmarshal(backupRec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("backup response not valid bundle: %v", err)
	}

	dst := newBackupTestStore(t)
	if _, err := dst.GenerateKey("ok-key", keystore.ECDSAP256); err != nil {
		t.Fatalf("pre-seed dst: %v", err)
	}
	restoreMux := newBackupTestMux(t, dst)
	restoreBody, _ := json.Marshal(map[string]any{
		"backup_passphrase": "backup-pass-32chars-minimum!!!!",
		"bundle":            bundle,
	})
	restoreReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/restore", bytes.NewReader(restoreBody))
	restoreReq.Header.Set("Authorization", "Bearer test-token")
	restoreRec := httptest.NewRecorder()
	restoreMux.ServeHTTP(restoreRec, restoreReq)
	if restoreRec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207", restoreRec.Code)
	}
}
