// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"
)

// W23-10: every CA row records its key backend in the canonical vocabulary,
// the label survives a restart, and key_storage_type can never change.

func newBackendDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ca-backend.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	return db
}

func newBackendEngine(t *testing.T, db *sql.DB, label string) *ca.Engine {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("backend-test-passphrase-32chars!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Close() })
	e := ca.NewEngine(keys, ca.NewDBStore(db, false))
	e.SetKeyBackend(label)
	return e
}

func TestCreateCAStoresBackendLabel(t *testing.T) {
	for label, want := range map[string]string{
		"software": "software", "pkcs11": "pkcs11", "vault": "vault", "cloudkms": "cloud_kms",
	} {
		t.Run(label, func(t *testing.T) {
			db := newBackendDB(t)
			engine := newBackendEngine(t, db, label)
			provider := NewEngineCAProvider(engine)
			created, err := provider.CreateCA(context.Background(), CACreateRequest{
				Name: "r", Type: "root", Algorithm: "ECDSA-P256", ValidityStr: "30d", SubjectCN: "Backend Root",
			})
			if err != nil {
				t.Fatalf("create under backend %q: %v", label, err)
			}
			if created.KeyStorageType != want {
				t.Fatalf("created item = %q, want %q", created.KeyStorageType, want)
			}
			got, err := ca.NewDBStore(db, false).Load(created.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.KeyStorageType != want {
				t.Fatalf("stored label = %q, want %q", got.KeyStorageType, want)
			}
			list, err := provider.ListCAs(context.Background(), CAListQuery{})
			if err != nil || len(list.Items) != 1 || list.Items[0].KeyStorageType != want {
				t.Fatalf("list = %+v err=%v, want key_storage_type %q", list.Items, err, want)
			}
		})
	}
}

func TestBackendLabelSurvivesRestart(t *testing.T) {
	db := newBackendDB(t)
	created, err := NewEngineCAProvider(newBackendEngine(t, db, "cloudkms")).CreateCA(context.Background(), CACreateRequest{
		Name: "r", Type: "root", Algorithm: "ECDSA-P256", ValidityStr: "30d", SubjectCN: "Restart Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewEngineCAProvider(newBackendEngine(t, db, "cloudkms"))
	item, found, err := restarted.GetCA(context.Background(), created.ID)
	if err != nil || !found || item.KeyStorageType != "cloud_kms" {
		t.Fatalf("after restart: %+v found=%v err=%v, want cloud_kms", item, found, err)
	}
}

func TestKeyStorageTypeImmutableAtStore(t *testing.T) {
	db := newBackendDB(t)
	store := ca.NewDBStore(db, false)
	c := &ca.CA{ID: "immut-1", Name: "n", Type: "root", Status: "active", KeyStorageType: "software"}
	if err := store.Save(c); err != nil {
		t.Fatal(err)
	}
	c.KeyStorageType = "pkcs11"
	c.Status = "suspended"
	if err := store.Save(c); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load("immut-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyStorageType != "software" {
		t.Fatalf("key_storage_type changed to %q on re-save; it is immutable", got.KeyStorageType)
	}
	if got.Status != "suspended" {
		t.Fatalf("status = %q, want the re-save to still update status", got.Status)
	}
}

func TestSaveRejectsUnknownKeyStorageType(t *testing.T) {
	store := ca.NewDBStore(newBackendDB(t), false)
	err := store.Save(&ca.CA{ID: "bad-1", Name: "n", Type: "root", Status: "active", KeyStorageType: "floppy"})
	if !errors.Is(err, ca.ErrUnknownKeyStorageType) {
		t.Fatalf("err = %v, want ErrUnknownKeyStorageType", err)
	}
}

func TestPatchKeyStorageTypeReturns422(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	db := newBackendDB(t)
	engine := newBackendEngine(t, db, "software")
	provider := NewEngineCAProvider(engine)
	created, err := provider.CreateCA(context.Background(), CACreateRequest{
		Name: "r", Type: "root", Algorithm: "ECDSA-P256", ValidityStr: "30d", SubjectCN: "Patch Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerCAHandlers(mux, NewAuthenticatorFromEnv(), provider, NewTenantStoreFromEnv(), stubAuditProviderForCA{})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/cas/"+created.ID, strings.NewReader(`{"key_storage_type":"pkcs11"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "immutable") {
		t.Fatalf("PATCH key_storage_type: %d %s, want 422 immutable", rec.Code, rec.Body.String())
	}
	got, err := ca.NewDBStore(db, false).Load(created.ID)
	if err != nil || got.KeyStorageType != "software" {
		t.Fatalf("stored value = %+v err=%v, want software unchanged", got, err)
	}
}

func TestGetCAsListsKeyStorageType(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	db := newBackendDB(t)
	provider := NewEngineCAProvider(newBackendEngine(t, db, "vault"))
	if _, err := provider.CreateCA(context.Background(), CACreateRequest{
		Name: "r", Type: "root", Algorithm: "ECDSA-P256", ValidityStr: "30d", SubjectCN: "List Root",
	}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerCAHandlers(mux, NewAuthenticatorFromEnv(), provider, NewTenantStoreFromEnv(), stubAuditProviderForCA{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cas", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var body struct {
		Data []struct {
			KeyStorageType string `json:"key_storage_type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Data) != 1 || body.Data[0].KeyStorageType != "vault" {
		t.Fatalf("GET /cas = %d %s, want data[0].key_storage_type vault", rec.Code, rec.Body.String())
	}
}

func TestNormalizeKeyStorageType(t *testing.T) {
	for in, want := range map[string]string{
		"": "software", " Software ": "software", "pkcs11": "pkcs11", "vault": "vault",
		"cloudkms": "cloud_kms", "cloud-kms": "cloud_kms", "cloud_kms": "cloud_kms", "EXTERNAL": "external", "weird": "weird",
	} {
		if got := ca.NormalizeKeyStorageType(in); got != want {
			t.Errorf("NormalizeKeyStorageType(%q) = %q, want %q", in, got, want)
		}
	}
}
