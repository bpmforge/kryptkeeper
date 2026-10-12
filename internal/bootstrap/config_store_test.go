// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func newFreshConfigStore(t *testing.T, passphrase []byte) *sqliteConfigStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "runtime-config-fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteConfigStore{db: db, passphrase: passphrase}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}
	// Re-run against the same DB to prove the migration is re-runnable
	// (PLAYBOOK: "migrations are forward-only and must be re-runnable").
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema second run (idempotency): %v", err)
	}
	return s
}

func TestConfigStore_SetGetRoundTrip_NonSecret(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	if err := s.Set(ctx, "notifications.smtp_host", "smtp.example.com", "admin-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entry, ok, err := s.Get(ctx, "notifications.smtp_host")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected an override to exist")
	}
	if entry.Value != "smtp.example.com" {
		t.Errorf("Value = %q, want %q", entry.Value, "smtp.example.com")
	}
	if entry.UpdatedBy != "admin-1" {
		t.Errorf("UpdatedBy = %q, want %q", entry.UpdatedBy, "admin-1")
	}
}

// TestConfigStore_Get_SecretValueNeverPopulated is the discriminating test
// for acceptance #2 (secrets write-only over the API): Get on a secret key
// must never return the plaintext, only that a row exists.
func TestConfigStore_Get_SecretValueNeverPopulated(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()
	const plaintextMarker = "sk-super-secret-webhook-token"

	if err := s.Set(ctx, "notifications.slack_webhook_url", plaintextMarker, "admin-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entry, ok, err := s.Get(ctx, "notifications.slack_webhook_url")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected an override to exist")
	}
	if entry.Value != "" {
		t.Fatalf("Get leaked secret plaintext: %q", entry.Value)
	}
	if entry.HasValue {
		t.Fatal("HasValue should be false for a secret key -- the plaintext lives only in envelope")
	}

	// Same guarantee through List, and through JSON marshaling of both, in
	// case a struct-tag change ever re-exposes the field.
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	listJSON, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal List: %v", err)
	}
	if strings.Contains(string(listJSON), plaintextMarker) {
		t.Fatalf("List's JSON output leaked the plaintext: %s", listJSON)
	}
}

func TestConfigStore_Resolve_DecryptsSecret(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	if err := s.Set(ctx, "notifications.pagerduty_routing_key", "R0ROUTINGKEY", "admin-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Resolve(ctx, "notifications.pagerduty_routing_key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "R0ROUTINGKEY" {
		t.Errorf("Resolve = %q, want %q", got, "R0ROUTINGKEY")
	}
}

// TestConfigStore_WebhookURL_SecretRoundTrip proves acceptance #1 for W8-16
// (notifications.webhook_url is readable and writable through the config
// store) and acceptance #4 (it is registered Secret:true -- Get never
// returns the plaintext, only Resolve does, matching pagerduty_routing_key's
// treatment).
func TestConfigStore_WebhookURL_SecretRoundTrip(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()
	const target = "https://hooks.example.com/t/abc123secret"

	if err := s.Set(ctx, "notifications.webhook_url", target, "admin-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entry, ok, err := s.Get(ctx, "notifications.webhook_url")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected an override to exist")
	}
	if entry.Value != "" {
		t.Fatalf("Get leaked secret plaintext: %q", entry.Value)
	}

	got, err := s.Resolve(ctx, "notifications.webhook_url")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != target {
		t.Errorf("Resolve = %q, want %q", got, target)
	}
}

func TestConfigStore_Resolve_RejectsNonSecretKey(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	if err := s.Set(ctx, "notifications.smtp_host", "smtp.example.com", "admin-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := s.Resolve(ctx, "notifications.smtp_host"); err == nil {
		t.Fatal("expected Resolve on a non-secret key to error")
	}
}

func TestConfigStore_Set_RejectsUnknownKey(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	err := s.Set(ctx, "not.a.real.key", "x", "admin-1")
	if !errors.Is(err, errConfigUnknownKey) {
		t.Fatalf("Set with unknown key: err = %v, want errConfigUnknownKey", err)
	}
}

func TestConfigStore_Set_RejectsOversizedValue(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	oversized := strings.Repeat("x", configValueMaxLen+1)
	if err := s.Set(ctx, "notifications.smtp_host", oversized, "admin-1"); err == nil {
		t.Fatal("expected an error for an oversized value")
	}
}

func TestConfigStore_Delete(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	if err := s.Set(ctx, "discovery.provider", "network", "admin-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete(ctx, "discovery.provider"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, err := s.Get(ctx, "discovery.provider"); err != nil || ok {
		t.Fatalf("Get after Delete: ok=%v err=%v, want ok=false", ok, err)
	}
	if err := s.Delete(ctx, "discovery.provider"); !errors.Is(err, errConfigOverrideNotFound) {
		t.Fatalf("double-delete: err = %v, want errConfigOverrideNotFound", err)
	}
}

func TestEffectiveSettings_Unset(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	settings, err := EffectiveSettings(context.Background(), s)
	if err != nil {
		t.Fatalf("EffectiveSettings: %v", err)
	}
	for _, setting := range settings {
		if setting.Key == "discovery.provider" {
			if setting.Source != configSourceUnset {
				t.Errorf("Source = %q, want %q", setting.Source, configSourceUnset)
			}
			if setting.Configured {
				t.Error("expected Configured = false")
			}
		}
	}
}

func TestEffectiveSettings_EnvDefault(t *testing.T) {
	t.Setenv("APP_DISCOVERY_PROVIDER", "cloud")
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	settings, err := EffectiveSettings(context.Background(), s)
	if err != nil {
		t.Fatalf("EffectiveSettings: %v", err)
	}
	found := false
	for _, setting := range settings {
		if setting.Key != "discovery.provider" {
			continue
		}
		found = true
		if setting.Source != configSourceEnvDefault {
			t.Errorf("Source = %q, want %q", setting.Source, configSourceEnvDefault)
		}
		if setting.Value != "cloud" {
			t.Errorf("Value = %q, want %q", setting.Value, "cloud")
		}
	}
	if !found {
		t.Fatal("discovery.provider not present in EffectiveSettings")
	}
}

// TestEffectiveSettings_DatabaseOverridesEnv is the acceptance-#1 proof:
// env remains the bootstrap default, but a DB override takes precedence at
// runtime with no code path requiring a restart.
func TestEffectiveSettings_DatabaseOverridesEnv(t *testing.T) {
	t.Setenv("APP_DISCOVERY_PROVIDER", "cloud")
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()
	if err := s.Set(ctx, "discovery.provider", "network", "admin-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	settings, err := EffectiveSettings(ctx, s)
	if err != nil {
		t.Fatalf("EffectiveSettings: %v", err)
	}
	for _, setting := range settings {
		if setting.Key != "discovery.provider" {
			continue
		}
		if setting.Source != configSourceDatabase {
			t.Errorf("Source = %q, want %q", setting.Source, configSourceDatabase)
		}
		if setting.Value != "network" {
			t.Errorf("Value = %q, want DB override %q (env default %q must not win)", setting.Value, "network", "cloud")
		}
	}
}

// TestEffectiveSettings_ReadsFreshAcrossStoreInstances is the acceptance-#2
// no-restart proof at the store layer: it writes through one *sqliteConfigStore
// instance and reads through a second, independent instance opened against the
// same DSN (no shared Go state), to rule out a process-lifetime cache masking
// as a fresh-per-call read. EffectiveSettings has no cache field to defeat, but
// this pins that guarantee against future regressions rather than trusting the
// implementation reading.
func TestEffectiveSettings_ReadsFreshAcrossStoreInstances(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "runtime-config-shared.db")
	passphrase := []byte("test-passphrase")
	ctx := context.Background()

	writerDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open writer db: %v", err)
	}
	t.Cleanup(func() { writerDB.Close() })
	writer := &sqliteConfigStore{db: writerDB, passphrase: passphrase}
	if err := writer.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	readerDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open reader db: %v", err)
	}
	t.Cleanup(func() { readerDB.Close() })
	reader := &sqliteConfigStore{db: readerDB, passphrase: passphrase}

	before, err := EffectiveSettings(ctx, reader)
	if err != nil {
		t.Fatalf("EffectiveSettings before write: %v", err)
	}
	for _, setting := range before {
		if setting.Key == "discovery.provider" && setting.Source == configSourceDatabase {
			t.Fatalf("reader observed a DB override before the writer wrote one")
		}
	}

	if err := writer.Set(ctx, "discovery.provider", "network", "admin-1"); err != nil {
		t.Fatalf("Set via writer instance: %v", err)
	}

	after, err := EffectiveSettings(ctx, reader)
	if err != nil {
		t.Fatalf("EffectiveSettings after write: %v", err)
	}
	found := false
	for _, setting := range after {
		if setting.Key != "discovery.provider" {
			continue
		}
		found = true
		if setting.Source != configSourceDatabase {
			t.Errorf("Source = %q, want %q -- reader instance did not observe writer's override with no restart", setting.Source, configSourceDatabase)
		}
		if setting.Value != "network" {
			t.Errorf("Value = %q, want %q", setting.Value, "network")
		}
	}
	if !found {
		t.Fatal("discovery.provider not present in EffectiveSettings")
	}
}

// TestEffectiveSettings_SecretNeverExposesValue is the discriminating test
// for acceptance #2 across the merged env+DB view, not just the store: even
// when a secret's env default is set, EffectiveSettings must never surface
// the plaintext, only Configured=true.
func TestEffectiveSettings_SecretNeverExposesValue(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.example/T000/B000/leaked-if-buggy")
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()
	if err := s.Set(ctx, "notifications.pagerduty_routing_key", "R0ROUTINGKEY", "admin-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	settings, err := EffectiveSettings(ctx, s)
	if err != nil {
		t.Fatalf("EffectiveSettings: %v", err)
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(settingsJSON), "leaked-if-buggy") {
		t.Fatalf("EffectiveSettings leaked a secret's env-default plaintext: %s", settingsJSON)
	}
	if strings.Contains(string(settingsJSON), "R0ROUTINGKEY") {
		t.Fatalf("EffectiveSettings leaked a secret's DB-override plaintext: %s", settingsJSON)
	}

	for _, setting := range settings {
		if !setting.Secret {
			continue
		}
		if setting.Value != "" {
			t.Fatalf("secret key %q has a non-empty Value in the response", setting.Key)
		}
		if (setting.Key == "notifications.slack_webhook_url" || setting.Key == "notifications.pagerduty_routing_key") && !setting.Configured {
			t.Fatalf("secret key %q should report Configured=true", setting.Key)
		}
	}
}

func TestEffectiveSettings_NilStoreFallsBackToEnvDefaults(t *testing.T) {
	t.Setenv("APP_DISCOVERY_PROVIDER", "cloud")
	settings, err := EffectiveSettings(context.Background(), nil)
	if err != nil {
		t.Fatalf("EffectiveSettings with nil store: %v", err)
	}
	for _, setting := range settings {
		if setting.Key == "discovery.provider" && setting.Source != configSourceEnvDefault {
			t.Errorf("Source = %q, want %q", setting.Source, configSourceEnvDefault)
		}
	}
}

// TestNewConfigStoreFromEnv_FailsClosedWithNoPassphrase mirrors
// TestNewOutboundCredentialStoreFromEnv_FailsClosedWithNoPassphrase (W5-10):
// an empty passphrase must not produce a working store that "encrypts"
// secret settings under a key anyone can re-derive.
func TestNewConfigStoreFromEnv_FailsClosedWithNoPassphrase(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "")
	t.Setenv("KRYPTKEEPER_KEYSTORE_PASSPHRASE", "")

	if s := newConfigStoreFromEnv(); s != nil {
		t.Fatal("expected newConfigStoreFromEnv to return nil with no passphrase configured, got a store")
	}
}

func TestNewConfigStoreFromEnv_OpensWithPassphrase(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "test-passphrase-for-config-store")

	s := newConfigStoreFromEnv()
	if s == nil {
		t.Fatal("expected a store, got nil")
	}
	if err := s.Set(context.Background(), "discovery.provider", "network", "admin-1"); err != nil {
		t.Fatalf("Set on env-constructed store: %v", err)
	}
}
