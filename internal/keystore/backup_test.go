// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"encoding/json"
	"testing"
)

// TestBackupRestoreAll_RoundTrip proves the actual point of a bundled backup
// feature: keys generated in one store can be recovered into a completely
// different, fresh store instance from the bundle alone (W10-03/G-36 —
// mirrors the cross-instance discipline W9-03 already established for
// single-key export/import).
func TestBackupRestoreAll_RoundTrip(t *testing.T) {
	src := newTestStore(t)
	ids := []struct {
		id   string
		algo Algorithm
	}{
		{"backup-rsa", RSA2048},
		{"backup-ecdsa", ECDSAP256},
		{"backup-mldsa", MLDSA65},
	}
	origPubs := map[string]any{}
	for _, k := range ids {
		if _, err := src.GenerateKey(k.id, k.algo); err != nil {
			t.Fatalf("GenerateKey(%s): %v", k.id, err)
		}
		pub, err := src.PublicKey(k.id)
		if err != nil {
			t.Fatalf("PublicKey(%s): %v", k.id, err)
		}
		origPubs[k.id] = pub
	}

	bundle, err := BackupAll(src, backupPassphrase)
	if err != nil {
		t.Fatalf("BackupAll: %v", err)
	}

	var parsed Bundle
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if len(parsed.Keys) != len(ids) {
		t.Fatalf("bundle has %d key entries, want %d", len(parsed.Keys), len(ids))
	}
	for _, k := range parsed.Keys {
		if k.Status != BackupKeyExported {
			t.Errorf("key %s: status %q, want %q", k.ID, k.Status, BackupKeyExported)
		}
	}

	dst := newTestStore(t) // fresh store instance, own dir/passphrase
	imported, err := RestoreAll(dst, bundle, backupPassphrase)
	if err != nil {
		t.Fatalf("RestoreAll: %v", err)
	}
	if imported != len(ids) {
		t.Fatalf("RestoreAll imported %d keys, want %d", imported, len(ids))
	}

	for _, k := range ids {
		gotPub, err := dst.PublicKey(k.id)
		if err != nil {
			t.Fatalf("restored store PublicKey(%s): %v", k.id, err)
		}
		if !publicKeysEqual(origPubs[k.id], gotPub) {
			t.Errorf("restored public key for %s does not match the original", k.id)
		}
	}
}

// TestBackupAll_EmptyStoreProducesEmptyBundle proves BackupAll doesn't error
// on a store with no keys yet (a fresh instance before any CA exists).
func TestBackupAll_EmptyStoreProducesEmptyBundle(t *testing.T) {
	store := newTestStore(t)
	bundle, err := BackupAll(store, backupPassphrase)
	if err != nil {
		t.Fatalf("BackupAll on empty store: %v", err)
	}
	var parsed Bundle
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if len(parsed.Keys) != 0 {
		t.Fatalf("expected 0 key entries, got %d", len(parsed.Keys))
	}
}

// TestRestoreAll_PartialFailureContinuesAndReportsCombinedError proves a
// bad/duplicate key entry doesn't abort the rest of a restore.
func TestRestoreAll_PartialFailureContinuesAndReportsCombinedError(t *testing.T) {
	src := newTestStore(t)
	if _, err := src.GenerateKey("ok-key", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := src.GenerateKey("dup-key", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bundle, err := BackupAll(src, backupPassphrase)
	if err != nil {
		t.Fatalf("BackupAll: %v", err)
	}

	dst := newTestStore(t)
	// Pre-create dup-key in the destination so its import collides (ErrKeyExists).
	if _, err := dst.GenerateKey("dup-key", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey (pre-seed dst): %v", err)
	}

	imported, err := RestoreAll(dst, bundle, backupPassphrase)
	if err == nil {
		t.Fatal("expected a combined error from the dup-key collision")
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1 (only ok-key should have succeeded)", imported)
	}
	if _, pubErr := dst.PublicKey("ok-key"); pubErr != nil {
		t.Errorf("ok-key should have imported despite dup-key's failure: %v", pubErr)
	}
}

func publicKeysEqual(a, b any) bool {
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(aj) == string(bj)
}
