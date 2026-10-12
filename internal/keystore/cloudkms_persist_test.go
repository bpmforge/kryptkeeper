// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// W9-02: cloud-KMS key references persist and survive a restart. No cloud
// calls anywhere — the persistence layer is exercised with fabricated
// entries; Sign() would be the first network touch and is never made.

func newCloudKMSTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "cloudkms.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// fabricateEntry inserts a reference the way generateKey* would, without the
// cloud round-trip.
func fabricateEntry(t *testing.T, s *CloudKMSStore, id, uri string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	entry := &cloudKMSKeyEntry{
		meta: KeyMetadata{ID: id, Algorithm: ECDSAP256, CreatedAt: time.Now().UTC().Format(time.RFC3339)},
		config: CloudKMSConfig{
			Provider: s.provider, KeyURI: uri, Region: "us-east-1",
		},
		pubKey: &key.PublicKey,
	}
	s.mu.Lock()
	s.keys[id] = entry
	s.mu.Unlock()
	if err := s.persistRef(id, entry); err != nil {
		t.Fatalf("persist: %v", err)
	}
}

func TestCloudKMSRefsSurviveRestart(t *testing.T) {
	db := newCloudKMSTestDB(t)

	first, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("first store: %v", err)
	}
	fabricateEntry(t, first, "ca-signing-key", "arn:aws:kms:us-east-1:123456789012:key/test-1")

	// Restart: a second store on the same DB must see the reference — this
	// is exactly what the in-memory map lost (G-34).
	second, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("second store: %v", err)
	}
	meta, err := second.Metadata("ca-signing-key")
	if err != nil {
		t.Fatalf("reference did not survive the restart: %v", err)
	}
	if meta.Algorithm != ECDSAP256 {
		t.Fatalf("algorithm lost: %+v", meta)
	}

	// The signer serves the parsed public key with zero KMS calls; the URI
	// rides along for the eventual Sign().
	signer, err := second.Signer("ca-signing-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	kmsSigner, ok := signer.(*CloudKMSSigner)
	if !ok {
		t.Fatalf("wrong signer type %T", signer)
	}
	if kmsSigner.config.KeyURI != "arn:aws:kms:us-east-1:123456789012:key/test-1" {
		t.Fatalf("key URI lost across restart: %q", kmsSigner.config.KeyURI)
	}
	if _, ok := kmsSigner.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("public key not reparsed: %T", kmsSigner.Public())
	}
}

func TestCloudKMSDeleteRemovesTheRow(t *testing.T) {
	db := newCloudKMSTestDB(t)
	store, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fabricateEntry(t, store, "doomed", "arn:aws:kms:us-east-1:123456789012:key/doomed")
	store.destroyKey = func(context.Context, CloudKMSConfig) error { return nil }

	if err := store.Delete("doomed"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	reloaded, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := reloaded.Metadata("doomed"); err == nil {
		t.Fatal("deleted reference resurrected after restart")
	}
}

func TestCloudKMSProviderIsolation(t *testing.T) {
	// Two providers on one DB must not see each other's references.
	db := newCloudKMSTestDB(t)
	aws, _ := NewCloudKMSStoreWithDB("aws", db, false)
	fabricateEntry(t, aws, "aws-key", "arn:aws:kms:us-east-1:1:key/a")

	gcp, err := NewCloudKMSStoreWithDB("gcp", db, false)
	if err != nil {
		t.Fatalf("gcp store: %v", err)
	}
	if _, err := gcp.Metadata("aws-key"); err == nil {
		t.Fatal("gcp store sees an aws reference")
	}
}

func TestCloudKMSRejectsUnknownProvider(t *testing.T) {
	if _, err := NewCloudKMSStoreWithDB("oracle", nil, false); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
