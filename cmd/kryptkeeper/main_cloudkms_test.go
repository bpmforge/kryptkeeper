// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// W9-02: the wiring itself — the backend switch can now actually reach the
// cloud KMS store (it was dead code), and refuses to run half-configured.

func TestBuildCloudKMSStoreRequiresProvider(t *testing.T) {
	if _, err := buildCloudKMSStore("", nil, false); err == nil {
		t.Fatal("cloudkms backend without KRYPTKEEPER_KMS_PROVIDER must refuse")
	}
	if _, err := buildCloudKMSStore("oracle", nil, false); err == nil {
		t.Fatal("unknown provider must refuse")
	}
}

func TestBuildCloudKMSStoreConstructsWithDB(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kms.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	store, err := buildCloudKMSStore("aws", db, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if store == nil {
		t.Fatal("nil store")
	}
	// The ref table exists — proof the persistence path is armed.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cloud_kms_keys`).Scan(&n); err != nil {
		t.Fatalf("cloud_kms_keys table missing after construction: %v", err)
	}
}
