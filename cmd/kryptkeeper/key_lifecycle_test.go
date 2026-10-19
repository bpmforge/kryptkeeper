// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/keystore"
)

func TestKeyLifecycleOptionWiresManager(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("KRYPTKEEPER_KEY_ROTATION_SWEEP_INTERVAL", "1h")
	t.Cleanup(func() { bootstrap.SetActiveKeyLifecycle(nil) })

	opt, stop := keyLifecycleOption(nil, nil, false, nil, nil, nil, nil, nil)
	if opt != nil || stop == nil || bootstrap.ActiveKeyLifecycle() != nil {
		t.Fatal("without keys and a DB the lifecycle must stay off")
	}

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "l.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("lifecycle-wiring-passphrase-32!!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Close() })

	opt, stop = keyLifecycleOption(keys, db, false, nil, nil, nil, nil, nil)
	defer stop()
	if opt == nil || bootstrap.ActiveKeyLifecycle() == nil {
		t.Fatal("keyLifecycleOption must publish the manager and return the executor option")
	}
}
