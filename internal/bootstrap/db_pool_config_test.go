// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPGPoolConfigFromEnv(t *testing.T) {
	cases := []struct {
		name      string
		open, idl string
		wantOpen  int
		wantIdle  int
	}{
		{"defaults", "", "", 3, 1},
		{"explicit", "8", "4", 8, 4},
		{"open only raises nothing else", "6", "", 6, 1},
		{"non-integer open", "abc", "", 3, 1},
		{"zero open", "0", "", 3, 1},
		{"negative idle", "", "-2", 3, 1},
		{"non-integer idle", "", "x", 3, 1},
		{"idle above open falls back", "2", "5", 2, 1},
		{"open 1 idle default", "1", "", 1, 1},
		{"whitespace trimmed", " 4 ", " 2 ", 4, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{dbMaxOpenConnsEnv: tc.open, dbMaxIdleConnsEnv: tc.idl}
			got := pgPoolConfigFromEnv(func(k string) string { return env[k] })
			if got.maxOpen != tc.wantOpen || got.maxIdle != tc.wantIdle {
				t.Fatalf("got open=%d idle=%d, want %d/%d", got.maxOpen, got.maxIdle, tc.wantOpen, tc.wantIdle)
			}
			if got.maxIdleTime != 60*time.Second {
				t.Fatalf("maxIdleTime = %s", got.maxIdleTime)
			}
		})
	}
}

// database/sql exposes no getter for ConnMaxIdleTime, so observe it: with a
// tiny idle time the idle connection must be closed and counted.
func TestOpenPoolAppliesIdleSettings(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "p.db") + sqliteDSNParams
	db, err := openPool("sqlite", dsn, dbPoolConfig{maxOpen: 2, maxIdle: 1, maxIdleTime: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := db.Stats().MaxOpenConnections; got != 2 {
		t.Fatalf("MaxOpenConnections = %d, want 2", got)
	}
	// openPool pinged once, leaving one idle connection; the pool's cleaner
	// closes it after maxIdleTime. No further use, which would reset the clock.
	deadline := time.Now().Add(3 * time.Second)
	for db.Stats().MaxIdleTimeClosed == 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if db.Stats().MaxIdleTimeClosed == 0 {
		t.Fatal("SetConnMaxIdleTime not applied: no connection closed for idleness")
	}
}
