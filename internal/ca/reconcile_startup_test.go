// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// The A3d scenario: the CA rows are in the database, but the keystore
// directory the hub now points at holds none of their keys.
func TestStartupKeyDecision_MovedKeystoreDirIsFatalByDefault(t *testing.T) {
	pass := []byte("consistency-test-passphrase-32by")
	origKeys, err := keystore.NewSoftwareStore(t.TempDir(), pass)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	root, err := NewEngine(origKeys, store).CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	emptyKeys, err := keystore.NewSoftwareStore(t.TempDir(), pass) // KEYSTORE_DIR changed
	if err != nil {
		t.Fatal(err)
	}
	findings, err := CheckKeyConsistency(emptyKeys, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !findings[0].Missing {
		t.Fatalf("expected one Missing finding, got %+v", findings)
	}

	err = StartupKeyDecision(findings, false)
	if err == nil {
		t.Fatal("a missing CA key must be fatal by default")
	}
	for _, want := range []string{root.ID, root.KeyID, "KRYPTKEEPER_KEYSTORE_DIR", AllowMissingCAKeysEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got:\n%v", want, err)
		}
	}
	if err := StartupKeyDecision(findings, true); err != nil {
		t.Fatalf("explicit opt-out must allow the start: %v", err)
	}
}

func TestStartupKeyDecision(t *testing.T) {
	missing := KeyConsistencyFinding{CAID: "ca-1", CAName: "Root", KeyID: "k1", Detail: "gone", Missing: true}
	mismatch := KeyConsistencyFinding{CAID: "ca-2", CAName: "Other", KeyID: "k2", Detail: "differs"}
	cases := []struct {
		name     string
		findings []KeyConsistencyFinding
		allow    bool
		wantErr  bool
	}{
		{"no findings", nil, false, false},
		{"missing, no opt-out", []KeyConsistencyFinding{missing}, false, true},
		{"missing, opt-out", []KeyConsistencyFinding{missing}, true, false},
		{"mismatch only stays a warning", []KeyConsistencyFinding{mismatch}, false, false},
		{"missing among mismatches", []KeyConsistencyFinding{mismatch, missing}, false, true},
	}
	for _, c := range cases {
		err := StartupKeyDecision(c.findings, c.allow)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
	// Only the missing CA is named, not the mismatching one.
	err := StartupKeyDecision([]KeyConsistencyFinding{mismatch, missing}, false)
	if err == nil || !strings.Contains(err.Error(), "ca-1") || strings.Contains(err.Error(), "ca-2") {
		t.Fatalf("error must name only the missing-key CA: %v", err)
	}
}
