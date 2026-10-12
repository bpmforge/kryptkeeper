// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadEnvFileAppliesAndRespectsExistingEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	os.WriteFile(path, []byte("# comment\n\nKK_T_HUB = https://hub:8443\nKK_T_KEEP=file\n"), 0o600)
	t.Setenv("KK_T_KEEP", "env")
	os.Unsetenv("KK_T_HUB")
	t.Cleanup(func() { os.Unsetenv("KK_T_HUB") })
	if err := loadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("KK_T_HUB") != "https://hub:8443" || os.Getenv("KK_T_KEEP") != "env" {
		t.Fatalf("got hub=%q keep=%q", os.Getenv("KK_T_HUB"), os.Getenv("KK_T_KEEP"))
	}
}

func TestLoadEnvFileRejectsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	os.WriteFile(path, []byte("not a pair\n"), 0o600)
	if err := loadEnvFile(path); err == nil {
		t.Fatal("malformed line accepted")
	}
}

func TestPersistCredentialsRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	os.WriteFile(path, []byte("KRYPTKEEPER_HUB_URL=https://hub\n"), 0o600)
	if err := persistCredentials(path, "agt-1", "tok-1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Unsetenv("KRYPTKEEPER_AGENT_ID")
		os.Unsetenv("KRYPTKEEPER_AGENT_TOKEN")
		os.Unsetenv("KRYPTKEEPER_HUB_URL")
	})
	if err := loadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("KRYPTKEEPER_AGENT_ID") != "agt-1" || os.Getenv("KRYPTKEEPER_AGENT_TOKEN") != "tok-1" {
		t.Fatal("persisted credentials not reloaded")
	}
}

func TestCredentialsFileRoundTripIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "credentials.env")
	t.Setenv("KRYPTKEEPER_AGENT_CREDENTIALS_FILE", path)
	if got := credentialsFilePath(); got != path {
		t.Fatalf("credentialsFilePath = %q, want %q", got, path)
	}
	if err := writeCredentialsFile(path, "agent-1", "tok-secret"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("credentials file mode %v, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Dir(path)); runtime.GOOS != "windows" && di.Mode().Perm() != 0o700 {
		t.Errorf("credentials dir mode %v, want 0700", di.Mode().Perm())
	}
	os.Unsetenv("KRYPTKEEPER_AGENT_ID")
	os.Unsetenv("KRYPTKEEPER_AGENT_TOKEN")
	t.Cleanup(func() { os.Unsetenv("KRYPTKEEPER_AGENT_ID"); os.Unsetenv("KRYPTKEEPER_AGENT_TOKEN") })
	if err := loadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("KRYPTKEEPER_AGENT_ID") != "agent-1" || os.Getenv("KRYPTKEEPER_AGENT_TOKEN") != "tok-secret" {
		t.Error("credentials did not round-trip through the file")
	}
	// A second registration replaces the first rather than appending.
	if err := writeCredentialsFile(path, "agent-2", "tok-2"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "agent-1") || !strings.Contains(string(raw), "agent-2") {
		t.Errorf("rewrite left stale credentials: %q", raw)
	}
}
