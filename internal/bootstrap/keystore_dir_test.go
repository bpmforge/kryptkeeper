// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestResolveKeystoreDir(t *testing.T) {
	// Run from an empty cwd so ./var/keys does not exist.
	t.Chdir(t.TempDir())

	if d, w := ResolveKeystoreDir(envMap(nil)); d != "./var/keys" || w != "" {
		t.Errorf("neither set: got %q %q", d, w)
	}
	if d, w := ResolveKeystoreDir(envMap(map[string]string{"KRYPTKEEPER_DATA_DIR": "/data"})); d != filepath.Join("/data", "keys") || w != "" {
		t.Errorf("data dir only: got %q %q, want /data/keys", d, w)
	}
	if d, _ := ResolveKeystoreDir(envMap(map[string]string{"KRYPTKEEPER_DATA_DIR": "/data", "KRYPTKEEPER_KEYSTORE_DIR": "/k"})); d != "/k" {
		t.Errorf("explicit keystore dir must win, got %q", d)
	}
}

func TestResolveKeystoreDirKeepsLegacyKeys(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	data := filepath.Join(cwd, "data")
	if err := os.MkdirAll("var/keys", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("var/keys/ca-1.key", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := envMap(map[string]string{"KRYPTKEEPER_DATA_DIR": data})

	d, w := ResolveKeystoreDir(env)
	if d != "./var/keys" || !strings.Contains(w, "WARNING") {
		t.Fatalf("legacy keys present, new empty: got %q %q", d, w)
	}

	// Once the new location holds keys it wins and the warning stops.
	if err := os.MkdirAll(filepath.Join(data, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "keys", "ca-1.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d, w := ResolveKeystoreDir(env); d != filepath.Join(data, "keys") || w != "" {
		t.Errorf("new dir populated: got %q %q", d, w)
	}
}

func TestEnsureWritableKeystoreDir(t *testing.T) {
	ok := filepath.Join(t.TempDir(), "a", "keys")
	if err := EnsureWritableKeystoreDir(ok); err != nil {
		t.Fatalf("fresh dir: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(ok, ".write-probe-*")); len(left) != 0 {
		t.Errorf("probe file left behind: %v", left)
	}

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := EnsureWritableKeystoreDir(ro); err == nil {
		t.Error("read-only existing dir must be rejected")
	}
}
