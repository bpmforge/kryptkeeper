// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// CB-13: file-provider stores follow KRYPTKEEPER_DATA_DIR instead of the
// working directory, without stranding data of deployments that rely on ./var.
func TestResolveStateFilePath(t *testing.T) {
	const name = "bootstrap-templates.json"
	data := t.TempDir()

	if got := resolveStateFilePath(envMap(nil), "APP_TEMPLATE_FILE", name); got != "./var/"+name {
		t.Errorf("no data dir keeps the historical default, got %q", got)
	}
	if got := resolveStateFilePath(envMap(map[string]string{"KRYPTKEEPER_DATA_DIR": data}), "APP_TEMPLATE_FILE", name); got != filepath.Join(data, name) {
		t.Errorf("data dir wins over ./var, got %q", got)
	}
	explicit := map[string]string{"KRYPTKEEPER_DATA_DIR": data, "APP_TEMPLATE_FILE": "/etc/kk/t.json"}
	if got := resolveStateFilePath(envMap(explicit), "APP_TEMPLATE_FILE", name); got != "/etc/kk/t.json" {
		t.Errorf("explicit env always wins, got %q", got)
	}
}

func TestResolveStateFilePathKeepsLegacyFileUntilDataDirHoldsOne(t *testing.T) {
	const name = "bootstrap-templates.json"
	wd := t.TempDir()
	t.Chdir(wd)
	if err := os.MkdirAll("var", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("var", name), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	env := envMap(map[string]string{"KRYPTKEEPER_DATA_DIR": data})
	if got := resolveStateFilePath(env, "APP_TEMPLATE_FILE", name); got != "./var/"+name {
		t.Fatalf("existing legacy store must not be stranded, got %q", got)
	}
	// Once the data dir holds its own copy, it takes over.
	if err := os.WriteFile(filepath.Join(data, name), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveStateFilePath(env, "APP_TEMPLATE_FILE", name); got != filepath.Join(data, name) {
		t.Fatalf("data dir copy must win, got %q", got)
	}
}

func TestFileProvidersDefaultUnderDataDir(t *testing.T) {
	data := t.TempDir()
	t.Setenv("KRYPTKEEPER_DATA_DIR", data)
	t.Setenv("APP_TEMPLATE_FILE", "")
	t.Chdir(t.TempDir())
	p := NewFileTemplateProviderFromEnv().(*fileTemplateProvider)
	if p.filePath != filepath.Join(data, "bootstrap-templates.json") {
		t.Fatalf("template store path = %q", p.filePath)
	}
}
