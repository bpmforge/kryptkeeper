// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileProvidersCreateMissingDataDir(t *testing.T) {
	ctx := context.Background()

	t.Run("startup creates the directory 0700", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "var")
		t.Setenv("APP_TEMPLATE_FILE", filepath.Join(dir, "bootstrap-templates.json"))
		NewFileTemplateProviderFromEnv()
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("data dir not created at startup: %v", err)
		}
		if got := st.Mode().Perm(); got != 0o700 {
			t.Fatalf("data dir mode = %o, want 700", got)
		}
	})

	t.Run("template write succeeds with no pre-existing dir", func(t *testing.T) {
		p := &fileTemplateProvider{filePath: filepath.Join(t.TempDir(), "var", "bootstrap-templates.json")}
		if _, err := p.CreateTemplate(ctx, TemplateUpsertRequest{
			Name: "t", DisplayName: "T", KeyUsage: []string{"digitalSignature"},
			ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"ECDSA"},
			ValidityPeriod: "P90D", Active: true,
		}); err != nil {
			t.Fatalf("create template in a fresh working directory: %v", err)
		}
	})

	t.Run("ca and certificate stores save with no pre-existing dir", func(t *testing.T) {
		root := t.TempDir()
		if err := (&fileCAProvider{filePath: filepath.Join(root, "a", "cas.json")}).saveItems(nil); err != nil {
			t.Fatalf("ca saveItems: %v", err)
		}
		if err := (&fileCertificateProvider{filePath: filepath.Join(root, "b", "certs.json")}).saveItems(nil); err != nil {
			t.Fatalf("certificate saveItems: %v", err)
		}
	})
}
