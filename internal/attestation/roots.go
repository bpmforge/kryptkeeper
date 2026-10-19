// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RootsDirEnv names an optional operator directory of extra root PEM files.
// Files only; roots are never fetched over the network.
const RootsDirEnv = "KRYPTKEEPER_ATTESTATION_ROOTS_DIR"

// The whole directory is embedded (not a *.pem glob) so the build still works
// while no root has been shipped; see roots/README.md for provenance rules.
//
//go:embed roots
var embeddedRoots embed.FS

// NewVerifier returns a verifier trusting the embedded roots plus any
// *.pem files in $KRYPTKEEPER_ATTESTATION_ROOTS_DIR. It may hold zero roots,
// in which case every verification fails closed.
func NewVerifier() (*Verifier, error) {
	v := &Verifier{Now: nil}
	entries, err := embeddedRoots.ReadDir("roots")
	if err != nil {
		return nil, fmt.Errorf("attestation roots: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".pem") {
			continue
		}
		b, err := embeddedRoots.ReadFile("roots/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("attestation roots: %s: %w", e.Name(), err)
		}
		if err := v.addPEM(b, e.Name()); err != nil {
			return nil, err
		}
	}
	if dir := strings.TrimSpace(os.Getenv(RootsDirEnv)); dir != "" {
		files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
		if err != nil {
			return nil, fmt.Errorf("attestation roots dir: %w", err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f) //nolint:gosec // operator-configured directory
			if err != nil {
				return nil, fmt.Errorf("attestation roots: %s: %w", f, err)
			}
			if err := v.addPEM(b, f); err != nil {
				return nil, err
			}
		}
	}
	return v, nil
}

func (v *Verifier) addPEM(data []byte, name string) error {
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("attestation roots: %s: %w", name, err)
		}
		v.Roots = append(v.Roots, c)
	}
}
