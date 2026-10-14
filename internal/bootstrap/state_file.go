// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"log"
	"os"
	"path/filepath"
)

// ensureStateDir creates the parent directory of a file-provider path. The
// defaults live under ./var, which does not exist when the hub starts from a
// fresh working directory; without this every template/CA/certificate write
// failed with ENOENT and surfaced as a 503.
func ensureStateDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}

// initStateDir is the startup-time variant: a failure is logged rather than
// fatal because read-only deployments legitimately mount these files.
func initStateDir(path string) {
	if err := ensureStateDir(path); err != nil {
		log.Printf("file provider: cannot create data directory for %q: %v", path, err)
	}
}

func writeStateFile(path string, body []byte) error {
	if err := ensureStateDir(path); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}
