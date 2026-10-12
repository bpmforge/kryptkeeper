// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const legacyKeystoreDir = "./var/keys"

// ResolveKeystoreDir picks the software-keystore directory.
//
// KRYPTKEEPER_KEYSTORE_DIR always wins. Otherwise, when KRYPTKEEPER_DATA_DIR
// is set the keys live in <data dir>/keys, so a container with only the data
// directory on a volume keeps its CA keys (the old "./var/keys" default is
// relative to the working directory, i.e. the container's writable layer).
// With neither set the historical ./var/keys is kept.
//
// Deployments that used to fall back to ./var/keys while DATA_DIR was set
// already have keys there: if the legacy directory holds files and the new
// default holds none, the legacy directory is kept (never strand keys) and a
// warning telling the operator to move or pin it is returned.
func ResolveKeystoreDir(getenv func(string) string) (dir, warning string) {
	if d := strings.TrimSpace(getenv("KRYPTKEEPER_KEYSTORE_DIR")); d != "" {
		return d, ""
	}
	dataDir := strings.TrimSpace(getenv("KRYPTKEEPER_DATA_DIR"))
	if dataDir == "" {
		return legacyKeystoreDir, ""
	}
	dir = filepath.Join(dataDir, "keys")
	if dirHasFiles(legacyKeystoreDir) && !dirHasFiles(dir) {
		return legacyKeystoreDir, fmt.Sprintf("WARNING: key files found in %s (the old default) but none in %s; "+
			"continuing to use %s so existing CA keys are not stranded. That path is relative to the working "+
			"directory and is lost if the container is recreated: move the files to %s or set KRYPTKEEPER_KEYSTORE_DIR explicitly",
			legacyKeystoreDir, dir, legacyKeystoreDir, dir)
	}
	return dir, ""
}

func dirHasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			return true
		}
	}
	return false
}

// EnsureWritableKeystoreDir creates dir and proves it is writable by creating
// and removing a probe file; MkdirAll alone succeeds on an existing directory
// inside a read-only filesystem, which would defer the failure to the first
// key generation.
func EnsureWritableKeystoreDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".write-probe-*")
	if err != nil {
		return fmt.Errorf("directory is not writable: %w", err)
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
