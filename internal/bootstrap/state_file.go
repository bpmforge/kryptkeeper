// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"path/filepath"
	"strings"

	"kryptkeeper/internal/logging"
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
		logging.Warnf("file provider: cannot create data directory for %q: %v", path, err)
	}
}

func writeStateFile(path string, body []byte) error {
	if err := ensureStateDir(path); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

// resolveStateFilePath picks a file-provider store path. An explicit env var
// always wins. Otherwise, when KRYPTKEEPER_DATA_DIR is set the store lives in
// <data dir>/<name>, so wiping or relocating the data dir really resets or
// moves it (the old "./var/<name>" default follows the working directory, so a
// fresh data dir silently inherited stale state, CB-13).
//
// A deployment that ran with DATA_DIR set but still wrote to ./var already
// has data there: if the legacy file exists and the data-dir file does not,
// the legacy path is kept (never strand data) with a warning to move or pin it.
func resolveStateFilePath(getenv func(string) string, envVar, name string) string {
	if p := strings.TrimSpace(getenv(envVar)); p != "" {
		return p
	}
	legacy := "./var/" + name
	dataDir := strings.TrimSpace(getenv("KRYPTKEEPER_DATA_DIR"))
	if dataDir == "" {
		return legacy
	}
	path := filepath.Join(dataDir, name)
	if fileExists(legacy) && !fileExists(path) {
		logging.Warnf("%s found in the old default %s but not in %s; continuing to use %s so existing data is not stranded. "+
			"That path is relative to the working directory: move the file to %s or set %s explicitly", name, legacy, path, legacy, path, envVar)
		return legacy
	}
	return path
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
