// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import "path/filepath"

// certSystemStoreLocalMachine selects the machine-wide store location. The
// CurrentUser view that CertOpenSystemStore opens merges Root/CA with the
// machine stores but not MY, which is where server TLS certificates live.
// Value is CERT_SYSTEM_STORE_LOCAL_MACHINE (windows.h); a Windows-only test
// (windows_flags_windows_test.go) checks it against golang.org/x/sys/windows.
const certSystemStoreLocalMachine = 0x00020000

// certStoreReadOnlyFlags opens an existing store without write access, so the
// agent can never create a store or modify one.
const (
	certStoreReadonly     = 0x00008000
	certStoreOpenExisting = 0x00004000
)

// machineStoreFlags is the CertOpenStore flag set for read-only enumeration of
// a LocalMachine system store.
func machineStoreFlags() uint32 {
	return certSystemStoreLocalMachine | certStoreReadonly | certStoreOpenExisting
}

// windowsStoreSource is the Source label the hub sees for a store cert.
func windowsStoreSource(store string) string { return "windows-store:" + store }

// DefaultWindowsPaths returns conservative default file-scan locations for a
// Windows host: the ACME client and common web-server certificate directories.
// getenv supplies ProgramData; an unset value falls back to C:\ProgramData.
// Missing directories are skipped by the walker. Override with
// KRYPTKEEPER_SCAN_PATHS.
func DefaultWindowsPaths(getenv func(string) string) []string {
	pd := getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return []string{
		filepath.Join(pd, "win-acme"),
		filepath.Join(pd, "ssl"),
		`C:\nginx\conf`,
		`C:\Apache24\conf`,
		`C:\xampp\apache\conf`,
	}
}
