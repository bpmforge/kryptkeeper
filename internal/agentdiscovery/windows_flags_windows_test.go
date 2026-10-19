// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agentdiscovery

import (
	"testing"

	"golang.org/x/sys/windows"
)

// The shared literals must equal the Win32 values the API actually uses.
func TestMachineStoreFlagsMatchWin32(t *testing.T) {
	want := uint32(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE | windows.CERT_STORE_READONLY_FLAG | windows.CERT_STORE_OPEN_EXISTING_FLAG)
	if machineStoreFlags() != want {
		t.Fatalf("got %#x want %#x", machineStoreFlags(), want)
	}
}
