// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"strings"
	"testing"
)

func TestMachineStoreFlags(t *testing.T) {
	f := machineStoreFlags()
	if f&0x00070000 != 0x00020000 {
		t.Fatalf("flags %#x do not select CERT_SYSTEM_STORE_LOCAL_MACHINE", f)
	}
	if f&certStoreReadonly == 0 || f&certStoreOpenExisting == 0 {
		t.Fatalf("flags %#x must be read-only and open-existing", f)
	}
}

func TestWindowsStoreSourceKeepsLabel(t *testing.T) {
	if got := windowsStoreSource("MY"); got != "windows-store:MY" {
		t.Fatalf("got %q", got)
	}
}

func TestDefaultWindowsPaths(t *testing.T) {
	p := DefaultWindowsPaths(func(string) string { return "" })
	if len(p) == 0 || !strings.Contains(p[0], "ProgramData") {
		t.Fatalf("unexpected defaults %v", p)
	}
	p = DefaultWindowsPaths(func(string) string { return `D:\PD` })
	if !strings.HasPrefix(p[0], `D:\PD`) {
		t.Fatalf("ProgramData not honoured: %v", p)
	}
}
