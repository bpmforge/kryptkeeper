// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"kryptkeeper/internal/privexec"
)

func TestNewHostDiscoveryModes(t *testing.T) {
	for _, mode := range []string{"", "none", "nopasswd", "helper"} {
		d, err := newHostDiscovery(mode)
		if err != nil {
			t.Fatalf("%q: %v", mode, err)
		}
		want := privexec.Mode(mode)
		if mode == "" {
			want = privexec.ModeNone
		}
		if d.mode != want || d.priv == nil || d.plain == nil {
			t.Fatalf("%q: %+v", mode, d)
		}
	}
	// The agent holds no stored sudo password; the mode is refused loudly.
	if _, err := newHostDiscovery("password"); err == nil || !strings.Contains(err.Error(), "not offered to the agent") {
		t.Fatalf("password mode: %v", err)
	}
	if _, err := newHostDiscovery("root"); err == nil || !strings.Contains(err.Error(), "KRYPTKEEPER_PRIVILEGE_MODE") {
		t.Fatalf("unknown mode: %v", err)
	}
}
