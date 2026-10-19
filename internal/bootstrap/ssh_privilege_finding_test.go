// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "testing"

func TestUnreadablePathOfStripsQuotes(t *testing.T) {
	for in, want := range map[string]string{
		"UNREADABLE_PATH: h:find: '/etc/ssl/private': Permission denied":  "/etc/ssl/private",
		"UNREADABLE_PATH: h:find: ‘/etc/ssl/private’: Permission denied":  "/etc/ssl/private",
		"UNREADABLE_PATH: h:/etc/nginx/ssl/locked.crt: permission denied": "/etc/nginx/ssl/locked.crt",
		"UNREADABLE_PATH: h:find: “/opt/x”: Permission denied":            "/opt/x",
	} {
		if got := unreadablePathOf(in); got != want {
			t.Errorf("unreadablePathOf(%q) = %q, want %q", in, got, want)
		}
	}
}
