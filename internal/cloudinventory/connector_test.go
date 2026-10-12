// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import "testing"

func TestTruncate(t *testing.T) {
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("got %q", got)
	}
	if got := truncate("hi", 10); got != "hi" {
		t.Errorf("short string should be unchanged, got %q", got)
	}
}
