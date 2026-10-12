// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"testing"
)

// The suite's httptest upstreams listen on loopback, which production refuses.
func TestMain(m *testing.M) {
	egressAllowLoopback = true
	os.Exit(m.Run())
}
