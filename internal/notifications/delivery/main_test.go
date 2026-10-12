// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"os"
	"testing"
)

// The suite's httptest servers listen on loopback, which production refuses.
func TestMain(m *testing.M) {
	egressAllowLoopback = true
	os.Exit(m.Run())
}
