// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"errors"
	"testing"

	"kryptkeeper/internal/egress"
)

func TestWSManDefaultClientRefusesMetadata(t *testing.T) {
	sh := NewWSManShell(WinRMConfig{}, nil)
	_, err := sh.client.Get("http://169.254.169.254:5985/wsman")
	if !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("want ErrBlockedDestination, got %v", err)
	}
}
