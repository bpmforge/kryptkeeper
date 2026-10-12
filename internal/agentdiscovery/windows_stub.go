// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agentdiscovery

import "kryptkeeper/internal/agentclient"

// DefaultWindowsStores are the Windows certificate stores scanned by default.
var DefaultWindowsStores = []string{"MY", "ROOT", "CA", "TrustedPublisher"}

// WalkWindowsCerts is a no-op stub on non-Windows platforms.
// On Windows, it enumerates system certificate stores using the Win32 API.
func WalkWindowsCerts(_ []string) ([]agentclient.DiscoveredCert, error) {
	return nil, nil
}
