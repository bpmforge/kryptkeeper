// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agentdiscovery

import "kryptkeeper/internal/agentclient"

func walkCertsPlatform(paths []string) ([]agentclient.DiscoveredCert, error) {
	return WalkLinuxCerts(paths)
}
