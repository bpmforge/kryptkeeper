// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import "kryptkeeper/internal/agentclient"

// WalkCerts discovers certificates using platform-appropriate methods.
//
// On Windows: reads the MY, ROOT, CA, and TrustedPublisher system stores
// via the Win32 CertEnumCertificatesInStore API, then also scans any
// explicit file paths provided.
//
// On Linux and macOS: walks the filesystem paths in paths using WalkLinuxCerts.
// Pass DefaultLinuxPaths for standard system locations.
//
// In both cases any cert paths extracted from web server config files are
// included when callers first expand them via WalkConfigCerts.
func WalkCerts(paths []string) ([]agentclient.DiscoveredCert, error) {
	return walkCertsPlatform(paths)
}
