// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package agentdiscovery provides certificate discovery for satellite agents.
// Each platform has its own file that scans the appropriate certificate stores.
package agentdiscovery

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"kryptkeeper/internal/logging"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kryptkeeper/internal/agentclient"
)

// DefaultLinuxPaths are the standard locations for TLS certificates on Linux.
var DefaultLinuxPaths = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/etc/ssl",
	"/usr/local/share/ca-certificates",
	"/usr/share/ca-certificates",
	"/etc/nginx/ssl",
	"/etc/apache2/ssl",
	"/etc/httpd/ssl",
	"/etc/letsencrypt/live",
	"/opt/ssl",
}

// WalkLinuxCerts scans the given directory paths for PEM-encoded certificate
// files and returns one DiscoveredCert per unique certificate found. Paths it
// cannot open are logged, not silently dropped; WalkLinuxCertsDetailed hands
// them back so the inventory push can report them (W34-09).
func WalkLinuxCerts(paths []string) ([]agentclient.DiscoveredCert, error) {
	certs, unreadable, err := WalkLinuxCertsDetailed(paths)
	if len(unreadable) > 0 {
		logging.Infof("discovery: %d path(s) unreadable (first: %s: %s)", len(unreadable), unreadable[0].Path, unreadable[0].Error)
	}
	return certs, err
}

// WalkLinuxCertsDetailed is WalkLinuxCerts plus every path the walk could not
// open or read for lack of permission. Other failures (a file that is not a
// certificate) are not unreadable paths.
func WalkLinuxCertsDetailed(paths []string) ([]agentclient.DiscoveredCert, []agentclient.UnreadablePath, error) {
	seen := make(map[string]struct{})
	var out []agentclient.DiscoveredCert
	var unreadable []agentclient.UnreadablePath
	note := func(path string, err error) {
		if errors.Is(err, fs.ErrPermission) {
			unreadable = append(unreadable, agentclient.UnreadablePath{Path: path, Error: err.Error()})
		}
	}
	add := func(certs []agentclient.DiscoveredCert) {
		for _, c := range certs {
			if _, dup := seen[c.Fingerprint]; !dup {
				seen[c.Fingerprint] = struct{}{}
				out = append(out, c)
			}
		}
	}

	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			note(root, err)
			continue // absent on this host, or not searchable
		}
		if !info.IsDir() {
			certs, err := certsFromFile(root)
			if err != nil {
				note(root, err)
				continue
			}
			add(certs)
			continue
		}

		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { // partial results are used as-is; walk errors are recorded, not fatal
			if err != nil {
				note(path, err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			switch {
			case keystoreCandidate(path):
				certs, err := keystoreCertsFromFile(path)
				note(path, err)
				add(certs)
			case isCertFile(path):
				certs, err := certsFromFile(path)
				note(path, err)
				add(certs)
			}
			return nil
		})
	}

	return out, unreadable, nil
}

// maxKeystoreFileSize bounds what the walker reads into memory per keystore.
const maxKeystoreFileSize = 16 << 20

// keystoreCandidate reports whether path looks like a keystore or kubeconfig
// that ScanKeystoreFile can read: Java/PKCS#12 stores by extension, kubeconfig
// by name. A bare "config" only counts inside a .kube directory, so the walk
// does not slurp every unrelated config file.
func keystoreCandidate(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jks", ".keystore", ".jceks", ".bcfks", ".p12", ".pfx":
		return true
	}
	if base == "kubeconfig" || strings.HasSuffix(base, ".kubeconfig") {
		return true
	}
	return base == "config" && filepath.Base(filepath.Dir(path)) == ".kube"
}

// keystoreCertsFromFile extracts the certificates (never keys) from a keystore
// file. Unreadable stores are logged with their reason and yield no certs.
func keystoreCertsFromFile(path string) ([]agentclient.DiscoveredCert, error) {
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxKeystoreFileSize {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var res KeystoreScanResult
	ScanKeystoreFile(path, data, nil, &res)
	for _, u := range res.UnreadableStores {
		logging.Infof("keystore: %s", u)
	}
	return res.Certs, nil
}

// isCertFile returns true for files with common certificate extensions.
func isCertFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".crt", ".cer", ".pem", ".cert":
		return true
	}
	return false
}

// certsFromFile parses all PEM CERTIFICATE blocks in a file.
func certsFromFile(path string) ([]agentclient.DiscoveredCert, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out []agentclient.DiscoveredCert
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, certToDiscovered(cert, path))
	}
	return out, nil
}

// certToDiscovered converts an x509.Certificate to an agentclient.DiscoveredCert.
func certToDiscovered(cert *x509.Certificate, source string) agentclient.DiscoveredCert {
	fp := sha256.Sum256(cert.Raw)
	fingerprint := colonHex(fp[:])

	autoRenewable := time.Until(cert.NotAfter) < 90*24*time.Hour &&
		cert.NotAfter.After(time.Now())

	return agentclient.DiscoveredCert{
		Fingerprint:   fingerprint,
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore.UTC(),
		NotAfter:      cert.NotAfter.UTC(),
		Source:        source,
		AutoRenewable: autoRenewable,
		// W19-13: report SAN DNS names so the hub can build ACME identifiers
		// instead of falling back to parsing Subject's RDN string.
		DNSNames: cert.DNSNames,
	}
}

// colonHex formats raw bytes as colon-separated hex (e.g. "aa:bb:cc").
func colonHex(b []byte) string {
	h := hex.EncodeToString(b)
	parts := make([]string, len(b))
	for i := 0; i < len(b); i++ {
		parts[i] = h[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}
