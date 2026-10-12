// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package agentdiscovery provides certificate discovery for satellite agents.
// Each platform has its own file that scans the appropriate certificate stores.
package agentdiscovery

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
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
// files and returns one DiscoveredCert per unique certificate found.
// Errors opening individual files are silently skipped.
func WalkLinuxCerts(paths []string) ([]agentclient.DiscoveredCert, error) {
	seen := make(map[string]struct{})
	var out []agentclient.DiscoveredCert

	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			continue // path doesn't exist on this host
		}
		if !info.IsDir() {
			if certs, err := certsFromFile(root); err == nil {
				for _, c := range certs {
					if _, dup := seen[c.Fingerprint]; !dup {
						seen[c.Fingerprint] = struct{}{}
						out = append(out, c)
					}
				}
			}
			continue
		}

		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { // partial results are used as-is; walk errors are non-fatal here
			if err != nil || d.IsDir() {
				return nil
			}
			if !isCertFile(path) {
				return nil
			}
			certs, err := certsFromFile(path)
			if err != nil {
				return nil
			}
			for _, c := range certs {
				if _, dup := seen[c.Fingerprint]; !dup {
					seen[c.Fingerprint] = struct{}{}
					out = append(out, c)
				}
			}
			return nil
		})
	}

	return out, nil
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

	autoRenewable := cert.NotAfter.Sub(time.Now()) < 90*24*time.Hour &&
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

// KeySize returns the public key size in bits for display purposes.
func KeySize(cert *x509.Certificate) int {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	default:
		return 0
	}
}

// IsExpired reports whether the certificate is past its NotAfter date.
func IsExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

// DaysUntilExpiry returns the number of days until the certificate expires.
// Negative values mean the certificate is already expired.
func DaysUntilExpiry(cert *x509.Certificate) int {
	return int(time.Until(cert.NotAfter).Hours() / 24)
}

// FormatFingerprint produces a colon-separated SHA-256 fingerprint string.
func FormatFingerprint(cert *x509.Certificate) string {
	fp := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", fp)
}
