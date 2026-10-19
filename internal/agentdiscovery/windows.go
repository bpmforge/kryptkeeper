// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agentdiscovery

import (
	"crypto/x509"
	"unsafe"

	"golang.org/x/sys/windows"
	"kryptkeeper/internal/agentclient"
)

// DefaultWindowsStores are the Windows certificate stores scanned by default.
var DefaultWindowsStores = []string{"MY", "ROOT", "CA", "TrustedPublisher"}

// WalkWindowsCerts enumerates certificates from Windows system certificate stores.
// Private key bytes never leave the store — only public cert data is returned.
func WalkWindowsCerts(storeNames []string) ([]agentclient.DiscoveredCert, error) {
	seen := make(map[string]struct{})
	var out []agentclient.DiscoveredCert

	for _, name := range storeNames {
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, machineStoreFlags(), uintptr(unsafe.Pointer(namePtr)))
		if err != nil {
			continue
		}

		var prev *windows.CertContext
		for {
			ctx, err := windows.CertEnumCertificatesInStore(store, prev)
			if err != nil || ctx == nil {
				break
			}
			prev = ctx

			if ctx.Length == 0 {
				continue
			}
			// ctx.EncodedCert is a pointer to the DER-encoded certificate bytes.
			der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			dc := certToDiscovered(cert, windowsStoreSource(name))
			if _, dup := seen[dc.Fingerprint]; !dup {
				seen[dc.Fingerprint] = struct{}{}
				out = append(out, dc)
			}
		}
		_ = windows.CertCloseStore(store, 0)
	}
	return out, nil
}
