// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build !pkcs11

package keystore

import "fmt"

// NewPKCS11StoreFromEnv returns an error because this binary was compiled
// without PKCS#11 support. Rebuild with -tags pkcs11 to enable.
func NewPKCS11StoreFromEnv() (Store, error) {
	return nil, fmt.Errorf(
		"PKCS#11 support not compiled into this binary; " +
			"rebuild with: go build -tags pkcs11 " +
			"(requires SoftHSM2 or a PKCS#11-compatible HSM and " +
			"github.com/ThalesGroup/crypto11)",
	)
}
