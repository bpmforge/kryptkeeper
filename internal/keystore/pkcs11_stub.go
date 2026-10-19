// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build !pkcs11

package keystore

import "errors"

// ErrPKCS11NotCompiled is a variable, not a literal in the return, so callers'
// `err != nil` checks stay meaningful to staticcheck (the pkcs11-tagged build
// really can succeed).
var ErrPKCS11NotCompiled = errors.New(
	"PKCS#11 support not compiled into this binary; " +
		"rebuild with: go build -tags pkcs11 " +
		"(requires SoftHSM2 or a PKCS#11-compatible HSM and " +
		"github.com/ThalesGroup/crypto11)")

// NewPKCS11StoreFromEnv returns ErrPKCS11NotCompiled because this binary was
// compiled without PKCS#11 support. Rebuild with -tags pkcs11 to enable.
func NewPKCS11StoreFromEnv() (Store, error) {
	return nil, ErrPKCS11NotCompiled
}
