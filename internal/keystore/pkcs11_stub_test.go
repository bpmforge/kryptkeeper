// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build !pkcs11

package keystore

import (
	"strings"
	"testing"
)

func TestNewPKCS11StoreFromEnv_StubReturnsError(t *testing.T) {
	store, err := NewPKCS11StoreFromEnv()
	if err == nil {
		t.Fatal("expected error from PKCS#11 stub, got nil")
	}
	if store != nil {
		t.Errorf("expected nil store from stub, got %v", store)
	}
	if !strings.Contains(err.Error(), "pkcs11") {
		t.Errorf("expected error to mention pkcs11, got: %v", err)
	}
	if !strings.Contains(err.Error(), "-tags pkcs11") {
		t.Errorf("expected error to mention build tag, got: %v", err)
	}
}
