// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"errors"
	"testing"
)

func newTestSoftware(t *testing.T) *SoftwareStore {
	t.Helper()
	s, err := NewSoftwareStore(t.TempDir(), []byte("passphrase-test-32chars-exactly!"))
	if err != nil {
		t.Fatalf("NewSoftwareStore: %v", err)
	}
	return s
}

func TestGenerateProtectedKeyRefusesSoftwareStore(t *testing.T) {
	sw := newTestSoftware(t)
	if _, _, err := GenerateProtectedKey(sw, "cs-key", ECDSAP256); !errors.Is(err, ErrProtectedStoreRequired) {
		t.Fatalf("plain software store: err = %v, want ErrProtectedStoreRequired", err)
	}
	r, err := NewRouter("software", map[string]Store{"software": sw})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenerateProtectedKey(r, "cs-key", ECDSAP256); !errors.Is(err, ErrProtectedStoreRequired) {
		t.Fatalf("software-only router: err = %v, want ErrProtectedStoreRequired", err)
	}
	if list, _ := sw.List(); len(list) != 0 {
		t.Fatalf("software store holds %d keys, want 0 (no fallback)", len(list))
	}
	if _, _, err := GenerateProtectedKey(nil, "cs-key", ECDSAP256); !errors.Is(err, ErrProtectedStoreRequired) {
		t.Fatalf("nil store: err = %v", err)
	}
}

func TestGenerateProtectedKeyPicksProtectedBackend(t *testing.T) {
	sw, hsm := newTestSoftware(t), newTestSoftware(t)
	r, err := NewRouter("software", map[string]Store{"software": sw, "pkcs11": hsm})
	if err != nil {
		t.Fatal(err)
	}
	meta, label, err := GenerateProtectedKey(r, "cs-key", ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateProtectedKey: %v", err)
	}
	if label != "pkcs11" || meta.ID != "cs-key" {
		t.Fatalf("label=%q id=%q", label, meta.ID)
	}
	if _, err := hsm.Metadata("cs-key"); err != nil {
		t.Fatalf("key not in protected backend: %v", err)
	}
	if _, err := sw.Metadata("cs-key"); err == nil {
		t.Fatal("key leaked into the software backend")
	}
}

func TestGenerateProtectedKeyBackendOverride(t *testing.T) {
	sw := newTestSoftware(t)
	r, _ := NewRouter("software", map[string]Store{"software": sw, "pkcs11": newTestSoftware(t)})
	t.Setenv("KRYPTKEEPER_CODESIGN_KEY_BACKEND", "software")
	if _, _, err := GenerateProtectedKey(r, "cs-key", ECDSAP256); !errors.Is(err, ErrProtectedStoreRequired) {
		t.Fatalf("override to software: err = %v, want ErrProtectedStoreRequired", err)
	}
}
