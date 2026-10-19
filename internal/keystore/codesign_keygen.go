// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrProtectedStoreRequired is returned when no HSM/KMS-backed store can hold
// a code-signing key. Callers must refuse; falling back to a software store
// would put an extractable signing key on the hub (FR-P91).
var ErrProtectedStoreRequired = errors.New("keystore: a non-extractable (HSM/KMS) store is required")

// protectedLabels are the Router backend labels that never release private
// key material, in preference order.
var protectedLabels = []string{"pkcs11", "cloudkms", "vault"}

// protectedTypeNames are the concrete Store types treated as protected when
// the store is not a Router.
var protectedTypeNames = []string{"PKCS11Store", "VaultStore", "CloudKMSStore"}

// GenerateProtectedKey generates id in an HSM/KMS backend and returns its
// metadata plus the backend label. The backend is KRYPTKEEPER_CODESIGN_KEY_BACKEND
// when set, else the first of pkcs11, cloudkms, vault the Router has enabled.
// It never falls back to a software store.
func GenerateProtectedKey(store Store, id string, algo Algorithm) (KeyMetadata, string, error) {
	if store == nil {
		return KeyMetadata{}, "", ErrProtectedStoreRequired
	}
	if r, ok := store.(*Router); ok {
		label, err := protectedLabel(r)
		if err != nil {
			return KeyMetadata{}, "", err
		}
		var meta KeyMetadata
		err = r.WithCreateBackend(label, func() error {
			var gerr error
			meta, gerr = r.GenerateKey(id, algo)
			return gerr
		})
		if err != nil {
			return KeyMetadata{}, "", err
		}
		return meta, label, nil
	}
	t := fmt.Sprintf("%T", store)
	for _, name := range protectedTypeNames {
		if strings.Contains(t, name) {
			meta, err := store.GenerateKey(id, algo)
			if err != nil {
				return KeyMetadata{}, "", err
			}
			return meta, strings.ToLower(strings.TrimSuffix(t[strings.LastIndex(t, ".")+1:], "Store")), nil
		}
	}
	return KeyMetadata{}, "", ErrProtectedStoreRequired
}

func protectedLabel(r *Router) (string, error) {
	enabled := map[string]bool{}
	for _, l := range r.Backends() {
		enabled[l] = true
	}
	if want := BackendLabelFromStorageType(os.Getenv("KRYPTKEEPER_CODESIGN_KEY_BACKEND")); want != "" {
		for _, l := range protectedLabels {
			if l == want && enabled[l] {
				return l, nil
			}
		}
		return "", fmt.Errorf("%w: backend %q is not an enabled protected backend", ErrProtectedStoreRequired, want)
	}
	for _, l := range protectedLabels {
		if enabled[l] {
			return l, nil
		}
	}
	return "", ErrProtectedStoreRequired
}
