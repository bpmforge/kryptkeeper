// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"kryptkeeper/internal/logging"
	"strings"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// parseExtraKeyBackends splits KRYPTKEEPER_KEY_BACKENDS into trimmed,
// lower-cased, de-duplicated names, dropping the default (already built).
func parseExtraKeyBackends(csv, def string) []string {
	seen := map[string]bool{def: true}
	var out []string
	for _, n := range strings.Split(csv, ",") {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// caKeyBackendResolver maps a CA's key ID to the backend recorded on its row,
// so signing still reaches the right backend after a restart.
func caKeyBackendResolver(store ca.Store) func(string) (string, bool) {
	byKey := map[string]string{}
	cas, err := store.List()
	if err != nil {
		logging.Fatalf("startup: list CAs for key-backend routing: %v", err)
	}
	for _, c := range cas {
		if c.KeyID == "" {
			continue
		}
		label := keystore.BackendLabelFromStorageType(c.KeyStorageType)
		switch label {
		case "", "external":
			continue
		}
		byKey[c.KeyID] = label
	}
	return func(id string) (string, bool) { l, ok := byKey[id]; return l, ok }
}
