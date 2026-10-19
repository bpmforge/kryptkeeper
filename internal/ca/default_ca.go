// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"errors"
	"fmt"
)

// ErrNoCAConfigured means the hub has no CA yet (first-run mode): nothing can
// be issued until an operator creates a root CA (UI onboarding wizard, API, or
// KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true). API layers report it as a conflict.
var ErrNoCAConfigured = errors.New("no CA configured yet; create a root CA")

// ResolveCAID returns configured when set, else the first stored CA. The
// lookup happens per call so a CA created after startup is picked up without
// a restart. A ListCAs failure is returned as-is (never read as "no CAs");
// an empty list is ErrNoCAConfigured.
func ResolveCAID(svc Service, configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	cas, err := svc.ListCAs()
	if err != nil {
		return "", fmt.Errorf("list CAs: %w", err)
	}
	if len(cas) == 0 {
		return "", ErrNoCAConfigured
	}
	return cas[0].ID, nil
}
