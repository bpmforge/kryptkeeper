// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"errors"
	"fmt"
)

// W9-08 (D-086/FR-P48): PQC keys are software-keystore-only, per
// docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md. Verified against the vendored
// sources: crypto11 v1.6.1 exposes no ML-DSA surface and miekg/pkcs11
// v1.1.2 predates PKCS#11 v3.2's CKM_ML_DSA mechanisms, so real HSM
// ML-DSA needs a new dependency (a human decision) plus v3.2 hardware.
// This file is deliberately tag-free — the refusal logic compiles and is
// tested in the default build; only the store behind it is tag-gated.

// ErrPQCHSMUnsupported is the sentinel for "this backend cannot hold
// post-quantum keys". Callers branch on it with errors.Is.
var ErrPQCHSMUnsupported = errors.New("post-quantum keys are software-keystore-only (see docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md)")

// hardwareBackends are the key backends that cannot hold ML-DSA/hybrid
// material today. The software store is intentionally absent — that
// asymmetry is the ADR's recorded decision, not an oversight.
var hardwareBackends = map[string]bool{
	"pkcs11":   true,
	"cloudkms": true,
	"vault":    true,
}

// CheckHSMPQCSupport refuses ML-DSA and hybrid algorithms on the
// hardware/remote key backends, citing the ADR. Classical algorithms and
// the software backend pass through untouched. It is the single,
// explicit refusal surface — a generic "unsupported algorithm" hides
// the reasoning an operator needs.
func CheckHSMPQCSupport(backend string, algo Algorithm) error {
	if !hardwareBackends[backend] {
		return nil
	}
	if IsMLDSA(algo) || IsHybrid(algo) {
		return fmt.Errorf("backend %q cannot hold %s: %w", backend, algo, ErrPQCHSMUnsupported)
	}
	return nil
}
