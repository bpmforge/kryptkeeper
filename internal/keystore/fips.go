// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto/fips140"
	"fmt"
	"os"
	"strings"
)

// W9-11 (D-089/FR-P51/NFR-011): FIPS 140-3 posture. Go ships a validated
// FIPS 140-3 Cryptographic Module natively — selected with
// GOFIPS140=<version> at build time and/or GODEBUG=fips140=on at run
// time, reported by stdlib crypto/fips140. No fork, no cgo, no new
// dependency. This file is the posture's single code surface; the
// documented boundary lives in docs/design/FIPS_POSTURE.md.

// FIPSPostureInfo is the inspectable truth about this process's posture.
type FIPSPostureInfo struct {
	// Mode140_3 is whether the Go FIPS 140-3 module is active
	// (GODEBUG=fips140=on / GOFIPS140 build).
	Mode140_3 bool `json:"mode_140_3"`
	// Enforced is whether non-approved algorithm use panics rather than
	// merely being out of scope.
	Enforced bool `json:"enforced"`
	// ModuleVersion is the validated module's version string.
	ModuleVersion string `json:"module_version"`
	// RootHSMRequired is whether NFR-011 root-key custody is being
	// enforced (KRYPTKEEPER_FIPS_ROOT_HSM=true, or implied by FIPS mode).
	RootHSMRequired bool `json:"root_hsm_required"`
}

// rootHSMRequired: NFR-011 enforcement is explicit via env, and implied
// whenever the FIPS module is on — a FIPS posture with software root
// custody would be a claim the deployment cannot back.
func rootHSMRequired() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_FIPS_ROOT_HSM")), "true") {
		return true
	}
	return fips140.Enabled()
}

// FIPSPosture reports the live posture.
func FIPSPosture() FIPSPostureInfo {
	return FIPSPostureInfo{
		Mode140_3:       fips140.Enabled(),
		Enforced:        fips140.Enforced(),
		ModuleVersion:   fips140.Version(),
		RootHSMRequired: rootHSMRequired(),
	}
}

// fipsApprovedFamily reports whether algo belongs to a FIPS-approved
// family: RSA and ECDSA and Ed25519 (FIPS 186-5), ML-DSA (FIPS 204).
// Hybrid composites are NOT approved — no NIST specification covers the
// composite signature format we produce, so in FIPS mode it cannot be
// claimed.
func fipsApprovedFamily(algo Algorithm) bool {
	switch {
	case IsHybrid(algo):
		return false
	case IsMLDSA(algo):
		return true
	}
	switch algo {
	case RSA2048, RSA4096, ECDSAP256, ECDSAP384, Ed25519:
		return true
	}
	return false
}

// CheckFIPSAlgorithm refuses non-approved algorithms while the FIPS
// module is active. Outside FIPS mode it is a no-op — posture is a
// deployment choice, not a universal restriction.
func CheckFIPSAlgorithm(algo Algorithm) error {
	if !fips140.Enabled() {
		return nil
	}
	if !fipsApprovedFamily(algo) {
		return fmt.Errorf("FIPS 140-3 mode: algorithm %s is not FIPS-approved (hybrid composites have no NIST specification; see docs/design/FIPS_POSTURE.md)", algo)
	}
	return nil
}

// fipsCustodyBackends are key backends that qualify as NFR-011 root-key
// custody: a PKCS#11 HSM, or a cloud KMS backed by FIPS 140-validated
// HSMs. The software file store and Vault transit (not validated in the
// default distribution) do not qualify.
var fipsCustodyBackends = map[string]bool{
	"pkcs11":   true,
	"cloudkms": true,
}

// CheckRootKeyCustody enforces NFR-011: when the posture requires it,
// running the CA role on a non-custody backend is refused — the caller
// (main.go) treats this as fatal at boot, which is stronger than
// refusing individual root creations later.
func CheckRootKeyCustody(backend string) error {
	if !rootHSMRequired() {
		return nil
	}
	if backend == "" {
		backend = "software"
	}
	if !fipsCustodyBackends[backend] {
		return fmt.Errorf("NFR-011: FIPS root-key custody requires an HSM-backed keystore (pkcs11 or cloudkms), not %q — see docs/design/FIPS_POSTURE.md", backend)
	}
	return nil
}
