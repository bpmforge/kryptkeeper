// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"strings"
	"testing"
)

// W9-05: the policy refuses below-floor and off-list algorithms with a
// cited rule, per purpose.

func TestKeygenPolicyDefaults(t *testing.T) {
	policy := DefaultKeygenPolicy()
	cases := []struct {
		algo    Algorithm
		purpose string
		wantErr string // "" = allowed; otherwise the rule the error must cite
	}{
		{RSA2048, PurposeGeneral, "min_rsa_bits"}, // below the 3072 floor
		{RSA4096, PurposeGeneral, ""},
		{RSA4096, PurposeCA, ""}, // meets the 4096 CA floor
		{RSA2048, PurposeCA, "min_rsa_bits"},
		{ECDSAP256, PurposeCA, ""},
		{Ed25519, PurposeGeneral, ""},
		{MLDSA65, PurposeCA, ""},
		{HybridECDSAP384MLDSA87, PurposeCA, ""},
		{Algorithm("DES"), PurposeGeneral, "allowed_algorithms"}, // unknown
		{RSA4096, "", ""},                                        // empty purpose = general
	}
	for _, tc := range cases {
		err := policy.Check(tc.algo, tc.purpose)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("Check(%s, %q): unexpected refusal: %v", tc.algo, tc.purpose, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("Check(%s, %q): expected refusal citing %s, got allow", tc.algo, tc.purpose, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("Check(%s, %q): refusal must cite rule %q, got: %v", tc.algo, tc.purpose, tc.wantErr, err)
		}
	}
}

func TestKeygenPolicyEnvAllowList(t *testing.T) {
	t.Setenv("KRYPTKEEPER_KEYGEN_ALLOWED_ALGOS", "ECDSA-P256, ML-DSA-65")
	policy := KeygenPolicyFromEnv()

	if err := policy.Check(ECDSAP256, PurposeGeneral); err != nil {
		t.Fatalf("allow-listed algorithm refused: %v", err)
	}
	err := policy.Check(RSA4096, PurposeGeneral)
	if err == nil || !strings.Contains(err.Error(), "allowed_algorithms") {
		t.Fatalf("off-list algorithm must be refused citing allowed_algorithms, got: %v", err)
	}
}

func TestKeygenPolicyEnvFloorOverride(t *testing.T) {
	t.Setenv("KRYPTKEEPER_KEYGEN_MIN_RSA_BITS", "2048")
	policy := KeygenPolicyFromEnv()
	if err := policy.Check(RSA2048, PurposeGeneral); err != nil {
		t.Fatalf("floor lowered by env, RSA-2048 should pass general: %v", err)
	}
	// The CA floor was not touched — still 4096.
	if err := policy.Check(RSA2048, PurposeCA); err == nil {
		t.Fatal("CA floor must remain 4096 when only the general floor is overridden")
	}
}

func TestKeygenPolicyBadEnvFallsBackLoudlyToDefaults(t *testing.T) {
	t.Setenv("KRYPTKEEPER_KEYGEN_MIN_RSA_BITS", "not-a-number")
	policy := KeygenPolicyFromEnv()
	// Default floor holds: RSA-2048 still refused.
	if err := policy.Check(RSA2048, PurposeGeneral); err == nil {
		t.Fatal("misparsed env must fall back to the default floor, not disable it")
	}
}
