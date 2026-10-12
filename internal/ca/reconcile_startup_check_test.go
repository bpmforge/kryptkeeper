// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"errors"
	"strings"
	"testing"
)

// A consistency check that errors proves nothing about the keys: booting on
// it fails open, so it is fatal unless the recovery opt-out is set.
func TestStartupKeyCheckDecision_CheckErrorIsFatalByDefault(t *testing.T) {
	boom := errors.New("kms unreachable")

	err := StartupKeyCheckDecision(nil, boom, false)
	if err == nil {
		t.Fatal("check error must be fatal without the opt-out")
	}
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), AllowMissingCAKeysEnv) {
		t.Fatalf("error should wrap the cause and name the opt-out, got: %v", err)
	}

	if err := StartupKeyCheckDecision(nil, boom, true); err != nil {
		t.Fatalf("opt-out must allow boot, got: %v", err)
	}
}

func TestStartupKeyCheckDecision_NoErrorDelegatesToFindings(t *testing.T) {
	if err := StartupKeyCheckDecision(nil, nil, false); err != nil {
		t.Fatalf("clean check must boot, got: %v", err)
	}
	missing := []KeyConsistencyFinding{{CAID: "ca1", CAName: "Root", KeyID: "k1", Missing: true, Detail: "gone"}}
	if err := StartupKeyCheckDecision(missing, nil, false); err == nil {
		t.Fatal("missing key must still be fatal")
	}
}
