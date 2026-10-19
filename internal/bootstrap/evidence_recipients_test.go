// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"testing"
)

func TestValidateEvidenceRecipients(t *testing.T) {
	if msg := validateEvidenceRecipients([]string{"auditor@example.com", "ciso@example.org"}); msg != "" {
		t.Fatalf("valid recipients rejected: %s", msg)
	}
	for _, bad := range [][]string{
		{"not-an-address"},
		{"Eve <eve@evil.example>"},
		{"a@example.com, eve@evil.example"},
	} {
		if msg := validateEvidenceRecipients(bad); msg == "" {
			t.Errorf("%q: want rejection", bad)
		}
	}
	many := make([]string, maxEvidenceRecipients+1)
	for i := range many {
		many[i] = fmt.Sprintf("u%d@example.com", i)
	}
	if msg := validateEvidenceRecipients(many); msg == "" {
		t.Error("over-cap recipient list accepted")
	}
}
