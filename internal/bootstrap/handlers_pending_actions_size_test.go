// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"strings"
	"testing"
)

// LLM-005: a proposal is stored verbatim and shown to approvers.
func TestProposalBodyIsBounded(t *testing.T) {
	h := newGrantHarness(t)
	admin := h.key(t, "pki-admin")
	small := map[string]any{"action_type": "revoke", "params": map[string]string{"fingerprint": "ab"}, "rationale": "r"}
	if got := h.json(admin, "POST", "/api/v1/pending-actions", small).Code; got != http.StatusCreated {
		t.Fatalf("small proposal: %d", got)
	}
	big := map[string]any{"action_type": "revoke", "params": map[string]string{"fingerprint": "ab"}, "rationale": strings.Repeat("x", maxProposalBodyBytes+1)}
	if got := h.json(admin, "POST", "/api/v1/pending-actions", big).Code; got != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize proposal: got %d, want 413", got)
	}
}
