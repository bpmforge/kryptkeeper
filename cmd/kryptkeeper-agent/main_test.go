// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"kryptkeeper/internal/agentclient"
)

// TestRenewalIdentifiers_UsesHubIdentifiers covers W19-13: when the hub sends
// Identifiers, the renewer must use those verbatim rather than parsing
// Subject at all.
func TestRenewalIdentifiers_UsesHubIdentifiers(t *testing.T) {
	task := agentclient.RenewalTask{Subject: "CN=localhost", Identifiers: []string{"shop.example.com"}}
	got := renewalIdentifiers(task)
	if len(got) != 1 || got[0] != "shop.example.com" {
		t.Fatalf("renewalIdentifiers = %v, want [shop.example.com]", got)
	}
}

// TestRenewalIdentifiers_FallsBackToSubjectCN covers the compatibility path:
// a pre-W19-13 hub sends no Identifiers, so the agent parses a hostname out
// of Subject's CN -- never uses Subject itself.
func TestRenewalIdentifiers_FallsBackToSubjectCN(t *testing.T) {
	task := agentclient.RenewalTask{Subject: "CN=localhost"}
	got := renewalIdentifiers(task)
	if len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("renewalIdentifiers = %v, want [localhost]", got)
	}
}

// TestRenewalIdentifiers_UnparsableSubjectYieldsNone covers the case where
// neither Identifiers nor a hostname-shaped CN is available: the renewer
// must not fall back to the raw RDN string.
func TestRenewalIdentifiers_UnparsableSubjectYieldsNone(t *testing.T) {
	task := agentclient.RenewalTask{Subject: "CN=My Service"}
	got := renewalIdentifiers(task)
	if len(got) != 0 {
		t.Fatalf("renewalIdentifiers = %v, want none for a non-hostname CN", got)
	}
}

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"shop.example.com", true},
		{"my-service.example.com", true},
		{"", false},
		{"My Service", false},
		{"192.168.1.1", false},
		{"-bad.example.com", false},
		{"bad-.example.com", false},
	}
	for _, tt := range tests {
		if got := isValidHostname(tt.host); got != tt.want {
			t.Errorf("isValidHostname(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}
