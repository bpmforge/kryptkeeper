// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
)

func TestFindUserByEmail_CaseInsensitiveMatch(t *testing.T) {
	provider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "Alice@Example.com", Role: "pki-viewer", Status: "active"},
	}}

	user, found, err := findUserByEmail(context.Background(), provider, "alice@example.com")
	if err != nil {
		t.Fatalf("findUserByEmail: %v", err)
	}
	if !found || user.ID != "user-1" {
		t.Fatalf("expected a case-insensitive match, got found=%v user=%+v", found, user)
	}
}

func TestFindUserByEmail_NoMatch(t *testing.T) {
	provider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-viewer", Status: "active"},
	}}

	_, found, err := findUserByEmail(context.Background(), provider, "bob@example.com")
	if err != nil {
		t.Fatalf("findUserByEmail: %v", err)
	}
	if found {
		t.Fatal("expected no match for an email with no corresponding user")
	}
}

func TestFindUserByEmail_EmptyEmail(t *testing.T) {
	provider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-viewer", Status: "active"},
	}}

	_, found, err := findUserByEmail(context.Background(), provider, "   ")
	if err != nil {
		t.Fatalf("findUserByEmail: %v", err)
	}
	if found {
		t.Fatal("expected no match for a blank email")
	}
}
