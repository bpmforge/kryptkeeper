// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
)

// S-40. NewUserProviderFromEnv had no test at all, which is how the default
// stayed on an in-memory adapter whose seed() returns an empty slice: a stock
// deployment answered "No users found" while the database held two active
// accounts, one of them pki-admin. You cannot revoke an admin you cannot see.
//
// These pin the selection in both directions so the default cannot silently
// flip back.

func TestUserProviderDefaultsToDatabase(t *testing.T) {
	t.Setenv("APP_USER_PROVIDER", "")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())

	if _, ok := NewUserProviderFromEnv().(*dbUserProvider); !ok {
		t.Fatalf("unset APP_USER_PROVIDER must select the database provider, got %T",
			NewUserProviderFromEnv())
	}
}

func TestUserProviderUnrecognisedValueDefaultsToDatabase(t *testing.T) {
	// The old switch sent every unrecognised value to the in-memory adapter,
	// so a typo silently hid every account. It must fail safe now.
	t.Setenv("APP_USER_PROVIDER", "postgres-ish-typo")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())

	if _, ok := NewUserProviderFromEnv().(*dbUserProvider); !ok {
		t.Fatalf("an unrecognised APP_USER_PROVIDER must fall back to the database, got %T",
			NewUserProviderFromEnv())
	}
}

func TestUserProviderInMemoryIsOptInByName(t *testing.T) {
	for _, mode := range []string{"file", "memory", "inmemory", "FILE"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_USER_PROVIDER", mode)
			if _, ok := NewUserProviderFromEnv().(*fileUserProvider); !ok {
				t.Fatalf("APP_USER_PROVIDER=%q must select the in-memory provider, got %T",
					mode, NewUserProviderFromEnv())
			}
		})
	}
}

// The in-memory adapter lists nothing, ever. That is the behaviour that made
// the old default dangerous, so state it outright: it is only acceptable
// because you now have to ask for it.
func TestInMemoryUserProviderStartsEmpty(t *testing.T) {
	t.Setenv("APP_USER_PROVIDER", "file")

	users, err := NewUserProviderFromEnv().ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("in-memory provider seeds nothing; got %d users", len(users))
	}
}
