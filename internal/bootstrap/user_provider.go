// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"log"
	"os"
	"strings"
)

type UserRecord struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

type UserProvider interface {
	ListUsers(ctx context.Context) ([]UserRecord, error)
	InviteUser(ctx context.Context, email string, role string) (UserRecord, error)
	UpdateUser(ctx context.Context, id string, role string, status string) (UserRecord, error)
	DeactivateUser(ctx context.Context, id string) error
}

// NewUserProviderFromEnv selects the user store. The database is the default.
//
// S-40: it used to be the other way round, and fileUserProvider.seed() returns
// an empty slice — so a stock deployment served "No users found" from an
// in-memory adapter while the database held real accounts, two of them active
// and one a pki-admin. An operator cannot audit or revoke an account they
// cannot see, and any user invited through the UI was lost on restart.
//
// The in-memory adapter is still available for tests and offline dev, but it
// has to be asked for by name, and it announces itself so nobody mistakes an
// empty list for an empty system. When the database is configured but
// unreachable, dbUserProvider returns the open error from every call rather
// than an empty slice — a visible failure instead of a convincing lie.
func NewUserProviderFromEnv() UserProvider {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_USER_PROVIDER"))) {
	case "file", "memory", "inmemory":
		log.Print("user provider: in-memory (APP_USER_PROVIDER=file) — accounts are not persisted, " +
			"and existing database accounts are NOT listed; do not use outside tests/offline dev")
		return &fileUserProvider{}
	default:
		return newDBUserProviderFromEnv()
	}
}

func NewFileUserProvider() UserProvider { return &fileUserProvider{} }

// OIDCIdentityLinker is an optional UserProvider capability (implemented by
// dbUserProvider only -- the in-memory dev-mode file adapter has nowhere
// durable to persist it) that records which OIDC identity (issuer+subject)
// an account authenticates as, using the oidc_subject/oidc_issuer columns
// migration 000001 already ships. This is UserProvider's "recorded identity
// source" (W6-02 acceptance #2) without changing the UserProvider interface
// itself -- fileUserProvider (user_file_provider.go, out of this ticket's
// write_scope) would otherwise need a matching method to keep compiling.
type OIDCIdentityLinker interface {
	LinkOIDCIdentity(ctx context.Context, userID, issuer, subject string) error
	FindByOIDCIdentity(ctx context.Context, issuer, subject string) (UserRecord, bool, error)
}

// findUserByEmail is the fallback account-resolution path for OIDC login and
// SCIM lookups when the provider doesn't support OIDCIdentityLinker (or has
// no identity link recorded yet): a case-insensitive scan over ListUsers.
// UserProvider has no Get-by-email method (adding one would change every
// implementer's interface, including the out-of-scope file adapter), so this
// is deliberately a helper over the existing interface, not a new method.
func findUserByEmail(ctx context.Context, userProvider UserProvider, email string) (UserRecord, bool, error) {
	users, err := userProvider.ListUsers(ctx)
	if err != nil {
		return UserRecord{}, false, err
	}
	target := strings.ToLower(strings.TrimSpace(email))
	if target == "" {
		return UserRecord{}, false, nil
	}
	for _, u := range users {
		if strings.ToLower(strings.TrimSpace(u.Email)) == target {
			return u, true, nil
		}
	}
	return UserRecord{}, false, nil
}
