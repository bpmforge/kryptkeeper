// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"strings"
)

// principalIDReserved reports whether id names a person or a built-in
// identity: the bootstrap token, the env-configured login admin (by subject or
// email), or a user in the user store. An API key may not carry such an id, so
// a minted key cannot impersonate a human in proposer/approver/grant records
// or spoof audit actor ids (RC1-B-02, RC2-N-02). Grant redemption is also
// bound to the canonical human; this is the second layer. It fails closed: a
// real user-store error is returned so the caller refuses rather than guesses,
// but a hub with no provisioned user store has an empty user set.
func (a *Authenticator) principalIDReserved(ctx context.Context, id string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == bootstrapHuman || a.isEnvLoginAdmin(id) || a.isEnvLoginEmail(id) {
		return true, nil
	}
	if a.userProvider == nil {
		return false, nil
	}
	users, err := a.userProvider.ListUsers(ctx)
	if errors.Is(err, errUserStoreNotProvisioned) {
		return false, nil // no user store, so no users; bootstrap and login admin were checked above
	}
	if err != nil {
		return false, err
	}
	for _, u := range users {
		if u.ID == id || (u.Email != "" && strings.EqualFold(u.Email, id)) {
			return true, nil
		}
	}
	return false, nil
}

func (a *Authenticator) isEnvLoginEmail(id string) bool {
	email := strings.TrimSpace(a.config.loginUser.Email)
	return a.config.loginEnabled && email != "" && strings.EqualFold(email, id)
}
