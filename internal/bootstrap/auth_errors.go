// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "errors"

var (
	errInvalidCredentials  = errors.New("invalid credentials")
	errAccountInactive     = errors.New("account inactive")
	errInvalidRefreshToken = errors.New("invalid refresh token")
	// errAuthUnavailable covers configuration/runtime auth failures that should map to 503.
	errAuthUnavailable = errors.New("auth unavailable")
	// errUserStoreUnavailable means a session principal's deprovisioned
	// status could not be checked because the user store failed. Authenticators
	// refuse the request (fail closed) rather than guess.
	errUserStoreUnavailable = errors.New("user store unavailable")
)
