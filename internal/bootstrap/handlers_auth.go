// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// registerAuthHandlers wires the hub's auth API surface. Its signature is
// load-bearing: handlers.go (RegisterHandlers, out of this ticket's
// write_scope) calls it with exactly these three arguments, so it cannot
// change. registerAuthHandlersWithUsers is the real implementation and the
// seam W6-02's OIDC login + SCIM additions (and their tests) need a
// UserProvider for -- tests call the *WithUsers form directly with a shared
// provider instance instead of each getting their own NewUserProviderFromEnv().
func registerAuthHandlers(mux *http.ServeMux, auth *Authenticator, auditProvider AuditProvider) {
	// Reuse auth.userProvider (set by NewAuthenticatorFromEnv, auth_config.go)
	// rather than minting a second NewUserProviderFromEnv() instance. That used
	// to be safe to keep separate because nothing read it back; now that
	// AuthenticatePrincipalDetails/Refresh (auth.go/auth_identity.go) consult
	// auth.userProvider to enforce SCIM deprovisioning, a second in-memory
	// fileUserProvider instance here would mean SCIM's DeactivateUser writes to
	// a store the enforcement check never sees -- deprovisioning would revoke
	// nothing in the default (non-DB) configuration. APP_USER_PROVIDER=db is
	// unaffected either way since all instances read/write the same physical
	// tables.
	//
	// KNOWN LIVE GAP, NOT FIXABLE HERE: handlers.go:102 calls
	// registerUserHandlers(mux, auth, NewUserProviderFromEnv(), auditProvider)
	// with a THIRD independent instance. Its DELETE /api/v1/users/{id}
	// (handlers_users.go, admin-console deactivate) writes to that instance,
	// so in file mode admin-console deactivation does not revoke access
	// either -- the same defect this fix closes for SCIM, reached through a
	// second door. handlers.go and handlers_users.go are both out of this
	// ticket's write_scope; the one-line fix is
	// registerUserHandlers(mux, auth, auth.userProvider, auditProvider).
	userProvider := auth.userProvider
	if userProvider == nil {
		userProvider = NewUserProviderFromEnv()
	}
	registerAuthHandlersWithUsers(mux, auth, userProvider, auditProvider)
}

func registerAuthHandlersWithUsers(mux *http.ServeMux, auth *Authenticator, userProvider UserProvider, auditProvider AuditProvider) {
	// Wiring-time write, before the server accepts requests: the middleware
	// has no audit sink of its own for fail-closed user-store refusals.
	auth.auditProvider = auditProvider
	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		now := time.Now()
		if !auth.allowRateLimit("login:"+clientIP(r), 10, time.Minute, now) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if !decodeJSONBodyOrReject(w, r, &req, maxAuthBodyBytes, "invalid request body") {
			return
		}
		accessToken, accessTTL, refreshToken, refreshTTL, principal, err := auth.LoginContext(r.Context(), strings.TrimSpace(req.Email), req.Password, now)
		if err != nil {
			if r.Context().Err() != nil {
				return // client left while queued for a KDF slot
			}
			if errors.Is(err, errInvalidCredentials) {
				emitAuditEvent(r, auditProvider, "", "auth.login", "auth", "login", AuditOutcomeDenied)
				writeInvalidLoginCredentials(w)
				return
			}
			if errors.Is(err, errAccountInactive) {
				emitAuditEvent(r, auditProvider, "", "auth.login", "auth", "login", AuditOutcomeDenied)
				writeForbidden(w, "account inactive")
				return
			}
			if errors.Is(err, errAuthUnavailable) {
				emitAuditEvent(r, auditProvider, "", "auth.login", "auth", "login", AuditOutcomeFailure)
				writeServiceUnavailable(w, "auth unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, "", "auth.login", "auth", "login", AuditOutcomeFailure)
			writeServiceUnavailable(w, "auth unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "auth.login", "auth", "login", AuditOutcomeSuccess)

		setSessionCookie(w, r, accessToken, accessTTL)

		resp := struct {
			Data struct {
				AccessToken      string `json:"access_token"`
				TokenType        string `json:"token_type"`
				ExpiresIn        int64  `json:"expires_in"`
				RefreshToken     string `json:"refresh_token"`
				RefreshExpiresIn int64  `json:"refresh_expires_in"`
				Principal        struct {
					UserID string `json:"user_id"`
					Role   string `json:"role"`
				} `json:"principal"`
			} `json:"data"`
		}{}
		resp.Data.AccessToken = accessToken
		resp.Data.TokenType = "Bearer"
		resp.Data.ExpiresIn = accessTTL
		resp.Data.RefreshToken = refreshToken
		resp.Data.RefreshExpiresIn = refreshTTL
		resp.Data.Principal.UserID = principal.ID
		resp.Data.Principal.Role = principal.Role

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/auth/login response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		// A2A7-003: end the session server-side. The caller proves who it is
		// with its cookie or bearer token, and every refresh token that
		// principal holds is revoked; a body-supplied refresh token is
		// revoked too, so a logout with only the refresh token still works.
		// The body is optional (the cookie alone is enough).
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) // optional body; absent or malformed is fine
		}
		// Only a login session sweeps the principal's refresh tokens: an API
		// key's PrincipalID is free text and may equal a human's subject.
		var principalID, sweepID string
		if pd, err := auth.AuthenticatePrincipalDetails(r, time.Now()); err == nil {
			principalID = pd.ID
			if pd.AuthType == AuthTypeLocal {
				sweepID = pd.ID
			}
		}
		auth.RevokeRefreshTokens(sweepID, req.RefreshToken)
		http.SetCookie(w, &http.Cookie{
			Name:     "kk_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   requestIsSecure(r),
		})
		emitAuditEvent(r, auditProvider, principalID, "auth.logout", "auth", "logout", AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/v1/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !auth.allowRateLimit("refresh:"+clientIP(r), 30, time.Minute, time.Now()) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if !decodeJSONBodyOrReject(w, r, &req, maxAuthBodyBytes, "invalid request body") {
			return
		}

		accessToken, accessTTL, refreshToken, refreshTTL, err := auth.Refresh(req.RefreshToken, time.Now())
		if err != nil {
			if errors.Is(err, errUserStoreUnavailable) {
				// The refresh token was kept (see Refresh), so the client
				// can retry once the user store is back.
				auth.reportUserStoreError(r, "", err)
				emitAuditEvent(r, auditProvider, "", "auth.refresh", "auth", "refresh", AuditOutcomeFailure)
				writeServiceUnavailable(w, "auth unavailable")
				return
			}
			if errors.Is(err, errInvalidRefreshToken) {
				emitAuditEvent(r, auditProvider, "", "auth.refresh", "auth", "refresh", AuditOutcomeDenied)
				writeInvalidRefreshToken(w)
				return
			}
			emitAuditEvent(r, auditProvider, "", "auth.refresh", "auth", "refresh", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		emitAuditEvent(r, auditProvider, "", "auth.refresh", "auth", "refresh", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				AccessToken      string `json:"access_token"`
				TokenType        string `json:"token_type"`
				ExpiresIn        int64  `json:"expires_in"`
				RefreshToken     string `json:"refresh_token"`
				RefreshExpiresIn int64  `json:"refresh_expires_in"`
			} `json:"data"`
		}{}
		resp.Data.AccessToken = accessToken
		resp.Data.TokenType = "Bearer"
		resp.Data.ExpiresIn = accessTTL
		resp.Data.RefreshToken = refreshToken
		resp.Data.RefreshExpiresIn = refreshTTL

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/auth/refresh response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/authz-check", func(w http.ResponseWriter, r *http.Request) {
		details, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		principal := details.ID
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "authz.check", "auth", "authz-check", AuditOutcomeDenied)
			if errors.Is(err, errUserStoreUnavailable) {
				writeServiceUnavailable(w, "auth unavailable")
				return
			}
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		// AuthenticatePrincipalDetails already refuses deprovisioned principals
		// against auth.userProvider. This handler's own provider can be a
		// different instance (tests wire a shared one into
		// registerAuthHandlersWithUsers), so check it too, failing closed like
		// the middleware and for the same principals (the bootstrap token and
		// API keys never use the store).
		if auth.principalUsesUserStore(details) {
			deprovisioned, lerr := principalIsDeprovisioned(r.Context(), userProvider, principal)
			if lerr != nil {
				auth.reportUserStoreError(r, principal, lerr)
				emitAuditEvent(r, auditProvider, principal, "authz.check", "auth", "authz-check", AuditOutcomeDenied)
				writeServiceUnavailable(w, "auth unavailable")
				return
			}
			if deprovisioned {
				emitAuditEvent(r, auditProvider, principal, "authz.check", "auth", "authz-check", AuditOutcomeDenied)
				writeUnauthorized(w)
				return
			}
		}
		emitAuditEvent(r, auditProvider, principal, "authz.check", "auth", "authz-check", AuditOutcomeSuccess)

		resp := struct {
			Service       string   `json:"service"`
			Authenticated bool     `json:"authenticated"`
			Principal     string   `json:"principal"`
			Role          string   `json:"role"`
			Scopes        []string `json:"scopes"`
		}{
			Service:       "kryptkeeper",
			Authenticated: true,
			Principal:     principal,
			Role:          "",
			Scopes:        []string{},
		}
		resp.Role = details.Role
		resp.Scopes = append([]string(nil), details.Scopes...)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/authz-check response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/api-keys", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "api-key.list", "api-key", "api-keys", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		switch r.Method {
		case http.MethodGet:
			items := auth.ListAPIKeys()
			filtered := make([]apiKeyRecord, 0, len(items))
			for _, item := range items {
				if isAdminRole(principal.Role) || strings.TrimSpace(item.PrincipalID) == principal.ID {
					filtered = append(filtered, item)
				}
			}
			emitAuditEvent(r, auditProvider, principal.ID, "api-key.list", "api-key", "api-keys", AuditOutcomeSuccess)

			resp := struct {
				Data []struct {
					Name        string   `json:"name,omitempty"`
					Kid         string   `json:"kid"`
					KeyPrefix   string   `json:"key_prefix"`
					PrincipalID string   `json:"principal_id"`
					Role        string   `json:"role"`
					Scopes      []string `json:"scopes"`
					Active      bool     `json:"active"`
					ExpiresAt   string   `json:"expires_at,omitempty"`
					CreatedAt   string   `json:"created_at,omitempty"`
				} `json:"data"`
			}{Data: make([]struct {
				Name        string   `json:"name,omitempty"`
				Kid         string   `json:"kid"`
				KeyPrefix   string   `json:"key_prefix"`
				PrincipalID string   `json:"principal_id"`
				Role        string   `json:"role"`
				Scopes      []string `json:"scopes"`
				Active      bool     `json:"active"`
				ExpiresAt   string   `json:"expires_at,omitempty"`
				CreatedAt   string   `json:"created_at,omitempty"`
			}, 0, len(filtered))}
			for _, item := range filtered {
				resp.Data = append(resp.Data, struct {
					Name        string   `json:"name,omitempty"`
					Kid         string   `json:"kid"`
					KeyPrefix   string   `json:"key_prefix"`
					PrincipalID string   `json:"principal_id"`
					Role        string   `json:"role"`
					Scopes      []string `json:"scopes"`
					Active      bool     `json:"active"`
					ExpiresAt   string   `json:"expires_at,omitempty"`
					CreatedAt   string   `json:"created_at,omitempty"`
				}{
					Name:        item.Name,
					Kid:         item.Kid,
					KeyPrefix:   "kk_" + item.Kid + "_",
					PrincipalID: item.PrincipalID,
					Role:        item.Role,
					Scopes:      append([]string(nil), item.Scopes...),
					Active:      item.Active,
					ExpiresAt:   item.ExpiresAt,
					CreatedAt:   item.CreatedAt,
				})
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/api-keys response: %v", err)
			}
			return
		case http.MethodPost:
			if !isAdminRole(principal.Role) {
				emitAuditEvent(r, auditProvider, principal.ID, "api-key.create", "api-key", "api-keys", AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			var req struct {
				Name        string   `json:"name"`
				PrincipalID string   `json:"principal_id"`
				Role        string   `json:"role"`
				Scopes      []string `json:"scopes"`
				ExpiresAt   string   `json:"expires_at"`
				Tenant      string   `json:"tenant"`
			}
			if !decodeJSONBodyOrReject(w, r, &req, maxAuthBodyBytes, "invalid request body") {
				return
			}
			if ref := checkRoleGrant(principal, auth.roleStore, firstNonEmpty(strings.TrimSpace(req.Role), "service-account")); ref != nil {
				refuseGrant(w, r, auditProvider, principal, "api-key.create", "api-key", "api-keys", ref)
				return
			}
			reserved, reservedErr := auth.principalIDReserved(r.Context(), req.PrincipalID)
			if reservedErr != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "api-key.create", "api-key", "api-keys", AuditOutcomeFailure)
				writeServiceUnavailable(w, "cannot verify principal_id against the user store; try again")
				return
			}
			if reserved {
				emitAuditEvent(r, auditProvider, principal.ID, "api-key.create", "api-key", "api-keys", AuditOutcomeDenied)
				writeBadRequest(w, "principal_id names an existing person or built-in identity; choose a service name")
				return
			}
			record, token, err := auth.CreateAPIKeyAs(auth.canonicalHuman(principal), req.Name, req.PrincipalID, req.Role, req.Scopes, req.ExpiresAt, req.Tenant, time.Now())
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "api-key.create", "api-key", "api-keys", AuditOutcomeFailure)
				if errors.Is(err, errAPIKeyPersist) {
					writeServiceUnavailable(w, "api key could not be saved; try again")
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "api-key.create", "api-key", record.Kid, AuditOutcomeSuccess)
			resp := struct {
				Data struct {
					Name        string   `json:"name,omitempty"`
					Kid         string   `json:"kid"`
					Token       string   `json:"token"`
					KeyPrefix   string   `json:"key_prefix"`
					PrincipalID string   `json:"principal_id"`
					Role        string   `json:"role"`
					Scopes      []string `json:"scopes"`
					Active      bool     `json:"active"`
					ExpiresAt   string   `json:"expires_at,omitempty"`
					CreatedAt   string   `json:"created_at,omitempty"`
					Tenant      string   `json:"tenant,omitempty"`
				} `json:"data"`
			}{}
			resp.Data.Name = record.Name
			resp.Data.Kid = record.Kid
			resp.Data.Token = token
			resp.Data.KeyPrefix = "kk_" + record.Kid + "_"
			resp.Data.PrincipalID = record.PrincipalID
			resp.Data.Role = record.Role
			resp.Data.Scopes = append([]string(nil), record.Scopes...)
			resp.Data.Active = record.Active
			resp.Data.ExpiresAt = record.ExpiresAt
			resp.Data.CreatedAt = record.CreatedAt
			resp.Data.Tenant = record.Tenant
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/api-keys create response: %v", err)
			}
			return
		default:
			writeMethodNotAllowed(w, "GET, POST")
			return
		}
	})

	mux.HandleFunc("/api/v1/api-keys/", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "api-key.delete", "api-key", "api-key-id", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		if !isAdminRole(principal.Role) {
			emitAuditEvent(r, auditProvider, principal.ID, "api-key.delete", "api-key", "api-key-id", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		kid := strings.TrimPrefix(r.URL.Path, "/api/v1/api-keys/")
		if strings.TrimSpace(kid) == "" || strings.Contains(kid, "/") {
			emitAuditEvent(r, auditProvider, principal.ID, "api-key.delete", "api-key", kid, AuditOutcomeFailure)
			writeNotFound(w, "api key not found")
			return
		}
		found, persistErr := auth.RevokeAPIKey(kid)
		if !found {
			emitAuditEvent(r, auditProvider, principal.ID, "api-key.delete", "api-key", kid, AuditOutcomeFailure)
			writeNotFound(w, "api key not found")
			return
		}
		if persistErr != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "api-key.delete", "api-key", kid, AuditOutcomeFailure)
			writeServiceUnavailable(w, "api key is revoked for this process but the revocation is not durable yet; repeat the DELETE until it succeeds")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "api-key.delete", "api-key", kid, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})

	registerOIDCLoginHandlers(mux, auth, userProvider, auditProvider)
	registerSAMLLoginHandlers(mux, auth, userProvider, auditProvider)
	registerAuthMethodsHandler(mux, auth)
	registerSCIMHandlers(mux, auth, userProvider, auditProvider)
}

// setSessionCookie sets the httpOnly session cookie POST /api/v1/auth/login
// issues, so the browser dashboard never exposes the token to JavaScript.
// Shared by the local-login handler above and the OIDC callback
// (auth_oidc_login.go) so both establish an identical session (acceptance #2).
func setSessionCookie(w http.ResponseWriter, r *http.Request, accessToken string, accessTTL int64) {
	http.SetCookie(w, &http.Cookie{
		Name:     "kk_token",
		Value:    accessToken,
		Path:     "/",
		MaxAge:   int(accessTTL),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsSecure(r),
	})
}

// principalIsDeprovisioned reports whether principalID matches a UserRecord
// (SCIM/OIDC-managed) whose Status marks it deactivated. UserProvider has no
// Get-by-ID method, so this is a linear ListUsers scan -- the same
// affordability tradeoff as findUserByEmail (user_provider.go): correctness
// over a new interface method that would have to land on the out-of-scope
// file adapter too. Now called from AuthenticatePrincipalDetails/Refresh
// (auth.go/auth_identity.go) as well as /api/v1/authz-check below, so this
// scan runs on every authenticated request, not just one endpoint --
// unindexed and O(n) in user count; no acceptance criterion covers the cost,
// but a future ticket adding a Get-by-ID (or a cache) should start here.
//
// userProvider is nil for Authenticators built directly in tests without one
// (auth.go's userProvider field) -- treated as "nothing to enforce" rather
// than a nil-interface panic, since those tests aren't exercising SCIM.
func principalIsDeprovisioned(ctx context.Context, userProvider UserProvider, principalID string) (bool, error) {
	if userProvider == nil || strings.TrimSpace(principalID) == "" {
		return false, nil
	}
	users, err := userProvider.ListUsers(ctx)
	if err != nil {
		return false, err
	}
	for _, u := range users {
		if u.ID == principalID {
			return isDeprovisionedStatus(u.Status), nil
		}
	}
	return false, nil
}
