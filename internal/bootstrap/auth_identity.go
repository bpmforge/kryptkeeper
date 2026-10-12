// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
)

func validateAPIKeyToken(token string, cfg authValidatorConfig, now time.Time) (AuthPrincipal, bool, error) {
	parts := strings.Split(token, "_")
	if len(parts) != 3 || parts[0] != "kk" {
		return AuthPrincipal{}, false, nil
	}
	kid := strings.TrimSpace(parts[1])
	secret := strings.TrimSpace(parts[2])
	if kid == "" || secret == "" {
		return AuthPrincipal{}, false, nil
	}

	record, ok := cfg.apiKeys[kid]
	if !ok {
		return AuthPrincipal{}, false, nil
	}
	if !record.Active {
		return AuthPrincipal{}, false, nil
	}
	if expiresAt := strings.TrimSpace(record.ExpiresAt); expiresAt != "" {
		ts, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return AuthPrincipal{}, false, fmt.Errorf("invalid api key expiry")
		}
		if !now.Before(ts) {
			return AuthPrincipal{}, false, nil
		}
	}
	if strings.TrimSpace(cfg.apiKeyPepper) == "" {
		return AuthPrincipal{}, false, nil
	}

	computed := apiKeyVerifier(secret, cfg.apiKeyPepper)
	stored := strings.TrimSpace(record.SecretVerifier)
	if subtle.ConstantTimeCompare([]byte(computed), []byte(stored)) != 1 {
		return AuthPrincipal{}, false, nil
	}

	role := strings.TrimSpace(record.Role)
	if role == "" {
		role = "service-account"
	}
	principal := AuthPrincipal{ID: strings.TrimSpace(record.PrincipalID), Role: role, Scopes: record.Scopes, AuthType: AuthTypeAPIKey, Tenant: strings.TrimSpace(record.Tenant), Kid: record.Kid}
	if principal.ID == "" {
		return AuthPrincipal{}, false, nil
	}
	return principal, true, nil
}

func apiKeyVerifier(secret string, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *Authenticator) Login(email string, password string, now time.Time) (string, int64, string, int64, AuthPrincipal, error) {
	return a.LoginContext(context.Background(), email, password, now)
}

// LoginContext is Login, abandoning the wait for a KDF slot when ctx ends.
func (a *Authenticator) LoginContext(ctx context.Context, email string, password string, now time.Time) (string, int64, string, int64, AuthPrincipal, error) {
	if !a.config.loginEnabled {
		return "", 0, "", 0, AuthPrincipal{}, errAuthUnavailable
	}
	storedHash := a.loginPasswordHash()
	if strings.TrimSpace(a.config.loginUser.Email) == "" || storedHash == "" || strings.TrimSpace(a.config.loginUser.Subject) == "" || strings.TrimSpace(a.config.loginSigning) == "" {
		return "", 0, "", 0, AuthPrincipal{}, errAuthUnavailable
	}

	// A07-8: per-account backoff. A locked-out account answers exactly like a
	// wrong password, and unknown emails are tracked the same way, so neither
	// the response nor the lockout reveals which address is configured.
	accountKey := loginAccountKey(email)
	if a.loginLockedOut(accountKey, now) {
		return "", 0, "", 0, AuthPrincipal{}, errInvalidCredentials
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(a.config.loginUser.Email)) {
		// Same KDF work as a real check, against the real verifier, so a wrong
		// email costs what a wrong password costs whatever its parameters.
		if _, _, err := a.verifyLoginPasswordLimited(ctx, password, a.config.loginPepper, storedHash); err != nil {
			return "", 0, "", 0, AuthPrincipal{}, err
		}
		a.recordLoginFailure(accountKey, now)
		return "", 0, "", 0, AuthPrincipal{}, errInvalidCredentials
	}
	ok, legacy, err := a.verifyLoginPasswordLimited(ctx, password, a.config.loginPepper, storedHash)
	if err != nil {
		return "", 0, "", 0, AuthPrincipal{}, err
	}
	if !ok {
		a.recordLoginFailure(accountKey, now)
		return "", 0, "", 0, AuthPrincipal{}, errInvalidCredentials
	}
	a.clearLoginFailures(accountKey)
	if legacy {
		a.upgradeLegacyLoginHash(password, a.config.loginPepper)
	}
	if !a.config.loginUser.Active {
		return "", 0, "", 0, AuthPrincipal{}, errAccountInactive
	}

	scopes := []string{}
	if isAdminRole(a.config.loginUser.Role) {
		scopes = []string{"*"}
	}
	principal := AuthPrincipal{ID: a.config.loginUser.Subject, Role: a.config.loginUser.Role, Scopes: scopes, AuthType: AuthTypeLocal}
	accessToken, err := mintHS256JWT(principal.ID, principal.Role, a.config.loginSigning, a.config.jwtIssuer, a.config.jwtAudience, now.Add(a.config.loginTTL))
	if err != nil {
		return "", 0, "", 0, AuthPrincipal{}, err
	}
	refreshToken, err := generateOpaqueToken("rfr")
	if err != nil {
		return "", 0, "", 0, AuthPrincipal{}, err
	}

	a.refreshMu.Lock()
	a.refreshSessions[refreshToken] = refreshSession{PrincipalID: principal.ID, Role: principal.Role, ExpiresAt: now.Add(a.config.refreshTTL)}
	a.refreshMu.Unlock()

	return accessToken, int64(a.config.loginTTL / time.Second), refreshToken, int64(a.config.refreshTTL / time.Second), principal, nil
}

// RevokeRefreshTokens deletes refreshToken (when non-empty) and, when
// principalID is non-empty, every other refresh token that principal holds:
// logout must end the session, not just clear a cookie (A2A7-003 / A07-5).
// The access JWT stays valid until its own short exp, since it carries no
// jti to deny-list.
func (a *Authenticator) RevokeRefreshTokens(principalID string, refreshToken string) {
	principalID = strings.TrimSpace(principalID)
	refreshToken = strings.TrimSpace(refreshToken)
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if refreshToken != "" {
		delete(a.refreshSessions, refreshToken)
	}
	if principalID == "" {
		return
	}
	for token, session := range a.refreshSessions {
		if session.PrincipalID == principalID {
			delete(a.refreshSessions, token)
		}
	}
}

// resolveRefreshIdentity re-reads the principal's current role and standing at
// refresh time, so a disabled account or a changed role takes effect at the
// next refresh instead of living on in the login-time claim (A2A7-003 /
// A07-5). The user store wins; the env-configured local user (not in the
// store) is judged against its config; anything else keeps the session's
// role. A user-store *error* fails closed (errUserStoreUnavailable) for any
// principal other than the env-configured login admin, which is judged
// against its config without the store (see principalUsesUserStore).
func (a *Authenticator) resolveRefreshIdentity(ctx context.Context, session refreshSession) (role string, ok bool, err error) {
	if a.userProvider != nil {
		users, lerr := a.userProvider.ListUsers(ctx)
		if lerr != nil {
			if !a.isEnvLoginAdmin(session.PrincipalID) {
				return "", false, errUserStoreUnavailable
			}
		} else {
			for _, u := range users {
				if u.ID != session.PrincipalID {
					continue
				}
				if isDeprovisionedStatus(u.Status) {
					return "", false, nil
				}
				role = strings.TrimSpace(u.Role)
				return role, role != "", nil
			}
		}
	}
	if a.isEnvLoginAdmin(session.PrincipalID) {
		role = strings.TrimSpace(a.config.loginUser.Role)
		return role, a.config.loginUser.Active && role != "", nil
	}
	role = strings.TrimSpace(session.Role)
	return role, role != "", nil
}

// isEnvLoginAdmin reports whether principalID is the login user configured
// through the environment, which lives outside the user store.
func (a *Authenticator) isEnvLoginAdmin(principalID string) bool {
	return a.config.loginEnabled && principalID == a.config.loginUser.Subject
}

// principalSkipsUserStore is true for principals that are never looked up in
// the user store: the raw bootstrap token and API keys.
func principalSkipsUserStore(pd AuthPrincipal) bool {
	if strings.TrimSpace(pd.ID) == "" {
		return true
	}
	return pd.AuthType == AuthTypeBootstrap || pd.AuthType == AuthTypeAPIKey
}

// principalUsesUserStore reports whether pd's standing is governed by the user
// store, i.e. whether a store failure must block it. Those are the sessions
// minted by the local, OIDC-callback and SAML logins (all AuthType "local"),
// whose accounts SCIM or the admin console can deactivate. The env-configured
// login admin is judged against its config instead, and externally issued
// jwt/oidc bearer tokens were never store identities.
func (a *Authenticator) principalUsesUserStore(pd AuthPrincipal) bool {
	return !principalSkipsUserStore(pd) && pd.AuthType == AuthTypeLocal && !a.isEnvLoginAdmin(pd.ID)
}

// userStoreErrInterval caps how often a sustained outage logs and audits, so
// the failure signal does not turn into a write storm against the same
// degraded backend.
const userStoreErrInterval = 30 * time.Second

// reportUserStoreError records a fail-closed refusal caused by a user-store
// error: one log line and one audit row per interval, not per request.
func (a *Authenticator) reportUserStoreError(r *http.Request, principalID string, err error) {
	a.userStoreErrMu.Lock()
	now := time.Now()
	if !a.userStoreErrAt.IsZero() && now.Sub(a.userStoreErrAt) < userStoreErrInterval {
		a.userStoreErrMu.Unlock()
		return
	}
	a.userStoreErrAt = now
	a.userStoreErrMu.Unlock()
	log.Printf("auth: user store error, refusing session principal %q (fail closed): %v", principalID, err)
	emitAuditEvent(r, a.auditProvider, principalID, "authz.userstore_error", "auth", "userstore", AuditOutcomeDenied)
}

func (a *Authenticator) Refresh(refreshToken string, now time.Time) (string, int64, string, int64, error) {
	trimmed := strings.TrimSpace(refreshToken)
	if trimmed == "" {
		return "", 0, "", 0, errInvalidRefreshToken
	}

	a.refreshMu.Lock()
	session, ok := a.refreshSessions[trimmed]
	if ok {
		delete(a.refreshSessions, trimmed)
	}
	a.refreshMu.Unlock()
	if !ok || !now.Before(session.ExpiresAt) {
		return "", 0, "", 0, errInvalidRefreshToken
	}

	// The refresh token above is single-use (deleted before this check), so
	// failing here still consumes it. A UserProvider *error* fails closed, same
	// as AuthenticatePrincipalDetails (auth.go), except for the env login
	// admin, whose refresh is part of how an operator recovers from a user-DB
	// outage; an error also re-issues the token rather than consuming it.
	role, active, ierr := a.resolveRefreshIdentity(context.Background(), session)
	if ierr != nil {
		// Not the client's fault and not a verdict on the session: put the
		// token back so the retry after the outage still works.
		a.refreshMu.Lock()
		a.refreshSessions[trimmed] = session
		a.refreshMu.Unlock()
		return "", 0, "", 0, ierr
	}
	if !active {
		return "", 0, "", 0, errInvalidRefreshToken
	}

	accessToken, err := mintHS256JWT(session.PrincipalID, role, a.config.loginSigning, a.config.jwtIssuer, a.config.jwtAudience, now.Add(a.config.loginTTL))
	if err != nil {
		return "", 0, "", 0, err
	}
	newRefresh, err := generateOpaqueToken("rfr")
	if err != nil {
		return "", 0, "", 0, err
	}

	a.refreshMu.Lock()
	a.refreshSessions[newRefresh] = refreshSession{PrincipalID: session.PrincipalID, Role: role, ExpiresAt: now.Add(a.config.refreshTTL)}
	a.refreshMu.Unlock()

	return accessToken, int64(a.config.loginTTL / time.Second), newRefresh, int64(a.config.refreshTTL / time.Second), nil
}

// mintHS256JWT embeds the principal's resolved role as a "role" claim (S-34)
// so authenticateBootstrap can recover it on every subsequent request instead
// of the caller hardcoding pki-admin for any session token that validates.
func mintHS256JWT(subject string, role string, secret string, issuer string, audience string, exp time.Time) (string, error) {
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	payload := map[string]any{"sub": subject, "exp": exp.Unix()}
	if strings.TrimSpace(role) != "" {
		payload["role"] = role
	}
	if strings.TrimSpace(issuer) != "" {
		payload["iss"] = issuer
	}
	if strings.TrimSpace(audience) != "" {
		payload["aud"] = audience
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	segment1 := base64.RawURLEncoding.EncodeToString(headerBytes)
	segment2 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := segment1 + "." + segment2

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

// jwtRoleClaim reads the "role" claim out of an HS256 JWT's payload without
// re-verifying its signature. Callers must only use this on a token whose
// signature has already been checked (e.g. via validateHS256JWT) — it exists
// so authenticateBootstrap can recover the role mintHS256JWT embedded without
// widening validateHS256JWT's return signature, which other callers rely on.
func jwtRoleClaim(token string) string {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return ""
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return ""
	}
	role, _ := payload["role"].(string)
	return role
}

func generateOpaqueToken(prefix string) (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func (a *Authenticator) ListAPIKeys() []apiKeyRecord {
	a.apiKeyMu.RLock()
	defer a.apiKeyMu.RUnlock()
	keys := make([]apiKeyRecord, 0, len(a.config.apiKeys))
	for _, item := range a.config.apiKeys {
		copied := item
		copied.Scopes = append([]string(nil), item.Scopes...)
		keys = append(keys, copied)
	}
	slices.SortFunc(keys, func(a, b apiKeyRecord) int {
		return strings.Compare(a.Kid, b.Kid)
	})
	return keys
}

func (a *Authenticator) CreateAPIKey(name string, principalID string, role string, scopes []string, expiresAt string, tenant string, now time.Time) (apiKeyRecord, string, error) {
	return a.CreateAPIKeyAs("", name, principalID, role, scopes, expiresAt, tenant, now)
}

// CreateAPIKeyAs mints a key recording createdBy (the minter's canonical
// human, see canonicalHuman) so approval separation of duties can see
// through the free-text principal id.
func (a *Authenticator) CreateAPIKeyAs(createdBy, name string, principalID string, role string, scopes []string, expiresAt string, tenant string, now time.Time) (apiKeyRecord, string, error) {
	if strings.TrimSpace(a.config.apiKeyPepper) == "" {
		return apiKeyRecord{}, "", fmt.Errorf("api key auth unavailable")
	}
	if strings.TrimSpace(principalID) == "" {
		return apiKeyRecord{}, "", fmt.Errorf("invalid api key principal")
	}
	if expiresAt != "" {
		if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
			return apiKeyRecord{}, "", fmt.Errorf("invalid api key expiry")
		}
	}
	kid, err := generateOpaqueToken("kid")
	if err != nil {
		return apiKeyRecord{}, "", err
	}
	secret, err := generateOpaqueToken("sk")
	if err != nil {
		return apiKeyRecord{}, "", err
	}
	kid = strings.ReplaceAll(kid, "_", "")
	secret = strings.ReplaceAll(secret, "_", "")
	if len(kid) > 12 {
		kid = kid[:12]
	}
	token := "kk_" + kid + "_" + secret

	record := apiKeyRecord{
		Name:           strings.TrimSpace(name),
		Kid:            kid,
		SecretVerifier: apiKeyVerifier(secret, a.config.apiKeyPepper),
		PrincipalID:    strings.TrimSpace(principalID),
		Role:           firstNonEmpty(strings.TrimSpace(role), "service-account"),
		Scopes:         append([]string(nil), scopes...),
		Active:         true,
		CreatedAt:      now.UTC().Format(time.RFC3339),
		ExpiresAt:      strings.TrimSpace(expiresAt),
		Tenant:         strings.TrimSpace(tenant),
		CreatedBy:      strings.TrimSpace(createdBy),
	}

	// Persist before taking the lock: every authenticated request RLocks
	// apiKeyMu, so a stalled core DB must never be waited on while holding it.
	// The kid is unguessable and not yet visible, so nothing can race it.
	a.apiKeyMu.RLock()
	store := a.apiKeyStore
	a.apiKeyMu.RUnlock()
	if store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), apiKeyDBTimeout)
		err := store.Insert(ctx, record)
		cancel()
		if err != nil {
			log.Printf("error: persist minted api key %s: %v", kid, err)
			return apiKeyRecord{}, "", errAPIKeyPersist
		}
	}
	a.apiKeyMu.Lock()
	defer a.apiKeyMu.Unlock()
	if store != nil {
		a.persistedKids[kid] = true
	}
	a.config.apiKeys[kid] = record

	return record, token, nil
}

// RevokeAPIKey removes the key from this process immediately, then persists
// the revocation (one retry). found is false for an unknown kid. A non-nil
// persistErr means the key is already rejected in-process but the revocation
// is not durable: it would come back at the next restart, so the caller must
// not report success. The kid is remembered so a repeated call retries the
// write instead of answering "not found".
func (a *Authenticator) RevokeAPIKey(kid string) (found bool, persistErr error) {
	trimmed := strings.TrimSpace(kid)
	if trimmed == "" {
		return false, nil
	}
	// Reject in memory first, under a brief lock, so the key stops working
	// immediately. The DB write happens after the lock is released.
	a.apiKeyMu.Lock()
	_, inMemory := a.config.apiKeys[trimmed]
	if !inMemory && !a.revokePending[trimmed] {
		a.apiKeyMu.Unlock()
		return false, nil
	}
	delete(a.config.apiKeys, trimmed)
	if !a.persistedKids[trimmed] && !a.revokePending[trimmed] {
		a.apiKeyMu.Unlock()
		return true, nil
	}
	// Mark pending until the write succeeds; a failure leaves it set so a
	// repeated DELETE retries instead of answering 404.
	if a.revokePending == nil {
		a.revokePending = map[string]bool{}
	}
	a.revokePending[trimmed] = true
	delete(a.persistedKids, trimmed)
	store := a.apiKeyStore
	a.apiKeyMu.Unlock()

	var err error
	at := time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), apiKeyDBTimeout)
		err = store.Revoke(ctx, trimmed, at)
		cancel()
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Printf("error: persist api key revocation %s (rejected in-process, not durable; retry the delete): %v", trimmed, err)
		return true, err
	}
	a.apiKeyMu.Lock()
	delete(a.revokePending, trimmed)
	delete(a.lastTouch, trimmed)
	a.apiKeyMu.Unlock()
	return true, nil
}

func isAdminRole(role string) bool {
	return strings.TrimSpace(role) == "pki-admin"
}
