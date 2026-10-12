// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The stamp on a target (ManagedTarget.AutoRenewSetBy) says who armed key
// egress. It is written as "<kind>:<ref>" so the scheduler can later ask
// whether that principal still holds the authority it was stamped under
// (RC1-A-01): a deleted user, a revoked or expired API key, or a role that
// lost certificate.renew must not keep pushing keys on the old say-so.
const (
	stampBootstrap = "bootstrap"
	stampKey       = "key:"   // API key, by kid
	stampUser      = "user:"  // login session, by user id
	stampToken     = "token:" // externally issued jwt/oidc bearer, by subject
)

// egressStamp is the value recorded for pd when it arms key egress, and false
// when pd's auth kind cannot be stamped. The switch is exhaustive on purpose:
// a new AuthType must be added here deliberately, and until then it cannot arm
// a target, because an unverifiable stamp would keep pushing keys on authority
// nobody can re-check. jwt/oidc bearers are the documented exception: they get
// a "token:" stamp that is accepted as stamped (they are not store identities).
func egressStamp(pd AuthPrincipal) (string, bool) {
	switch pd.AuthType {
	case AuthTypeBootstrap:
		return stampBootstrap, true
	case AuthTypeAPIKey:
		return stampKey + pd.Kid, true
	case AuthTypeLocal:
		return stampUser + pd.ID, true
	case AuthTypeJWT, AuthTypeOIDC:
		return stampToken + pd.ID, true
	default:
		return "", false
	}
}

// armStamp resolves the stamp for a request that arms egress, answering 403
// (audited) when the caller's auth kind cannot be stamped.
func armStamp(w http.ResponseWriter, r *http.Request, ap AuditProvider, pd AuthPrincipal, action, id string) (string, bool) {
	stamp, ok := egressStamp(pd)
	if !ok {
		emitAuditEventDetail(r, ap, pd.ID, action, "target", id, AuditOutcomeDenied, "unstampable auth type")
		writeForbidden(w, "this credential type cannot arm key egress on a target")
	}
	return stamp, ok
}

var (
	errStampUnresolvable = errors.New("the principal that armed this target no longer exists")
	errStampLostAuth     = errors.New("the principal that armed this target no longer holds certificate.renew")
	errStampUnrecognized = errors.New("the stamp is not in a form the scheduler can verify")
)

// StampVerifier returns the check the renewal scheduler runs before pushing a
// key: nil means the stamped principal still exists and still holds
// certificate.renew. Externally issued bearer tokens (jwt/oidc) are not store
// identities and cannot be re-checked here; they are accepted as stamped. A
// user-store outage returns an error, so the push is skipped, not assumed.
func (a *Authenticator) StampVerifier() func(ctx context.Context, stamp string) error {
	return func(ctx context.Context, stamp string) error {
		return a.verifyEgressStamp(ctx, stamp, time.Now())
	}
}

func (a *Authenticator) verifyEgressStamp(ctx context.Context, stamp string, now time.Time) error {
	switch {
	case stamp == stampBootstrap:
		return nil
	case strings.HasPrefix(stamp, stampToken):
		return nil
	case strings.HasPrefix(stamp, stampKey):
		rec, ok := a.apiKeysSnapshot()[strings.TrimPrefix(stamp, stampKey)]
		if !ok || !rec.Active {
			return errStampUnresolvable
		}
		if exp := strings.TrimSpace(rec.ExpiresAt); exp != "" {
			if ts, err := time.Parse(time.RFC3339, exp); err != nil || !now.Before(ts) {
				return errStampUnresolvable
			}
		}
		role := strings.TrimSpace(rec.Role)
		if role == "" {
			role = "service-account"
		}
		return a.requireRenew(AuthPrincipal{ID: rec.PrincipalID, Role: role, Scopes: rec.Scopes, AuthType: AuthTypeAPIKey})
	case strings.HasPrefix(stamp, stampUser):
		id := strings.TrimPrefix(stamp, stampUser)
		role, err := a.currentUserRole(ctx, id)
		if err != nil {
			return err
		}
		return a.requireRenew(AuthPrincipal{ID: id, Role: role, AuthType: AuthTypeLocal})
	}
	return errStampUnrecognized
}

// currentUserRole is the user's role right now, from the user store, or from
// config for the env-configured login admin.
func (a *Authenticator) currentUserRole(ctx context.Context, id string) (string, error) {
	if a.userProvider != nil {
		users, err := a.userProvider.ListUsers(ctx)
		if err != nil {
			if !a.isEnvLoginAdmin(id) {
				return "", fmt.Errorf("user store unavailable: %w", err)
			}
		} else {
			for _, u := range users {
				if u.ID != id {
					continue
				}
				if isDeprovisionedStatus(u.Status) {
					return "", errStampUnresolvable
				}
				return strings.TrimSpace(u.Role), nil
			}
		}
	}
	if a.isEnvLoginAdmin(id) && a.config.loginUser.Active {
		return strings.TrimSpace(a.config.loginUser.Role), nil
	}
	return "", errStampUnresolvable
}

func (a *Authenticator) requireRenew(pd AuthPrincipal) error {
	perms, admin := principalPermissions(pd, a.roleStore)
	if admin || perms["certificate.renew"] {
		return nil
	}
	return errStampLostAuth
}
