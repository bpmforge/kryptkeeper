// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// W29-06 (FR-P23): operator-minted, hashed, single-use, expiring enrollment
// tokens. They replace the shared CSV secret as the preferred evidence kind
// in the W5-07 gate: a leaked token enrols at most one agent, once.

const (
	agentEnrollTokenDefaultTTL = 24 * time.Hour
	agentEnrollTokenMaxTTL     = 7 * 24 * time.Hour
	agentEnrollTokenPrefix     = "kkenr_"
)

// ErrEnrollmentTokenInvalid covers unknown, expired, revoked and already
// redeemed tokens alike, so a refusal never reveals which one it was.
var ErrEnrollmentTokenInvalid = errors.New("enrollment token invalid")

// AgentEnrollmentToken is the listable view of a token; it never carries the
// secret or its hash. Tenant (W33-24) scopes list/revoke and is not exposed.
type AgentEnrollmentToken struct {
	ID              string `json:"id"`
	Label           string `json:"label"`
	CreatedBy       string `json:"created_by"`
	Tenant          string `json:"-"`
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at"`
	RedeemedAt      string `json:"redeemed_at"`
	RedeemedAgentID string `json:"redeemed_agent_id"`
	RevokedAt       string `json:"revoked_at"`
}

type memEnrollToken struct {
	AgentEnrollmentToken
	hash string
}

func newEnrollmentToken(label, createdBy, tenant string, ttl time.Duration, now time.Time) (tok AgentEnrollmentToken, secret, hash string, err error) {
	rawID, err := generateToken(8)
	if err != nil {
		return tok, "", "", fmt.Errorf("generate enrollment token id: %w", err)
	}
	rawSecret, err := generateToken(32)
	if err != nil {
		return tok, "", "", fmt.Errorf("generate enrollment token: %w", err)
	}
	secret = agentEnrollTokenPrefix + rawSecret
	now = now.UTC()
	tok = AgentEnrollmentToken{
		ID:        "aet-" + rawID,
		Label:     label,
		CreatedBy: createdBy,
		Tenant:    tenant,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(ttl).Format(time.RFC3339),
	}
	return tok, secret, hashAgentToken(secret), nil
}

func (s *memAgentStore) mintEnrollmentToken(label, createdBy, tenant string, ttl time.Duration, now time.Time) (AgentEnrollmentToken, string, error) {
	tok, secret, hash, err := newEnrollmentToken(label, createdBy, tenant, ttl, now)
	if err != nil {
		return tok, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enroll[tok.ID] = &memEnrollToken{AgentEnrollmentToken: tok, hash: hash}
	return tok, secret, nil
}

func (s *memAgentStore) redeemEnrollmentToken(secret, agentID string, now time.Time) (string, error) {
	hash := hashAgentToken(secret)
	nowS := now.UTC().Format(time.RFC3339)
	s.mu.Lock()
	defer s.mu.Unlock()
	var match *memEnrollToken
	for _, t := range s.enroll { // scan every entry: no early exit on a hash match
		if subtle.ConstantTimeCompare([]byte(t.hash), []byte(hash)) == 1 {
			match = t
		}
	}
	if match == nil || match.RedeemedAt != "" || match.RevokedAt != "" || match.ExpiresAt <= nowS {
		return "", ErrEnrollmentTokenInvalid
	}
	match.RedeemedAt = nowS
	match.RedeemedAgentID = agentID
	return match.ID, nil
}

func (s *memAgentStore) listEnrollmentTokens() []AgentEnrollmentToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AgentEnrollmentToken, 0, len(s.enroll))
	for _, t := range s.enroll {
		out = append(out, t.AgentEnrollmentToken)
	}
	sortEnrollmentTokens(out)
	return out
}

func (s *memAgentStore) revokeEnrollmentToken(id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.enroll[id]
	if !ok {
		return ErrAgentNotFound
	}
	if t.RedeemedAt != "" || t.RevokedAt != "" {
		return ErrEnrollmentTokenInvalid
	}
	t.RevokedAt = now.UTC().Format(time.RFC3339)
	return nil
}

func sortEnrollmentTokens(ts []AgentEnrollmentToken) {
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].CreatedAt != ts[j].CreatedAt {
			return ts[i].CreatedAt > ts[j].CreatedAt
		}
		return ts[i].ID < ts[j].ID
	})
}

func (s *dbAgentStore) mintEnrollmentToken(label, createdBy, tenant string, ttl time.Duration, now time.Time) (AgentEnrollmentToken, string, error) {
	tok, secret, hash, err := newEnrollmentToken(label, createdBy, tenant, ttl, now)
	if err != nil {
		return tok, "", err
	}
	q := fmt.Sprintf(`INSERT INTO agent_enrollment_tokens (id, token_hash, label, created_by, tenant_id, created_at, expires_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s)`, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7))
	if _, err := s.db.ExecContext(context.Background(), q, tok.ID, hash, label, createdBy, tenant, tok.CreatedAt, tok.ExpiresAt); err != nil {
		return tok, "", fmt.Errorf("insert enrollment token: %w", err)
	}
	return tok, secret, nil
}

// redeemEnrollmentToken is one conditional UPDATE that also records the
// agent the token enrols (W33-24 attach), so two concurrent redemptions cannot
// both succeed and a redeemed row always names its agent. The lookup is by
// hash, never plaintext.
func (s *dbAgentStore) redeemEnrollmentToken(secret, agentID string, now time.Time) (string, error) {
	nowS := now.UTC().Format(time.RFC3339)
	hash := hashAgentToken(secret)
	ctx := context.Background()
	q := fmt.Sprintf(`UPDATE agent_enrollment_tokens SET redeemed_at = %s, redeemed_agent_id = %s
		WHERE token_hash = %s AND redeemed_at = '' AND revoked_at = '' AND expires_at > %s`, s.ph(1), s.ph(2), s.ph(3), s.ph(4))
	res, err := s.db.ExecContext(ctx, q, nowS, agentID, hash, nowS)
	if err != nil {
		return "", fmt.Errorf("redeem enrollment token: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return "", ErrEnrollmentTokenInvalid
	}
	var id string
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT id FROM agent_enrollment_tokens WHERE token_hash = %s", s.ph(1)), hash).Scan(&id); err != nil {
		return "", fmt.Errorf("read redeemed enrollment token id: %w", err)
	}
	return id, nil
}

func (s *dbAgentStore) listEnrollmentTokens() []AgentEnrollmentToken {
	rows, err := s.db.QueryContext(context.Background(), `SELECT id, label, created_by, tenant_id, created_at, expires_at, redeemed_at, redeemed_agent_id, revoked_at
		FROM agent_enrollment_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return []AgentEnrollmentToken{}
	}
	defer func() { _ = rows.Close() }()
	out := []AgentEnrollmentToken{}
	for rows.Next() {
		var t AgentEnrollmentToken
		if err := rows.Scan(&t.ID, &t.Label, &t.CreatedBy, &t.Tenant, &t.CreatedAt, &t.ExpiresAt, &t.RedeemedAt, &t.RedeemedAgentID, &t.RevokedAt); err != nil {
			return out
		}
		out = append(out, t)
	}
	return out
}

func (s *dbAgentStore) revokeEnrollmentToken(id string, now time.Time) error {
	ctx := context.Background()
	q := fmt.Sprintf(`UPDATE agent_enrollment_tokens SET revoked_at = %s
		WHERE id = %s AND redeemed_at = '' AND revoked_at = ''`, s.ph(1), s.ph(2))
	res, err := s.db.ExecContext(ctx, q, now.UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 1 {
		return nil
	}
	var one int
	err = s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT 1 FROM agent_enrollment_tokens WHERE id = %s", s.ph(1)), id).Scan(&one)
	if err != nil {
		return ErrAgentNotFound
	}
	return ErrEnrollmentTokenInvalid
}

// enrollmentTokenTenant is the tenant a principal mints into and sees tokens
// of (W33-24). Normalised so a principal without a tenant matches the
// 'default' rows the migration backfills.
func enrollmentTokenTenant(pd AuthPrincipal) string {
	if !multiTenancyEnabled() || pd.Tenant == "" {
		return DefaultTenant
	}
	return pd.Tenant
}

func enrollmentTokenVisible(pd AuthPrincipal, t AgentEnrollmentToken) bool {
	return tenantBypass(pd) || t.Tenant == enrollmentTokenTenant(pd)
}

// enrollmentTokenVisibleByID reports whether id exists in the caller's tenant;
// a cross-tenant id is reported exactly like an unknown one.
func enrollmentTokenVisibleByID(store AgentStore, pd AuthPrincipal, id string) bool {
	for _, t := range store.listEnrollmentTokens() {
		if t.ID == id {
			return enrollmentTokenVisible(pd, t)
		}
	}
	return false
}

// registerAgentEnrollmentTokenHandlers mounts the admin mint/list/revoke
// routes. /api/v1/agent/** is permSelf in the write gate, so the explicit
// isAdminRole check here is the guard.
func registerAgentEnrollmentTokenHandlers(mux routeRegistrar, auth *Authenticator, store AgentStore, auditProvider AuditProvider) {
	mux.HandleFunc("POST /api/v1/agent/enrollment-tokens", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "agent.token_mint", "agent_enrollment_token", "-", AuditOutcomeDenied)
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_mint", "agent_enrollment_token", "-", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		var req struct {
			Label      string `json:"label"`
			TTLSeconds int64  `json:"ttl_seconds"`
		}
		if !decodeJSONBodyOrReject(w, r, &req, maxAgentSmallBodyBytes, "invalid JSON") {
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_mint", "agent_enrollment_token", "-", AuditOutcomeFailure)
			return
		}
		ttl := agentEnrollTokenDefaultTTL
		if req.TTLSeconds < 0 || time.Duration(req.TTLSeconds) > agentEnrollTokenMaxTTL/time.Second {
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_mint", "agent_enrollment_token", "-", AuditOutcomeFailure)
			writeBadRequest(w, "ttl_seconds must be between 1 and 604800")
			return
		}
		if req.TTLSeconds > 0 {
			ttl = time.Duration(req.TTLSeconds) * time.Second
		}
		label := strings.TrimSpace(req.Label)
		if len(label) > 128 {
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_mint", "agent_enrollment_token", "-", AuditOutcomeFailure)
			writeBadRequest(w, "label must be at most 128 characters")
			return
		}
		tok, secret, err := store.mintEnrollmentToken(label, pd.ID, enrollmentTokenTenant(pd), ttl, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_mint", "agent_enrollment_token", "-", AuditOutcomeFailure)
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "agent.token_mint", "agent_enrollment_token", tok.ID, AuditOutcomeSuccess)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		writeJSONData(w, map[string]string{
			"id": tok.ID, "token": secret, "expires_at": tok.ExpiresAt, "label": tok.Label,
		})
	})

	mux.HandleFunc("GET /api/v1/agent/enrollment-tokens", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		if !isAdminRole(pd.Role) {
			writeForbidden(w, "forbidden")
			return
		}
		out := []AgentEnrollmentToken{}
		for _, t := range store.listEnrollmentTokens() {
			if enrollmentTokenVisible(pd, t) {
				out = append(out, t)
			}
		}
		writeJSONData(w, out)
	})

	mux.HandleFunc("DELETE /api/v1/agent/enrollment-tokens/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "agent.token_revoke", "agent_enrollment_token", id, AuditOutcomeDenied)
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_revoke", "agent_enrollment_token", id, AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		if !enrollmentTokenVisibleByID(store, pd, id) {
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_revoke", "agent_enrollment_token", id, AuditOutcomeFailure)
			writeNotFound(w, "enrollment token not found")
			return
		}
		switch err := store.revokeEnrollmentToken(id, time.Now()); {
		case err == nil:
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_revoke", "agent_enrollment_token", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, ErrAgentNotFound):
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_revoke", "agent_enrollment_token", id, AuditOutcomeFailure)
			writeNotFound(w, "enrollment token not found")
		case errors.Is(err, ErrEnrollmentTokenInvalid):
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_revoke", "agent_enrollment_token", id, AuditOutcomeFailure)
			writeConflict(w, "enrollment token already redeemed or revoked")
		default:
			emitAuditEvent(r, auditProvider, pd.ID, "agent.token_revoke", "agent_enrollment_token", id, AuditOutcomeFailure)
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal_error", "internal error")
		}
	})
}
