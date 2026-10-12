// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// apiKeyLastUsedInterval bounds last_used_at writes to one per key per
// interval so authenticating never turns into a DB write per request.
const apiKeyLastUsedInterval = time.Minute

// apiKeyDBTimeout bounds every core-DB call made on behalf of API keys.
const apiKeyDBTimeout = 5 * time.Second

// errAPIKeyPersist marks a minted key that could not be written to the core
// DB. The key is not handed out: a token that would stop working at the next
// restart is worse than a failed request.
var errAPIKeyPersist = errors.New("api key could not be persisted")

// apiKeyStore persists keys minted through POST /api/v1/api-keys. Keys from
// APP_API_KEYS_JSON never pass through it. Only the HMAC secret_verifier is
// stored, never the secret.
type apiKeyStore interface {
	LoadActive(ctx context.Context) ([]apiKeyRecord, error)
	Insert(ctx context.Context, rec apiKeyRecord) error
	Revoke(ctx context.Context, kid string, at time.Time) error
	TouchLastUsed(ctx context.Context, kid string, at time.Time) error
}

type dbAPIKeyStore struct {
	db *sql.DB
	ph func(int) string
}

// NewAPIKeyStore wraps the core DB (already migrated by OpenCoreDB).
func NewAPIKeyStore(db *sql.DB, postgres bool) apiKeyStore {
	if postgres {
		return &dbAPIKeyStore{db: db, ph: postgresPlaceholder}
	}
	return &dbAPIKeyStore{db: db, ph: sqlitePlaceholder}
}

func (s *dbAPIKeyStore) LoadActive(ctx context.Context) ([]apiKeyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kid, name, secret_verifier, principal_id, role, scopes, active,
		created_at, created_by, expires_at, last_used_at, tenant FROM minted_api_keys WHERE active = `+s.activeLiteral())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []apiKeyRecord
	for rows.Next() {
		var r apiKeyRecord
		var scopes string
		if err := rows.Scan(&r.Kid, &r.Name, &r.SecretVerifier, &r.PrincipalID, &r.Role, &scopes, &r.Active,
			&r.CreatedAt, &r.CreatedBy, &r.ExpiresAt, &r.LastUsedAt, &r.Tenant); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &r.Scopes); err != nil {
			return nil, fmt.Errorf("api key %s: bad scopes: %w", r.Kid, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// activeLiteral is the engine-correct "true" for the active column.
func (s *dbAPIKeyStore) activeLiteral() string {
	if s.ph(1) == "?" {
		return "1"
	}
	return "TRUE"
}

func (s *dbAPIKeyStore) Insert(ctx context.Context, r apiKeyRecord) error {
	scopes, err := json.Marshal(append([]string{}, r.Scopes...))
	if err != nil {
		return err
	}
	q := fmt.Sprintf(`INSERT INTO minted_api_keys (kid, name, secret_verifier, principal_id, role, scopes, active,
		created_at, created_by, expires_at, last_used_at, tenant) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11), s.ph(12))
	_, err = s.db.ExecContext(ctx, q, r.Kid, r.Name, r.SecretVerifier, r.PrincipalID, r.Role, string(scopes), r.Active,
		r.CreatedAt, r.CreatedBy, r.ExpiresAt, r.LastUsedAt, r.Tenant)
	return err
}

func (s *dbAPIKeyStore) Revoke(ctx context.Context, kid string, at time.Time) error {
	off := "0"
	if s.activeLiteral() == "TRUE" {
		off = "FALSE"
	}
	q := fmt.Sprintf(`UPDATE minted_api_keys SET active = %s, revoked_at = %s WHERE kid = %s`, off, s.ph(1), s.ph(2))
	_, err := s.db.ExecContext(ctx, q, at.UTC().Format(time.RFC3339), kid)
	return err
}

func (s *dbAPIKeyStore) TouchLastUsed(ctx context.Context, kid string, at time.Time) error {
	q := fmt.Sprintf(`UPDATE minted_api_keys SET last_used_at = %s WHERE kid = %s`, s.ph(1), s.ph(2))
	_, err := s.db.ExecContext(ctx, q, at.UTC().Format(time.RFC3339), kid)
	return err
}

// SetAPIKeyStore attaches a persistent store and loads previously minted
// keys. Keys from APP_API_KEYS_JSON already in memory win on a kid collision.
// Call before the server accepts requests.
func (a *Authenticator) SetAPIKeyStore(ctx context.Context, store apiKeyStore) error {
	records, err := store.LoadActive(ctx)
	if err != nil {
		return fmt.Errorf("load persisted api keys: %w", err)
	}
	a.apiKeyMu.Lock()
	defer a.apiKeyMu.Unlock()
	a.apiKeyStore = store
	a.persistedKids = map[string]bool{}
	loaded := 0
	for _, rec := range records {
		kid := strings.TrimSpace(rec.Kid)
		if _, exists := a.config.apiKeys[kid]; exists {
			log.Printf("warning: persisted api key %q shadowed by an APP_API_KEYS_JSON key with the same kid; the configured key wins", kid)
			continue
		}
		a.config.apiKeys[kid] = rec
		a.persistedKids[kid] = true
		loaded++
	}
	log.Printf("api keys: loaded %d persisted minted key(s) from the core database", loaded)
	return nil
}

// APIKeyMintingAvailable reports whether POST /api/v1/api-keys can mint keys
// (api-key auth on and a pepper set), i.e. whether a startup warning about
// non-persistent keys is relevant.
func (a *Authenticator) APIKeyMintingAvailable() bool {
	return a.config.apiKeyAuthEnabled && strings.TrimSpace(a.config.apiKeyPepper) != ""
}

// touchAPIKey records last_used_at for a persisted key, at most once per
// apiKeyLastUsedInterval. A failed write is logged, never fails the request.
func (a *Authenticator) touchAPIKey(kid string, now time.Time) {
	a.apiKeyMu.Lock()
	if a.apiKeyStore == nil || !a.persistedKids[kid] {
		a.apiKeyMu.Unlock()
		return
	}
	if last, ok := a.lastTouch[kid]; ok && now.Sub(last) < apiKeyLastUsedInterval {
		a.apiKeyMu.Unlock()
		return
	}
	if a.lastTouch == nil {
		a.lastTouch = map[string]time.Time{}
	}
	a.lastTouch[kid] = now
	if rec, ok := a.config.apiKeys[kid]; ok {
		rec.LastUsedAt = now.UTC().Format(time.RFC3339)
		a.config.apiKeys[kid] = rec
	}
	store := a.apiKeyStore
	a.apiKeyMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), apiKeyDBTimeout)
	defer cancel()
	if err := store.TouchLastUsed(ctx, kid, now); err != nil {
		log.Printf("warning: api key last_used_at update failed: %v", err)
	}
}
