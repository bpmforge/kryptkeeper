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
	"net/http"
	"time"
)

const userPrefsMaxBody = 4096

// UserPrefs is the per-user UI preference set (W33-03, FR-P29).
type UserPrefs struct {
	OnboardingDismissed bool `json:"onboarding_dismissed"`
}

// UserPrefsStore persists prefs keyed on the authenticated principal id. The
// key is never client-supplied, so a caller can only ever touch its own row.
type UserPrefsStore interface {
	EnsureSchema(ctx context.Context) error
	// Get returns defaults when no row exists.
	Get(ctx context.Context, principalID string) (UserPrefs, error)
	Set(ctx context.Context, principalID string, prefs UserPrefs) error
}

// Mirrors migration 000324_user_prefs; stores self-heal their own schema (G-33).
const userPrefsSchemaSQLite = `
CREATE TABLE IF NOT EXISTS user_prefs (
    principal_id          TEXT PRIMARY KEY,
    onboarding_dismissed  INTEGER NOT NULL DEFAULT 0,
    updated_at            TEXT NOT NULL
);`

const userPrefsSchemaPostgres = `
CREATE TABLE IF NOT EXISTS user_prefs (
    principal_id          TEXT PRIMARY KEY,
    onboarding_dismissed  BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at            TEXT NOT NULL
);`

type dbUserPrefsStore struct {
	db     *sql.DB
	ph     func(int) string
	schema string
}

func (s *dbUserPrefsStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, s.schema)
	return err
}

func (s *dbUserPrefsStore) Get(ctx context.Context, principalID string) (UserPrefs, error) {
	var p UserPrefs
	err := s.db.QueryRowContext(ctx,
		`SELECT onboarding_dismissed FROM user_prefs WHERE principal_id = `+s.ph(1), principalID).Scan(&p.OnboardingDismissed)
	if errors.Is(err, sql.ErrNoRows) {
		return UserPrefs{}, nil
	}
	return p, err
}

func (s *dbUserPrefsStore) Set(ctx context.Context, principalID string, p UserPrefs) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO user_prefs (principal_id, onboarding_dismissed, updated_at)
		VALUES (%s, %s, %s)
		ON CONFLICT(principal_id) DO UPDATE SET onboarding_dismissed = excluded.onboarding_dismissed,
			updated_at = excluded.updated_at`, s.ph(1), s.ph(2), s.ph(3)),
		principalID, p.OnboardingDismissed, time.Now().UTC().Format(time.RFC3339))
	return err
}

// newUserPrefsStoreFromEnv returns nil on any failure (nil-tolerant, like
// every newXFromEnv here); the handlers answer 503 then.
func newUserPrefsStoreFromEnv() UserPrefsStore {
	state := newDBProviderState[UserPrefsStore](
		"user-prefs",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_CONFIG_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_CONFIG_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_CONFIG_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) UserPrefsStore {
			return &dbUserPrefsStore{db: db, ph: sqlitePlaceholder, schema: userPrefsSchemaSQLite}
		},
		func(db *sql.DB) UserPrefsStore {
			return &dbUserPrefsStore{db: db, ph: postgresPlaceholder, schema: userPrefsSchemaPostgres}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("user-prefs", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("user-prefs", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

// registerUserPrefsHandlers mounts GET/PUT /api/v1/users/me/prefs. The exact
// pattern is registered (no trailing slash) so /api/v1/users/{id} lookups in
// handlers_users.go are not shadowed.
func registerUserPrefsHandlers(mux *http.ServeMux, auth *Authenticator, store UserPrefsStore, auditProvider AuditProvider) {
	const action, resource = "user.prefs.set", "user_prefs"
	mux.HandleFunc("/api/v1/users/me/prefs", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if store == nil {
				writeServiceUnavailable(w, "user prefs store unavailable")
				return
			}
			prefs, err := store.Get(r.Context(), pd.ID)
			if err != nil {
				writeServiceUnavailable(w, "user prefs lookup failed")
				return
			}
			writeJSONData(w, prefs)
		case http.MethodPut:
			if store == nil {
				emitAuditEvent(r, auditProvider, pd.ID, action, resource, pd.ID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "user prefs store unavailable")
				return
			}
			var req struct {
				OnboardingDismissed *bool `json:"onboarding_dismissed"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, userPrefsMaxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil || req.OnboardingDismissed == nil {
				emitAuditEvent(r, auditProvider, pd.ID, action, resource, pd.ID, AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			prefs := UserPrefs{OnboardingDismissed: *req.OnboardingDismissed}
			if err := store.Set(r.Context(), pd.ID, prefs); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, action, resource, pd.ID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "user prefs update failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, action, resource, pd.ID, AuditOutcomeSuccess)
			writeJSONData(w, prefs)
		default:
			writeMethodNotAllowed(w, "GET, PUT")
		}
	})
}
