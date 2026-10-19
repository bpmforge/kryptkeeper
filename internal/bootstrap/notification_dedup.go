// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"kryptkeeper/internal/logging"
)

// renewalAlertCooldownStore persists the last time a renewal-reminder
// notification was sent for a certificate, so the cooldown enforced at
// dispatch (renewal_scheduler.go) survives a hub restart. W1-06/D-033: an
// in-memory-only tracker (the pattern used for W2-07's dead-letter map)
// would reset to empty on every restart — since the scheduler runs a scan
// immediately on Start(), a restart inside the cooldown window would
// silently re-alert, reproducing the exact "same cert re-alerts every poll"
// symptom this ticket exists to close. Persisting is deliberate, not the
// default in-memory shortcut used elsewhere this session.
type renewalAlertCooldownStore interface {
	EnsureSchema(ctx context.Context) error
	LastAlertedAt(ctx context.Context, fingerprint string) (time.Time, bool, error)
	RecordAlerted(ctx context.Context, fingerprint string, at time.Time) error
}

// isWithinCooldown is a pure helper (no DB access) so the cooldown-window
// comparison is unit-testable in isolation from persistence — mirrors
// FindingException.IsActive's pattern (W2-06).
func isWithinCooldown(lastAlertedAt time.Time, cooldown time.Duration, now time.Time) bool {
	return now.Before(lastAlertedAt.Add(cooldown))
}

const renewalAlertCooldownSchema = `
CREATE TABLE IF NOT EXISTS renewal_alert_cooldowns (
    fingerprint     TEXT PRIMARY KEY,
    last_alerted_at TEXT NOT NULL
);`

// --- SQLite implementation ---

type sqliteRenewalAlertCooldownStore struct{ db *sql.DB }

func (s *sqliteRenewalAlertCooldownStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, renewalAlertCooldownSchema)
	return err
}

func (s *sqliteRenewalAlertCooldownStore) LastAlertedAt(ctx context.Context, fingerprint string) (time.Time, bool, error) {
	var raw string
	err := s.db.QueryRowContext(ctx,
		"SELECT last_alerted_at FROM renewal_alert_cooldowns WHERE fingerprint = ?", fingerprint).Scan(&raw)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

func (s *sqliteRenewalAlertCooldownStore) RecordAlerted(ctx context.Context, fingerprint string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO renewal_alert_cooldowns (fingerprint, last_alerted_at) VALUES (?, ?)
ON CONFLICT (fingerprint) DO UPDATE SET last_alerted_at = excluded.last_alerted_at
`, fingerprint, at.UTC().Format(time.RFC3339))
	return err
}

// --- Postgres implementation ---

type postgresRenewalAlertCooldownStore struct{ db *sql.DB }

func (s *postgresRenewalAlertCooldownStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, renewalAlertCooldownSchema)
	return err
}

func (s *postgresRenewalAlertCooldownStore) LastAlertedAt(ctx context.Context, fingerprint string) (time.Time, bool, error) {
	var raw string
	err := s.db.QueryRowContext(ctx,
		"SELECT last_alerted_at FROM renewal_alert_cooldowns WHERE fingerprint = $1", fingerprint).Scan(&raw)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

func (s *postgresRenewalAlertCooldownStore) RecordAlerted(ctx context.Context, fingerprint string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO renewal_alert_cooldowns (fingerprint, last_alerted_at) VALUES ($1, $2)
ON CONFLICT (fingerprint) DO UPDATE SET last_alerted_at = excluded.last_alerted_at
`, fingerprint, at.UTC().Format(time.RFC3339))
	return err
}

// newRenewalAlertCooldownStoreFromEnv opens the same SQLite/Postgres DB as
// other providers and self-heals its schema (G-33 pattern). Soft-fail: the
// caller (renewal_scheduler.go) treats a nil store as "cooldown not
// enforced" rather than blocking notifications entirely — this is an
// annoyance-prevention feature, not a correctness-critical one, so a store
// outage should not silently stop all renewal reminders.
func newRenewalAlertCooldownStoreFromEnv() (renewalAlertCooldownStore, error) {
	state := newDBProviderState[renewalAlertCooldownStore](
		"renewal-alert-cooldown",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_RENEWAL_COOLDOWN_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_RENEWAL_COOLDOWN_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_RENEWAL_COOLDOWN_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) renewalAlertCooldownStore { return &sqliteRenewalAlertCooldownStore{db: db} },
		func(db *sql.DB) renewalAlertCooldownStore { return &postgresRenewalAlertCooldownStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// newRenewalAlertCooldownStoreFromEnvLogged is the soft-fail wrapper used at
// scheduler construction time: logs and returns nil rather than propagating
// an error, since a cooldown-store outage should degrade (no cooldown
// enforced) rather than prevent the scheduler from starting at all.
func newRenewalAlertCooldownStoreFromEnvLogged() renewalAlertCooldownStore {
	store, err := newRenewalAlertCooldownStoreFromEnv()
	if err != nil {
		logging.Warnf("renewal scheduler: alert-cooldown store unavailable, cooldown will not be enforced: %v", err)
		return nil
	}
	return store
}

// crossingKey is the cooldown-store key recording that rule ruleID already
// fired for the certificate with fingerprint certFP. A renewal changes the
// fingerprint, which starts a new cycle.
func crossingKey(certFP, ruleID string) string {
	return certFP + "#rule:" + ruleID + "#crossed"
}

// hasCrossed reports whether a crossing was recorded under key. A store error
// counts as not crossed, matching the old fail-open cooldown read.
func hasCrossed(ctx context.Context, store renewalAlertCooldownStore, key string) bool {
	if store == nil {
		return false
	}
	_, ok, err := store.LastAlertedAt(ctx, key)
	return err == nil && ok
}
