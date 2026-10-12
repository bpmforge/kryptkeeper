// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
)

var errNotificationSilenceNotFound = errors.New("notification silence not found")

// Fixed target-type values a silence can scope to — D-033/W1-06's "a rule
// can target/silence a specific cert/CA/template." Deliberately a NEW,
// standalone concept rather than an extension of NotificationRule
// (notification_provider.go, out of this ticket's write_scope, and shared by
// both the file and DB notification providers — adding a field there would
// force every implementation to handle it). A silence is orthogonal to the
// existing threshold/channel/target rule CRUD: it does not change what a
// rule alerts on, it unconditionally suppresses the renewal-reminder
// dispatch for one specific target, independent of any rule's Enabled flag
// (an earlier design considered overloading Enabled for this — rejected:
// "disabled" and "actively suppressing a target" are different meanings and
// conflating them would invert the semantics of a false Enabled value).
const (
	SilenceTargetCertificate = "certificate"
	SilenceTargetCA          = "ca"
	SilenceTargetTemplate    = "template"
)

// NotificationSilence suppresses renewal-reminder notifications for one
// specific certificate, CA, or template — an operator's explicit "stop
// alerting me about this" for a target already tracked by the renewal
// scheduler.
type NotificationSilence struct {
	ID         string `json:"id"`
	TargetType string `json:"target_type"` // certificate | ca | template
	TargetID   string `json:"target_id"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  string `json:"created_at"`
}

// NotificationSilenceStore persists per-target silences.
type NotificationSilenceStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, s NotificationSilence) error
	IsSilenced(ctx context.Context, targetType, targetID string) (bool, error)
	ListForTarget(ctx context.Context, targetType, targetID string) ([]NotificationSilence, error)
	Delete(ctx context.Context, id string) error
}

const notificationSilenceSchema = `
CREATE TABLE IF NOT EXISTS notification_silences (
    id          TEXT PRIMARY KEY,
    target_type TEXT NOT NULL
                 CHECK (target_type IN ('certificate', 'ca', 'template')),
    target_id   TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notification_silences_target ON notification_silences(target_type, target_id);`

func newNotificationSilenceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sil-" + hex.EncodeToString(b), nil
}

// --- SQLite implementation ---

type sqliteNotificationSilenceStore struct{ db *sql.DB }

func (s *sqliteNotificationSilenceStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, notificationSilenceSchema)
	return err
}

func (s *sqliteNotificationSilenceStore) Create(ctx context.Context, sil NotificationSilence) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_silences (id, target_type, target_id, created_by, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		sil.ID, sil.TargetType, sil.TargetID, sil.CreatedBy, sil.CreatedAt)
	return err
}

func (s *sqliteNotificationSilenceStore) IsSilenced(ctx context.Context, targetType, targetID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM notification_silences WHERE target_type = ? AND target_id = ?",
		targetType, targetID).Scan(&n)
	return n > 0, err
}

func (s *sqliteNotificationSilenceStore) ListForTarget(ctx context.Context, targetType, targetID string) ([]NotificationSilence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_type, target_id, created_by, created_at
		FROM notification_silences WHERE target_type = ? AND target_id = ?
		ORDER BY created_at DESC`, targetType, targetID)
	if err != nil {
		return nil, err
	}
	return scanNotificationSilenceRows(rows)
}

func (s *sqliteNotificationSilenceStore) Delete(ctx context.Context, id string) error {
	return deleteNotificationSilenceRow(ctx, s.db, "DELETE FROM notification_silences WHERE id = ?", id)
}

// --- Postgres implementation ---

type postgresNotificationSilenceStore struct{ db *sql.DB }

func (s *postgresNotificationSilenceStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, notificationSilenceSchema)
	return err
}

func (s *postgresNotificationSilenceStore) Create(ctx context.Context, sil NotificationSilence) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_silences (id, target_type, target_id, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		sil.ID, sil.TargetType, sil.TargetID, sil.CreatedBy, sil.CreatedAt)
	return err
}

func (s *postgresNotificationSilenceStore) IsSilenced(ctx context.Context, targetType, targetID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM notification_silences WHERE target_type = $1 AND target_id = $2",
		targetType, targetID).Scan(&n)
	return n > 0, err
}

func (s *postgresNotificationSilenceStore) ListForTarget(ctx context.Context, targetType, targetID string) ([]NotificationSilence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_type, target_id, created_by, created_at
		FROM notification_silences WHERE target_type = $1 AND target_id = $2
		ORDER BY created_at DESC`, targetType, targetID)
	if err != nil {
		return nil, err
	}
	return scanNotificationSilenceRows(rows)
}

func (s *postgresNotificationSilenceStore) Delete(ctx context.Context, id string) error {
	return deleteNotificationSilenceRow(ctx, s.db, "DELETE FROM notification_silences WHERE id = $1", id)
}

// --- shared helpers ---

func scanNotificationSilenceRows(rows *sql.Rows) ([]NotificationSilence, error) {
	defer rows.Close()
	items := []NotificationSilence{}
	for rows.Next() {
		var s NotificationSilence
		if err := rows.Scan(&s.ID, &s.TargetType, &s.TargetID, &s.CreatedBy, &s.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	return items, rows.Err()
}

func deleteNotificationSilenceRow(ctx context.Context, db *sql.DB, query, id string) error {
	res, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotificationSilenceNotFound
	}
	return nil
}

// newNotificationSilenceStoreFromEnv opens the same SQLite/Postgres DB as
// other providers and self-heals its schema (G-33 pattern). Not yet wired
// into any handler for Create/Delete/List — phase 1 (W1-06) wires only the
// read path (IsSilenced) into the renewal scheduler's dispatch;
// handlers_notifications.go, the only place a Create/Delete/List endpoint
// could live, is not in this ticket's write_scope. There is currently NO
// operator-facing way to create a silence in a running system — see G-60 in
// DESIGN_REVIEW.md, split into ticket W1-10 (not just a comment; W1-10 is a
// real board entry, following the W4-02→W4-05 split precedent).
func newNotificationSilenceStoreFromEnv() (NotificationSilenceStore, error) {
	state := newDBProviderState[NotificationSilenceStore](
		"notification-silence",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_NOTIFICATION_SILENCE_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_NOTIFICATION_SILENCE_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_NOTIFICATION_SILENCE_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) NotificationSilenceStore { return &sqliteNotificationSilenceStore{db: db} },
		func(db *sql.DB) NotificationSilenceStore { return &postgresNotificationSilenceStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// newNotificationSilenceStoreFromEnvLogged is the soft-fail wrapper used at
// scheduler construction time: a silence-store outage should degrade (no
// silencing enforced) rather than prevent the scheduler from starting.
func newNotificationSilenceStoreFromEnvLogged() NotificationSilenceStore {
	store, err := newNotificationSilenceStoreFromEnv()
	if err != nil {
		log.Printf("renewal scheduler: notification-silence store unavailable, silencing will not be enforced: %v", err)
		return nil
	}
	return store
}
