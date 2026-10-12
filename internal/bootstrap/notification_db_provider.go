// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type dbNotificationStore interface {
	GetSummary(context.Context) (NotificationSummary, error)
	ListDeliveries(context.Context, NotificationDeliveryQuery) (NotificationDeliveryResult, error)
	AckDelivery(ctx context.Context, deliveryID string, note string) (NotificationDeliveryActionResult, error)
	RetryDelivery(ctx context.Context, deliveryID string, reason string) (NotificationDeliveryActionResult, error)
	TestDelivery(ctx context.Context, channel string, target string, message string) (NotificationTestDeliveryResult, error)
	ListRules(ctx context.Context) ([]NotificationRule, error)
	CreateRule(ctx context.Context, name string, thresholdDays int, channel string, target string) (NotificationRule, error)
	UpdateRule(ctx context.Context, id string, enabled bool, target string) (NotificationRule, error)
	DeleteRule(ctx context.Context, id string) error
}

type dbNotificationProvider struct {
	store   dbNotificationStore
	openErr error
}

func newDBNotificationProviderFromEnv() NotificationProvider {
	state := newDBProviderState[dbNotificationStore](
		"notification",
		notificationDBSQLiteDSNFromEnv,
		notificationDBPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_NOTIFICATION_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) dbNotificationStore { return &sqliteNotificationStore{db: db} },
		func(db *sql.DB) dbNotificationStore { return &postgresNotificationStore{db: db} },
	)
	return &dbNotificationProvider{store: state.store, openErr: state.openErr}
}

func newDBNotificationStoreFromEnv() (dbNotificationStore, error) {
	state := newDBProviderState[dbNotificationStore](
		"notification",
		notificationDBSQLiteDSNFromEnv,
		notificationDBPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_NOTIFICATION_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) dbNotificationStore { return &sqliteNotificationStore{db: db} },
		func(db *sql.DB) dbNotificationStore { return &postgresNotificationStore{db: db} },
	)
	return state.store, state.openErr
}

func notificationDBSQLiteDSNFromEnv() (string, error) {
	return resolveSQLiteDSNFromEnv("APP_NOTIFICATION_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
}

func notificationDBPostgresDSNFromEnv() string {
	return resolvePostgresDSNFromEnv("APP_NOTIFICATION_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
}

func (p *dbNotificationProvider) GetSummary(ctx context.Context) (NotificationSummary, error) {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return NotificationSummary{}, err
	}
	return p.store.GetSummary(ctx)
}

func (p *dbNotificationProvider) ListDeliveries(ctx context.Context, q NotificationDeliveryQuery) (NotificationDeliveryResult, error) {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return NotificationDeliveryResult{}, err
	}
	return p.store.ListDeliveries(ctx, q)
}

func (p *dbNotificationProvider) AckDelivery(ctx context.Context, deliveryID string, note string) (NotificationDeliveryActionResult, error) {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return NotificationDeliveryActionResult{}, err
	}
	return p.store.AckDelivery(ctx, deliveryID, note)
}

func (p *dbNotificationProvider) RetryDelivery(ctx context.Context, deliveryID string, reason string) (NotificationDeliveryActionResult, error) {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return NotificationDeliveryActionResult{}, err
	}
	return p.store.RetryDelivery(ctx, deliveryID, reason)
}

func (p *dbNotificationProvider) TestDelivery(ctx context.Context, channel string, target string, message string) (NotificationTestDeliveryResult, error) {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return NotificationTestDeliveryResult{}, err
	}
	res, err := p.store.TestDelivery(ctx, channel, target, message)
	if err != nil {
		return res, err
	}
	// The store inserts a queued row that no worker consumes.
	res.Dispatched = false
	res.Note = notDispatchedNote(notificationProviderDB)
	return res, nil
}

// Delivers is false: db rows are recorded as queued and nothing dequeues them.
func (p *dbNotificationProvider) Delivers() bool { return false }

func (p *dbNotificationProvider) Name() string { return notificationProviderDB }

func (p *dbNotificationProvider) ListRules(ctx context.Context) ([]NotificationRule, error) {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return nil, err
	}
	return p.store.ListRules(ctx)
}

func (p *dbNotificationProvider) CreateRule(ctx context.Context, name string, thresholdDays int, channel string, target string) (NotificationRule, error) {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return NotificationRule{}, err
	}
	return p.store.CreateRule(ctx, name, thresholdDays, channel, target)
}

func (p *dbNotificationProvider) UpdateRule(ctx context.Context, id string, enabled bool, target string) (NotificationRule, error) {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return NotificationRule{}, err
	}
	return p.store.UpdateRule(ctx, id, enabled, target)
}

func (p *dbNotificationProvider) DeleteRule(ctx context.Context, id string) error {
	if err := dbProviderUnavailable("notification", p.openErr); err != nil {
		return err
	}
	return p.store.DeleteRule(ctx, id)
}

// --- SQLite store ---

type sqliteNotificationStore struct{ db *sql.DB }

func (s *sqliteNotificationStore) GetSummary(ctx context.Context) (NotificationSummary, error) {
	var summary NotificationSummary
	err := s.db.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM notification_deliveries WHERE status IN ('queued', 'sending')) AS pending,
    (SELECT COUNT(*) FROM notification_deliveries WHERE status = 'failed' AND queued_at > datetime('now', '-24 hours')) AS failures_24h
`).Scan(&summary.PendingNotifications, &summary.DeliveryFailures24h)
	if err != nil {
		return NotificationSummary{}, err
	}
	// Escalations = acknowledged deliveries that were previously failed
	err = s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM notification_deliveries WHERE status = 'acknowledged' AND retry_of_id IS NOT NULL
`).Scan(&summary.OwnershipEscalations)
	return summary, err
}

func (s *sqliteNotificationStore) ListDeliveries(ctx context.Context, q NotificationDeliveryQuery) (NotificationDeliveryResult, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	cursor := q.Cursor
	if cursor < 0 {
		cursor = 0
	}

	where := make([]string, 0)
	args := make([]any, 0)
	if q.Status != "" {
		where = append(where, "status = ?")
		args = append(args, q.Status)
	}
	if q.Channel != "" {
		where = append(where, "channel = ?")
		args = append(args, q.Channel)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_deliveries"+whereSQL, args...).Scan(&total); err != nil {
		return NotificationDeliveryResult{}, err
	}

	if cursor > total {
		cursor = total
	}

	listArgs := append(append([]any{}, args...), limit, cursor)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, channel, target, status, queued_at
FROM notification_deliveries`+whereSQL+`
ORDER BY queued_at DESC
LIMIT ? OFFSET ?
`, listArgs...)
	if err != nil {
		return NotificationDeliveryResult{}, err
	}
	defer rows.Close()

	deliveries := make([]NotificationDelivery, 0)
	for rows.Next() {
		var d NotificationDelivery
		if err := rows.Scan(&d.ID, &d.Channel, &d.Target, &d.Status, &d.QueuedAt); err != nil {
			return NotificationDeliveryResult{}, err
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return NotificationDeliveryResult{}, err
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	var nextCursor *int
	if end < total {
		n := end
		nextCursor = &n
	}
	var prevCursor *int
	if cursor > 0 {
		p := cursor - limit
		if p < 0 {
			p = 0
		}
		prevCursor = &p
	}

	return NotificationDeliveryResult{
		Deliveries: deliveries,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursor,
		PrevCursor: prevCursor,
	}, nil
}

func (s *sqliteNotificationStore) AckDelivery(ctx context.Context, deliveryID string, note string) (NotificationDeliveryActionResult, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.ExecContext(ctx, `
UPDATE notification_deliveries SET status = 'acknowledged', acknowledged_at = ?, acknowledged_note = ?
WHERE id = ?
`, now, note, deliveryID)
	if err != nil {
		return NotificationDeliveryActionResult{}, err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return NotificationDeliveryActionResult{}, fmt.Errorf("delivery %s not found", deliveryID)
	}
	return NotificationDeliveryActionResult{
		DeliveryID: deliveryID,
		Status:     "acknowledged",
		Note:       note,
		UpdatedAt:  now,
	}, nil
}

func (s *sqliteNotificationStore) RetryDelivery(ctx context.Context, deliveryID string, reason string) (NotificationDeliveryActionResult, error) {
	now := time.Now().UTC()
	retryID := fmt.Sprintf("retry-%d", now.UnixNano())

	var channel, target string
	err := s.db.QueryRowContext(ctx, "SELECT channel, target FROM notification_deliveries WHERE id = ?", deliveryID).Scan(&channel, &target)
	if err != nil {
		return NotificationDeliveryActionResult{}, fmt.Errorf("original delivery not found: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO notification_deliveries (id, channel, target, status, retry_of_id, triggered_by, message)
VALUES (?, ?, ?, 'retrying', ?, 'retry', ?)
`, retryID, channel, target, deliveryID, reason)
	if err != nil {
		return NotificationDeliveryActionResult{}, err
	}

	return NotificationDeliveryActionResult{
		DeliveryID: deliveryID,
		RetryJobID: retryID,
		Status:     "queued",
		Reason:     reason,
		QueuedAt:   now.Format(time.RFC3339),
	}, nil
}

func (s *sqliteNotificationStore) TestDelivery(ctx context.Context, channel string, target string, message string) (NotificationTestDeliveryResult, error) {
	now := time.Now().UTC()
	id := fmt.Sprintf("notif-%d", now.UnixNano())

	_, err := s.db.ExecContext(ctx, `
INSERT INTO notification_deliveries (id, channel, target, message, status, triggered_by)
VALUES (?, ?, ?, ?, 'queued', 'test')
`, id, channel, target, message)
	if err != nil {
		return NotificationTestDeliveryResult{}, err
	}

	return NotificationTestDeliveryResult{
		ID:       id,
		Channel:  channel,
		Target:   target,
		Status:   "queued",
		QueuedAt: now.Format(time.RFC3339),
	}, nil
}

// --- Postgres store ---

type postgresNotificationStore struct{ db *sql.DB }

func (s *postgresNotificationStore) GetSummary(ctx context.Context) (NotificationSummary, error) {
	var summary NotificationSummary
	err := s.db.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM notification_deliveries WHERE status IN ('queued', 'sending')) AS pending,
    (SELECT COUNT(*) FROM notification_deliveries WHERE status = 'failed' AND queued_at > CURRENT_TIMESTAMP - INTERVAL '24 hours') AS failures_24h
`).Scan(&summary.PendingNotifications, &summary.DeliveryFailures24h)
	if err != nil {
		return NotificationSummary{}, err
	}
	err = s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM notification_deliveries WHERE status = 'acknowledged' AND retry_of_id IS NOT NULL
`).Scan(&summary.OwnershipEscalations)
	return summary, err
}

func (s *postgresNotificationStore) ListDeliveries(ctx context.Context, q NotificationDeliveryQuery) (NotificationDeliveryResult, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	cursor := q.Cursor
	if cursor < 0 {
		cursor = 0
	}

	where := make([]string, 0)
	args := make([]any, 0)
	nextArg := 1
	if q.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", nextArg))
		args = append(args, q.Status)
		nextArg++
	}
	if q.Channel != "" {
		where = append(where, fmt.Sprintf("channel = $%d", nextArg))
		args = append(args, q.Channel)
		nextArg++
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_deliveries"+whereSQL, args...).Scan(&total); err != nil {
		return NotificationDeliveryResult{}, err
	}

	if cursor > total {
		cursor = total
	}

	limitP := fmt.Sprintf("$%d", nextArg)
	args = append(args, limit)
	nextArg++
	offsetP := fmt.Sprintf("$%d", nextArg)
	args = append(args, cursor)

	rows, err := s.db.QueryContext(ctx, `
SELECT id, channel, target, status, queued_at
FROM notification_deliveries`+whereSQL+`
ORDER BY queued_at DESC
LIMIT `+limitP+` OFFSET `+offsetP+`
`, args...)
	if err != nil {
		return NotificationDeliveryResult{}, err
	}
	defer rows.Close()

	deliveries := make([]NotificationDelivery, 0)
	for rows.Next() {
		var d NotificationDelivery
		var queuedAt time.Time
		if err := rows.Scan(&d.ID, &d.Channel, &d.Target, &d.Status, &queuedAt); err != nil {
			return NotificationDeliveryResult{}, err
		}
		d.QueuedAt = queuedAt.UTC().Format(time.RFC3339)
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return NotificationDeliveryResult{}, err
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	var nextCursor *int
	if end < total {
		n := end
		nextCursor = &n
	}
	var prevCursor *int
	if cursor > 0 {
		p := cursor - limit
		if p < 0 {
			p = 0
		}
		prevCursor = &p
	}

	return NotificationDeliveryResult{
		Deliveries: deliveries,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursor,
		PrevCursor: prevCursor,
	}, nil
}

func (s *postgresNotificationStore) AckDelivery(ctx context.Context, deliveryID string, note string) (NotificationDeliveryActionResult, error) {
	now := time.Now().UTC()
	if !uuidRe.MatchString(deliveryID) {
		return NotificationDeliveryActionResult{}, fmt.Errorf("delivery %s not found", deliveryID)
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE notification_deliveries SET status = 'acknowledged', acknowledged_at = $1, acknowledged_note = $2
WHERE id = $3
`, now, note, deliveryID)
	if err != nil {
		return NotificationDeliveryActionResult{}, err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return NotificationDeliveryActionResult{}, fmt.Errorf("delivery %s not found", deliveryID)
	}
	return NotificationDeliveryActionResult{
		DeliveryID: deliveryID,
		Status:     "acknowledged",
		Note:       note,
		UpdatedAt:  now.Format(time.RFC3339),
	}, nil
}

func (s *postgresNotificationStore) RetryDelivery(ctx context.Context, deliveryID string, reason string) (NotificationDeliveryActionResult, error) {
	now := time.Now().UTC()
	if !uuidRe.MatchString(deliveryID) {
		return NotificationDeliveryActionResult{}, fmt.Errorf("original delivery not found: %q", deliveryID)
	}

	var channel, target string
	err := s.db.QueryRowContext(ctx, "SELECT channel, target FROM notification_deliveries WHERE id = $1", deliveryID).Scan(&channel, &target)
	if err != nil {
		return NotificationDeliveryActionResult{}, fmt.Errorf("original delivery not found: %w", err)
	}

	// notification_deliveries.id is a UUID with a database default; the
	// "retry-<nanos>" id the SQLite store mints is not a valid UUID.
	var retryID string
	err = s.db.QueryRowContext(ctx, `
INSERT INTO notification_deliveries (channel, target, status, retry_of_id, triggered_by, message)
VALUES ($1, $2, 'retrying', $3, 'retry', $4) RETURNING id
`, channel, target, deliveryID, reason).Scan(&retryID)
	if err != nil {
		return NotificationDeliveryActionResult{}, err
	}

	return NotificationDeliveryActionResult{
		DeliveryID: deliveryID,
		RetryJobID: retryID,
		Status:     "queued",
		Reason:     reason,
		QueuedAt:   now.Format(time.RFC3339),
	}, nil
}

func (s *postgresNotificationStore) TestDelivery(ctx context.Context, channel string, target string, message string) (NotificationTestDeliveryResult, error) {
	now := time.Now().UTC()

	var id string
	err := s.db.QueryRowContext(ctx, `
INSERT INTO notification_deliveries (channel, target, message, status, triggered_by)
VALUES ($1, $2, $3, 'queued', 'test') RETURNING id
`, channel, target, message).Scan(&id)
	if err != nil {
		return NotificationTestDeliveryResult{}, err
	}

	return NotificationTestDeliveryResult{
		ID:       id,
		Channel:  channel,
		Target:   target,
		Status:   "queued",
		QueuedAt: now.Format(time.RFC3339),
	}, nil
}

// --- Notification rules: SQLite ---

func (s *sqliteNotificationStore) ListRules(ctx context.Context) ([]NotificationRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, threshold_days, channel, target, enabled, created_at FROM notification_rules ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNotificationRulesSQLite(rows)
}

func (s *sqliteNotificationStore) CreateRule(ctx context.Context, name string, thresholdDays int, channel string, target string) (NotificationRule, error) {
	id := fmt.Sprintf("rule-%d", time.Now().UnixNano())
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO notification_rules (id, name, threshold_days, channel, target, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`,
		id, name, thresholdDays, channel, target, now, now)
	if err != nil {
		return NotificationRule{}, err
	}
	return NotificationRule{ID: id, Name: name, ThresholdDays: thresholdDays, Channel: channel, Target: target, Enabled: true, CreatedAt: now}, nil
}

func (s *sqliteNotificationStore) UpdateRule(ctx context.Context, id string, enabled bool, target string) (NotificationRule, error) {
	act := 0
	if enabled {
		act = 1
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx,
		`UPDATE notification_rules SET enabled = ?, target = ?, updated_at = ? WHERE id = ?`, act, target, now, id)
	if err != nil {
		return NotificationRule{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return NotificationRule{}, fmt.Errorf("rule %q not found", id)
	}
	var r NotificationRule
	var en int
	err = s.db.QueryRowContext(ctx,
		`SELECT id, name, threshold_days, channel, target, enabled, created_at FROM notification_rules WHERE id = ?`, id,
	).Scan(&r.ID, &r.Name, &r.ThresholdDays, &r.Channel, &r.Target, &en, &r.CreatedAt)
	r.Enabled = en == 1
	return r, err
}

func (s *sqliteNotificationStore) DeleteRule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notification_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("rule %q not found", id)
	}
	return nil
}

// --- Notification rules: Postgres ---

func (s *postgresNotificationStore) ListRules(ctx context.Context) ([]NotificationRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, threshold_days, channel, target, enabled, created_at FROM notification_rules ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNotificationRulesPostgres(rows)
}

func (s *postgresNotificationStore) CreateRule(ctx context.Context, name string, thresholdDays int, channel string, target string) (NotificationRule, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	var id string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO notification_rules (name, threshold_days, channel, target) VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		name, thresholdDays, channel, target,
	).Scan(&id, &now)
	if err != nil {
		return NotificationRule{}, err
	}
	return NotificationRule{ID: id, Name: name, ThresholdDays: thresholdDays, Channel: channel, Target: target, Enabled: true, CreatedAt: now}, nil
}

func (s *postgresNotificationStore) UpdateRule(ctx context.Context, id string, enabled bool, target string) (NotificationRule, error) {
	var r NotificationRule
	err := s.db.QueryRowContext(ctx,
		`UPDATE notification_rules SET enabled = $1, target = $2, updated_at = NOW() WHERE id = $3
		 RETURNING id, name, threshold_days, channel, target, enabled, created_at`,
		enabled, target, id,
	).Scan(&r.ID, &r.Name, &r.ThresholdDays, &r.Channel, &r.Target, &r.Enabled, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return NotificationRule{}, fmt.Errorf("rule %q not found", id)
	}
	return r, err
}

func (s *postgresNotificationStore) DeleteRule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notification_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("rule %q not found", id)
	}
	return nil
}

func scanNotificationRulesSQLite(rows *sql.Rows) ([]NotificationRule, error) {
	var out []NotificationRule
	for rows.Next() {
		var r NotificationRule
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.ThresholdDays, &r.Channel, &r.Target, &en, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanNotificationRulesPostgres(rows *sql.Rows) ([]NotificationRule, error) {
	var out []NotificationRule
	for rows.Next() {
		var r NotificationRule
		if err := rows.Scan(&r.ID, &r.Name, &r.ThresholdDays, &r.Channel, &r.Target, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
