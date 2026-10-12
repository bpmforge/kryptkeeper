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

type dbDashboardActionStore interface {
	ListHistory(context.Context, DashboardActionHistoryQuery) (DashboardActionHistoryResult, error)
	AckAction(ctx context.Context, actionID string, note string) (DashboardActionAckResult, error)
	ResolveAction(ctx context.Context, actionID string, note string) (DashboardActionResolveResult, error)
}

type dbDashboardActionProvider struct {
	store   dbDashboardActionStore
	openErr error
}

func newDBDashboardActionProviderFromEnv() DashboardActionProvider {
	state := newDBProviderState[dbDashboardActionStore](
		"dashboard action",
		dashboardActionDBSQLiteDSNFromEnv,
		dashboardActionDBPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_DASHBOARD_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) dbDashboardActionStore { return &sqliteDashboardActionStore{db: db} },
		func(db *sql.DB) dbDashboardActionStore { return &postgresDashboardActionStore{db: db} },
	)
	return &dbDashboardActionProvider{store: state.store, openErr: state.openErr}
}

func newDBDashboardActionStoreFromEnv() (dbDashboardActionStore, error) {
	state := newDBProviderState[dbDashboardActionStore](
		"dashboard action",
		dashboardActionDBSQLiteDSNFromEnv,
		dashboardActionDBPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_DASHBOARD_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) dbDashboardActionStore { return &sqliteDashboardActionStore{db: db} },
		func(db *sql.DB) dbDashboardActionStore { return &postgresDashboardActionStore{db: db} },
	)
	return state.store, state.openErr
}

func dashboardActionDBSQLiteDSNFromEnv() (string, error) {
	return resolveSQLiteDSNFromEnv("APP_DASHBOARD_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
}

func dashboardActionDBPostgresDSNFromEnv() string {
	return resolvePostgresDSNFromEnv("APP_DASHBOARD_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
}

func (p *dbDashboardActionProvider) ListHistory(ctx context.Context, q DashboardActionHistoryQuery) (DashboardActionHistoryResult, error) {
	if err := dbProviderUnavailable("dashboard action", p.openErr); err != nil {
		return DashboardActionHistoryResult{}, err
	}
	return p.store.ListHistory(ctx, q)
}

func (p *dbDashboardActionProvider) AckAction(ctx context.Context, actionID string, note string) (DashboardActionAckResult, error) {
	if err := dbProviderUnavailable("dashboard action", p.openErr); err != nil {
		return DashboardActionAckResult{}, err
	}
	return p.store.AckAction(ctx, actionID, note)
}

func (p *dbDashboardActionProvider) ResolveAction(ctx context.Context, actionID string, note string) (DashboardActionResolveResult, error) {
	if err := dbProviderUnavailable("dashboard action", p.openErr); err != nil {
		return DashboardActionResolveResult{}, err
	}
	return p.store.ResolveAction(ctx, actionID, note)
}

// --- SQLite store (reads/writes audit_log for dashboard action history) ---

type sqliteDashboardActionStore struct{ db *sql.DB }

func (s *sqliteDashboardActionStore) ListHistory(ctx context.Context, q DashboardActionHistoryQuery) (DashboardActionHistoryResult, error) {
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

	where := []string{"action LIKE 'dashboard.action.%'"}
	args := make([]any, 0)
	if q.Status != "" {
		where = append(where, "outcome = ?")
		args = append(args, q.Status)
	}
	if q.Category != "" {
		where = append(where, "resource_type = ?")
		args = append(args, q.Category)
	}
	whereSQL := " WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log"+whereSQL, args...).Scan(&total); err != nil {
		return DashboardActionHistoryResult{}, err
	}

	if cursor > total {
		cursor = total
	}

	listArgs := append(append([]any{}, args...), limit, cursor)
	rows, err := s.db.QueryContext(ctx, `
SELECT resource_id, resource_type, outcome, actor_id, timestamp, COALESCE(trace_id, '')
FROM audit_log`+whereSQL+`
ORDER BY timestamp DESC
LIMIT ? OFFSET ?
`, listArgs...)
	if err != nil {
		return DashboardActionHistoryResult{}, err
	}
	defer rows.Close()

	history := make([]DashboardActionHistoryRecord, 0)
	for rows.Next() {
		var rec DashboardActionHistoryRecord
		if err := rows.Scan(&rec.ActionID, &rec.Category, &rec.Status, &rec.UpdatedBy, &rec.UpdatedAt, &rec.Note); err != nil {
			return DashboardActionHistoryResult{}, err
		}
		history = append(history, rec)
	}
	if err := rows.Err(); err != nil {
		return DashboardActionHistoryResult{}, err
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

	return DashboardActionHistoryResult{
		History:    history,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursor,
		PrevCursor: prevCursor,
	}, nil
}

func (s *sqliteDashboardActionStore) AckAction(ctx context.Context, actionID string, note string) (DashboardActionAckResult, error) {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log (timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome)
VALUES (?, 'dashboard.action.ack', 'system', 'dashboard', 'dashboard', ?, ?, 'success')
`, now.Format(time.RFC3339), actionID, nullableString(note))
	if err != nil {
		return DashboardActionAckResult{}, err
	}
	return DashboardActionAckResult{
		ActionID:   actionID,
		Status:     "acknowledged",
		Note:       note,
		AckedAtUTC: now.Format(time.RFC3339),
	}, nil
}

func (s *sqliteDashboardActionStore) ResolveAction(ctx context.Context, actionID string, note string) (DashboardActionResolveResult, error) {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log (timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome)
VALUES (?, 'dashboard.action.resolve', 'system', 'dashboard', 'dashboard', ?, ?, 'success')
`, now.Format(time.RFC3339), actionID, nullableString(note))
	if err != nil {
		return DashboardActionResolveResult{}, err
	}
	return DashboardActionResolveResult{
		ActionID:   actionID,
		Status:     "resolved",
		Note:       note,
		ResolvedAt: now.Format(time.RFC3339),
	}, nil
}

// --- Postgres store ---

type postgresDashboardActionStore struct{ db *sql.DB }

func (s *postgresDashboardActionStore) ListHistory(ctx context.Context, q DashboardActionHistoryQuery) (DashboardActionHistoryResult, error) {
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

	where := []string{"action LIKE 'dashboard.action.%'"}
	args := make([]any, 0)
	nextArg := 1
	if q.Status != "" {
		where = append(where, fmt.Sprintf("outcome = $%d", nextArg))
		args = append(args, q.Status)
		nextArg++
	}
	if q.Category != "" {
		where = append(where, fmt.Sprintf("resource_type = $%d", nextArg))
		args = append(args, q.Category)
		nextArg++
	}
	whereSQL := " WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log"+whereSQL, args...).Scan(&total); err != nil {
		return DashboardActionHistoryResult{}, err
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
SELECT resource_id, resource_type, outcome, actor_id, timestamp, COALESCE(trace_id, '')
FROM audit_log`+whereSQL+`
ORDER BY timestamp DESC
LIMIT `+limitP+` OFFSET `+offsetP+`
`, args...)
	if err != nil {
		return DashboardActionHistoryResult{}, err
	}
	defer rows.Close()

	history := make([]DashboardActionHistoryRecord, 0)
	for rows.Next() {
		var rec DashboardActionHistoryRecord
		var ts time.Time
		if err := rows.Scan(&rec.ActionID, &rec.Category, &rec.Status, &rec.UpdatedBy, &ts, &rec.Note); err != nil {
			return DashboardActionHistoryResult{}, err
		}
		rec.UpdatedAt = ts.UTC().Format(time.RFC3339)
		history = append(history, rec)
	}
	if err := rows.Err(); err != nil {
		return DashboardActionHistoryResult{}, err
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	var nextCursorP *int
	if end < total {
		n := end
		nextCursorP = &n
	}
	var prevCursorP *int
	if cursor > 0 {
		p := cursor - limit
		if p < 0 {
			p = 0
		}
		prevCursorP = &p
	}

	return DashboardActionHistoryResult{
		History:    history,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursorP,
		PrevCursor: prevCursorP,
	}, nil
}

func (s *postgresDashboardActionStore) AckAction(ctx context.Context, actionID string, note string) (DashboardActionAckResult, error) {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log (timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome)
VALUES ($1, 'dashboard.action.ack', 'system', 'dashboard', 'dashboard', $2, $3, 'success')
`, now, actionID, nullableString(note))
	if err != nil {
		return DashboardActionAckResult{}, err
	}
	return DashboardActionAckResult{
		ActionID:   actionID,
		Status:     "acknowledged",
		Note:       note,
		AckedAtUTC: now.Format(time.RFC3339),
	}, nil
}

func (s *postgresDashboardActionStore) ResolveAction(ctx context.Context, actionID string, note string) (DashboardActionResolveResult, error) {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log (timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome)
VALUES ($1, 'dashboard.action.resolve', 'system', 'dashboard', 'dashboard', $2, $3, 'success')
`, now, actionID, nullableString(note))
	if err != nil {
		return DashboardActionResolveResult{}, err
	}
	return DashboardActionResolveResult{
		ActionID:   actionID,
		Status:     "resolved",
		Note:       note,
		ResolvedAt: now.Format(time.RFC3339),
	}, nil
}
