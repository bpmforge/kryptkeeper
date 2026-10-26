// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tsLayout is fixed-width UTC so TEXT columns compare chronologically.
const tsLayout = "2006-01-02T15:04:05Z"

func fmtTS(t time.Time) string { return t.UTC().Format(tsLayout) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(tsLayout, s)
	return t
}

// SQLStore is the durable Store over notification_delivery_queue (migration
// 000381), following the itsm.Store pattern: one *sql.DB plus a postgres flag.
type SQLStore struct {
	db       *sql.DB
	postgres bool
}

func NewSQLStore(db *sql.DB, postgres bool) *SQLStore { return &SQLStore{db: db, postgres: postgres} }

func (s *SQLStore) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *SQLStore) Put(ctx context.Context, e Entry) error {
	ev, err := json.Marshal(e.Event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO notification_delivery_queue
		(id, channel, event_json, status, attempts, next_attempt_at, last_error, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET channel = excluded.channel, event_json = excluded.event_json,
			status = excluded.status, attempts = excluded.attempts, next_attempt_at = excluded.next_attempt_at,
			last_error = excluded.last_error, updated_at = excluded.updated_at`),
		e.ID, e.Event.Channel, string(ev), e.Status, e.Attempts, fmtTS(e.NextAttemptAt), e.LastError, fmtTS(time.Now()))
	return err
}

// Update only touches a row that exists, so a settle racing a prune cannot
// resurrect a deleted entry.
func (s *SQLStore) Update(ctx context.Context, e Entry) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE notification_delivery_queue
		SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?, updated_at = ? WHERE id = ?`),
		e.Status, e.Attempts, fmtTS(e.NextAttemptAt), e.LastError, fmtTS(time.Now()), e.ID)
	return err
}

func (s *SQLStore) ClaimDue(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, event_json, attempts, last_error
		FROM notification_delivery_queue
		WHERE status = 'retrying' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?`), fmtTS(now), limit)
	if err != nil {
		return nil, err
	}
	var cand []Entry
	for rows.Next() {
		var e Entry
		var ev string
		if err := rows.Scan(&e.ID, &ev, &e.Attempts, &e.LastError); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal([]byte(ev), &e.Event); err != nil {
			rows.Close()
			return nil, fmt.Errorf("decode event %s: %w", e.ID, err)
		}
		cand = append(cand, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// Compare-and-set on the attempt count: of two replicas racing for one
	// row, only the one whose UPDATE matches proceeds.
	var claimed []Entry
	next := now.Add(lease)
	for _, e := range cand {
		res, err := s.db.ExecContext(ctx, s.q(`UPDATE notification_delivery_queue
			SET attempts = attempts + 1, next_attempt_at = ?, updated_at = ?
			WHERE id = ? AND status = 'retrying' AND attempts = ?`), fmtTS(next), fmtTS(now), e.ID, e.Attempts)
		if err != nil {
			return claimed, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			e.Attempts++
			e.NextAttemptAt, e.Status = next, StatusRetrying
			claimed = append(claimed, e)
		}
	}
	return claimed, nil
}

func (s *SQLStore) Prune(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM notification_delivery_queue
		WHERE status <> 'retrying' AND updated_at < ?`), fmtTS(before))
	return err
}

// Pending counts entries still waiting for a retry (ops visibility).
func (s *SQLStore) Pending(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_delivery_queue WHERE status = 'retrying'`).Scan(&n)
	return n, err
}
