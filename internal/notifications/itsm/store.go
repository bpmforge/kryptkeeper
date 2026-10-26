// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is returned for a missing connection or event.
var ErrNotFound = errors.New("itsm: not found")

// ErrConnectionInUse is returned when deleting a connection that still has
// ticket links: dropping them would orphan the audit trail's event ids.
var ErrConnectionInUse = errors.New("itsm: connection has ticket history")

// tsLayout is fixed-width UTC so TEXT columns sort and compare chronologically.
const tsLayout = "2006-01-02T15:04:05Z"

func fmtTS(t time.Time) string { return t.UTC().Format(tsLayout) }

func parseTS(s string) time.Time {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Store persists connections and the event/ticket-link queue. It follows the
// DeliveryPluginManager pattern: one *sql.DB, a postgres flag, and a q() that
// rewrites ? placeholders to $n.
type Store struct {
	db       *sql.DB
	postgres bool
}

// NewStore returns a Store over db. postgres selects $n placeholders.
func NewStore(db *sql.DB, postgres bool) *Store { return &Store{db: db, postgres: postgres} }

func (s *Store) q(query string) string {
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

const connCols = "id, kind, name, base_url, credential_ref, plugin_id, event_classes, enabled, tenant, created_at, updated_at"

func scanConn(sc interface{ Scan(...any) error }) (Connection, error) {
	var c Connection
	var classes, created, updated string
	var enabled int
	if err := sc.Scan(&c.ID, &c.Kind, &c.Name, &c.BaseURL, &c.CredentialRef, &c.PluginID, &classes, &enabled, &c.Tenant, &created, &updated); err != nil {
		return Connection{}, err
	}
	c.Enabled = enabled != 0
	c.CreatedAt, c.UpdatedAt = parseTS(created), parseTS(updated)
	c.EventClasses = parseEventClasses(classes)
	return c, nil
}

// parseEventClasses reads the event_classes TEXT column. Rows written before
// W32-25 hold a plain string array; those read back as classes with no ticket
// type (the connector default).
func parseEventClasses(raw string) []EventClass {
	var out []EventClass
	if err := json.Unmarshal([]byte(raw), &out); err == nil && out != nil {
		return out
	}
	var legacy []string
	if err := json.Unmarshal([]byte(raw), &legacy); err == nil {
		out = make([]EventClass, 0, len(legacy))
		for _, c := range legacy {
			out = append(out, EventClass{Class: c})
		}
		return out
	}
	return []EventClass{}
}

// CreateConnection inserts c; CreatedAt/UpdatedAt are stamped from now.
func (s *Store) CreateConnection(ctx context.Context, c Connection, now time.Time) (Connection, error) {
	if c.EventClasses == nil {
		c.EventClasses = []EventClass{}
	}
	classes, err := json.Marshal(c.EventClasses)
	if err != nil {
		return Connection{}, err
	}
	if c.Tenant == "" {
		c.Tenant = "default"
	}
	c.CreatedAt, c.UpdatedAt = now.UTC(), now.UTC()
	enabled := 0
	if c.Enabled {
		enabled = 1
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO itsm_connections (`+connCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`),
		c.ID, c.Kind, c.Name, c.BaseURL, c.CredentialRef, c.PluginID, string(classes), enabled, c.Tenant, fmtTS(now), fmtTS(now))
	if err != nil {
		return Connection{}, err
	}
	return c, nil
}

func (s *Store) GetConnection(ctx context.Context, id string) (Connection, error) {
	c, err := scanConn(s.db.QueryRowContext(ctx, s.q(`SELECT `+connCols+` FROM itsm_connections WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, ErrNotFound
	}
	return c, err
}

func (s *Store) ListConnections(ctx context.Context) ([]Connection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+connCols+` FROM itsm_connections ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Connection{}
	for rows.Next() {
		c, err := scanConn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteConnection removes a connection with no ticket history.
func (s *Store) DeleteConnection(ctx context.Context, id string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM itsm_events WHERE connection_id = ?`), id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConnectionInUse
	}
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM itsm_connections WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrNotFound
	}
	return nil
}

const eventCols = "event_id, connection_id, class, fingerprint, payload, status, ticket_key, ticket_url, attempts, next_attempt_at, last_error, recreated, tenant, created_at, updated_at"

func scanEvent(sc interface{ Scan(...any) error }) (EventRow, error) {
	var e EventRow
	var next, created, updated string
	var recreated int
	if err := sc.Scan(&e.EventID, &e.ConnectionID, &e.Class, &e.Fingerprint, &e.Payload, &e.Status, &e.TicketKey, &e.TicketURL,
		&e.Attempts, &next, &e.LastError, &recreated, &e.Tenant, &created, &updated); err != nil {
		return EventRow{}, err
	}
	e.Recreated = recreated != 0
	e.NextAttemptAt, e.CreatedAt, e.UpdatedAt = parseTS(next), parseTS(created), parseTS(updated)
	return e, nil
}

// InsertEvent enqueues a pending row due immediately. A repeat of the same
// event id is a no-op and reports inserted=false.
func (s *Store) InsertEvent(ctx context.Context, e EventRow, now time.Time) (inserted bool, err error) {
	if e.Tenant == "" {
		e.Tenant = "default"
	}
	res, err := s.db.ExecContext(ctx, s.q(`INSERT INTO itsm_events (`+eventCols+`) VALUES (?,?,?,?,?,'pending','','',0,?,'',0,?,?,?)
		ON CONFLICT(event_id) DO NOTHING`),
		e.EventID, e.ConnectionID, e.Class, e.Fingerprint, e.Payload, fmtTS(now), e.Tenant, fmtTS(now), fmtTS(now))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) GetEvent(ctx context.Context, eventID string) (EventRow, error) {
	e, err := scanEvent(s.db.QueryRowContext(ctx, s.q(`SELECT `+eventCols+` FROM itsm_events WHERE event_id = ?`), eventID))
	if errors.Is(err, sql.ErrNoRows) {
		return EventRow{}, ErrNotFound
	}
	return e, err
}

// SaveEvent writes the mutable queue and ticket-link fields of e.
func (s *Store) SaveEvent(ctx context.Context, e EventRow, now time.Time) error {
	recreated := 0
	if e.Recreated {
		recreated = 1
	}
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE itsm_events SET status = ?, ticket_key = ?, ticket_url = ?, attempts = ?,
		next_attempt_at = ?, last_error = ?, recreated = ?, updated_at = ? WHERE event_id = ?`),
		e.Status, e.TicketKey, e.TicketURL, e.Attempts, fmtTS(e.NextAttemptAt), e.LastError, recreated, fmtTS(now), e.EventID)
	return err
}

// DueEvents returns pending rows whose next attempt is due, oldest first.
func (s *Store) DueEvents(ctx context.Context, now time.Time, limit int) ([]EventRow, error) {
	return s.queryEvents(ctx, `SELECT `+eventCols+` FROM itsm_events WHERE status = 'pending' AND next_attempt_at <= ?
		ORDER BY next_attempt_at, event_id LIMIT ?`, fmtTS(now), limit)
}

// ListEvents returns recent rows, newest first, optionally filtered by status.
func (s *Store) ListEvents(ctx context.Context, status string, limit int) ([]EventRow, error) {
	if status == "" {
		return s.queryEvents(ctx, `SELECT `+eventCols+` FROM itsm_events ORDER BY created_at DESC, event_id LIMIT ?`, limit)
	}
	return s.queryEvents(ctx, `SELECT `+eventCols+` FROM itsm_events WHERE status = ? ORDER BY created_at DESC, event_id LIMIT ?`, status, limit)
}

// CreatedByFingerprint returns the `created` rows carrying fingerprint.
func (s *Store) CreatedByFingerprint(ctx context.Context, fingerprint string) ([]EventRow, error) {
	return s.queryEvents(ctx, `SELECT `+eventCols+` FROM itsm_events WHERE fingerprint = ? AND status = 'created' ORDER BY created_at, event_id`, fingerprint)
}

func (s *Store) queryEvents(ctx context.Context, query string, args ...any) ([]EventRow, error) {
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []EventRow{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
