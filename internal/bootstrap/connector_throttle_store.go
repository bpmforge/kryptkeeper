// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/logging"
)

// W35-01 / W27-39: the database side of connectors.RetryGateStore and
// connectors.IssueLogStore (migrations 000360, 000361). internal/connectors
// stays free of database code.

// storeTimeFormat is fixed width so that, on SQLite where timestamps are
// text, SQL string comparison orders them correctly.
const storeTimeFormat = "2006-01-02T15:04:05.000000000Z"

type dbConnectorThrottleStore struct {
	db *sql.DB
	pg bool
	ph func(int) string
}

func newDBConnectorThrottleStore(db *sql.DB, postgres bool) *dbConnectorThrottleStore {
	s := &dbConnectorThrottleStore{db: db, pg: postgres, ph: sqlitePlaceholder}
	if postgres {
		s.ph = postgresPlaceholder
	}
	return s
}

// ts converts a time to the engine's column representation.
func (s *dbConnectorThrottleStore) ts(t time.Time) any {
	if s.pg {
		return t.UTC()
	}
	return t.UTC().Format(storeTimeFormat)
}

func (s *dbConnectorThrottleStore) scanTime(row interface{ Scan(...any) error }) (time.Time, error) {
	if s.pg {
		var t time.Time
		err := row.Scan(&t)
		return t, err
	}
	var raw string
	if err := row.Scan(&raw); err != nil {
		return time.Time{}, err
	}
	return time.Parse(storeTimeFormat, raw)
}

// Load implements connectors.RetryGateStore.
func (s *dbConnectorThrottleStore) Load(ctx context.Context, id string) (time.Time, error) {
	t, err := s.scanTime(s.db.QueryRowContext(ctx, `SELECT retry_at FROM connector_retry_gate WHERE connector_id = `+s.ph(1), id))
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return t, err
}

// Save implements connectors.RetryGateStore. The upsert keeps the later
// deadline in SQL, so two replicas saving at once can never shorten a hold.
func (s *dbConnectorThrottleStore) Save(ctx context.Context, id string, until time.Time, reason string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO connector_retry_gate (connector_id, retry_at, reason, updated_at)
		VALUES (`+s.ph(1)+`,`+s.ph(2)+`,`+s.ph(3)+`,`+s.ph(4)+`)
		ON CONFLICT (connector_id) DO UPDATE SET
		  reason = CASE WHEN excluded.retry_at > connector_retry_gate.retry_at THEN excluded.reason ELSE connector_retry_gate.reason END,
		  retry_at = CASE WHEN excluded.retry_at > connector_retry_gate.retry_at THEN excluded.retry_at ELSE connector_retry_gate.retry_at END,
		  updated_at = excluded.updated_at`,
		id, s.ts(until), reason, s.ts(time.Now()))
	return err
}

// Append implements connectors.IssueLogStore.
func (s *dbConnectorThrottleStore) Append(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO connector_issue_log (connector_id, issued_at) VALUES (`+s.ph(1)+`,`+s.ph(2)+`)`, id, s.ts(at))
	return err
}

// Since implements connectors.IssueLogStore.
func (s *dbConnectorThrottleStore) Since(ctx context.Context, id string, since time.Time) ([]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT issued_at FROM connector_issue_log WHERE connector_id = `+s.ph(1)+` AND issued_at > `+s.ph(2)+` ORDER BY issued_at`, id, s.ts(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		t, err := s.scanTime(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Prune implements connectors.IssueLogStore.
func (s *dbConnectorThrottleStore) Prune(ctx context.Context, id string, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM connector_issue_log WHERE connector_id = `+s.ph(1)+` AND issued_at <= `+s.ph(2), id, s.ts(before))
	return err
}

// AttachConnectorThrottleStores makes the process-wide throttle persist its
// Retry-After holds and rolling-window order log on the core database. Call it
// once at startup, after migrations ran; a nil db leaves the throttle
// memory-only.
func AttachConnectorThrottleStores(db *sql.DB, postgres bool) {
	attachConnectorThrottleStores(connectors.DefaultThrottle, db, postgres)
}

func attachConnectorThrottleStores(th *connectors.Throttle, db *sql.DB, postgres bool) {
	if db == nil {
		return
	}
	st := newDBConnectorThrottleStore(db, postgres)
	th.SetStores(st, st)
}

// applyConnectorWindowConfig reads rate_window / rate_budget from a
// connector's config_json into the process throttle. A malformed pair is
// logged and ignored so a typo cannot stop a connector working.
func applyConnectorWindowConfig(th *connectors.Throttle, rec ConnectorRecord) {
	var cfg struct {
		RateWindow json.RawMessage `json:"rate_window"`
		RateBudget int             `json:"rate_budget"`
	}
	if json.Unmarshal([]byte(rec.ConfigJSON), &cfg) != nil || (len(cfg.RateWindow) == 0 && cfg.RateBudget == 0) {
		th.ConfigureWindow(rec.ID, 0, 0)
		return
	}
	w, err := connectors.ParseWindow(cfg.RateWindow)
	if err != nil || cfg.RateBudget < 0 || (w > 0) != (cfg.RateBudget > 0) {
		logging.Infof("connectors: connector %s has an invalid rate_window/rate_budget pair, ignoring it", rec.ID)
		th.ConfigureWindow(rec.ID, 0, 0)
		return
	}
	th.ConfigureWindow(rec.ID, w, cfg.RateBudget)
}
