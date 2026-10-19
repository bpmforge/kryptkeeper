// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Approval link statuses (itsm_approval_links.status).
const (
	LinkWaiting  = "waiting"
	LinkApproved = "approved"
	LinkRefused  = "refused"
	LinkDone     = "done"
)

// Link ties an approval-pending ticket (by event id) to the hub approval it decides.
type Link struct{ EventID, ApprovalID string }

// Mapping names the hub user an external ITSM approver acts as. Kind is the
// connector kind; ExternalID is whatever the connector reports as the approver.
type Mapping struct {
	Kind       string `json:"kind"`
	ExternalID string `json:"external_id"`
	UserID     string `json:"user_id"`
	Tenant     string `json:"tenant"`
}

// AddLink records that the ticket of eventID decides approvalID. A repeat is a
// no-op, so a retried delivery cannot reset a decided link to waiting.
func (s *Store) AddLink(ctx context.Context, eventID, approvalID string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO itsm_approval_links (event_id, approval_id, created_at) VALUES (?,?,?)
		ON CONFLICT(event_id) DO NOTHING`), eventID, approvalID, fmtTS(now))
	return err
}

// WaitingLinks returns links still waiting for an external decision, oldest first.
func (s *Store) WaitingLinks(ctx context.Context, limit int) ([]Link, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT event_id, approval_id FROM itsm_approval_links WHERE status = 'waiting'
		ORDER BY created_at, event_id LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Link{}
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.EventID, &l.ApprovalID); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SetLinkStatus moves a waiting link to a terminal status; a link that is no
// longer waiting is left alone (reports ErrNotFound), so a decided link never
// reverts.
func (s *Store) SetLinkStatus(ctx context.Context, eventID, status string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE itsm_approval_links SET status = ?, decided_at = ? WHERE event_id = ? AND status = 'waiting'`),
		status, fmtTS(now), eventID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// LinkStatus reads one link's status.
func (s *Store) LinkStatus(ctx context.Context, eventID string) (string, error) {
	var st string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT status FROM itsm_approval_links WHERE event_id = ?`), eventID).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return st, err
}

// LookupMapping finds the mapping of an external approver.
func (s *Store) LookupMapping(ctx context.Context, kind, externalID string) (Mapping, bool, error) {
	m := Mapping{Kind: kind, ExternalID: externalID}
	err := s.db.QueryRowContext(ctx, s.q(`SELECT user_id, tenant FROM itsm_principal_map WHERE kind = ? AND external_id = ?`),
		kind, externalID).Scan(&m.UserID, &m.Tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return Mapping{}, false, nil
	}
	return m, err == nil, err
}

// UpsertMapping creates or replaces a mapping.
func (s *Store) UpsertMapping(ctx context.Context, m Mapping) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO itsm_principal_map (kind, external_id, user_id, tenant) VALUES (?,?,?,?)
		ON CONFLICT(kind, external_id) DO UPDATE SET user_id = excluded.user_id, tenant = excluded.tenant`),
		m.Kind, m.ExternalID, m.UserID, m.Tenant)
	return err
}

// ListMappings returns the mappings of one tenant.
func (s *Store) ListMappings(ctx context.Context, tenant string) ([]Mapping, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT kind, external_id, user_id, tenant FROM itsm_principal_map WHERE tenant = ?
		ORDER BY kind, external_id`), tenant)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Mapping{}
	for rows.Next() {
		var m Mapping
		if err := rows.Scan(&m.Kind, &m.ExternalID, &m.UserID, &m.Tenant); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteMapping removes one mapping; ErrNotFound when absent.
func (s *Store) DeleteMapping(ctx context.Context, kind, externalID string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM itsm_principal_map WHERE kind = ? AND external_id = ?`), kind, externalID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
