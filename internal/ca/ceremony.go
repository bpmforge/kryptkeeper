// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"kryptkeeper/internal/keystore"
)

// W9-06 (D-084/G-41/FR-P46): the M-of-N root-CA key ceremony. The engine
// births CAs active — a root key usable the instant one admin clicks. A
// ceremony creates the CA, immediately parks it pending_ceremony (the
// issuance paths refuse any non-active CA), and only the Mth distinct
// approval flips it active.

const (
	CeremonyPending   = "pending"
	CeremonyCompleted = "completed"
	CeremonyAborted   = "aborted"

	// CAStatusPendingCeremony is the parked state: the key exists but
	// lookupActiveCA refuses it everywhere.
	CAStatusPendingCeremony = "pending_ceremony"
)

// CeremonyEngine is the slice of *Engine the ceremony needs. Engine
// satisfies it; tests may substitute.
type CeremonyEngine interface {
	CreateRootCA(name string, subject pkix.Name, algo keystore.Algorithm, validity time.Duration) (*CA, error)
	UpdateCAStatus(id, status string) error
}

// Ceremony is one ceremony's state.
type Ceremony struct {
	ID           string    `json:"id"`
	CAID         string    `json:"ca_id"`
	CAName       string    `json:"ca_name"`
	CommonName   string    `json:"common_name"`
	Algorithm    string    `json:"algorithm"`
	ValidityDays int       `json:"validity_days"`
	Initiator    string    `json:"initiator"`
	Approvers    []string  `json:"approvers"`
	Quorum       int       `json:"quorum"`
	Approvals    []string  `json:"approvals"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// RootCACeremonyParams starts a ceremony.
type RootCACeremonyParams struct {
	Name         string
	CommonName   string
	Algorithm    keystore.Algorithm
	ValidityDays int
	Initiator    string
	Approvers    []string
	Quorum       int
}

// CeremonyManager owns the key_ceremonies table and the transitions over
// it. Constructor-injected; no globals.
type CeremonyManager struct {
	db       *sql.DB
	postgres bool
	engine   CeremonyEngine
	now      func() time.Time
}

func NewCeremonyManager(db *sql.DB, postgres bool, engine CeremonyEngine) (*CeremonyManager, error) {
	if db == nil {
		return nil, fmt.Errorf("ceremony manager requires a database")
	}
	if engine == nil {
		return nil, fmt.Errorf("ceremony manager requires a CA engine")
	}
	return &CeremonyManager{db: db, postgres: postgres, engine: engine, now: time.Now}, nil
}

// SetClock overrides the clock for tests.
func (m *CeremonyManager) SetClock(now func() time.Time) { m.now = now }

func (m *CeremonyManager) rebind(q string) string {
	if !m.postgres {
		return q
	}
	out := make([]byte, 0, len(q)+8)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, fmt.Sprintf("$%d", n)...)
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

func newCeremonyID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is a platform emergency; an ID collision is
		// caught by the PK constraint.
		return fmt.Sprintf("cer-%d", time.Now().UnixNano())
	}
	return "cer-" + hex.EncodeToString(b)
}

// StartRootCACeremony creates the root CA parked pending_ceremony and
// files the ceremony. The engine births CAs active (G-41); the downgrade
// happens here, inside the same call, before the CA ID is returned to
// anyone. Quorum must be >= 2 — a one-person ceremony is not a ceremony.
func (m *CeremonyManager) StartRootCACeremony(p RootCACeremonyParams) (Ceremony, error) {
	if p.Name == "" || p.CommonName == "" {
		return Ceremony{}, fmt.Errorf("ceremony: name and common name are required")
	}
	if p.ValidityDays <= 0 {
		return Ceremony{}, fmt.Errorf("ceremony: validity_days must be > 0")
	}
	if p.Initiator == "" {
		return Ceremony{}, fmt.Errorf("ceremony: initiator is required")
	}
	seen := map[string]bool{}
	for _, a := range p.Approvers {
		if a == "" {
			return Ceremony{}, fmt.Errorf("ceremony: empty approver name")
		}
		if seen[a] {
			return Ceremony{}, fmt.Errorf("ceremony: duplicate approver %q", a)
		}
		seen[a] = true
	}
	if p.Quorum < 2 {
		return Ceremony{}, fmt.Errorf("ceremony: quorum must be at least 2 — a single approver is not a ceremony (NFR-011)")
	}
	if p.Quorum > len(p.Approvers) {
		return Ceremony{}, fmt.Errorf("ceremony: quorum %d exceeds the %d eligible approvers", p.Quorum, len(p.Approvers))
	}

	caObj, err := m.engine.CreateRootCA(p.Name, pkix.Name{CommonName: p.CommonName}, p.Algorithm, time.Duration(p.ValidityDays)*24*time.Hour)
	if err != nil {
		return Ceremony{}, fmt.Errorf("ceremony: create root CA: %w", err)
	}
	if err := m.engine.UpdateCAStatus(caObj.ID, CAStatusPendingCeremony); err != nil {
		return Ceremony{}, fmt.Errorf("ceremony REFUSED: CA %s was created but could not be parked pending_ceremony and may be ACTIVE — suspend it manually: %w", caObj.ID, err)
	}

	approversJSON, err := json.Marshal(p.Approvers)
	if err != nil {
		return Ceremony{}, fmt.Errorf("ceremony: approvers marshal: %w", err)
	}
	now := m.now().UTC()
	c := Ceremony{
		ID:           newCeremonyID(),
		CAID:         caObj.ID,
		CAName:       p.Name,
		CommonName:   p.CommonName,
		Algorithm:    string(p.Algorithm),
		ValidityDays: p.ValidityDays,
		Initiator:    p.Initiator,
		Approvers:    p.Approvers,
		Quorum:       p.Quorum,
		Approvals:    []string{},
		Status:       CeremonyPending,
		CreatedAt:    now,
	}
	_, err = m.db.Exec(m.rebind(`
		INSERT INTO key_ceremonies (id, ca_id, ca_name, common_name, algorithm, validity_days,
			initiator, approvers, quorum, approvals, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', 'pending', ?, ?)`),
		c.ID, c.CAID, c.CAName, c.CommonName, c.Algorithm, c.ValidityDays,
		c.Initiator, string(approversJSON), c.Quorum,
		now.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return Ceremony{}, fmt.Errorf("ceremony: persist (CA %s stays pending_ceremony): %w", caObj.ID, err)
	}
	return c, nil
}

// Get loads one ceremony.
func (m *CeremonyManager) Get(id string) (Ceremony, bool, error) {
	row := m.db.QueryRow(m.rebind(`
		SELECT id, ca_id, ca_name, common_name, algorithm, validity_days,
		       initiator, approvers, quorum, approvals, status, created_at
		FROM key_ceremonies WHERE id = ?`), id)
	c, err := scanCeremony(row)
	if err == sql.ErrNoRows {
		return Ceremony{}, false, nil
	}
	if err != nil {
		return Ceremony{}, false, err
	}
	return c, true, nil
}

// List returns every ceremony, newest first.
func (m *CeremonyManager) List() ([]Ceremony, error) {
	rows, err := m.db.Query(`
		SELECT id, ca_id, ca_name, common_name, algorithm, validity_days,
		       initiator, approvers, quorum, approvals, status, created_at
		FROM key_ceremonies ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("ceremony: list: %w", err)
	}
	defer rows.Close()
	var out []Ceremony
	for rows.Next() {
		c, err := scanCeremony(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(dest ...any) error }

func scanCeremony(row rowScanner) (Ceremony, error) {
	var c Ceremony
	var approversJSON, approvalsJSON, createdAt string
	if err := row.Scan(&c.ID, &c.CAID, &c.CAName, &c.CommonName, &c.Algorithm, &c.ValidityDays,
		&c.Initiator, &approversJSON, &c.Quorum, &approvalsJSON, &c.Status, &createdAt); err != nil {
		return Ceremony{}, err
	}
	if err := json.Unmarshal([]byte(approversJSON), &c.Approvers); err != nil {
		return Ceremony{}, fmt.Errorf("ceremony %s: approvers parse: %w", c.ID, err)
	}
	if err := json.Unmarshal([]byte(approvalsJSON), &c.Approvals); err != nil {
		return Ceremony{}, fmt.Errorf("ceremony %s: approvals parse: %w", c.ID, err)
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return Ceremony{}, fmt.Errorf("ceremony %s: created_at parse: %w", c.ID, err)
	}
	c.CreatedAt = t
	return c, nil
}

// Approve records one distinct approval. The caller passes the
// AUTHENTICATED identity — the HTTP layer must never accept a
// body-supplied approver, or one person could replay N approvals. On
// reaching quorum the CA flips pending_ceremony → active and the
// ceremony completes.
func (m *CeremonyManager) Approve(id, approver string) (Ceremony, error) {
	if approver == "" {
		return Ceremony{}, fmt.Errorf("ceremony: approver identity is required")
	}
	c, found, err := m.Get(id)
	if err != nil {
		return Ceremony{}, err
	}
	if !found {
		return Ceremony{}, fmt.Errorf("ceremony %s not found", id)
	}
	if c.Status != CeremonyPending {
		return Ceremony{}, fmt.Errorf("ceremony %s is %s — no further approvals accepted", id, c.Status)
	}
	eligible := false
	for _, a := range c.Approvers {
		if a == approver {
			eligible = true
			break
		}
	}
	if !eligible {
		return Ceremony{}, fmt.Errorf("ceremony %s: %q is not an eligible approver", id, approver)
	}
	for _, a := range c.Approvals {
		if a == approver {
			return Ceremony{}, fmt.Errorf("ceremony %s: %q has already approved — approvals must come from distinct identities", id, approver)
		}
	}

	c.Approvals = append(c.Approvals, approver)
	approvalsJSON, err := json.Marshal(c.Approvals)
	if err != nil {
		return Ceremony{}, fmt.Errorf("ceremony: approvals marshal: %w", err)
	}
	now := m.now().UTC().Format(time.RFC3339)

	if len(c.Approvals) >= c.Quorum {
		// Activate FIRST, then complete: a completed ceremony with a
		// still-parked CA would strand it, while a pending ceremony with an
		// active CA self-heals on the next (refused-as-completed) approval
		// path below.
		if err := m.engine.UpdateCAStatus(c.CAID, "active"); err != nil {
			return Ceremony{}, fmt.Errorf("ceremony %s reached quorum but CA %s activation failed — approvals NOT recorded, retry: %w", id, c.CAID, err)
		}
		c.Status = CeremonyCompleted
	}
	if _, err := m.db.Exec(m.rebind(
		`UPDATE key_ceremonies SET approvals = ?, status = ?, updated_at = ? WHERE id = ?`),
		string(approvalsJSON), c.Status, now, id); err != nil {
		return Ceremony{}, fmt.Errorf("ceremony %s: persist approval: %w", id, err)
	}
	return c, nil
}

// Abort parks a pending ceremony. The CA stays pending_ceremony —
// permanently refused by issuance, the safe direction for an aborted
// root ceremony.
func (m *CeremonyManager) Abort(id string) (Ceremony, error) {
	c, found, err := m.Get(id)
	if err != nil {
		return Ceremony{}, err
	}
	if !found {
		return Ceremony{}, fmt.Errorf("ceremony %s not found", id)
	}
	if c.Status != CeremonyPending {
		return Ceremony{}, fmt.Errorf("ceremony %s is %s — only pending ceremonies can be aborted", id, c.Status)
	}
	c.Status = CeremonyAborted
	now := m.now().UTC().Format(time.RFC3339)
	if _, err := m.db.Exec(m.rebind(
		`UPDATE key_ceremonies SET status = 'aborted', updated_at = ? WHERE id = ?`),
		now, id); err != nil {
		return Ceremony{}, fmt.Errorf("ceremony %s: persist abort: %w", id, err)
	}
	return c, nil
}
