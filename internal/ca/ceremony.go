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
	"kryptkeeper/internal/logging"
	"os"
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
	// CeremonyExpired is terminal: the ceremony sat pending past its TTL and
	// was auto-aborted. The parked CA is deliberately left pending_ceremony.
	CeremonyExpired = "expired"

	// DefaultCeremonyTTL is how long a ceremony may stay pending, measured
	// from created_at (absolute, not last activity).
	DefaultCeremonyTTL = 72 * time.Hour
	// ceremonyReminderLead is how long before expiry approvers are reminded.
	ceremonyReminderLead = 24 * time.Hour

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
	// ExpiresAt is CreatedAt + the manager's TTL; derived, not stored.
	ExpiresAt time.Time `json:"expires_at"`
}

// CeremonyNotifier delivers a message to one designated approver. Approver
// identities are principal ids; mapping them to a contact channel is a
// follow-up (UC-A03 / I01), so the default only logs.
type CeremonyNotifier interface {
	NotifyApprover(approver, subject, body string) error
}

// LogCeremonyNotifier is the log-only default notifier.
type LogCeremonyNotifier struct{}

func (LogCeremonyNotifier) NotifyApprover(approver, subject, body string) error {
	logging.Infof("ceremony notification to approver %q: %s", approver, subject)
	return nil
}

// CeremonyTTLFromEnv reads KRYPTKEEPER_CEREMONY_TTL (a Go duration). Unset,
// unparsable or non-positive values fall back to 72h.
func CeremonyTTLFromEnv() time.Duration {
	raw := os.Getenv("KRYPTKEEPER_CEREMONY_TTL")
	if raw == "" {
		return DefaultCeremonyTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		logging.Infof("KRYPTKEEPER_CEREMONY_TTL=%q is invalid; using %s", raw, DefaultCeremonyTTL)
		return DefaultCeremonyTTL
	}
	return d
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
	ttl      time.Duration
	notifier CeremonyNotifier
}

func NewCeremonyManager(db *sql.DB, postgres bool, engine CeremonyEngine) (*CeremonyManager, error) {
	if db == nil {
		return nil, fmt.Errorf("ceremony manager requires a database")
	}
	if engine == nil {
		return nil, fmt.Errorf("ceremony manager requires a CA engine")
	}
	return &CeremonyManager{db: db, postgres: postgres, engine: engine, now: time.Now, ttl: CeremonyTTLFromEnv()}, nil
}

// SetClock overrides the clock for tests.
func (m *CeremonyManager) SetClock(now func() time.Time) { m.now = now }

// SetNotifier installs the approver notifier; nil disables notifications.
func (m *CeremonyManager) SetNotifier(n CeremonyNotifier) { m.notifier = n }

func (m *CeremonyManager) notifyAll(c Ceremony, subject, body string) {
	if m.notifier == nil {
		return
	}
	for _, a := range c.Approvers {
		if err := m.notifier.NotifyApprover(a, subject, body); err != nil {
			logging.Warnf("ceremony %s: notify approver %q failed: %v", c.ID, a, err)
		}
	}
}

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
	// Persisted as RFC3339; truncate so the response equals a later Get.
	now := m.now().UTC().Truncate(time.Second)
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
		ExpiresAt:    now.Add(m.ttl),
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
	m.notifyAll(c, fmt.Sprintf("Ceremony %s needs your approval", c.ID),
		fmt.Sprintf("Root CA %q (%s) needs %d of %d approvals before %s.",
			c.CAName, c.CAID, c.Quorum, len(c.Approvers), c.ExpiresAt.Format(time.RFC3339)))
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
	c.ExpiresAt = c.CreatedAt.Add(m.ttl)
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
		c.ExpiresAt = c.CreatedAt.Add(m.ttl)
		out = append(out, c)
	}
	return out, rows.Err()
}

// expire flips one pending ceremony to expired (CAS) and reports whether
// this call did it. The CA stays pending_ceremony: destroying its parked key
// is a second-human action (A07), out of scope here.
func (m *CeremonyManager) expire(id string) (bool, error) {
	res, err := m.db.Exec(m.rebind(
		`UPDATE key_ceremonies SET status = 'expired', updated_at = ? WHERE id = ? AND status = 'pending'`),
		m.now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return false, fmt.Errorf("ceremony %s: persist expiry: %w", id, err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ExpireDue expires every pending ceremony whose TTL has elapsed and
// returns the ones this call flipped.
func (m *CeremonyManager) ExpireDue() ([]Ceremony, error) {
	all, err := m.List()
	if err != nil {
		return nil, err
	}
	now := m.now()
	var out []Ceremony
	for _, c := range all {
		if c.Status != CeremonyPending || now.Before(c.ExpiresAt) {
			continue
		}
		flipped, err := m.expire(c.ID)
		if err != nil {
			return out, err
		}
		if flipped {
			c.Status = CeremonyExpired
			out = append(out, c)
		}
	}
	return out, nil
}

// SendDueReminders notifies every designated approver of each pending
// ceremony that is within 24h of expiry (once; reminder_sent_at persists the
// fact) and returns how many ceremonies were reminded.
func (m *CeremonyManager) SendDueReminders() (int, error) {
	rows, err := m.db.Query(`SELECT id FROM key_ceremonies WHERE status = 'pending' AND reminder_sent_at IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("ceremony: reminder scan: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	now := m.now()
	reminded := 0
	for _, id := range ids {
		c, found, err := m.Get(id)
		if err != nil {
			return reminded, err
		}
		if !found || c.Status != CeremonyPending || now.Before(c.ExpiresAt.Add(-ceremonyReminderLead)) || !now.Before(c.ExpiresAt) {
			continue
		}
		res, err := m.db.Exec(m.rebind(
			`UPDATE key_ceremonies SET reminder_sent_at = ? WHERE id = ? AND status = 'pending' AND reminder_sent_at IS NULL`),
			now.UTC().Format(time.RFC3339), id)
		if err != nil {
			return reminded, fmt.Errorf("ceremony %s: persist reminder: %w", id, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue
		}
		m.notifyAll(c, fmt.Sprintf("Ceremony %s expires within 24h", c.ID),
			fmt.Sprintf("Root CA %q (%s) still needs %d of %d approvals; the ceremony expires at %s.",
				c.CAName, c.CAID, c.Quorum-len(c.Approvals), len(c.Approvers), c.ExpiresAt.Format(time.RFC3339)))
		reminded++
	}
	return reminded, nil
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
	if !m.now().Before(c.ExpiresAt) {
		if _, err := m.expire(id); err != nil {
			return Ceremony{}, err
		}
		return Ceremony{}, fmt.Errorf("ceremony %s expired", id)
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
