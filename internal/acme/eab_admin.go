// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

// Operator-managed EAB credentials (W26-01, D-043). Keys minted through the
// admin API live in acme_eab_admin; the env-seeded acme_eab_keys table is
// untouched and read-only. acme_eab_use records the one account key each kid
// (seed or API) has registered with.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/clientip"
)

var (
	// ErrEABNotFound means no admin-minted key has that kid.
	ErrEABNotFound = errors.New("eab key not found")
	// ErrEABAlreadyRevoked means the key was revoked earlier.
	ErrEABAlreadyRevoked = errors.New("eab key already revoked")
)

// EABAdminKey is an admin-minted credential without its secret.
type EABAdminKey struct {
	KID, Label, Provisioner, TemplateID, CreatedBy string
	CreatedAt                                      time.Time
	RevokedAt, LastUsedAt                          *time.Time
	Uses                                           int
}

// EABAdmin stores operator-minted EAB credentials and key-use records.
type EABAdmin interface {
	Create(ctx context.Context, k EABAdminKey, sealedMAC string) error
	List(ctx context.Context) ([]EABAdminKey, error) // newest first
	Revoke(ctx context.Context, kid string, at time.Time) error
	LoadEABKey(kid string) (*EABKey, bool) // Disabled = revoked
	// RecordUse notes a successful registration of kid by the account key with
	// this thumbprint. bound is false when kid is already bound to a
	// different thumbprint.
	RecordUse(kid, thumbprint string, at time.Time) (bound bool, err error)
}

// AuditEvent is one ACME EAB outcome. Detail never carries a MAC or secret.
type AuditEvent struct {
	Action   string // "acme.eab.reject"
	Actor    string // the presented kid, or empty
	Outcome  string // "denied"
	SourceIP string
	Detail   string
}

// AuditFunc records an AuditEvent; main adapts it to the hub audit log.
type AuditFunc func(ctx context.Context, ev AuditEvent)

// AlertFunc raises an operator alert (kind e.g. "acme.eab.failures").
type AlertFunc func(ctx context.Context, kind string, detail map[string]string)

const (
	eabFailureLimit  = 10
	eabFailureWindow = time.Minute
	eabSweepAbove    = 1024
)

type eabFailureState struct {
	start   time.Time
	count   int
	alerted bool
}

// eabRuntime is the server's mutable EAB state: the admin store, the audit
// and alert hooks, and the per-source failure window.
type eabRuntime struct {
	admin EABAdmin
	audit AuditFunc
	alert AlertFunc
	now   func() time.Time

	mu    sync.Mutex
	fails map[string]*eabFailureState
}

func newEABRuntime() *eabRuntime {
	return &eabRuntime{admin: NewMemEABAdmin(), now: time.Now, fails: map[string]*eabFailureState{}}
}

// WithEABAdmin wires the operator-minted key store (default: in-memory).
func (s *Server) WithEABAdmin(a EABAdmin) *Server {
	if a != nil {
		s.eab.admin = a
	}
	return s
}

// WithAuditFunc records EAB rejections.
func (s *Server) WithAuditFunc(fn AuditFunc) *Server {
	s.eab.audit = fn
	return s
}

// WithAlertFunc raises brute-force alerts.
func (s *Server) WithAlertFunc(fn AlertFunc) *Server {
	s.eab.alert = fn
	return s
}

// LookupEABKey resolves a kid from the env-seed table, then the admin store.
func (s *Server) LookupEABKey(kid string) (*EABKey, bool) {
	if k, ok := s.store.LoadEABKey(kid); ok {
		return k, true
	}
	return s.eab.admin.LoadEABKey(kid)
}

type eabLookupFunc func(kid string) (*EABKey, bool)

func (f eabLookupFunc) LoadEABKey(kid string) (*EABKey, bool) { return f(kid) }

// peekEABKID reads the kid out of an EAB's protected header, "" if unreadable.
func peekEABKID(eab *ExternalAccountBinding) string {
	if eab == nil {
		return ""
	}
	return eabKIDFromProtected(eab.Protected)
}

var errEABWrongProvisioner = errors.New("key is bound to another provisioner")

// checkNewAccountEAB runs the new-account EAB policy: verify against the seed
// then admin keys, enforce one account key per kid, and record the use. A
// returned error is a rejection that has already been audited and counted;
// errEABRequired means a binding was needed and absent.
func (s *Server) checkNewAccountEAB(r *http.Request, eab *ExternalAccountBinding, thumbprint string) (string, error) {
	rt := s.eab
	if eab == nil {
		if !s.eabConfig.required {
			return "", nil
		}
		s.rejectEAB(r, "", "missing binding")
		return "", errEABRequired
	}
	kid := peekEABKID(eab)
	if err := verifyExternalAccountBinding(eabLookupFunc(s.LookupEABKey), eab, s.baseURL+"/acme/new-account", thumbprint); err != nil {
		s.rejectEAB(r, kid, err.Error())
		return "", err
	}
	if key, ok := s.LookupEABKey(kid); ok && key.Provisioner != "" && (s.provisioner == nil || s.provisioner.Name != key.Provisioner) {
		s.rejectEAB(r, kid, "key bound to provisioner "+key.Provisioner)
		return "", errEABWrongProvisioner
	}
	bound, err := rt.admin.RecordUse(kid, thumbprint, rt.now().UTC())
	if err != nil {
		// Fail closed: without the use record the reuse rule is unenforceable.
		logging.Warnf("acme: eab use record for %s failed: %v", kid, err)
		s.rejectEAB(r, kid, "use record failed")
		return "", errors.New("eab use record failed")
	}
	if !bound {
		s.rejectEAB(r, kid, errEABKeyReused.Error())
		return "", errEABKeyReused
	}
	return kid, nil
}

// rejectEAB audits one EAB rejection and counts it toward the per-source
// alert threshold.
func (s *Server) rejectEAB(r *http.Request, kid, detail string) {
	rt := s.eab
	ip := clientip.FromEnv().ClientIP(r)
	if rt.audit != nil {
		rt.audit(r.Context(), AuditEvent{Action: "acme.eab.reject", Actor: kid, Outcome: "denied", SourceIP: ip, Detail: detail})
	}
	if n, fire := rt.recordFailure(ip); fire && rt.alert != nil {
		rt.alert(r.Context(), "acme.eab.failures", map[string]string{"source": ip, "count": fmt.Sprint(n)})
	}
}

// recordFailure counts a failure for source in a fixed one-minute window and
// reports the count and whether this failure is the one that should alert
// (the first past the limit in the window).
func (rt *eabRuntime) recordFailure(source string) (int, bool) {
	now := rt.now()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.fails) > eabSweepAbove {
		for k, v := range rt.fails {
			if now.Sub(v.start) >= eabFailureWindow {
				delete(rt.fails, k)
			}
		}
	}
	st := rt.fails[source]
	if st == nil || now.Sub(st.start) >= eabFailureWindow {
		st = &eabFailureState{start: now}
		rt.fails[source] = st
	}
	st.count++
	if st.count > eabFailureLimit && !st.alerted {
		st.alerted = true
		return st.count, true
	}
	return st.count, false
}

// MemEABAdmin is the in-memory EABAdmin: the default when no database is
// wired, and the test double.
type MemEABAdmin struct {
	mu   sync.Mutex
	keys map[string]EABAdminKey
	macs map[string]string
	use  map[string]memEABUse
	open func(string) ([]byte, error)
}

type memEABUse struct {
	thumbprint string
	uses       int
	last       time.Time
}

// NewMemEABAdmin returns an empty in-memory store whose sealed MACs are the
// raw key bytes (no sealing).
func NewMemEABAdmin() *MemEABAdmin {
	return &MemEABAdmin{keys: map[string]EABAdminKey{}, macs: map[string]string{}, use: map[string]memEABUse{},
		open: func(s string) ([]byte, error) { return []byte(s), nil }}
}

func (m *MemEABAdmin) Create(_ context.Context, k EABAdminKey, sealedMAC string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[k.KID], m.macs[k.KID] = k, sealedMAC
	return nil
}

func (m *MemEABAdmin) List(context.Context) ([]EABAdminKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]EABAdminKey, 0, len(m.keys))
	for kid, k := range m.keys {
		if u, ok := m.use[kid]; ok {
			last := u.last
			k.LastUsedAt, k.Uses = &last, u.uses
		}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemEABAdmin) Revoke(_ context.Context, kid string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[kid]
	if !ok {
		return ErrEABNotFound
	}
	if k.RevokedAt != nil {
		return ErrEABAlreadyRevoked
	}
	k.RevokedAt = &at
	m.keys[kid] = k
	return nil
}

func (m *MemEABAdmin) LoadEABKey(kid string) (*EABKey, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[kid]
	if !ok {
		return nil, false
	}
	mac, err := m.open(m.macs[kid])
	if err != nil {
		return nil, false
	}
	return &EABKey{KID: kid, MACKey: mac, Disabled: k.RevokedAt != nil, CreatedAt: k.CreatedAt, Provisioner: k.Provisioner}, true
}

func (m *MemEABAdmin) RecordUse(kid, thumbprint string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.use[kid]
	if ok && u.thumbprint != thumbprint {
		return false, nil
	}
	m.use[kid] = memEABUse{thumbprint: thumbprint, uses: u.uses + 1, last: at}
	return true, nil
}

const eabTimeLayout = "2006-01-02T15:04:05Z" // fixed width, UTC: compares as text

// DBEABAdmin keeps admin-minted keys and key use in acme_eab_admin and
// acme_eab_use (migration 000180).
type DBEABAdmin struct {
	db       *sql.DB
	postgres bool
	open     func(sealed string) ([]byte, error)
}

// NewDBEABAdmin returns a store on db. open unseals a stored MAC key.
func NewDBEABAdmin(db *sql.DB, postgres bool, open func(sealed string) ([]byte, error)) *DBEABAdmin {
	return &DBEABAdmin{db: db, postgres: postgres, open: open}
}

// EnsureSchema creates the tables for a database that skipped migrations.
func (s *DBEABAdmin) EnsureSchema() error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS acme_eab_admin (
  kid TEXT PRIMARY KEY, label TEXT NOT NULL DEFAULT '', provisioner TEXT NOT NULL DEFAULT '',
  template_id TEXT NOT NULL DEFAULT '', sealed_mac_key TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS acme_eab_use (
  kid TEXT PRIMARY KEY, thumbprint TEXT NOT NULL, uses INTEGER NOT NULL DEFAULT 0,
  first_used_at TEXT NOT NULL, last_used_at TEXT NOT NULL)`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("acme eab admin schema: %w", err)
		}
	}
	return nil
}

func (s *DBEABAdmin) q(query string) string {
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

func eabTime(t time.Time) string { return t.UTC().Format(eabTimeLayout) }

func (s *DBEABAdmin) Create(ctx context.Context, k EABAdminKey, sealedMAC string) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO acme_eab_admin
 (kid, label, provisioner, template_id, sealed_mac_key, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		k.KID, k.Label, k.Provisioner, k.TemplateID, sealedMAC, k.CreatedBy, eabTime(k.CreatedAt))
	return err
}

func (s *DBEABAdmin) List(ctx context.Context) ([]EABAdminKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.kid, a.label, a.provisioner, a.template_id, a.created_by, a.created_at,
 a.revoked_at, u.last_used_at, COALESCE(u.uses, 0)
 FROM acme_eab_admin a LEFT JOIN acme_eab_use u ON u.kid = a.kid ORDER BY a.created_at DESC, a.kid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EABAdminKey{}
	for rows.Next() {
		var k EABAdminKey
		var created string
		var revoked, last sql.NullString
		if err := rows.Scan(&k.KID, &k.Label, &k.Provisioner, &k.TemplateID, &k.CreatedBy, &created, &revoked, &last, &k.Uses); err != nil {
			return nil, err
		}
		k.CreatedAt = parseEABTime(created)
		if revoked.Valid {
			t := parseEABTime(revoked.String)
			k.RevokedAt = &t
		}
		if last.Valid {
			t := parseEABTime(last.String)
			k.LastUsedAt = &t
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func parseEABTime(v string) time.Time {
	t, _ := time.Parse(eabTimeLayout, v)
	return t
}

func (s *DBEABAdmin) Revoke(ctx context.Context, kid string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE acme_eab_admin SET revoked_at = ? WHERE kid = ? AND revoked_at IS NULL`), eabTime(at), kid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var one int
	err = s.db.QueryRowContext(ctx, s.q(`SELECT 1 FROM acme_eab_admin WHERE kid = ?`), kid).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEABNotFound
	}
	if err != nil {
		return err
	}
	return ErrEABAlreadyRevoked
}

func (s *DBEABAdmin) LoadEABKey(kid string) (*EABKey, bool) {
	var sealed, prov, created string
	var revoked sql.NullString
	err := s.db.QueryRow(s.q(`SELECT sealed_mac_key, provisioner, created_at, revoked_at FROM acme_eab_admin WHERE kid = ?`), kid).
		Scan(&sealed, &prov, &created, &revoked)
	if err != nil {
		return nil, false
	}
	mac, err := s.open(sealed)
	if err != nil {
		return nil, false
	}
	return &EABKey{KID: kid, MACKey: mac, Disabled: revoked.Valid, CreatedAt: parseEABTime(created), Provisioner: prov}, true
}

func (s *DBEABAdmin) RecordUse(kid, thumbprint string, at time.Time) (bool, error) {
	now := eabTime(at)
	// First registration wins the row; a concurrent second thumbprint loses.
	if _, err := s.db.Exec(s.q(`INSERT INTO acme_eab_use (kid, thumbprint, uses, first_used_at, last_used_at)
 VALUES (?, ?, 0, ?, ?) ON CONFLICT (kid) DO NOTHING`), kid, thumbprint, now, now); err != nil {
		return false, err
	}
	res, err := s.db.Exec(s.q(`UPDATE acme_eab_use SET uses = uses + 1, last_used_at = ? WHERE kid = ? AND thumbprint = ?`), now, kid, thumbprint)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
