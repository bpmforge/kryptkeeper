// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// W27-02: explicit cert-to-target binding. The renewal sweep renews a
// certificate only onto targets an operator bound to it; a CN/SAN that merely
// equals a target's host no longer arms a private-key push.

var (
	errBindingExists   = errors.New("certificate is already bound to this target")
	errBindingNotFound = errors.New("binding not found")
)

const (
	bindingSourceOperator = "operator"
	bindingSourceBackfill = "backfill"
	bindingStateBackfill  = "backfill_done"
)

// CertTargetBinding says "renew this certificate onto this target".
// ServedFingerprint is the certificate currently installed there: it starts as
// CertFingerprint and advances on every renewal, because fingerprints rotate.
type CertTargetBinding struct {
	CertFingerprint   string `json:"cert_fingerprint"`
	TargetID          string `json:"target_id"`
	ServedFingerprint string `json:"served_fingerprint"`
	Tenant            string `json:"tenant"`
	Source            string `json:"source"`
	CreatedBy         string `json:"created_by"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type CertTargetBindingStore interface {
	EnsureSchema(ctx context.Context) error
	// Create returns errBindingExists on a primary-key conflict.
	Create(ctx context.Context, b CertTargetBinding) (CertTargetBinding, error)
	// Delete returns errBindingNotFound when no row matched.
	Delete(ctx context.Context, targetID, certFingerprint string) error
	ListByTarget(ctx context.Context, targetID string) ([]CertTargetBinding, error)
	ListAll(ctx context.Context) ([]CertTargetBinding, error)
	DeleteByTarget(ctx context.Context, targetID string) error
	SetServed(ctx context.Context, targetID, certFingerprint, servedFP string) error
	// AdvanceServed moves every binding of targetID whose served certificate
	// is fromFP to toFP (a manual renewal installed a successor).
	AdvanceServed(ctx context.Context, targetID, fromFP, toFP string) error
	BackfillDone(ctx context.Context) (bool, error)
	MarkBackfillDone(ctx context.Context) error
}

// activeCertTargetBindingStore lets handlers that live apart from the binding
// routes (target delete, manual renewal execute) reach the store, the same
// shape as activeTenantStore. Nil means the store is unavailable.
var activeCertTargetBindingStore CertTargetBindingStore

func setActiveCertTargetBindingStore(s CertTargetBindingStore) { activeCertTargetBindingStore = s }

// certTargetBindingSchema mirrors migration 000200_cert_target_bindings; like
// every DB-backed store here it self-heals its own schema (G-33).
const certTargetBindingSchema = `
CREATE TABLE IF NOT EXISTS cert_target_bindings (
    cert_fingerprint   TEXT NOT NULL,
    target_id          TEXT NOT NULL,
    served_fingerprint TEXT NOT NULL,
    tenant             TEXT NOT NULL DEFAULT 'default',
    source             TEXT NOT NULL DEFAULT 'operator' CHECK (source IN ('operator', 'backfill')),
    created_by         TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (cert_fingerprint, target_id)
);
CREATE INDEX IF NOT EXISTS idx_ctb_target ON cert_target_bindings(target_id);
CREATE INDEX IF NOT EXISTS idx_ctb_served ON cert_target_bindings(served_fingerprint);
CREATE TABLE IF NOT EXISTS cert_target_binding_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);`

// sqlCertTargetBindingStore serves both engines; only the placeholder style
// differs, so each statement is written once with "?" and rebound for Postgres.
type sqlCertTargetBindingStore struct {
	db       *sql.DB
	postgres bool
}

func (s *sqlCertTargetBindingStore) q(query string) string {
	if !s.postgres {
		return query
	}
	return rebindToDollar(query)
}

// rebindToDollar rewrites "?" placeholders as Postgres $1..$n.
func rebindToDollar(query string) string {
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

const bindingColumns = "cert_fingerprint, target_id, served_fingerprint, tenant, source, created_by, created_at, updated_at"

func (s *sqlCertTargetBindingStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, certTargetBindingSchema)
	return err
}

func (s *sqlCertTargetBindingStore) Create(ctx context.Context, b CertTargetBinding) (CertTargetBinding, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if b.ServedFingerprint == "" {
		b.ServedFingerprint = b.CertFingerprint
	}
	if b.Tenant == "" {
		b.Tenant = DefaultTenant
	}
	if b.Source == "" {
		b.Source = bindingSourceOperator
	}
	b.CreatedAt, b.UpdatedAt = now, now
	res, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO cert_target_bindings (`+bindingColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (cert_fingerprint, target_id) DO NOTHING`),
		b.CertFingerprint, b.TargetID, b.ServedFingerprint, b.Tenant, b.Source, b.CreatedBy, b.CreatedAt, b.UpdatedAt)
	if err != nil {
		return CertTargetBinding{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return CertTargetBinding{}, err
	}
	if n == 0 {
		return CertTargetBinding{}, errBindingExists
	}
	return b, nil
}

func (s *sqlCertTargetBindingStore) Delete(ctx context.Context, targetID, certFingerprint string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM cert_target_bindings WHERE target_id = ? AND cert_fingerprint = ?`), targetID, certFingerprint)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errBindingNotFound
	}
	return nil
}

func (s *sqlCertTargetBindingStore) list(ctx context.Context, where string, args ...any) ([]CertTargetBinding, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+bindingColumns+` FROM cert_target_bindings `+where+` ORDER BY created_at, cert_fingerprint, target_id`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CertTargetBinding{}
	for rows.Next() {
		var b CertTargetBinding
		if err := rows.Scan(&b.CertFingerprint, &b.TargetID, &b.ServedFingerprint, &b.Tenant, &b.Source, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *sqlCertTargetBindingStore) ListByTarget(ctx context.Context, targetID string) ([]CertTargetBinding, error) {
	return s.list(ctx, "WHERE target_id = ?", targetID)
}

func (s *sqlCertTargetBindingStore) ListAll(ctx context.Context) ([]CertTargetBinding, error) {
	return s.list(ctx, "")
}

func (s *sqlCertTargetBindingStore) DeleteByTarget(ctx context.Context, targetID string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM cert_target_bindings WHERE target_id = ?`), targetID)
	return err
}

func (s *sqlCertTargetBindingStore) SetServed(ctx context.Context, targetID, certFingerprint, servedFP string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE cert_target_bindings SET served_fingerprint = ?, updated_at = ? WHERE target_id = ? AND cert_fingerprint = ?`),
		servedFP, time.Now().UTC().Format(time.RFC3339), targetID, certFingerprint)
	return err
}

func (s *sqlCertTargetBindingStore) AdvanceServed(ctx context.Context, targetID, fromFP, toFP string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE cert_target_bindings SET served_fingerprint = ?, updated_at = ? WHERE target_id = ? AND served_fingerprint = ?`),
		toFP, time.Now().UTC().Format(time.RFC3339), targetID, fromFP)
	return err
}

func (s *sqlCertTargetBindingStore) BackfillDone(ctx context.Context) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT value FROM cert_target_binding_state WHERE key = ?`), bindingStateBackfill).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return v == "1", nil
}

func (s *sqlCertTargetBindingStore) MarkBackfillDone(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO cert_target_binding_state (key, value) VALUES (?, '1')
		ON CONFLICT (key) DO UPDATE SET value = '1'`), bindingStateBackfill)
	return err
}

func newCertTargetBindingStoreFromEnv() CertTargetBindingStore {
	state := newDBProviderState[CertTargetBindingStore](
		"cert-target-binding",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_TARGETS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) CertTargetBindingStore { return &sqlCertTargetBindingStore{db: db} },
		func(db *sql.DB) CertTargetBindingStore { return &sqlCertTargetBindingStore{db: db, postgres: true} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("cert-target-binding", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("cert-target-binding", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

// --- sweep support ---------------------------------------------------------

// bindingSweepIndex is one tick's view of the bindings, built once so the
// per-certificate loop does no store reads.
type bindingSweepIndex struct {
	byServed map[string][]CertTargetBinding
	// bound holds every fingerprint that is either a binding's cert or its
	// currently served certificate: those are the certs an operator chose.
	bound      map[string]bool
	autoByID   map[string]ManagedTarget
	autoByHost map[string][]ManagedTarget
}

func newBindingSweepIndex(binds []CertTargetBinding, eligible []ManagedTarget) *bindingSweepIndex {
	idx := &bindingSweepIndex{
		byServed:   make(map[string][]CertTargetBinding, len(binds)),
		bound:      make(map[string]bool, 2*len(binds)),
		autoByID:   make(map[string]ManagedTarget, len(eligible)),
		autoByHost: make(map[string][]ManagedTarget, len(eligible)),
	}
	for _, b := range binds {
		idx.byServed[b.ServedFingerprint] = append(idx.byServed[b.ServedFingerprint], b)
		idx.bound[b.CertFingerprint] = true
		idx.bound[b.ServedFingerprint] = true
	}
	for _, t := range eligible {
		idx.autoByID[t.ID] = t
		idx.autoByHost[t.Host] = append(idx.autoByHost[t.Host], t)
	}
	return idx
}

// hostMatches lists the eligible targets whose host equals cert's CN or a SAN:
// the pairs the old heuristic would have renewed.
func (idx *bindingSweepIndex) hostMatches(cert CertificateItem) []ManagedTarget {
	var out []ManagedTarget
	seen := map[string]bool{}
	add := func(host string) {
		for _, t := range idx.autoByHost[host] {
			if !seen[t.ID] {
				seen[t.ID] = true
				out = append(out, t)
			}
		}
	}
	add(cert.CommonName)
	for _, san := range cert.SubjectAltNames {
		add(san)
	}
	return out
}

// backfillBindings turns every live CN/SAN == host match into a binding, once,
// so upgrading does not silently stop a renewal that was working. It returns
// the number created. Callers mark the backfill done only on a nil error.
func backfillBindings(ctx context.Context, store CertTargetBindingStore, certs []CertificateItem, eligible []ManagedTarget, now time.Time) (int, error) {
	idx := newBindingSweepIndex(nil, eligible)
	created := 0
	for _, cert := range certs {
		if cert.RevokedAt != nil || cert.SuccessorFP != nil || cert.ValidUntil == "" {
			continue
		}
		expiry, err := time.Parse(time.RFC3339, cert.ValidUntil)
		if err != nil || expiry.Before(now) {
			continue
		}
		for _, t := range idx.hostMatches(cert) {
			_, err := store.Create(ctx, CertTargetBinding{
				CertFingerprint: cert.FingerprintSHA256, TargetID: t.ID, Tenant: t.Tenant, Source: bindingSourceBackfill,
			})
			switch {
			case err == nil:
				created++
			case errors.Is(err, errBindingExists):
			default:
				return created, err
			}
		}
	}
	return created, nil
}

// unboundNoteSeen dedupes the "matches a host but has no binding" log to once
// per certificate per day, so it neither floods the log nor feeds the
// alert-skip counter.
type unboundNoteSeen struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (u *unboundNoteSeen) should(key string, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.seen == nil {
		u.seen = map[string]time.Time{}
	}
	if last, ok := u.seen[key]; ok && now.Sub(last) < skipAuditEvery {
		return false
	}
	if len(u.seen) > 10000 {
		for k, t := range u.seen {
			if now.Sub(t) >= skipAuditEvery {
				delete(u.seen, k)
			}
		}
	}
	u.seen[key] = now
	return true
}

func (u *unboundNoteSeen) log(cert CertificateItem, t ManagedTarget, now time.Time) {
	if u.should(cert.FingerprintSHA256+"#"+t.ID, now) {
		logging.Infof("renewal scheduler: cert %s matches target %s host %q but has no binding; not auto-renewing (POST /api/v1/targets/{id}/bindings)",
			cert.FingerprintSHA256, t.ID, t.Host)
	}
}
