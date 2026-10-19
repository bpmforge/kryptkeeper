// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"kryptkeeper/internal/logging"
)

// W22-29: persisted dedup identity for findings (funnel stage 2) — see
// docs/design/FINDING_ECONOMICS.md.

// findingIdentityThrottle bounds last_seen writes: a finding that is re-read
// on every dashboard poll must not turn each read into a row update.
const findingIdentityThrottle = time.Hour

// maxObservedFindings caps one Observe call so a pathological estate cannot
// hold a transaction open for minutes; the funnel counts are unaffected.
const maxObservedFindings = 50000

// FindingIdentityID is the stable id of "this finding on this target".
// Tenant is part of the identity: discovery endpoints are per-tenant rows, so
// two tenants that each find the same certificate flaw hold two findings, and
// one tenant's identity row must never be shared with, or refreshed by,
// another's. A certificate target is identified by its fingerprint alone (one
// CA, hence one tenant), so posture findings use tenant "".
func FindingIdentityID(tenant, targetType, targetID, code string) string {
	sum := sha256.Sum256([]byte(tenant + "\x00" + targetType + "\x00" + targetID + "\x00" + code))
	return "fnd-" + hex.EncodeToString(sum[:])[:32]
}

// IdentityID is the id of the finding this exception covers in tenant's
// funnel. Exceptions themselves are not tenant-stamped (see FindingException).
func (e FindingException) IdentityID(tenant string) string {
	return FindingIdentityID(tenant, e.TargetType, e.TargetID, e.FindingCode)
}

type FindingKey struct{ Tenant, TargetType, TargetID, Code string }

func (k FindingKey) id() string { return FindingIdentityID(k.Tenant, k.TargetType, k.TargetID, k.Code) }

type FindingIdentity struct {
	ID          string `json:"id"`
	Tenant      string `json:"tenant"`
	TargetType  string `json:"target_type"`
	TargetID    string `json:"target_id"`
	FindingCode string `json:"finding_code"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

// funnelBuilder turns a stream of raw findings into the five funnel counts.
type funnelBuilder struct {
	raw        int
	seen       map[FindingKey]bool // value: suppressed
	persistent []FindingKey        // identities stable enough to persist
	unstable   int                 // unmerged keys (never persisted)
}

func newFunnelBuilder() *funnelBuilder {
	return &funnelBuilder{seen: map[FindingKey]bool{}}
}

// Add records one raw finding. Raw always increments; the identity counts
// once, and is suppressed if any of its occurrences was.
func (b *funnelBuilder) Add(tenant, targetType, targetID, code string, suppressed bool) {
	b.raw++
	k := FindingKey{tenant, targetType, targetID, code}
	prev, ok := b.seen[k]
	if !ok {
		b.persistent = append(b.persistent, k)
	}
	b.seen[k] = prev || suppressed
}

// addUnmerged records a finding that has no stable target (an endpoint with
// no certificate). It is its own identity and is not persisted, because its
// key is positional and would churn the table on every scan.
func (b *funnelBuilder) addUnmerged(suppressed bool) {
	b.raw++
	b.unstable++
	b.seen[FindingKey{TargetType: "unmerged", TargetID: fmt.Sprintf("%d", b.unstable)}] = suppressed
}

// Summary: Deduped = distinct identities; InScope = Deduped, because every
// funnel surface is a super-admin aggregate or already tenant-scoped at the
// source, so the scope stage removes nothing yet; Effective = InScope -
// Suppressed.
func (b *funnelBuilder) Summary() FindingFunnelSummary {
	suppressed := 0
	for _, s := range b.seen {
		if s {
			suppressed++
		}
	}
	deduped := len(b.seen)
	return FindingFunnelSummary{
		Raw: b.raw, Deduped: deduped, InScope: deduped,
		Effective: deduped - suppressed, Suppressed: suppressed,
	}
}

// Identities returns the distinct, persistable findings in first-seen order.
func (b *funnelBuilder) Identities() []FindingKey { return b.persistent }

type FindingIdentityStore interface {
	EnsureSchema(ctx context.Context) error
	// Observe upserts the keys: first_seen is kept, last_seen is bumped only
	// when the stored value is older than findingIdentityThrottle.
	Observe(ctx context.Context, keys []FindingKey, now time.Time) error
	Get(ctx context.Context, id string) (FindingIdentity, bool, error)
}

// findingIdentitySchema mirrors migration 000093 (G-33: every DB-backed store
// self-heals its own schema).
const findingIdentitySchema = `
CREATE TABLE IF NOT EXISTS finding_identities (
    id           TEXT PRIMARY KEY,
    tenant       TEXT NOT NULL DEFAULT '',
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    finding_code TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_identities_target ON finding_identities(tenant, target_type, target_id);`

type sqlFindingIdentityStore struct {
	db       *sql.DB
	postgres bool
}

func (s *sqlFindingIdentityStore) ph(n int) string {
	if s.postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *sqlFindingIdentityStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, findingIdentitySchema)
	return err
}

func (s *sqlFindingIdentityStore) Observe(ctx context.Context, keys []FindingKey, now time.Time) error {
	if len(keys) == 0 {
		return nil
	}
	if len(keys) > maxObservedFindings {
		keys = keys[:maxObservedFindings]
	}
	ts := now.UTC().Format(time.RFC3339)
	cutoff := now.UTC().Add(-findingIdentityThrottle).Format(time.RFC3339)
	q := fmt.Sprintf(`INSERT INTO finding_identities (id, tenant, target_type, target_id, finding_code, first_seen, last_seen)
		VALUES (%s,%s,%s,%s,%s,%s,%s)
		ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen WHERE finding_identities.last_seen < %s`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, k := range keys {
		if _, err := stmt.ExecContext(ctx, k.id(), k.Tenant, k.TargetType, k.TargetID, k.Code, ts, ts, cutoff); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *sqlFindingIdentityStore) Get(ctx context.Context, id string) (FindingIdentity, bool, error) {
	var f FindingIdentity
	err := s.db.QueryRowContext(ctx, `SELECT id, tenant, target_type, target_id, finding_code, first_seen, last_seen
		FROM finding_identities WHERE id = `+s.ph(1), id).
		Scan(&f.ID, &f.Tenant, &f.TargetType, &f.TargetID, &f.FindingCode, &f.FirstSeen, &f.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return FindingIdentity{}, false, nil
	}
	if err != nil {
		return FindingIdentity{}, false, err
	}
	return f, true, nil
}

// newFindingIdentityStoreFromEnv opens the same DB as the exception store.
func newFindingIdentityStoreFromEnv() (FindingIdentityStore, error) {
	state := newDBProviderState[FindingIdentityStore](
		"finding-identity",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_FINDINGS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_FINDINGS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_FINDINGS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) FindingIdentityStore { return &sqlFindingIdentityStore{db: db} },
		func(db *sql.DB) FindingIdentityStore { return &sqlFindingIdentityStore{db: db, postgres: true} },
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// observeFindingIdentities persists the funnel's identities, best-effort: a
// nil store or a write error is logged and ignored, because a report must
// never fail on identity bookkeeping.
func observeFindingIdentities(ctx context.Context, store FindingIdentityStore, keys []FindingKey) {
	if store == nil || len(keys) == 0 {
		return
	}
	if err := store.Observe(ctx, keys, time.Now()); err != nil {
		logging.Infof("finding identities not recorded (funnel counts unaffected): %v", err)
	}
}
