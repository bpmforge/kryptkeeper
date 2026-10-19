// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"kryptkeeper/internal/logging"
)

// W27-04: fleet-level renewal policy. A target group holds a renewal threshold
// that its member targets inherit unless they carry their own.

// maxGroupThresholdDays is the group bound the acceptance asks for. It is wider
// than the per-target bound (maxRenewalThresholdDays, 365) on purpose; a 398-day
// threshold stays safe because effectiveThresholdDays still caps successors at
// half their life.
const maxGroupThresholdDays = 398

var (
	errGroupInvalidThreshold = errors.New("renewal_threshold_days must be between 1 and 398 days")
	errGroupInvalidName      = errors.New("group name must be 1-64 characters of letters, digits, '.', '_' or '-'")
	errTargetGroupNotFound   = errors.New("target group not found")
	groupNameRE              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

func validateGroupThresholdDays(d int) error {
	if d < 1 || d > maxGroupThresholdDays {
		return errGroupInvalidThreshold
	}
	return nil
}

func validateGroupName(name string) error {
	if !groupNameRE.MatchString(name) {
		return errGroupInvalidName
	}
	return nil
}

// Where a target's effective threshold came from.
const (
	thresholdSourceTarget  = "target"
	thresholdSourceGroup   = "group"
	thresholdSourceDefault = "default"
)

// effectiveTargetThreshold resolves a target's own override, then its group's,
// then the global default. A target with its own threshold wins even when its
// group's is larger.
func effectiveTargetThreshold(t ManagedTarget, groupDays, defaultDays int) (days int, source string) {
	switch {
	case t.RenewalThresholdDays > 0:
		return t.RenewalThresholdDays, thresholdSourceTarget
	case groupDays > 0:
		return groupDays, thresholdSourceGroup
	default:
		return defaultDays, thresholdSourceDefault
	}
}

// TargetGroup is a named set of targets sharing one renewal threshold. A target
// belongs to at most one group.
type TargetGroup struct {
	Name                 string   `json:"name"`
	Tenant               string   `json:"tenant"`
	RenewalThresholdDays int      `json:"renewal_threshold_days"`
	TargetIDs            []string `json:"target_ids"`
}

type TargetGroupStore interface {
	EnsureSchema(ctx context.Context) error
	// List returns every group with its members.
	List(ctx context.Context) ([]TargetGroup, error)
	// Upsert creates or replaces g and its membership. A target already in
	// another group is moved here.
	Upsert(ctx context.Context, g TargetGroup) (TargetGroup, error)
	// Delete returns errTargetGroupNotFound when the group does not exist.
	Delete(ctx context.Context, tenant, name string) error
}

// groupDaysByTarget flattens groups into target id -> group threshold.
func groupDaysByTarget(groups []TargetGroup) map[string]int {
	out := map[string]int{}
	for _, g := range groups {
		for _, id := range g.TargetIDs {
			out[id] = g.RenewalThresholdDays
		}
	}
	return out
}

// targetGroupSchema mirrors migration 000201_target_groups (self-heal, G-33).
const targetGroupSchema = `
CREATE TABLE IF NOT EXISTS target_groups (
    tenant                 TEXT NOT NULL DEFAULT 'default',
    name                   TEXT NOT NULL,
    renewal_threshold_days INTEGER NOT NULL CHECK (renewal_threshold_days BETWEEN 1 AND 398),
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    PRIMARY KEY (tenant, name)
);
CREATE TABLE IF NOT EXISTS target_group_members (
    target_id  TEXT PRIMARY KEY,
    tenant     TEXT NOT NULL,
    group_name TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tgm_group ON target_group_members(tenant, group_name);`

// sqlTargetGroupStore serves both engines; only the placeholder style differs.
type sqlTargetGroupStore struct {
	db       *sql.DB
	postgres bool
}

func (s *sqlTargetGroupStore) q(query string) string {
	if !s.postgres {
		return query
	}
	return rebindToDollar(query)
}

func (s *sqlTargetGroupStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, targetGroupSchema)
	return err
}

func (s *sqlTargetGroupStore) List(ctx context.Context) ([]TargetGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant, name, renewal_threshold_days FROM target_groups ORDER BY tenant, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TargetGroup{}
	index := map[[2]string]int{}
	for rows.Next() {
		g := TargetGroup{TargetIDs: []string{}}
		if err := rows.Scan(&g.Tenant, &g.Name, &g.RenewalThresholdDays); err != nil {
			return nil, err
		}
		index[[2]string{g.Tenant, g.Name}] = len(out)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	members, err := s.db.QueryContext(ctx, `SELECT tenant, group_name, target_id FROM target_group_members ORDER BY target_id`)
	if err != nil {
		return nil, err
	}
	defer members.Close()
	for members.Next() {
		var tenant, group, id string
		if err := members.Scan(&tenant, &group, &id); err != nil {
			return nil, err
		}
		if i, ok := index[[2]string{tenant, group}]; ok {
			out[i].TargetIDs = append(out[i].TargetIDs, id)
		}
	}
	return out, members.Err()
}

func (s *sqlTargetGroupStore) Upsert(ctx context.Context, g TargetGroup) (TargetGroup, error) {
	if err := validateGroupThresholdDays(g.RenewalThresholdDays); err != nil {
		return TargetGroup{}, err
	}
	if g.Tenant == "" {
		g.Tenant = DefaultTenant
	}
	ids := slices.Clone(g.TargetIDs)
	slices.Sort(ids)
	g.TargetIDs = slices.Compact(ids)
	if g.TargetIDs == nil {
		g.TargetIDs = []string{}
	}
	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TargetGroup{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO target_groups (tenant, name, renewal_threshold_days, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (tenant, name) DO UPDATE SET renewal_threshold_days = excluded.renewal_threshold_days, updated_at = excluded.updated_at`),
		g.Tenant, g.Name, g.RenewalThresholdDays, now, now); err != nil {
		return TargetGroup{}, err
	}
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM target_group_members WHERE tenant = ? AND group_name = ?`), g.Tenant, g.Name); err != nil {
		return TargetGroup{}, err
	}
	for _, id := range g.TargetIDs {
		if _, err := tx.ExecContext(ctx, s.q(`
			INSERT INTO target_group_members (target_id, tenant, group_name) VALUES (?, ?, ?)
			ON CONFLICT (target_id) DO UPDATE SET tenant = excluded.tenant, group_name = excluded.group_name`),
			id, g.Tenant, g.Name); err != nil {
			return TargetGroup{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return TargetGroup{}, err
	}
	return g, nil
}

func (s *sqlTargetGroupStore) Delete(ctx context.Context, tenant, name string) error {
	if tenant == "" {
		tenant = DefaultTenant
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	res, err := tx.ExecContext(ctx, s.q(`DELETE FROM target_groups WHERE tenant = ? AND name = ?`), tenant, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errTargetGroupNotFound
	}
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM target_group_members WHERE tenant = ? AND group_name = ?`), tenant, name); err != nil {
		return err
	}
	return tx.Commit()
}

func newTargetGroupStoreFromEnv() TargetGroupStore {
	state := newDBProviderState[TargetGroupStore](
		"target-group",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_TARGETS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) TargetGroupStore { return &sqlTargetGroupStore{db: db} },
		func(db *sql.DB) TargetGroupStore { return &sqlTargetGroupStore{db: db, postgres: true} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("target-group", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("target-group", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

// WithGroupStore arms group threshold inheritance. Nil means "no groups".
func (s *RenewalScheduler) WithGroupStore(g TargetGroupStore) *RenewalScheduler {
	s.groupStore = g
	return s
}

// tickGroupDays reads the groups once per tick (not per certificate), so a
// changed group threshold takes effect on the next tick with no restart. A read
// failure is logged and degrades to "no group thresholds": targets keep their
// own override and everything else uses the default, as before groups existed.
func (s *RenewalScheduler) tickGroupDays(ctx context.Context) map[string]int {
	if s.groupStore == nil {
		return nil
	}
	groups, err := s.groupStore.List(ctx)
	if err != nil {
		logging.Warnf("renewal scheduler: target group list failed, ignoring group thresholds this tick: %v", err)
		return nil
	}
	return groupDaysByTarget(groups)
}
