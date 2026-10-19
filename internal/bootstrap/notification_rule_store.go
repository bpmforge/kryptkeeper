// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"kryptkeeper/internal/logging"
)

var errNotificationSilenceNotFound = errors.New("notification silence not found")

// Fixed target-type values a silence can scope to — D-033/W1-06's "a rule
// can target/silence a specific cert/CA/template." Deliberately a NEW,
// standalone concept rather than an extension of NotificationRule
// (notification_provider.go, out of this ticket's write_scope, and shared by
// both the file and DB notification providers — adding a field there would
// force every implementation to handle it). A silence is orthogonal to the
// existing threshold/channel/target rule CRUD: it does not change what a
// rule alerts on, it unconditionally suppresses the renewal-reminder
// dispatch for one specific target, independent of any rule's Enabled flag
// (an earlier design considered overloading Enabled for this — rejected:
// "disabled" and "actively suppressing a target" are different meanings and
// conflating them would invert the semantics of a false Enabled value).
const (
	SilenceTargetCertificate = "certificate"
	SilenceTargetCA          = "ca"
	SilenceTargetTemplate    = "template"
)

// NotificationSilence suppresses renewal-reminder notifications for one
// specific certificate, CA, or template — an operator's explicit "stop
// alerting me about this" for a target already tracked by the renewal
// scheduler.
type NotificationSilence struct {
	ID         string `json:"id"`
	TargetType string `json:"target_type"` // certificate | ca | template
	TargetID   string `json:"target_id"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  string `json:"created_at"`
	// Tenant is the creator's tenant ("" = legacy row, default tenant). Not
	// serialised; enforced server-side.
	Tenant string `json:"-"`
}

// NotificationSilenceStore persists per-target silences.
type NotificationSilenceStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, s NotificationSilence) error
	IsSilenced(ctx context.Context, targetType, targetID string) (bool, error)
	ListForTarget(ctx context.Context, targetType, targetID string) ([]NotificationSilence, error)
	Delete(ctx context.Context, id string) error
}

const notificationSilenceSchema = `
CREATE TABLE IF NOT EXISTS notification_silences (
    id          TEXT PRIMARY KEY,
    target_type TEXT NOT NULL
                 CHECK (target_type IN ('certificate', 'ca', 'template')),
    target_id   TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    tenant      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_notification_silences_target ON notification_silences(target_type, target_id);`

func newNotificationSilenceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sil-" + hex.EncodeToString(b), nil
}

// --- SQLite implementation ---

type sqliteNotificationSilenceStore struct{ db *sql.DB }

func (s *sqliteNotificationSilenceStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, notificationSilenceSchema); err != nil {
		return err
	}
	// A table created before migration 000082 lacks the tenant column; SQLite has
	// no ADD COLUMN IF NOT EXISTS, so a duplicate-column error is the steady state.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE notification_silences ADD COLUMN tenant TEXT NOT NULL DEFAULT ''") // best-effort upgrade
	return nil
}

func (s *sqliteNotificationSilenceStore) Create(ctx context.Context, sil NotificationSilence) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_silences (id, target_type, target_id, created_by, created_at, tenant)
		VALUES (?, ?, ?, ?, ?, ?)`,
		sil.ID, sil.TargetType, sil.TargetID, sil.CreatedBy, sil.CreatedAt, sil.Tenant)
	return err
}

func (s *sqliteNotificationSilenceStore) IsSilenced(ctx context.Context, targetType, targetID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM notification_silences WHERE target_type = ? AND target_id = ?",
		targetType, targetID).Scan(&n)
	return n > 0, err
}

func (s *sqliteNotificationSilenceStore) ListForTarget(ctx context.Context, targetType, targetID string) ([]NotificationSilence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_type, target_id, created_by, created_at, tenant
		FROM notification_silences WHERE target_type = ? AND target_id = ?
		ORDER BY created_at DESC`, targetType, targetID)
	if err != nil {
		return nil, err
	}
	return scanNotificationSilenceRows(rows)
}

// Get returns one silence by id (used for the tenant ownership check on delete).
func (s *sqliteNotificationSilenceStore) Get(ctx context.Context, id string) (NotificationSilence, error) {
	return getNotificationSilenceRow(ctx, s.db, "SELECT id, target_type, target_id, created_by, created_at, tenant FROM notification_silences WHERE id = ?", id)
}

func (s *sqliteNotificationSilenceStore) Delete(ctx context.Context, id string) error {
	return deleteNotificationSilenceRow(ctx, s.db, "DELETE FROM notification_silences WHERE id = ?", id)
}

// --- Postgres implementation ---

type postgresNotificationSilenceStore struct{ db *sql.DB }

func (s *postgresNotificationSilenceStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, notificationSilenceSchema); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "ALTER TABLE notification_silences ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT ''")
	return err
}

func (s *postgresNotificationSilenceStore) Create(ctx context.Context, sil NotificationSilence) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_silences (id, target_type, target_id, created_by, created_at, tenant)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		sil.ID, sil.TargetType, sil.TargetID, sil.CreatedBy, sil.CreatedAt, sil.Tenant)
	return err
}

func (s *postgresNotificationSilenceStore) IsSilenced(ctx context.Context, targetType, targetID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM notification_silences WHERE target_type = $1 AND target_id = $2",
		targetType, targetID).Scan(&n)
	return n > 0, err
}

func (s *postgresNotificationSilenceStore) ListForTarget(ctx context.Context, targetType, targetID string) ([]NotificationSilence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_type, target_id, created_by, created_at, tenant
		FROM notification_silences WHERE target_type = $1 AND target_id = $2
		ORDER BY created_at DESC`, targetType, targetID)
	if err != nil {
		return nil, err
	}
	return scanNotificationSilenceRows(rows)
}

func (s *postgresNotificationSilenceStore) Get(ctx context.Context, id string) (NotificationSilence, error) {
	return getNotificationSilenceRow(ctx, s.db, "SELECT id, target_type, target_id, created_by, created_at, tenant FROM notification_silences WHERE id = $1", id)
}

func (s *postgresNotificationSilenceStore) Delete(ctx context.Context, id string) error {
	return deleteNotificationSilenceRow(ctx, s.db, "DELETE FROM notification_silences WHERE id = $1", id)
}

// --- shared helpers ---

func scanNotificationSilenceRows(rows *sql.Rows) ([]NotificationSilence, error) {
	defer rows.Close()
	items := []NotificationSilence{}
	for rows.Next() {
		var s NotificationSilence
		if err := rows.Scan(&s.ID, &s.TargetType, &s.TargetID, &s.CreatedBy, &s.CreatedAt, &s.Tenant); err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	return items, rows.Err()
}

func getNotificationSilenceRow(ctx context.Context, db *sql.DB, query, id string) (NotificationSilence, error) {
	var sil NotificationSilence
	err := db.QueryRowContext(ctx, query, id).Scan(&sil.ID, &sil.TargetType, &sil.TargetID, &sil.CreatedBy, &sil.CreatedAt, &sil.Tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationSilence{}, errNotificationSilenceNotFound
	}
	return sil, err
}

func deleteNotificationSilenceRow(ctx context.Context, db *sql.DB, query, id string) error {
	res, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotificationSilenceNotFound
	}
	return nil
}

// newNotificationSilenceStoreFromEnv opens the same SQLite/Postgres DB as
// other providers and self-heals its schema (G-33 pattern). Not yet wired
// into any handler for Create/Delete/List — phase 1 (W1-06) wires only the
// read path (IsSilenced) into the renewal scheduler's dispatch;
// handlers_notifications.go, the only place a Create/Delete/List endpoint
// could live, is not in this ticket's write_scope. There is currently NO
// operator-facing way to create a silence in a running system — see G-60 in
// DESIGN_REVIEW.md, split into ticket W1-10 (not just a comment; W1-10 is a
// real board entry, following the W4-02→W4-05 split precedent).
func newNotificationSilenceStoreFromEnv() (NotificationSilenceStore, error) {
	state := newDBProviderState[NotificationSilenceStore](
		"notification-silence",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_NOTIFICATION_SILENCE_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_NOTIFICATION_SILENCE_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_NOTIFICATION_SILENCE_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) NotificationSilenceStore { return &sqliteNotificationSilenceStore{db: db} },
		func(db *sql.DB) NotificationSilenceStore { return &postgresNotificationSilenceStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// newNotificationSilenceStoreFromEnvLogged is the soft-fail wrapper used at
// scheduler construction time: a silence-store outage should degrade (no
// silencing enforced) rather than prevent the scheduler from starting.
func newNotificationSilenceStoreFromEnvLogged() NotificationSilenceStore {
	store, err := newNotificationSilenceStoreFromEnv()
	if err != nil {
		logging.Warnf("renewal scheduler: notification-silence store unavailable, silencing will not be enforced: %v", err)
		return nil
	}
	return store
}

// NotificationRuleOption carries the W30-01 per-rule settings that cannot live
// on NotificationRule (shared by the file and DB providers): a percent-of-
// lifetime threshold and a template scope. A rule without a row is a plain
// absolute-days rule scoped to every template.
type NotificationRuleOption struct {
	RuleID       string
	ThresholdPct *int // nil = absolute-days rule; 0..100, 0 = EXPIRED
	TemplateID   string
	Tenant       string
}

// NotificationRuleOptionsStore persists NotificationRuleOption rows by rule id.
type NotificationRuleOptionsStore interface {
	EnsureSchema(ctx context.Context) error
	Set(ctx context.Context, o NotificationRuleOption) error
	List(ctx context.Context) (map[string]NotificationRuleOption, error)
	Delete(ctx context.Context, ruleID string) error
}

const notificationRuleOptionsSchema = `
CREATE TABLE IF NOT EXISTS notification_rule_options (
    rule_id       TEXT PRIMARY KEY,
    threshold_pct INTEGER,
    template_id   TEXT NOT NULL DEFAULT '',
    tenant        TEXT NOT NULL DEFAULT ''
);`

type sqliteNotificationRuleOptionsStore struct{ db *sql.DB }

func (s *sqliteNotificationRuleOptionsStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, notificationRuleOptionsSchema)
	return err
}

func (s *sqliteNotificationRuleOptionsStore) Set(ctx context.Context, o NotificationRuleOption) error {
	return setNotificationRuleOption(ctx, s.db, `
INSERT INTO notification_rule_options (rule_id, threshold_pct, template_id, tenant) VALUES (?, ?, ?, ?)
ON CONFLICT (rule_id) DO UPDATE SET threshold_pct = excluded.threshold_pct, template_id = excluded.template_id, tenant = excluded.tenant`, o)
}

func (s *sqliteNotificationRuleOptionsStore) List(ctx context.Context) (map[string]NotificationRuleOption, error) {
	return listNotificationRuleOptions(ctx, s.db)
}

func (s *sqliteNotificationRuleOptionsStore) Delete(ctx context.Context, ruleID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM notification_rule_options WHERE rule_id = ?", ruleID)
	return err
}

type postgresNotificationRuleOptionsStore struct{ db *sql.DB }

func (s *postgresNotificationRuleOptionsStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, notificationRuleOptionsSchema)
	return err
}

func (s *postgresNotificationRuleOptionsStore) Set(ctx context.Context, o NotificationRuleOption) error {
	return setNotificationRuleOption(ctx, s.db, `
INSERT INTO notification_rule_options (rule_id, threshold_pct, template_id, tenant) VALUES ($1, $2, $3, $4)
ON CONFLICT (rule_id) DO UPDATE SET threshold_pct = excluded.threshold_pct, template_id = excluded.template_id, tenant = excluded.tenant`, o)
}

func (s *postgresNotificationRuleOptionsStore) List(ctx context.Context) (map[string]NotificationRuleOption, error) {
	return listNotificationRuleOptions(ctx, s.db)
}

func (s *postgresNotificationRuleOptionsStore) Delete(ctx context.Context, ruleID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM notification_rule_options WHERE rule_id = $1", ruleID)
	return err
}

func setNotificationRuleOption(ctx context.Context, db *sql.DB, query string, o NotificationRuleOption) error {
	var pct any // NULL for an absolute-days rule
	if o.ThresholdPct != nil {
		pct = *o.ThresholdPct
	}
	_, err := db.ExecContext(ctx, query, o.RuleID, pct, o.TemplateID, o.Tenant)
	return err
}

func listNotificationRuleOptions(ctx context.Context, db *sql.DB) (map[string]NotificationRuleOption, error) {
	rows, err := db.QueryContext(ctx, "SELECT rule_id, threshold_pct, template_id, tenant FROM notification_rule_options")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]NotificationRuleOption{}
	for rows.Next() {
		var o NotificationRuleOption
		var pct sql.NullInt64
		if err := rows.Scan(&o.RuleID, &pct, &o.TemplateID, &o.Tenant); err != nil {
			return nil, err
		}
		if pct.Valid {
			v := int(pct.Int64)
			o.ThresholdPct = &v
		}
		out[o.RuleID] = o
	}
	return out, rows.Err()
}

func newNotificationRuleOptionsStoreFromEnv() (NotificationRuleOptionsStore, error) {
	state := newDBProviderState[NotificationRuleOptionsStore](
		"notification-rule-options",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_NOTIFICATION_RULE_OPTIONS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_NOTIFICATION_RULE_OPTIONS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_NOTIFICATION_RULE_OPTIONS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) NotificationRuleOptionsStore { return &sqliteNotificationRuleOptionsStore{db: db} },
		func(db *sql.DB) NotificationRuleOptionsStore { return &postgresNotificationRuleOptionsStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// newNotificationRuleOptionsStoreFromEnvLogged soft-fails: without the store
// every rule evaluates as a plain days rule and pct rules cannot be created.
func newNotificationRuleOptionsStoreFromEnvLogged() NotificationRuleOptionsStore {
	store, err := newNotificationRuleOptionsStoreFromEnv()
	if err != nil {
		logging.Warnf("notification rule-options store unavailable, percent/template rule options disabled: %v", err)
		return nil
	}
	return store
}

var (
	errNotificationTeamRouteNotFound = errors.New("notification team route not found")
	errNotificationTeamRouteExists   = errors.New("notification team route already exists")
)

// globalInboxTeam is the owner_team value of the global inbox: the routes a
// routed rule falls back to when the certificate's own team has none.
const globalInboxTeam = "*"

// NotificationTeamRoute sends a routed rule's alerts for one owner team's
// certificates to one target on one channel. OwnerTeam "*" is the global inbox.
type NotificationTeamRoute struct {
	ID        string `json:"id"`
	OwnerTeam string `json:"owner_team"`
	Channel   string `json:"channel"`
	Target    string `json:"target"`
	// Tenant is the creator's tenant ("" = default tenant). Not serialised.
	Tenant string `json:"-"`
}

// NotificationTeamRouteStore persists the owner_team routing table.
type NotificationTeamRouteStore interface {
	EnsureSchema(ctx context.Context) error
	// Create returns errNotificationTeamRouteExists for a duplicate
	// (owner_team, channel, target).
	Create(ctx context.Context, r NotificationTeamRoute) error
	List(ctx context.Context) ([]NotificationTeamRoute, error)
	Get(ctx context.Context, id string) (NotificationTeamRoute, error)
	Delete(ctx context.Context, id string) error
}

const notificationTeamRouteSchema = `
CREATE TABLE IF NOT EXISTS notification_team_routes (
    id         TEXT PRIMARY KEY,
    owner_team TEXT NOT NULL,
    channel    TEXT NOT NULL,
    target     TEXT NOT NULL,
    tenant     TEXT NOT NULL DEFAULT '',
    UNIQUE (owner_team, channel, target)
);`

func newNotificationTeamRouteID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "route-" + hex.EncodeToString(b), nil
}

// sqlite and postgres differ only in placeholder syntax, so one implementation
// carries the placeholders.
type sqlNotificationTeamRouteStore struct {
	db *sql.DB
	ph func(n int) string
}

func (s *sqlNotificationTeamRouteStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, notificationTeamRouteSchema)
	return err
}

func (s *sqlNotificationTeamRouteStore) Create(ctx context.Context, r NotificationTeamRoute) error {
	res, err := s.db.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO notification_team_routes (id, owner_team, channel, target, tenant)
VALUES (%s, %s, %s, %s, %s) ON CONFLICT (owner_team, channel, target) DO NOTHING`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5)),
		r.ID, r.OwnerTeam, r.Channel, r.Target, r.Tenant)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotificationTeamRouteExists
	}
	return nil
}

func (s *sqlNotificationTeamRouteStore) List(ctx context.Context) ([]NotificationTeamRoute, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, owner_team, channel, target, tenant FROM notification_team_routes ORDER BY owner_team, channel, target")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationTeamRoute{}
	for rows.Next() {
		var r NotificationTeamRoute
		if err := rows.Scan(&r.ID, &r.OwnerTeam, &r.Channel, &r.Target, &r.Tenant); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqlNotificationTeamRouteStore) Get(ctx context.Context, id string) (NotificationTeamRoute, error) {
	var r NotificationTeamRoute
	err := s.db.QueryRowContext(ctx,
		"SELECT id, owner_team, channel, target, tenant FROM notification_team_routes WHERE id = "+s.ph(1), id).
		Scan(&r.ID, &r.OwnerTeam, &r.Channel, &r.Target, &r.Tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationTeamRoute{}, errNotificationTeamRouteNotFound
	}
	return r, err
}

func (s *sqlNotificationTeamRouteStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM notification_team_routes WHERE id = "+s.ph(1), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotificationTeamRouteNotFound
	}
	return nil
}

func newNotificationTeamRouteStoreFromEnv() (NotificationTeamRouteStore, error) {
	state := newDBProviderState[NotificationTeamRouteStore](
		"notification-team-routes",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_NOTIFICATION_ROUTE_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_NOTIFICATION_ROUTE_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_NOTIFICATION_ROUTE_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) NotificationTeamRouteStore {
			return &sqlNotificationTeamRouteStore{db: db, ph: func(int) string { return "?" }}
		},
		func(db *sql.DB) NotificationTeamRouteStore {
			return &sqlNotificationTeamRouteStore{db: db, ph: func(n int) string { return fmt.Sprintf("$%d", n) }}
		},
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// newNotificationTeamRouteStoreFromEnvLogged soft-fails: without the store a
// routed rule has no routes and queues to the dashboard.
func newNotificationTeamRouteStoreFromEnvLogged() NotificationTeamRouteStore {
	store, err := newNotificationTeamRouteStoreFromEnv()
	if err != nil {
		logging.Warnf("notification team-route store unavailable, routed rules will queue to the dashboard: %v", err)
		return nil
	}
	return store
}
