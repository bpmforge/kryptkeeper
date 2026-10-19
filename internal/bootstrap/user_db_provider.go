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
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// errUserStoreNotProvisioned marks "the users table does not exist": the hub
// has no provisioned user store (a hub that never ran the core migrations, such
// as a non-CA hub driven by the bootstrap token alone). It is not an outage:
// there are simply no users to collide with.
var errUserStoreNotProvisioned = errors.New("user store not provisioned")

// isMissingUsersTable recognises SQLite's and Postgres' "no such table" errors
// for the users table without importing driver error types.
func isMissingUsersTable(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no such table: users") ||
		(strings.Contains(msg, `relation "users" does not exist`))
}

type dbUserProvider struct {
	db       *sql.DB
	openErr  error
	postgres bool
}

// q rewrites ?-style placeholders to $n for Postgres.
func (p *dbUserProvider) q(query string) string {
	if !p.postgres {
		return query
	}
	return rebindPostgres(query)
}

// userSelectColumns is engine-neutral: last_login_at is timestamptz on
// Postgres and TEXT on SQLite, so it is scanned as a nullable value instead of
// being COALESCEd to ” (which Postgres rejects for timestamptz).
const userSelectColumns = "id, email, role, active, last_login_at, created_at, tenant"

// userRowScanner is the Scan half of *sql.Row / *sql.Rows.
type userRowScanner interface{ Scan(dest ...any) error }

// scanUser reads userSelectColumns. active is a BOOLEAN on Postgres and an
// INTEGER 0/1 on SQLite; scanning into bool accepts both. Timestamps arrive as
// time.Time (Postgres) or string (SQLite) and are normalised by database/sql.
func scanUser(row userRowScanner) (UserRecord, error) {
	var u UserRecord
	var active bool
	var lastLogin sql.NullString
	if err := row.Scan(&u.ID, &u.Email, &u.Role, &active, &lastLogin, &u.CreatedAt, &u.Tenant); err != nil {
		return UserRecord{}, err
	}
	u.Status = statusFromActive(active)
	if lastLogin.Valid && lastLogin.String != "" {
		u.LastSeenAt = lastLogin.String
	}
	return u, nil
}

func newDBUserProviderFromEnv() UserProvider {
	postgres := false
	state := newDBProviderState[*sql.DB](
		"user",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_USER_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_USER_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_USER_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *sql.DB { return db },
		func(db *sql.DB) *sql.DB { postgres = true; return db },
	)
	return &dbUserProvider{db: state.store, openErr: state.openErr, postgres: postgres}
}

func (p *dbUserProvider) ListUsers(ctx context.Context) ([]UserRecord, error) {
	if err := dbProviderUnavailable("user", p.openErr); err != nil {
		return nil, err
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+userSelectColumns+`
		FROM users
		ORDER BY created_at ASC
	`)
	if err != nil {
		if isMissingUsersTable(err) {
			return nil, fmt.Errorf("%w: %v", errUserStoreNotProvisioned, err)
		}
		return nil, err
	}
	defer rows.Close()

	var out []UserRecord
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ts is the engine-correct timestamp argument: Postgres columns are
// timestamptz (bind a time.Time), SQLite columns are RFC 3339 TEXT.
func (p *dbUserProvider) ts(t time.Time) any {
	if p.postgres {
		return t
	}
	return t.UTC().Format(time.RFC3339)
}

// uuidRe matches the canonical 8-4-4-4-12 form. Postgres users.id is UUID, and
// comparing it with a malformed string is a driver error, not "no rows".
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// idPossible reports whether id can name a row at all on this engine.
func (p *dbUserProvider) idPossible(id string) bool {
	return !p.postgres || uuidRe.MatchString(id)
}

func (p *dbUserProvider) InviteUser(ctx context.Context, email string, role string) (UserRecord, error) {
	return p.InviteUserInTenant(ctx, email, role, "")
}

// InviteUserInTenant implements TenantUserInviter. DefaultTenant is stored as
// "" so legacy rows and new default-tenant rows are indistinguishable.
func (p *dbUserProvider) InviteUserInTenant(ctx context.Context, email, role, tenant string) (UserRecord, error) {
	if tenant == DefaultTenant {
		tenant = ""
	}
	if err := dbProviderUnavailable("user", p.openErr); err != nil {
		return UserRecord{}, err
	}
	now := time.Now().UTC()
	email = strings.TrimSpace(email)

	var id string
	if p.postgres {
		// users.id is UUID with a gen_random_uuid() default; let the database mint it.
		err := p.db.QueryRowContext(ctx, p.q(`
			INSERT INTO users (email, role, active, created_at, updated_at, tenant)
			VALUES (?, ?, ?, ?, ?, ?) RETURNING id::text
		`), email, role, true, p.ts(now), p.ts(now), tenant).Scan(&id)
		if err != nil {
			return UserRecord{}, err
		}
	} else {
		id = fmt.Sprintf("usr-%d", now.UnixNano())
		if _, err := p.db.ExecContext(ctx, `
			INSERT INTO users (id, email, role, active, created_at, updated_at, tenant)
			VALUES (?, ?, ?, 1, ?, ?, ?)
		`, id, email, role, p.ts(now), p.ts(now), tenant); err != nil {
			return UserRecord{}, err
		}
	}
	return UserRecord{
		ID:        id,
		Email:     email,
		Role:      role,
		Status:    "active",
		CreatedAt: now.Format(time.RFC3339),
		Tenant:    tenant,
	}, nil
}

func (p *dbUserProvider) UpdateUser(ctx context.Context, id string, role string, status string) (UserRecord, error) {
	if err := dbProviderUnavailable("user", p.openErr); err != nil {
		return UserRecord{}, err
	}
	if !p.idPossible(id) {
		return UserRecord{}, fmt.Errorf("user %q not found", id)
	}
	now := time.Now().UTC()

	setParts := []string{"updated_at = ?"}
	args := []any{p.ts(now)}
	if role != "" {
		setParts = append(setParts, "role = ?")
		args = append(args, role)
	}
	if status != "" {
		setParts = append(setParts, "active = ?")
		args = append(args, status != "deactivated")
	}
	args = append(args, id)

	_, err := p.db.ExecContext(ctx,
		p.q("UPDATE users SET "+strings.Join(setParts, ", ")+" WHERE id = ?"),
		args...,
	)
	if err != nil {
		return UserRecord{}, err
	}

	u, err := scanUser(p.db.QueryRowContext(ctx,
		p.q("SELECT "+userSelectColumns+" FROM users WHERE id = ?"), id))
	if err == sql.ErrNoRows {
		return UserRecord{}, fmt.Errorf("user %q not found", id)
	}
	if err != nil {
		return UserRecord{}, err
	}
	return u, nil
}

func (p *dbUserProvider) DeactivateUser(ctx context.Context, id string) error {
	if err := dbProviderUnavailable("user", p.openErr); err != nil {
		return err
	}
	if !p.idPossible(id) {
		return fmt.Errorf("user %q not found", id)
	}
	res, err := p.db.ExecContext(ctx,
		p.q("UPDATE users SET active = ?, updated_at = ? WHERE id = ?"),
		false, p.ts(time.Now().UTC()), id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user %q not found", id)
	}
	return nil
}

// LinkOIDCIdentity implements OIDCIdentityLinker (user_provider.go), storing
// the OIDC identity a SCIM-provisioned account authenticates as. Uses the
// oidc_subject/oidc_issuer columns migration 000001 already ships -- no
// schema change needed here.
func (p *dbUserProvider) LinkOIDCIdentity(ctx context.Context, userID string, issuer string, subject string) error {
	if err := dbProviderUnavailable("user", p.openErr); err != nil {
		return err
	}
	if !p.idPossible(userID) {
		return fmt.Errorf("user %q not found", userID)
	}
	_, err := p.db.ExecContext(ctx,
		p.q("UPDATE users SET oidc_subject = ?, oidc_issuer = ?, updated_at = ? WHERE id = ?"),
		strings.TrimSpace(subject), strings.TrimSpace(issuer), p.ts(time.Now().UTC()), userID,
	)
	return err
}

// FindByOIDCIdentity implements OIDCIdentityLinker (user_provider.go).
func (p *dbUserProvider) FindByOIDCIdentity(ctx context.Context, issuer string, subject string) (UserRecord, bool, error) {
	if err := dbProviderUnavailable("user", p.openErr); err != nil {
		return UserRecord{}, false, err
	}
	u, err := scanUser(p.db.QueryRowContext(ctx, p.q(`
		SELECT `+userSelectColumns+`
		FROM users WHERE oidc_subject = ? AND oidc_issuer = ?
	`), strings.TrimSpace(subject), strings.TrimSpace(issuer)))
	if err == sql.ErrNoRows {
		return UserRecord{}, false, nil
	}
	if err != nil {
		return UserRecord{}, false, err
	}
	return u, true, nil
}

func statusFromActive(active bool) string {
	if active {
		return "active"
	}
	return "deactivated"
}

// rebindPostgres rewrites ?-style placeholders to Postgres $1..$n.
func rebindPostgres(q string) string {
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
