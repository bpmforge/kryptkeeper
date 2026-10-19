// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

// W34-06 (D-205): the operator's declared "CA groups". A row says "certificates
// from this issuer are ours to accept", which is what separates an
// authorized-external certificate from one issued by a CA nobody here knows.
// Tenant is the stored form used by the other discovery tables: "" is the
// default tenant.

var (
	errAuthorizedIssuerNotFound = errors.New("authorized issuer not found")
	errAuthorizedIssuerExists   = errors.New("authorized issuer already exists")
)

const (
	authorizedIssuerNameMax  = 200
	authorizedIssuerNotesMax = 1000
	authorizedIssuerValueMax = 64 << 10
)

// AuthorizedIssuer is one declared issuer.
type AuthorizedIssuer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"` // ca_cert | issuer_dn | spki_sha256
	Value     string `json:"value"`
	Notes     string `json:"notes,omitempty"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	// Tenant is the stored tenant ("" = DefaultTenant); never serialized.
	Tenant string `json:"-"`
}

type authorizedIssuerStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, a AuthorizedIssuer) error
	Get(ctx context.Context, id string) (AuthorizedIssuer, error)
	// List returns the issuers of one stored tenant; tenant == nil means every
	// tenant (an unscoped administrator).
	List(ctx context.Context, tenant *string) ([]AuthorizedIssuer, error)
	Delete(ctx context.Context, id string) error
}

// authorizedIssuerSchema mirrors migration 000341 so the store self-heals on a
// database the migrations have not reached (G-33).
const authorizedIssuerSchema = `
CREATE TABLE IF NOT EXISTS authorized_issuers (
    id          TEXT PRIMARY KEY,
    tenant      TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('ca_cert', 'issuer_dn', 'spki_sha256')),
    value       TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorized_issuers_identity ON authorized_issuers(tenant, kind, value);`

func newAuthorizedIssuerID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b) // crypto/rand does not fail on supported platforms
	return "ai-" + hex.EncodeToString(b)
}

var spkiHexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validateAuthorizedIssuer checks the request and returns the canonical value
// that is stored and matched: PEM re-encoded from the parsed certificates, a
// whitespace-normalised DN, a lower-case hash. A ca_cert must be a CA: an end
// entity certificate would authorize one server, not an issuer.
func validateAuthorizedIssuer(a AuthorizedIssuer) (AuthorizedIssuer, error) {
	a.Name = strings.TrimSpace(a.Name)
	a.Notes = strings.TrimSpace(a.Notes)
	if a.Name == "" || len(a.Name) > authorizedIssuerNameMax {
		return a, errors.New("name is required (at most 200 characters)")
	}
	if len(a.Notes) > authorizedIssuerNotesMax {
		return a, errors.New("notes must be at most 1000 characters")
	}
	v := strings.TrimSpace(a.Value)
	if v == "" || len(v) > authorizedIssuerValueMax {
		return a, errors.New("value is required")
	}
	switch a.Kind {
	case scanner.IssuerRuleDN:
		if !strings.Contains(v, "=") || len(v) > 1024 {
			return a, errors.New("issuer_dn value must be a distinguished name such as CN=Corp Issuing CA,O=Corp")
		}
		a.Value = v
	case scanner.IssuerRuleSPKI:
		v = strings.ToLower(strings.ReplaceAll(v, ":", ""))
		if !spkiHexRe.MatchString(v) {
			return a, errors.New("spki_sha256 value must be 64 hexadecimal characters")
		}
		a.Value = v
	case scanner.IssuerRuleCACert:
		certs := parseCACertsPEM(v)
		if len(certs) == 0 {
			return a, errors.New("ca_cert value must be a PEM certificate")
		}
		var out strings.Builder
		for _, c := range certs {
			if !c.IsCA {
				return a, errors.New("ca_cert must be a CA certificate (basicConstraints CA:TRUE)")
			}
			out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
		a.Value = out.String()
	default:
		return a, errors.New("kind must be one of ca_cert, issuer_dn, spki_sha256")
	}
	return a, nil
}

// authorizedIssuerAnchors turns declared issuers into the scanner's anchor
// inputs. A ca_cert contributes its certificates; the other kinds are rules.
func authorizedIssuerAnchors(list []AuthorizedIssuer) ([]*x509.Certificate, []scanner.IssuerRule) {
	var certs []*x509.Certificate
	var rules []scanner.IssuerRule
	for _, a := range list {
		if a.Kind == scanner.IssuerRuleCACert {
			certs = append(certs, parseCACertsPEM(a.Value)...)
			continue
		}
		rules = append(rules, scanner.IssuerRule{Kind: a.Kind, Value: a.Value})
	}
	return certs, rules
}

// ---- SQL (sqlite + postgres) ----

type dbAuthorizedIssuerStore struct {
	db *sql.DB
	ph func(n int) string
}

func (s *dbAuthorizedIssuerStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, authorizedIssuerSchema)
	return err
}

func (s *dbAuthorizedIssuerStore) Create(ctx context.Context, a AuthorizedIssuer) error {
	q := fmt.Sprintf(`INSERT INTO authorized_issuers (id, tenant, name, kind, value, notes, created_by, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s)`, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8))
	_, err := s.db.ExecContext(ctx, q, a.ID, a.Tenant, a.Name, a.Kind, a.Value, a.Notes, a.CreatedBy, a.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return errAuthorizedIssuerExists
	}
	return err
}

const authorizedIssuerColumns = `id, tenant, name, kind, value, notes, created_by, created_at`

func scanAuthorizedIssuer(sc interface{ Scan(...any) error }) (AuthorizedIssuer, error) {
	var a AuthorizedIssuer
	err := sc.Scan(&a.ID, &a.Tenant, &a.Name, &a.Kind, &a.Value, &a.Notes, &a.CreatedBy, &a.CreatedAt)
	return a, err
}

func (s *dbAuthorizedIssuerStore) Get(ctx context.Context, id string) (AuthorizedIssuer, error) {
	a, err := scanAuthorizedIssuer(s.db.QueryRowContext(ctx,
		`SELECT `+authorizedIssuerColumns+` FROM authorized_issuers WHERE id = `+s.ph(1), id))
	if errors.Is(err, sql.ErrNoRows) {
		return AuthorizedIssuer{}, errAuthorizedIssuerNotFound
	}
	return a, err
}

func (s *dbAuthorizedIssuerStore) List(ctx context.Context, tenant *string) ([]AuthorizedIssuer, error) {
	q, args := `SELECT `+authorizedIssuerColumns+` FROM authorized_issuers`, []any{}
	if tenant != nil {
		q += ` WHERE tenant = ` + s.ph(1)
		args = append(args, *tenant)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at ASC, id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuthorizedIssuer{}
	for rows.Next() {
		a, err := scanAuthorizedIssuer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *dbAuthorizedIssuerStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM authorized_issuers WHERE id = `+s.ph(1), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errAuthorizedIssuerNotFound
	}
	return nil
}

// ---- in-memory (tests, handler fixtures) ----

type memoryAuthorizedIssuerStore struct {
	mu   sync.Mutex
	rows []AuthorizedIssuer
}

func (m *memoryAuthorizedIssuerStore) EnsureSchema(context.Context) error { return nil }

func (m *memoryAuthorizedIssuerStore) Create(_ context.Context, a AuthorizedIssuer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.Tenant == a.Tenant && r.Kind == a.Kind && r.Value == a.Value {
			return errAuthorizedIssuerExists
		}
	}
	m.rows = append(m.rows, a)
	return nil
}

func (m *memoryAuthorizedIssuerStore) Get(_ context.Context, id string) (AuthorizedIssuer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.ID == id {
			return r, nil
		}
	}
	return AuthorizedIssuer{}, errAuthorizedIssuerNotFound
}

func (m *memoryAuthorizedIssuerStore) List(_ context.Context, tenant *string) ([]AuthorizedIssuer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []AuthorizedIssuer{}
	for _, r := range m.rows {
		if tenant == nil || r.Tenant == *tenant {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memoryAuthorizedIssuerStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.rows {
		if r.ID == id {
			m.rows = append(m.rows[:i], m.rows[i+1:]...)
			return nil
		}
	}
	return errAuthorizedIssuerNotFound
}

// newAuthorizedIssuerStoreFromEnv opens the discovery database and ensures the
// schema; nil when unavailable, which the handlers answer with 503.
func newAuthorizedIssuerStoreFromEnv() authorizedIssuerStore {
	state := newDBProviderState[authorizedIssuerStore](
		"authorized-issuer",
		discoveryDBSQLiteDSNFromEnv,
		discoveryDBPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_DISCOVERY_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) authorizedIssuerStore { return &dbAuthorizedIssuerStore{db: db, ph: sqlitePlaceholder} },
		func(db *sql.DB) authorizedIssuerStore {
			return &dbAuthorizedIssuerStore{db: db, ph: postgresPlaceholder}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("authorized-issuer", state.openErr) // logs the outage itself
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("authorized-issuer", err) // logs the outage itself
		return nil
	}
	return state.store
}

// authorizedIssuerNow is the clock for created_at, a variable for tests.
var authorizedIssuerNow = func() time.Time { return time.Now().UTC() }
