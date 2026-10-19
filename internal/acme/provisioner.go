// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

// ACME provisioners (W26-02): named directories at /acme/<name>/directory,
// each bound to one CA, an optional enrollment template, a domain allow-list
// and a challenge-method policy. The default /acme/directory is untouched.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/ca"
)

// Provisioner is one named ACME directory.
type Provisioner struct {
	Name       string    `json:"name"`
	CAID       string    `json:"ca_id"`
	TemplateID string    `json:"template_id"`
	AllowNames []string  `json:"allow_names"`
	Challenges []string  `json:"challenges"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

var (
	// ErrProvisionerNotFound means no provisioner has that name.
	ErrProvisionerNotFound = errors.New("acme provisioner not found")
	// ErrProvisionerExists means the name is taken.
	ErrProvisionerExists = errors.New("acme provisioner already exists")
)

const maxProvisionerEntries = 100

var provisionerNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// reservedProvisionerNames are the first path segments the default directory
// already uses, plus "acme" and "api".
var reservedProvisionerNames = map[string]bool{
	"directory": true, "new-nonce": true, "new-account": true, "new-order": true, "order": true,
	"authz": true, "challenge": true, "finalize": true, "cert": true, "renewalInfo": true,
	"revoke-cert": true, "key-change": true, "account": true, "acme": true, "api": true,
}

// ValidateProvisioner returns an error whose text names the offending field
// or allow-list entry, or nil when p is acceptable.
func ValidateProvisioner(p Provisioner) error {
	switch {
	case !provisionerNamePattern.MatchString(p.Name):
		return errors.New("name must be 1-32 characters: lowercase letters, digits and hyphens, not starting or ending with a hyphen")
	case reservedProvisionerNames[p.Name]:
		return fmt.Errorf("name %q is reserved", p.Name)
	case strings.TrimSpace(p.CAID) == "":
		return errors.New("ca_id is required")
	case len(p.AllowNames) == 0:
		return errors.New("allow_names needs at least one entry")
	case len(p.AllowNames) > maxProvisionerEntries:
		return fmt.Errorf("allow_names allows at most %d entries", maxProvisionerEntries)
	}
	for _, e := range p.AllowNames {
		if _, err := validateAllowEntry(e); err != nil {
			return fmt.Errorf("allow_names entry %q: %w", e, err)
		}
	}
	for _, c := range p.Challenges {
		switch c {
		case "http-01", "dns-01":
		case "tls-alpn-01":
			return errors.New(`challenge "tls-alpn-01" is not supported`)
		default:
			return fmt.Errorf("challenge %q is not supported; use http-01 or dns-01", c)
		}
	}
	return nil
}

// Allows reports whether identifier (already lowercased by
// normalizeDNSIdentifier) is inside the allow-list. "host.example.com"
// matches only that name; "*.internal" matches any name strictly below
// "internal" at any depth, wildcard orders included.
func (p *Provisioner) Allows(identifier string) bool {
	for _, e := range p.AllowNames {
		if suffix, ok := strings.CutPrefix(e, "*."); ok {
			if ca.DNSNameMatchesSuffixes(identifier, []string{"." + suffix}) {
				return true
			}
			continue
		}
		if identifier == e {
			return true
		}
	}
	return false
}

// offers reports whether the provisioner offers challenge type t.
func (p *Provisioner) offers(t string) bool {
	if len(p.Challenges) == 0 {
		return true
	}
	for _, c := range p.Challenges {
		if c == t {
			return true
		}
	}
	return false
}

// ProvisionerStore persists provisioners.
type ProvisionerStore interface {
	List(ctx context.Context) ([]Provisioner, error) // by name
	Get(ctx context.Context, name string) (Provisioner, bool, error)
	Create(ctx context.Context, p Provisioner) error // ErrProvisionerExists
	Update(ctx context.Context, p Provisioner) error // ErrProvisionerNotFound
	Delete(ctx context.Context, name string) error   // ErrProvisionerNotFound
}

// MemProvisionerStore is the in-memory ProvisionerStore.
type MemProvisionerStore struct {
	mu sync.Mutex
	m  map[string]Provisioner
}

// NewMemProvisionerStore returns an empty store.
func NewMemProvisionerStore() *MemProvisionerStore {
	return &MemProvisionerStore{m: map[string]Provisioner{}}
}

func (s *MemProvisionerStore) List(context.Context) ([]Provisioner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Provisioner, 0, len(s.m))
	for _, p := range s.m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *MemProvisionerStore) Get(_ context.Context, name string) (Provisioner, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[name]
	return p, ok, nil
}

func (s *MemProvisionerStore) Create(_ context.Context, p Provisioner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[p.Name]; ok {
		return ErrProvisionerExists
	}
	s.m[p.Name] = p
	return nil
}

func (s *MemProvisionerStore) Update(_ context.Context, p Provisioner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.m[p.Name]
	if !ok {
		return ErrProvisionerNotFound
	}
	p.CreatedBy, p.CreatedAt = old.CreatedBy, old.CreatedAt
	s.m[p.Name] = p
	return nil
}

func (s *MemProvisionerStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; !ok {
		return ErrProvisionerNotFound
	}
	delete(s.m, name)
	return nil
}

const provisionerTimeLayout = "2006-01-02T15:04:05Z" // fixed width, UTC: compares as text

// DBProvisionerStore keeps provisioners in acme_provisioners (migration 000181).
type DBProvisionerStore struct {
	db       *sql.DB
	postgres bool
}

// NewDBProvisionerStore returns a store on db.
func NewDBProvisionerStore(db *sql.DB, postgres bool) *DBProvisionerStore {
	return &DBProvisionerStore{db: db, postgres: postgres}
}

// EnsureSchema creates the table for a database that skipped migrations.
func (s *DBProvisionerStore) EnsureSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS acme_provisioners (
  name TEXT PRIMARY KEY, ca_id TEXT NOT NULL, template_id TEXT NOT NULL DEFAULT '',
  allow_names TEXT NOT NULL DEFAULT '[]', challenges TEXT NOT NULL DEFAULT '[]',
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`)
	if err != nil {
		return fmt.Errorf("acme provisioners schema: %w", err)
	}
	return nil
}

func (s *DBProvisionerStore) q(query string) string {
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

const provisionerColumns = `name, ca_id, template_id, allow_names, challenges, created_by, created_at, updated_at`

type provisionerScanner interface{ Scan(...any) error }

func scanProvisioner(row provisionerScanner) (Provisioner, error) {
	var p Provisioner
	var allow, chal, created, updated string
	if err := row.Scan(&p.Name, &p.CAID, &p.TemplateID, &allow, &chal, &p.CreatedBy, &created, &updated); err != nil {
		return Provisioner{}, err
	}
	if err := json.Unmarshal([]byte(allow), &p.AllowNames); err != nil {
		return Provisioner{}, fmt.Errorf("acme provisioner %s: allow_names: %w", p.Name, err)
	}
	if err := json.Unmarshal([]byte(chal), &p.Challenges); err != nil {
		return Provisioner{}, fmt.Errorf("acme provisioner %s: challenges: %w", p.Name, err)
	}
	var err error
	if p.CreatedAt, err = time.Parse(provisionerTimeLayout, created); err != nil {
		return Provisioner{}, err
	}
	if p.UpdatedAt, err = time.Parse(provisionerTimeLayout, updated); err != nil {
		return Provisioner{}, err
	}
	return p, nil
}

func provisionerJSON(p Provisioner) (allow, chal string, err error) {
	if p.AllowNames == nil {
		p.AllowNames = []string{}
	}
	if p.Challenges == nil {
		p.Challenges = []string{}
	}
	a, err := json.Marshal(p.AllowNames)
	if err != nil {
		return "", "", err
	}
	c, err := json.Marshal(p.Challenges)
	if err != nil {
		return "", "", err
	}
	return string(a), string(c), nil
}

func (s *DBProvisionerStore) List(ctx context.Context) ([]Provisioner, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+provisionerColumns+` FROM acme_provisioners ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list acme provisioners: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Provisioner{}
	for rows.Next() {
		p, err := scanProvisioner(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *DBProvisionerStore) Get(ctx context.Context, name string) (Provisioner, bool, error) {
	p, err := scanProvisioner(s.db.QueryRowContext(ctx, s.q(`SELECT `+provisionerColumns+` FROM acme_provisioners WHERE name = ?`), name))
	if errors.Is(err, sql.ErrNoRows) {
		return Provisioner{}, false, nil
	}
	if err != nil {
		return Provisioner{}, false, fmt.Errorf("get acme provisioner: %w", err)
	}
	return p, true, nil
}

func (s *DBProvisionerStore) Create(ctx context.Context, p Provisioner) error {
	allow, chal, err := provisionerJSON(p)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO acme_provisioners
		(name, ca_id, template_id, allow_names, challenges, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		p.Name, p.CAID, p.TemplateID, allow, chal, p.CreatedBy,
		p.CreatedAt.UTC().Format(provisionerTimeLayout), p.UpdatedAt.UTC().Format(provisionerTimeLayout))
	if err != nil {
		if _, found, gerr := s.Get(ctx, p.Name); gerr == nil && found {
			return ErrProvisionerExists
		}
		return fmt.Errorf("create acme provisioner: %w", err)
	}
	return nil
}

func (s *DBProvisionerStore) Update(ctx context.Context, p Provisioner) error {
	allow, chal, err := provisionerJSON(p)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE acme_provisioners
		SET ca_id = ?, template_id = ?, allow_names = ?, challenges = ?, updated_at = ? WHERE name = ?`),
		p.CAID, p.TemplateID, allow, chal, p.UpdatedAt.UTC().Format(provisionerTimeLayout), p.Name)
	if err != nil {
		return fmt.Errorf("update acme provisioner: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrProvisionerNotFound
	}
	return nil
}

func (s *DBProvisionerStore) Delete(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM acme_provisioners WHERE name = ?`), name)
	if err != nil {
		return fmt.Errorf("delete acme provisioner: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrProvisionerNotFound
	}
	return nil
}

// WithProvisioners enables named provisioner directories. gate builds the
// enrollment gate for a provisioner's template; nil (or a nil result) leaves
// the server's default gate in force.
func (s *Server) WithProvisioners(store ProvisionerStore, gate func(templateID string) EnrollmentGate) *Server {
	s.provisioners = store
	s.provGate = gate
	return s
}

// forProvisioner returns a view of s scoped to p. It shares every pointer and
// map with s (store, nonces, mutex, revocation state) and differs only in its
// base URL, CA, gate and provisioner.
func (s *Server) forProvisioner(p Provisioner) *Server {
	v := *s
	v.baseURL = s.baseURL + "/acme/" + p.Name
	v.caID = p.CAID
	v.provisioner = &p
	if p.TemplateID != "" && s.provGate != nil {
		if g := s.provGate(p.TemplateID); g != nil {
			v.enrollGate = g
		}
	}
	return &v
}

// handleProvisionerPath serves /acme/<name>/directory and
// /acme/<name>/acme/<endpoint>. Unknown, reserved and unconfigured all answer
// the same plain 404 so names cannot be enumerated.
func (s *Server) handleProvisionerPath(w http.ResponseWriter, r *http.Request) {
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/acme/"), "/")
	var inner string
	switch {
	case rest == "directory":
		inner = "/acme/directory"
	case strings.HasPrefix(rest, "acme/") && len(rest) > len("acme/"):
		inner = "/" + rest
	default:
		http.NotFound(w, r)
		return
	}
	if s.provisioners == nil || reservedProvisionerNames[name] || !provisionerNamePattern.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	p, found, err := s.provisioners.Get(r.Context(), name)
	if err != nil {
		s.writeACMEError(w, http.StatusServiceUnavailable, "urn:ietf:params:acme:error:serverInternal", "provisioner lookup failed")
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path, r2.URL.RawPath = inner, ""
	s.forProvisioner(p).Handler().ServeHTTP(w, r2)
}
