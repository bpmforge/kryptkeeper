// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

// EST label routes (W26-06). An operator publishes a named endpoint,
// /.well-known/est/<label>/, and binds it to one certificate template. The
// label comes only from the request path. The bare /.well-known/est/ routes
// remain the default label and keep using the server's single enrollment gate.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Label is one named EST endpoint.
type Label struct {
	Label       string    `json:"label"`
	TemplateID  string    `json:"template_id"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ErrLabelExists and ErrLabelNotFound are the LabelStore's lookup outcomes.
var (
	ErrLabelExists   = errors.New("est label already exists")
	ErrLabelNotFound = errors.New("est label not found")
)

// LabelStore persists labels.
type LabelStore interface {
	Get(ctx context.Context, label string) (Label, error)
	List(ctx context.Context) ([]Label, error)
	Create(ctx context.Context, l Label) (Label, error)
	Update(ctx context.Context, label, templateID, description string) (Label, error)
	Delete(ctx context.Context, label string) error
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// reservedLabels are the EST operation names: a label equal to one would be
// ambiguous with a bare route.
var reservedLabels = map[string]bool{
	"cacerts": true, "simpleenroll": true, "simplereenroll": true,
	"csrattrs": true, "serverkeygen": true, "fullcmc": true,
}

// ValidLabel reports whether s is a usable label: lower-case letters, digits
// and inner hyphens, at most 32 characters, and not an EST operation name.
func ValidLabel(s string) bool {
	return labelRE.MatchString(s) && !reservedLabels[s]
}

type ctxLabelKey struct{}

func withLabel(ctx context.Context, l *Label) context.Context {
	return context.WithValue(ctx, ctxLabelKey{}, l)
}

func labelFrom(ctx context.Context) *Label {
	l, _ := ctx.Value(ctxLabelKey{}).(*Label)
	return l
}

// WithLabels enables /.well-known/est/<label>/ routes. gateFor builds the
// enrollment gate for a label's template; without it label enrollment fails
// closed.
func (s *Server) WithLabels(store LabelStore, gateFor func(templateID string) EnrollmentGate) *Server {
	s.labels = store
	s.labelGate = gateFor
	return s
}

// handleLabelPath serves /.well-known/est/<label>/<op>. Every path that is
// not a known label and operation answers the same 404.
func (s *Server) handleLabelPath(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/.well-known/est/")
	name, op, ok := strings.Cut(rest, "/")
	if !ok || s.labels == nil || !ValidLabel(name) {
		http.NotFound(w, r)
		return
	}
	var handler http.HandlerFunc
	switch op {
	case "cacerts":
		handler = s.handleCACerts
	case "simpleenroll":
		handler = s.handleSimpleEnroll
	case "simplereenroll":
		handler = s.handleSimpleReenroll
	case "csrattrs":
		handler = s.handleCSRAttrs
	default:
		http.NotFound(w, r)
		return
	}
	l, err := s.labels.Get(r.Context(), name)
	if errors.Is(err, ErrLabelNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "EST labels unavailable", http.StatusServiceUnavailable)
		return
	}
	handler(w, r.WithContext(withLabel(r.Context(), &l)))
}

// MemLabelStore is an in-memory LabelStore for tests and database-less runs.
type MemLabelStore struct {
	mu sync.Mutex
	m  map[string]Label
}

// NewMemLabelStore returns an empty MemLabelStore.
func NewMemLabelStore() *MemLabelStore { return &MemLabelStore{m: map[string]Label{}} }

// Get returns one label, or ErrLabelNotFound.
func (s *MemLabelStore) Get(_ context.Context, label string) (Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.m[label]
	if !ok {
		return Label{}, ErrLabelNotFound
	}
	return l, nil
}

// List returns every label ordered by name.
func (s *MemLabelStore) List(_ context.Context) ([]Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Label, 0, len(s.m))
	for _, l := range s.m {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

// Create stores l, or returns ErrLabelExists.
func (s *MemLabelStore) Create(_ context.Context, l Label) (Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[l.Label]; ok {
		return Label{}, ErrLabelExists
	}
	now := time.Now().UTC().Truncate(time.Second)
	l.CreatedAt, l.UpdatedAt = now, now
	s.m[l.Label] = l
	return l, nil
}

// Update changes a label's template and description.
func (s *MemLabelStore) Update(_ context.Context, label, templateID, description string) (Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.m[label]
	if !ok {
		return Label{}, ErrLabelNotFound
	}
	l.TemplateID, l.Description, l.UpdatedAt = templateID, description, time.Now().UTC().Truncate(time.Second)
	s.m[label] = l
	return l, nil
}

// Delete removes a label.
func (s *MemLabelStore) Delete(_ context.Context, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[label]; !ok {
		return ErrLabelNotFound
	}
	delete(s.m, label)
	return nil
}

const labelTimeLayout = "2006-01-02T15:04:05Z" // fixed width, UTC

// DBLabelStore keeps labels in est_labels (migration 000188).
type DBLabelStore struct {
	db       *sql.DB
	postgres bool
}

// NewDBLabelStore returns a store on db.
func NewDBLabelStore(db *sql.DB, postgres bool) *DBLabelStore {
	return &DBLabelStore{db: db, postgres: postgres}
}

func (s *DBLabelStore) q(query string) string {
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

// EnsureSchema creates est_labels when migrations have not (same DDL as 000188).
func (s *DBLabelStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS est_labels (
  label TEXT PRIMARY KEY, template_id TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`)
	return err
}

const labelCols = `label, template_id, description, created_by, created_at, updated_at`

func scanLabel(sc rowScanner) (Label, error) {
	var (
		l                Label
		created, updated string
	)
	if err := sc.Scan(&l.Label, &l.TemplateID, &l.Description, &l.CreatedBy, &created, &updated); err != nil {
		return Label{}, err
	}
	var err error
	if l.CreatedAt, err = time.Parse(labelTimeLayout, created); err != nil {
		return Label{}, err
	}
	if l.UpdatedAt, err = time.Parse(labelTimeLayout, updated); err != nil {
		return Label{}, err
	}
	return l, nil
}

// Get returns one label, or ErrLabelNotFound.
func (s *DBLabelStore) Get(ctx context.Context, label string) (Label, error) {
	l, err := scanLabel(s.db.QueryRowContext(ctx, s.q(`SELECT `+labelCols+` FROM est_labels WHERE label = ?`), label))
	if errors.Is(err, sql.ErrNoRows) {
		return Label{}, ErrLabelNotFound
	}
	return l, err
}

// List returns every label ordered by name.
func (s *DBLabelStore) List(ctx context.Context) ([]Label, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+labelCols+` FROM est_labels ORDER BY label`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Label{}
	for rows.Next() {
		l, err := scanLabel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Create stores l, or returns ErrLabelExists.
func (s *DBLabelStore) Create(ctx context.Context, l Label) (Label, error) {
	now := time.Now().UTC().Truncate(time.Second)
	l.CreatedAt, l.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO est_labels (`+labelCols+`) VALUES (?, ?, ?, ?, ?, ?)`),
		l.Label, l.TemplateID, l.Description, l.CreatedBy, now.Format(labelTimeLayout), now.Format(labelTimeLayout))
	if err != nil {
		if _, getErr := s.Get(ctx, l.Label); getErr == nil {
			return Label{}, ErrLabelExists
		}
		return Label{}, fmt.Errorf("store est label: %w", err)
	}
	return l, nil
}

// Update changes a label's template and description.
func (s *DBLabelStore) Update(ctx context.Context, label, templateID, description string) (Label, error) {
	l, err := s.Get(ctx, label)
	if err != nil {
		return Label{}, err
	}
	l.TemplateID, l.Description = templateID, description
	l.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	if _, err := s.db.ExecContext(ctx, s.q(`UPDATE est_labels SET template_id = ?, description = ?, updated_at = ? WHERE label = ?`),
		templateID, description, l.UpdatedAt.Format(labelTimeLayout), label); err != nil {
		return Label{}, err
	}
	return l, nil
}

// Delete removes a label.
func (s *DBLabelStore) Delete(ctx context.Context, label string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM est_labels WHERE label = ?`), label)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLabelNotFound
	}
	return nil
}
