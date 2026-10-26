// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

// SCEP labels (W20-23, D-327). A label is a named endpoint, /scep/<label>,
// whose challenge mode is "intune": each enrollment's challenge is validated
// through the Intune SCEP validation API instead of the hub's own one-time
// challenge table. The bare /scep route keeps the one-time challenges. The
// label comes only from the request path; the Entra app's secret lives in the
// outbound credential store and a label carries only its reference.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ModeIntune is the only challenge mode a label can have today.
const ModeIntune = "intune"

// Label is one named SCEP endpoint.
type Label struct {
	Label            string    `json:"label"`
	Mode             string    `json:"mode"`
	TemplateID       string    `json:"template_id"`
	IntuneTenantID   string    `json:"intune_tenant_id"`
	IntuneClientID   string    `json:"intune_client_id"`
	CredentialRef    string    `json:"credential_ref"`
	IssuingAuthority string    `json:"issuing_authority"`
	Description      string    `json:"description"`
	CreatedBy        string    `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
}

// ErrLabelExists and ErrLabelNotFound are the LabelStore's lookup outcomes.
var (
	ErrLabelExists   = errors.New("scep label already exists")
	ErrLabelNotFound = errors.New("scep label not found")
)

// LabelStore persists labels.
type LabelStore interface {
	Get(ctx context.Context, label string) (Label, error)
	List(ctx context.Context) ([]Label, error)
	Create(ctx context.Context, l Label) (Label, error)
	Delete(ctx context.Context, label string) error
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidLabel reports whether s is a usable label: lower-case letters, digits
// and inner hyphens, at most 32 characters. Underscores are excluded on
// purpose, so the removed /scep/mscep_admin can never match a label.
func ValidLabel(s string) bool { return labelRE.MatchString(s) }

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
	l.CreatedAt = time.Now().UTC().Truncate(time.Second)
	s.m[l.Label] = l
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

// DBLabelStore keeps labels in scep_labels (migration 000388).
type DBLabelStore struct {
	db       *sql.DB
	postgres bool
}

// NewDBLabelStore returns a store on db, which must carry migration 000388.
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

const labelCols = `label, mode, template_id, intune_tenant_id, intune_client_id, credential_ref, issuing_authority, description, created_by, created_at`

func scanLabel(sc rowScanner) (Label, error) {
	var l Label
	var created string
	if err := sc.Scan(&l.Label, &l.Mode, &l.TemplateID, &l.IntuneTenantID, &l.IntuneClientID, &l.CredentialRef,
		&l.IssuingAuthority, &l.Description, &l.CreatedBy, &created); err != nil {
		return Label{}, err
	}
	var err error
	l.CreatedAt, err = time.Parse(timeLayout, created)
	return l, err
}

// Get returns one label, or ErrLabelNotFound.
func (s *DBLabelStore) Get(ctx context.Context, label string) (Label, error) {
	l, err := scanLabel(s.db.QueryRowContext(ctx, s.q(`SELECT `+labelCols+` FROM scep_labels WHERE label = ?`), label))
	if errors.Is(err, sql.ErrNoRows) {
		return Label{}, ErrLabelNotFound
	}
	return l, err
}

// List returns every label ordered by name.
func (s *DBLabelStore) List(ctx context.Context) ([]Label, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+labelCols+` FROM scep_labels ORDER BY label`)
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
	l.CreatedAt = time.Now().UTC().Truncate(time.Second)
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO scep_labels (`+labelCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		l.Label, l.Mode, l.TemplateID, l.IntuneTenantID, l.IntuneClientID, l.CredentialRef, l.IssuingAuthority,
		l.Description, l.CreatedBy, l.CreatedAt.Format(timeLayout))
	if err != nil {
		if _, getErr := s.Get(ctx, l.Label); getErr == nil {
			return Label{}, ErrLabelExists
		}
		return Label{}, fmt.Errorf("store scep label: %w", err)
	}
	return l, nil
}

// Delete removes a label.
func (s *DBLabelStore) Delete(ctx context.Context, label string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM scep_labels WHERE label = ?`), label)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLabelNotFound
	}
	return nil
}
