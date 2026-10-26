// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

// The device inventory behind device-attest-01 (W40-02, D-317): permanent
// identifiers (serial numbers, UDIDs) the operator owns. Attestation proves a
// device is genuine hardware; only this list says the device is the hub
// owner's, so an identifier absent from it is never issued to.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrDeviceExists means the identifier is already in the inventory.
	ErrDeviceExists = errors.New("device already in the inventory")
	// ErrDeviceNotFound means the identifier is not in the inventory.
	ErrDeviceNotFound = errors.New("device not in the inventory")
)

// DeviceEntry is one inventory row. TenantID is "" for the default tenant.
type DeviceEntry struct {
	Identifier string
	TenantID   string
	Label      string
	CreatedBy  string
	CreatedAt  time.Time
}

// ValidateDeviceIdentifier applies the same rule the order does, so an entry
// can only ever be one an order could name.
func ValidateDeviceIdentifier(v string) error {
	_, err := parsePermanentIdentifier(v)
	return err
}

// DeviceAllowlist stores the inventory.
type DeviceAllowlist interface {
	Add(ctx context.Context, e DeviceEntry) error // ErrDeviceExists
	List(ctx context.Context) ([]DeviceEntry, error)
	Lookup(ctx context.Context, identifier string) (DeviceEntry, bool, error)
	Delete(ctx context.Context, identifier string) error // ErrDeviceNotFound
}

// MemDeviceAllowlist is the in-memory DeviceAllowlist.
type MemDeviceAllowlist struct {
	mu sync.Mutex
	m  map[string]DeviceEntry
}

// NewMemDeviceAllowlist returns an empty inventory.
func NewMemDeviceAllowlist() *MemDeviceAllowlist {
	return &MemDeviceAllowlist{m: map[string]DeviceEntry{}}
}

func (l *MemDeviceAllowlist) Add(_ context.Context, e DeviceEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.m[e.Identifier]; ok {
		return ErrDeviceExists
	}
	l.m[e.Identifier] = e
	return nil
}

func (l *MemDeviceAllowlist) List(context.Context) ([]DeviceEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]DeviceEntry, 0, len(l.m))
	for _, e := range l.m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identifier < out[j].Identifier })
	return out, nil
}

func (l *MemDeviceAllowlist) Lookup(_ context.Context, id string) (DeviceEntry, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[id]
	return e, ok, nil
}

func (l *MemDeviceAllowlist) Delete(_ context.Context, id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.m[id]; !ok {
		return ErrDeviceNotFound
	}
	delete(l.m, id)
	return nil
}

// DBDeviceAllowlist keeps the inventory in acme_device_allowlist (migration
// 000370).
type DBDeviceAllowlist struct {
	db       *sql.DB
	postgres bool
}

// NewDBDeviceAllowlist returns an inventory on db.
func NewDBDeviceAllowlist(db *sql.DB, postgres bool) *DBDeviceAllowlist {
	return &DBDeviceAllowlist{db: db, postgres: postgres}
}

// EnsureSchema creates the table for a database that skipped migrations.
func (s *DBDeviceAllowlist) EnsureSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS acme_device_allowlist (
  identifier TEXT PRIMARY KEY, tenant_id TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL, created_at TEXT NOT NULL)`)
	if err != nil {
		return fmt.Errorf("acme device allowlist schema: %w", err)
	}
	return nil
}

func (s *DBDeviceAllowlist) q(query string) string {
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

func (s *DBDeviceAllowlist) Add(ctx context.Context, e DeviceEntry) error {
	res, err := s.db.ExecContext(ctx, s.q(`INSERT INTO acme_device_allowlist (identifier, tenant_id, label, created_by, created_at)
 VALUES (?, ?, ?, ?, ?) ON CONFLICT (identifier) DO NOTHING`), e.Identifier, e.TenantID, e.Label, e.CreatedBy, eabTime(e.CreatedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDeviceExists
	}
	return nil
}

func (s *DBDeviceAllowlist) List(ctx context.Context) ([]DeviceEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT identifier, tenant_id, label, created_by, created_at FROM acme_device_allowlist ORDER BY identifier`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceEntry{}
	for rows.Next() {
		var e DeviceEntry
		var created string
		if err := rows.Scan(&e.Identifier, &e.TenantID, &e.Label, &e.CreatedBy, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = parseEABTime(created)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *DBDeviceAllowlist) Lookup(ctx context.Context, id string) (DeviceEntry, bool, error) {
	var e DeviceEntry
	var created string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT identifier, tenant_id, label, created_by, created_at FROM acme_device_allowlist WHERE identifier = ?`), id).
		Scan(&e.Identifier, &e.TenantID, &e.Label, &e.CreatedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceEntry{}, false, nil
	}
	if err != nil {
		return DeviceEntry{}, false, err
	}
	e.CreatedAt = parseEABTime(created)
	return e, true, nil
}

func (s *DBDeviceAllowlist) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM acme_device_allowlist WHERE identifier = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDeviceNotFound
	}
	return nil
}
