// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package xcep

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"kryptkeeper/internal/ca"
)

// policyReads counts statements that read issuance_policies.
type policyReads struct {
	driver.Driver
	n *atomic.Int64
}

type countingConn struct {
	driver.Conn
	n *atomic.Int64
}

func (c countingConn) count(q string) {
	if strings.Contains(q, "FROM issuance_policies") {
		c.n.Add(1)
	}
}

func (c countingConn) Prepare(q string) (driver.Stmt, error) {
	c.count(q)
	return c.Conn.Prepare(q)
}

func (c countingConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	c.count(q)
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, q)
	}
	return c.Conn.Prepare(q)
}

type countingConnector struct {
	drv  policyReads
	name string
}

func (c countingConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.drv.Driver.Open(c.name)
	return countingConn{conn, c.drv.n}, err
}
func (c countingConnector) Driver() driver.Driver { return c.drv }

// S-09 / H-F5: GetPolicies read the policy table once per candidate key size
// per template (up to 5 x templates per poll). It must read it once per request.
func TestGetPoliciesReadsIssuancePoliciesOncePerRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	base, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int64
	db := sql.OpenDB(countingConnector{drv: policyReads{base.Driver(), &reads}, name: path})
	t.Cleanup(func() { db.Close(); base.Close() })
	if _, err := db.Exec(`CREATE TABLE issuance_policies (
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, ca_id TEXT NOT NULL DEFAULT '',
    rules TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	pe, err := ca.NewPolicyEngine(db, false)
	if err != nil {
		t.Fatal(err)
	}
	// A 16384 floor forces the probe up the whole ladder for every template.
	if _, err := pe.UpsertPolicy(ca.IssuancePolicy{ID: "p", Name: "Strict", Enabled: true, Rules: ca.PolicyRules{MinRSABits: 16384}}); err != nil {
		t.Fatal(err)
	}
	tmpls := []Template{
		{Name: "A", OID: "1.3.6.1.4.1.311.21.8.1", MinKeySize: 2048},
		{Name: "B", OID: "1.3.6.1.4.1.311.21.8.2", MinKeySize: 2048},
		{Name: "C", OID: "1.3.6.1.4.1.311.21.8.3", MinKeySize: 3072},
		{Name: "D", OID: "1.3.6.1.4.1.311.21.8.4", MinKeySize: 4096},
	}
	srv := keyPolicyServer(pe, tmpls, nil)
	reads.Store(0)
	got := advertisedKeys(t, srv)
	if len(got) != 4 {
		t.Fatalf("every template should advertise 16384: %v", got)
	}
	for _, g := range got {
		if g != "16384" {
			t.Fatalf("semantics changed, advertised %v", got)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("issuance_policies read %d times for one GetPolicies; want 1", n)
	}
}
