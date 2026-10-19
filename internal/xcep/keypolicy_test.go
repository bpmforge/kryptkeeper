// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package xcep

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/wstep"

	_ "modernc.org/sqlite"
)

// policyEngineWith returns a real issuance PolicyEngine holding one enabled
// "Baseline" policy with rules, so the advertised key is what issuance enforces.
func policyEngineWith(t *testing.T, rules ca.PolicyRules) *ca.PolicyEngine {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
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
	if _, err := pe.UpsertPolicy(ca.IssuancePolicy{ID: "pol-baseline", Name: "Baseline", Enabled: true, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	return pe
}

func keyPolicyServer(pe *ca.PolicyEngine, tmpls []Template, audit wstep.AuditFunc) *Server {
	srv := NewServer(func() ([]Template, error) { return tmpls, nil }, "").
		WithKeyPolicy(func() (KeyPolicyFunc, error) {
			probe, err := pe.RSAProbe("")
			if err != nil {
				return nil, err
			}
			return probe.AcceptedRSABits, nil
		})
	if audit != nil {
		srv.WithAuditFunc(audit)
	}
	return srv
}

func advertisedKeys(t *testing.T, srv *Server) []string {
	t.Helper()
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))
	if rr.Code != 200 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var out []string
	rest := rr.Body.String()
	for {
		_, after, ok := strings.Cut(rest, "<minimalKeyLength>")
		if !ok {
			return out
		}
		v, after, _ := strings.Cut(after, "</minimalKeyLength>")
		out = append(out, v)
		rest = after
	}
}

func TestAdvertisedKeySizeFollowsIssuancePolicy(t *testing.T) {
	tmpls := []Template{
		{Name: "KKMachine", OID: "1.3.6.1.4.1.311.21.8.1", MinKeySize: 2048},
		{Name: "Big", OID: "1.3.6.1.4.1.311.21.8.2", MinKeySize: 4096},
	}
	t.Run("baseline floor raises 2048 to 3072, 4096 stays", func(t *testing.T) {
		pe := policyEngineWith(t, ca.PolicyRules{MinRSABits: 3072})
		got := advertisedKeys(t, keyPolicyServer(pe, tmpls, nil))
		if len(got) != 2 || got[0] != "3072" || got[1] != "4096" {
			t.Fatalf("advertised %v, want [3072 4096]", got)
		}
	})
	t.Run("allow-list without RSA-2048 raises to its smallest RSA", func(t *testing.T) {
		pe := policyEngineWith(t, ca.PolicyRules{AllowedAlgorithms: []string{"ECDSA-P256", "RSA-4096"}})
		got := advertisedKeys(t, keyPolicyServer(pe, tmpls[:1], nil))
		if len(got) != 1 || got[0] != "4096" {
			t.Fatalf("advertised %v, want [4096]", got)
		}
	})
	t.Run("no policy rules leaves the template minimum", func(t *testing.T) {
		pe := policyEngineWith(t, ca.PolicyRules{})
		got := advertisedKeys(t, keyPolicyServer(pe, tmpls, nil))
		if len(got) != 2 || got[0] != "2048" || got[1] != "4096" {
			t.Fatalf("advertised %v, want [2048 4096]", got)
		}
	})
	t.Run("ECDSA-only policy withholds the template", func(t *testing.T) {
		// Windows enrolls through XCEP with RSA; offering it into a certain
		// WSTEP refusal would only make autoenrollment retry every pulse.
		pe := policyEngineWith(t, ca.PolicyRules{AllowedAlgorithms: []string{"ECDSA-P256"}})
		got := advertisedKeys(t, keyPolicyServer(pe, tmpls, nil))
		if len(got) != 0 {
			t.Fatalf("advertised %v, want no policies", got)
		}
	})
	t.Run("template allow-list disjoint from policy withholds it", func(t *testing.T) {
		pe := policyEngineWith(t, ca.PolicyRules{MinRSABits: 3072})
		only2048 := []Template{{Name: "Old", OID: "1.3.6.1.4.1.311.21.8.3", AllowedAlgorithms: []string{"RSA-2048"}}}
		if got := advertisedKeys(t, keyPolicyServer(pe, only2048, nil)); len(got) != 0 {
			t.Fatalf("advertised %v, want none", got)
		}
	})
}

func TestPolicyFetchAuditedOncePerWindow(t *testing.T) {
	pe := policyEngineWith(t, ca.PolicyRules{MinRSABits: 3072})
	var rows []wstep.AuditEvent
	srv := keyPolicyServer(pe, []Template{{Name: "KKMachine", OID: "1.3.6.1.4.1.311.21.8.1"}},
		func(_ context.Context, ev wstep.AuditEvent) { rows = append(rows, ev) })
	now := time.Now()
	srv.now = func() time.Time { return now }

	advertisedKeys(t, srv)
	advertisedKeys(t, srv)
	if len(rows) != 1 {
		t.Fatalf("want one row inside the window, got %d: %+v", len(rows), rows)
	}
	ev := rows[0]
	if ev.Action != "xcep.policy" || ev.Outcome != "success" || ev.Actor != "WS01$@CORP.EXAMPLE" ||
		!strings.Contains(ev.Detail, "KKMachine(min_key=3072)") {
		t.Fatalf("unexpected row %+v", ev)
	}
	now = now.Add(policyAuditWindow + time.Second)
	advertisedKeys(t, srv)
	if len(rows) != 2 {
		t.Fatalf("want a new row after the window, got %d", len(rows))
	}
}
