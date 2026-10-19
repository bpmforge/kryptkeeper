// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"

	_ "modernc.org/sqlite"
)

// W22-14: an issuance-policy refusal at finalize reaches the ACME client as
// 400 badCSR carrying the policy and rule (it used to be an opaque 500). The
// order is invalid and nothing is signed.
func TestACMEFinalizePolicyRefusalCitesRule(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	sqldb, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqldb.Close() })
	if err := kkdb.RunMigrations(sqldb, "sqlite"); err != nil {
		t.Fatal(err)
	}
	pe, err := ca.NewPolicyEngine(sqldb, false)
	if err != nil {
		t.Fatal(err)
	}
	eng, ok := srv.caEngine.(*ca.Engine)
	if !ok {
		t.Fatalf("test engine is %T, want *ca.Engine", srv.caEngine)
	}
	eng.SetPolicyEngine(pe)

	// Positive control: the baseline alone lets a P-256 leaf through.
	okHost := startChallengeHost(t, keyAuthHandler(t, client))
	o := readyOrderFor(t, ts, client, okHost)
	if status, prob, _ := finalizeWith(t, ts, client, o, csrSpec{cn: okHost, dns: []string{okHost}}.der(t)); status != http.StatusOK {
		t.Fatalf("baseline must allow a P-256 leaf: %d %+v", status, prob)
	}

	if _, err := pe.UpsertPolicy(ca.IssuancePolicy{Name: "p384-only", Enabled: true, Rules: ca.PolicyRules{AllowedAlgorithms: []string{"ECDSA-P384"}}}); err != nil {
		t.Fatal(err)
	}
	h := startChallengeHost(t, keyAuthHandler(t, client))
	o = readyOrderFor(t, ts, client, h)
	status, prob, final := finalizeWith(t, ts, client, o, csrSpec{cn: h, dns: []string{h}}.der(t))
	if status != http.StatusBadRequest || prob.Type != problemBadCSR {
		t.Fatalf("status=%d problem=%+v, want 400 badCSR", status, prob)
	}
	for _, want := range []string{"p384-only", "allowed_algorithms"} {
		if !strings.Contains(prob.Detail, want) {
			t.Errorf("problem detail %q must cite %q", prob.Detail, want)
		}
	}
	if final.Certificate != "" {
		t.Error("a refused finalize must not return a certificate")
	}
	if st := getOrder(t, ts.URL+"/acme/order/"+o.ID).Status; st != "invalid" {
		t.Errorf("order status = %q, want invalid", st)
	}
}
