// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"crypto/x509/pkix"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"

	_ "modernc.org/sqlite"
)

// W22-14: an issuance-policy refusal at enroll reaches the EST client as 403
// with the policy and rule in the body (it used to be an opaque 500).
func TestESTEnrollPolicyRefusalCitesRule(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("est-test-passphrase-32chars-ok!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("EST Test Root", pkix.Name{CommonName: "EST Test Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
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
	engine.SetPolicyEngine(pe)
	srv := NewServer(engine, rootCA.ID)
	if err := srv.WithBasicUsers(testUsers(t)); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()

	enroll := func(cn string) (int, string) {
		resp, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(generateCSRBase64(t, cn)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Positive control: baseline-only allows a P-256 enroll (365d < 398d).
	if code, body := enroll("ok.example.com"); code != http.StatusOK {
		t.Fatalf("baseline must allow the enroll: %d %s", code, body)
	}
	if _, err := pe.UpsertPolicy(ca.IssuancePolicy{Name: "p384-only", Enabled: true, Rules: ca.PolicyRules{AllowedAlgorithms: []string{"ECDSA-P384"}}}); err != nil {
		t.Fatal(err)
	}
	code, body := enroll("refused.example.com")
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", code, body)
	}
	for _, want := range []string{"p384-only", "allowed_algorithms"} {
		if !strings.Contains(body, want) {
			t.Errorf("body %q must cite %q", body, want)
		}
	}
	if strings.Contains(body, "BEGIN") || len(body) > 600 {
		t.Errorf("refusal body must be short text, got %d bytes", len(body))
	}
}
