// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"

	_ "modernc.org/sqlite"
)

const issuancePoliciesSchema = `CREATE TABLE issuance_policies (
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, ca_id TEXT NOT NULL DEFAULT '',
    rules TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);`

// A Baseline policy that refuses RSA-2048 is what a Windows client enrolling
// with the template's advertised minimum ran into: the refusal must reach the
// client as a fault naming the rule and leave a denied wstep.enroll row.
func TestPolicyRefusalFaultReasonAndDeniedAudit(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(issuancePoliciesSchema); err != nil {
		t.Fatal(err)
	}
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-wstep-passphrase-32chars!!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Close() })
	engine := ca.NewEngine(keys, ca.NewMemStore())
	pe, err := ca.NewPolicyEngine(db, false)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetPolicyEngine(pe)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pe.UpsertPolicy(ca.IssuancePolicy{ID: "pol-baseline", Name: "Baseline", Enabled: true, Rules: ca.PolicyRules{MinRSABits: 3072}}); err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ws01"}}, key)
	if err != nil {
		t.Fatal(err)
	}

	var audited []AuditEvent
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	lookup := func(tt string) (TemplateRef, bool) {
		return TemplateRef{Name: "KKMachine", OID: "1.3.6.1.4.1.311.21.8.1"}, tt == "KKMachine"
	}
	h := NewServer(engine, root.ID).WithAuthenticator(asIdentity(machine)).WithTemplateLookup(lookup).
		WithAuditFunc(func(_ context.Context, ev AuditEvent) { audited = append(audited, ev) }).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(buildWSTEPRequestWithTokenType(csrDER, "KKMachine"))))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want the fault status 500", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Fault", `issuance policy &#34;Baseline&#34;`, "min_rsa_bits"} {
		if !strings.Contains(body, want) {
			t.Errorf("fault lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Errorf("fault leaks key material: %s", body)
	}
	if len(audited) != 1 {
		t.Fatalf("want one audit row, got %+v", audited)
	}
	ev := audited[0]
	if ev.Action != "wstep.enroll" || ev.Outcome != "denied" || ev.Actor != machine.Principal ||
		ev.Template != "KKMachine" || !strings.Contains(ev.Detail, "rule=min_rsa_bits") {
		t.Errorf("unexpected audit row %+v", ev)
	}
}
