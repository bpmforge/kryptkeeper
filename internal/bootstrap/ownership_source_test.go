// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W22-24: every ownership assignment records its source, and "unowned" is one
// definition shared by the ?owner=unassigned list and the dashboard count.

func ownershipTestMux(t *testing.T, p CertificateProvider, audit AuditProvider) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	mux := http.NewServeMux()
	registerCertificateHandlers(mux, NewAuthenticatorFromEnv(), p, audit, nil)
	return mux
}

func ownershipDo(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func seedOwnershipCert(p *caCertificateProvider, fp, team, source string, revoked bool) {
	item := CertificateItem{
		FingerprintSHA256: fp, SerialNumber: fp, CommonName: fp + ".example.com",
		CAID: "ca-A", CreatedAt: "2026-08-19T10:00:00Z", ValidFrom: "2026-08-19T10:00:00Z",
		ValidUntil: time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339), RenewalStatus: "active",
		OwnerTeam: team, OwnershipSource: source,
	}
	if revoked {
		ts := "2026-09-01T00:00:00Z"
		item.RevokedAt = &ts
		item.RenewalStatus = "revoked"
	}
	p.mu.Lock()
	p.addLocked(fp, &storedCert{item: item})
	p.mu.Unlock()
}

func listTotal(t *testing.T, mux *http.ServeMux, query string) int {
	t.Helper()
	rec := ownershipDo(mux, http.MethodGet, "/api/v1/certificates"+query, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list %q: %d %s", query, rec.Code, rec.Body.String())
	}
	var resp struct {
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Meta.Total
}

func TestPatchOwnershipSetsManualSource(t *testing.T) {
	p := NewCACertificateProvider(nil, nil, nil, false).(*caCertificateProvider)
	seedOwnershipCert(p, "fp-1", "", "", false)
	audit := &recordingAuditProvider{}
	mux := ownershipTestMux(t, p, audit)

	// A client-supplied source must be ignored: only the server assigns it.
	rec := ownershipDo(mux, http.MethodPatch, "/api/v1/certificates/fp-1/ownership",
		`{"owner_team":"platform","owner_email":"a@example.com","source":"cmdb","ownership_source":"cmdb"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data CertificateItem `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.OwnershipSource != OwnershipSourceManual {
		t.Fatalf("response source = %q, want manual", resp.Data.OwnershipSource)
	}
	got, _, _ := p.GetCertificate(context.Background(), "fp-1")
	if got.OwnershipSource != OwnershipSourceManual {
		t.Fatalf("stored source = %q, want manual", got.OwnershipSource)
	}
	found := false
	for _, e := range audit.entries {
		if e.Action == "certificate.ownership_update" && strings.Contains(e.ChangeSummary, `"ownership_source":"manual"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no certificate.ownership_update audit row recording the source: %+v", audit.entries)
	}
}

func TestOwnedCertLeavesUnownedListImmediately(t *testing.T) {
	p := NewCACertificateProvider(nil, nil, nil, false).(*caCertificateProvider)
	seedOwnershipCert(p, "fp-1", "", "", false)
	seedOwnershipCert(p, "fp-2", "ops", "manual", false)
	mux := ownershipTestMux(t, p, stubAuditProvider{})

	if n := listTotal(t, mux, "?owner=unassigned"); n != 1 {
		t.Fatalf("unowned before = %d, want 1", n)
	}
	start := time.Now()
	if rec := ownershipDo(mux, http.MethodPatch, "/api/v1/certificates/fp-1/ownership", `{"owner_team":"platform"}`); rec.Code != http.StatusOK {
		t.Fatalf("patch: %d", rec.Code)
	}
	n := listTotal(t, mux, "?owner=unassigned")
	if time.Since(start) >= time.Second {
		t.Fatalf("owner change took %v to show in the list", time.Since(start))
	}
	if n != 0 {
		t.Fatalf("unowned after = %d, want 0", n)
	}
}

func TestClearingOwnerClearsSource(t *testing.T) {
	p := NewCACertificateProvider(nil, nil, nil, false).(*caCertificateProvider)
	seedOwnershipCert(p, "fp-1", "ops", "cmdb", false)
	item, err := p.UpdateOwnership(context.Background(), "fp-1", CertificateOwnershipRequest{OwnerTeam: "  "})
	if err != nil {
		t.Fatal(err)
	}
	if item.OwnershipSource != "" || item.OwnerTeam != "" {
		t.Fatalf("cleared owner kept source %q team %q", item.OwnershipSource, item.OwnerTeam)
	}
	if !isUnownedCertificate(&item) {
		t.Fatal("cleared cert must be unowned again")
	}
	if _, err := p.UpdateOwnership(context.Background(), "fp-1", CertificateOwnershipRequest{OwnerTeam: "x", Source: "bogus"}); err == nil {
		t.Fatal("invalid source must be rejected")
	}
}

func TestOwnerParamRejectsOtherValues(t *testing.T) {
	p := NewCACertificateProvider(nil, nil, nil, false).(*caCertificateProvider)
	mux := ownershipTestMux(t, p, stubAuditProvider{})
	if rec := ownershipDo(mux, http.MethodGet, "/api/v1/certificates?owner=platform", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("owner=platform: %d, want 400", rec.Code)
	}
}

// The list filter and the dashboard SQL must agree on a DB-backed estate
// that mixes owned, unowned and revoked-unowned certificates.
func TestUnassignedFilterEqualsDashboardCount(t *testing.T) {
	db := setupIntegrationDB(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, common_name, issuer_dn, valid_from, valid_until,
		 public_key_algorithm, signature_algorithm, renewal_status, revoked_at, owner_team, ownership_source,
		 created_at, updated_at, origin, management_state, source)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(72 * time.Hour).Format(time.RFC3339)
	for i := 0; i < 1000; i++ {
		fp := fmt.Sprintf("fp-%04d", i)
		var team, src, status string = "", "", "active"
		var revoked any
		switch {
		case i%2 == 0: // 500 owned
			team, src = "team-a", "manual"
		case i < 100: // 50 revoked and unowned: NOT unowned
			status, revoked = "revoked", "2026-09-01T00:00:00Z"
		}
		if _, err := stmt.Exec(fp, fp, "CN="+fp, fp+".example.com", "CN=issuer", "2026-08-01T00:00:00Z", until,
			"ECDSA", "ECDSA-SHA256", status, revoked, team, src,
			"2026-08-19T10:00:00Z", "2026-08-19T10:00:00Z", "imported", "managed", "api"); err != nil {
			t.Fatalf("seed %s: %v", fp, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	provider := NewCACertificateProvider(nil, nil, db, false)
	listed, err := provider.ListCertificates(context.Background(), CertificateListQuery{Owner: ownerFilterUnassigned, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := (&sqliteCertSummaryStore{db: db}).LoadSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if listed.Total == 0 || listed.Total != summary.Unowned {
		t.Fatalf("list total %d != dashboard unowned %d", listed.Total, summary.Unowned)
	}
	if want := 450; listed.Total != want { // 500 odd - 50 revoked
		t.Fatalf("unowned = %d, want %d", listed.Total, want)
	}
}
