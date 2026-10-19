// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"kryptkeeper/internal/connectors"
)

// W27-24: DCV lifetime tracker.

func utcDay(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func newDCVTestStore(t *testing.T) DCVStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "dcv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := newDCVStore(db, false)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}

func newDCVTestTracker(t *testing.T, sched DCVSchedule, audit AuditProvider, now *time.Time) *DCVTracker {
	t.Helper()
	tr := NewDCVTracker(newDCVTestStore(t), sched, audit)
	tr.now = func() time.Time { return *now }
	return tr
}

func TestDCVScheduleBoundaries(t *testing.T) {
	s := DefaultDCVSchedule()
	cases := []struct {
		name        string
		validatedAt time.Time
		now         time.Time
		want        int
	}{
		// 398 -> 200 on 2026-03-15: the step-down shortens validations already on file.
		{"398 day before step", utcDay(2026, 3, 14), utcDay(2026, 3, 14), 398},
		{"398 on step day", utcDay(2026, 3, 14), utcDay(2026, 3, 15), 199},
		{"398 day after step", utcDay(2026, 3, 14), utcDay(2026, 3, 16), 198},
		{"398 stepped down and lapsed", utcDay(2026, 3, 14), utcDay(2026, 12, 1), 0},
		// 200 -> 100 on 2027-03-15.
		{"200 day before step", utcDay(2027, 3, 14), utcDay(2027, 3, 14), 200},
		{"200 on step day", utcDay(2027, 3, 14), utcDay(2027, 3, 15), 99},
		{"200 day after step", utcDay(2027, 3, 14), utcDay(2027, 3, 16), 98},
		// 100 -> 10 on 2029-03-15.
		{"100 day before step", utcDay(2029, 3, 14), utcDay(2029, 3, 14), 100},
		{"100 on step day", utcDay(2029, 3, 14), utcDay(2029, 3, 15), 9},
		{"100 day after step", utcDay(2029, 3, 14), utcDay(2029, 3, 16), 8},
	}
	for _, tc := range cases {
		if got := s.DaysRemaining(tc.validatedAt, tc.now); got != tc.want {
			t.Errorf("%s: DaysRemaining = %d, want %d", tc.name, got, tc.want)
		}
	}
	if got := s.PeriodAt(utcDay(1999, 1, 1)); got != 398 {
		t.Errorf("PeriodAt before the table = %d, want the first step (398)", got)
	}
}

func TestDCVScheduleFromEnv(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DCV_REUSE_SCHEDULE", "")
	if s, err := LoadDCVScheduleFromEnv(); err != nil || len(s) != 4 {
		t.Fatalf("default: %v %v", s, err)
	}
	t.Setenv("KRYPTKEEPER_DCV_REUSE_SCHEDULE", `[{"effective":"2030-01-01","days":30},{"effective":"2020-01-01","days":90}]`)
	s, err := LoadDCVScheduleFromEnv()
	if err != nil || len(s) != 2 || s[0].Days != 90 || s[1].Days != 30 {
		t.Fatalf("override not sorted: %v %v", s, err)
	}
	if s.PeriodAt(utcDay(2031, 1, 1)) != 30 {
		t.Fatal("override not applied")
	}
	for _, bad := range []string{`[{"effective":"2030-13-45","days":30}]`, `[{"effective":"2030-01-01","days":0}]`, `[]`, `nope`} {
		t.Setenv("KRYPTKEEPER_DCV_REUSE_SCHEDULE", bad)
		if _, err := LoadDCVScheduleFromEnv(); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

type dcvFakeConnector struct{ fail bool }

func (dcvFakeConnector) ID() string     { return "conn-dcv" }
func (dcvFakeConnector) Type() string   { return "acme" }
func (dcvFakeConnector) Origin() string { return "synced" }
func (dcvFakeConnector) Health(context.Context) connectors.Health {
	return connectors.Health{Status: "healthy"}
}
func (f dcvFakeConnector) Issue(context.Context, connectors.IssueRequest) (connectors.IssueResult, error) {
	if f.fail {
		return connectors.IssueResult{}, errors.New("ca said no")
	}
	return connectors.IssueResult{FingerprintSHA256: "ff"}, nil
}

func dcvCSR(t *testing.T, cn string, sans ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: sans}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestDCVRecordAfterIssue(t *testing.T) {
	now := utcDay(2026, 10, 16)
	tr := newDCVTestTracker(t, DefaultDCVSchedule(), nil, &now)
	req := connectors.IssueRequest{CSRPEM: dcvCSR(t, "A.example.com", "a.example.com", "b.example.com", "*.c.example.com")}

	if _, err := wrapWithDCVTracking(dcvFakeConnector{fail: true}, "acme", tr).Issue(context.Background(), req); err == nil {
		t.Fatal("expected failure")
	}
	if rows, _ := tr.store.List(context.Background()); len(rows) != 0 {
		t.Fatalf("failed issue recorded %d rows", len(rows))
	}
	if _, err := wrapWithDCVTracking(dcvFakeConnector{}, "acme", tr).Issue(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	rows, _ := tr.store.List(context.Background())
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (CN deduped with SAN, wildcard kept), got %+v", rows)
	}
	for _, r := range rows {
		if r.ConnectorID != "conn-dcv" || r.Tenant != "acme" || r.ReuseDays != 200 || !r.ExpiresAt.Equal(now.AddDate(0, 0, 200)) {
			t.Fatalf("row %+v", r)
		}
	}
	if c := (dcvFakeConnector{}); wrapWithDCVTracking(c, "t", nil) != connectors.IssuerConnector(c) {
		t.Fatal("nil tracker must return the connector unchanged")
	}
}

func TestDCVPlanRevalidationReusesValid(t *testing.T) {
	now := utcDay(2026, 10, 16)
	tr := newDCVTestTracker(t, DefaultDCVSchedule(), nil, &now)
	ctx := context.Background()
	if err := tr.Record(ctx, "c1", "default", []string{"fresh.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := tr.store.Upsert(ctx, DCVValidation{Domain: "old.example.com", ConnectorID: "c1", ValidatedAt: now.AddDate(0, 0, -300), ReuseDays: 200, ExpiresAt: now.AddDate(0, 0, -100)}); err != nil {
		t.Fatal(err)
	}
	reuse, reval := tr.PlanRevalidation(ctx, "c1", []string{"old.example.com", "fresh.example.com", "never.example.com"})
	if len(reuse) != 1 || reuse[0] != "fresh.example.com" || len(reval) != 2 || reval[0] != "never.example.com" || reval[1] != "old.example.com" {
		t.Fatalf("plan reuse=%v revalidate=%v", reuse, reval)
	}
	if !tr.Valid(ctx, "fresh.example.com", "c1") || tr.Valid(ctx, "fresh.example.com", "other") || tr.Valid(ctx, "old.example.com", "c1") {
		t.Fatal("Valid disagrees with plan")
	}
}

func TestDCVWarnAt20Percent(t *testing.T) {
	audit := &memAuditProvider{}
	t0 := utcDay(2026, 1, 1)
	now := t0
	tr := newDCVTestTracker(t, DCVSchedule{{Effective: utcDay(1970, 1, 1), Days: 100}}, audit, &now)
	ctx := context.Background()
	if err := tr.Record(ctx, "c1", "default", []string{"w.example.com"}); err != nil {
		t.Fatal(err)
	}
	scan := func(day int) int {
		now = t0.AddDate(0, 0, day)
		n, err := tr.WarnScan(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if scan(79) != 0 { // 21 days left
		t.Fatal("warned with 21 days left")
	}
	if scan(80) != 1 { // exactly 20% left
		t.Fatal("no warning at 20%")
	}
	if scan(81) != 0 || scan(99) != 0 {
		t.Fatal("warned twice for one validation")
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "dcv.expiry_warning" || audit.entries[0].ResourceID != "w.example.com" ||
		audit.entries[0].ChangeSummary != "connector=c1 days_remaining=20 reuse_days=100" {
		t.Fatalf("audit %+v", audit.entries)
	}
	// Re-validation re-arms the warning.
	now = t0.AddDate(0, 0, 90)
	if err := tr.Record(ctx, "c1", "default", []string{"w.example.com"}); err != nil {
		t.Fatal(err)
	}
	if scan(90+80) != 1 || len(audit.entries) != 2 {
		t.Fatalf("no second warning after re-validation: %d", len(audit.entries))
	}
	if scan(90+100) != 0 { // expired: nothing left to warn about
		t.Fatal("warned on an expired validation")
	}
}

func TestDCVListEndpoint(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	now := utcDay(2026, 10, 16)
	tr := newDCVTestTracker(t, DefaultDCVSchedule(), nil, &now)
	ctx := context.Background()
	if err := tr.Record(ctx, "c-acme", "acme", []string{"a.acme.example"}); err != nil {
		t.Fatal(err)
	}
	if err := tr.Record(ctx, "c-globex", "globex", []string{"g.globex.example"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDCVHandlers(mux, NewAuthenticatorFromEnv(), func() *DCVTracker { return tr }, &memAuditProvider{})

	if rec := httptest.NewRecorder(); true {
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/connectors/dcv-validations", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauth: %d", rec.Code)
		}
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/connectors/dcv-validations", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}

	type body struct {
		Data []struct {
			Domain        string `json:"domain"`
			ConnectorID   string `json:"connector_id"`
			ReuseDays     int    `json:"reuse_days"`
			DaysRemaining int    `json:"days_remaining"`
			Warn          bool   `json:"warn"`
		} `json:"data"`
		Schedule []struct {
			Effective string `json:"effective"`
			Days      int    `json:"days"`
		} `json:"schedule"`
		CurrentReuseDays int `json:"current_reuse_days"`
	}
	get := func(tenant string) body {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/connectors/dcv-validations", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		if tenant != "" {
			req.Header.Set("X-Tenant", tenant)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
		}
		var b body
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	all := get("")
	if len(all.Data) != 2 || len(all.Schedule) != 4 || all.CurrentReuseDays != 200 || all.Schedule[1].Effective != "2026-03-15" {
		t.Fatalf("shape: %+v", all)
	}
	if all.Data[0].DaysRemaining != 200 || all.Data[0].ReuseDays != 200 || all.Data[0].Warn {
		t.Fatalf("row: %+v", all.Data[0])
	}
	if scoped := get("acme"); len(scoped.Data) != 1 || scoped.Data[0].ConnectorID != "c-acme" {
		t.Fatalf("tenant scoped caller saw %+v", scoped.Data)
	}
}
