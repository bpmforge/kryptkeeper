// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// exportFake generates rows lazily so a 100k-row test never materialises
// the log; it records the largest page asked for and returned.
type exportFake struct {
	mu          sync.Mutex
	n           int
	gen         func(i int) AuditEntry
	maxLimit    int
	maxReturned int
	appended    []AuditEntry
	failAfter   int // fail the call whose Offset >= failAfter (0 = never)
}

func (f *exportFake) ListEntries(_ context.Context, q AuditListQuery) (AuditListResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if q.Limit > f.maxLimit {
		f.maxLimit = q.Limit
	}
	if f.failAfter > 0 && q.Offset >= f.failAfter {
		return AuditListResult{}, fmt.Errorf("boom")
	}
	if q.ActionPrefix != "" { // the handler filters by action family; the fake matches the same rule
		q.Action = q.ActionPrefix
	}
	match := func(e AuditEntry) bool {
		return (q.Action == "" || e.Action == q.Action) &&
			(q.Tenant == "" || auditEntryTenantOrDefault(e.Tenant) == q.Tenant)
	}
	var page []AuditEntry
	if q.Action == "" && q.Tenant == "" { // unfiltered: generate only the page asked for
		for i := q.Offset; i < f.n && len(page) < q.Limit; i++ {
			page = append(page, f.gen(i))
		}
		if len(page) > f.maxReturned {
			f.maxReturned = len(page)
		}
		return AuditListResult{Entries: page, Total: f.n, Limit: q.Limit}, nil
	}
	total := 0
	for i := 0; i < f.n; i++ {
		e := f.gen(i)
		if !match(e) {
			continue
		}
		if total >= q.Offset && len(page) < q.Limit {
			page = append(page, e)
		}
		total++
	}
	if len(page) > f.maxReturned {
		f.maxReturned = len(page)
	}
	return AuditListResult{Entries: page, Total: total, Limit: q.Limit}, nil
}

func (f *exportFake) AppendEntry(_ context.Context, e AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.appended = append(f.appended, e)
	return nil
}

func exportRow(i int) AuditEntry {
	action := "cert.issue"
	if i%5 == 0 {
		action = "cert.revoke"
	}
	return AuditEntry{
		ID: int64(i + 1), Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(time.RFC3339),
		Action: action, ActorType: "user", ActorID: "alice", ResourceType: "certificate",
		ResourceID: fmt.Sprintf("fp-%d", i), Outcome: AuditOutcomeSuccess, Tenant: "default",
	}
}

func exportMux(t *testing.T, p AuditProvider) *http.ServeMux {
	t.Helper()
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	RegisterAuditExportHandlers(mux, auth, NewCustomRoleStoreFromEnv(), p)
	return mux
}

type flushCounter struct {
	*httptest.ResponseRecorder
	flushes int
}

func (f *flushCounter) Flush() { f.flushes++; f.ResponseRecorder.Flush() }

func TestAuditExportCSVAllRows(t *testing.T) {
	f := &exportFake{n: 2500, gen: exportRow}
	mux := exportMux(t, f)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export?format=csv", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type %q", ct)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "audit-evidence-") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", rec.Header())
	}
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2501 {
		t.Fatalf("want header+2500 rows, got %d", len(recs))
	}
	if strings.Join(recs[0], ",") != "id,timestamp,action,actor_type,actor_id,resource_type,resource_id,trace_id,outcome,tenant" {
		t.Fatalf("header %v", recs[0])
	}
	for i := 1; i < len(recs); i++ {
		if recs[i][0] != fmt.Sprint(i) {
			t.Fatalf("row %d out of order: id %s", i, recs[i][0])
		}
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export?action=cert.revoke", nil))
	recs, _ = csv.NewReader(rec.Body).ReadAll()
	if len(recs) != 501 { // every 5th of 2500
		t.Fatalf("action filter: want 500 rows, got %d", len(recs)-1)
	}
}

func TestAuditExport100kStreams(t *testing.T) {
	f := &exportFake{n: 100000, gen: exportRow}
	mux := exportMux(t, f)
	rec := &flushCounter{ResponseRecorder: httptest.NewRecorder()}
	start := time.Now()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("too slow: %v", d)
	}
	if f.maxLimit > auditExportPageSize || f.maxReturned > auditExportPageSize {
		t.Fatalf("buffered more than a page: limit %d returned %d", f.maxLimit, f.maxReturned)
	}
	if rec.flushes < 2 {
		t.Fatalf("expected a flush per page, got %d", rec.flushes)
	}
	if lines := strings.Count(rec.Body.String(), "\n"); lines != 100001 {
		t.Fatalf("want 100001 lines, got %d", lines)
	}
}

func TestAuditExportJSONValid(t *testing.T) {
	for _, n := range []int{0, 1, 2500} {
		f := &exportFake{n: n, gen: exportRow}
		rec := httptest.NewRecorder()
		exportMux(t, f).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export?format=json", nil))
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("n=%d: %d %v", n, rec.Code, rec.Header())
		}
		var out []AuditEntry
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("n=%d invalid JSON: %v", n, err)
		}
		if len(out) != n {
			t.Fatalf("n=%d got %d", n, len(out))
		}
	}
}

func TestAuditExportWritesAuditRow(t *testing.T) {
	f := &exportFake{n: 30, gen: exportRow}
	rec := httptest.NewRecorder()
	exportMux(t, f).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export?action=cert.revoke&after=2026-01-01T00:00:00Z", nil))
	if len(f.appended) != 1 {
		t.Fatalf("want 1 audit row, got %d", len(f.appended))
	}
	e := f.appended[0]
	if e.Action != "audit.export" || e.Outcome != AuditOutcomeSuccess {
		t.Fatalf("row %+v", e)
	}
	for _, want := range []string{"format=csv", "action=cert.revoke", "after=2026-01-01T00:00:00Z", "rows=6"} {
		if !strings.Contains(e.ChangeSummary, want) {
			t.Fatalf("summary %q missing %q", e.ChangeSummary, want)
		}
	}
	if strings.Contains(rec.Body.String(), "audit.export") {
		t.Fatal("export must not contain its own row")
	}
}

func TestAuditExportMidStreamFailureRecorded(t *testing.T) {
	f := &exportFake{n: 3000, gen: exportRow, failAfter: 1000}
	rec := httptest.NewRecorder()
	exportMux(t, f).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export?format=json", nil))
	if json.Valid(rec.Body.Bytes()) {
		t.Fatal("a truncated export must not look like a complete document")
	}
	if len(f.appended) != 1 || f.appended[0].Outcome != AuditOutcomeFailure {
		t.Fatalf("want one failure row, got %+v", f.appended)
	}
}

func TestAuditExportCSVFormulaInjection(t *testing.T) {
	f := &exportFake{n: 1, gen: func(int) AuditEntry {
		e := exportRow(0)
		e.ActorID = "=cmd|' /C calc'!A0"
		return e
	}}
	rec := httptest.NewRecorder()
	exportMux(t, f).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export", nil))
	recs, _ := csv.NewReader(rec.Body).ReadAll()
	if !strings.HasPrefix(recs[1][4], "'=") {
		t.Fatalf("formula not neutralised: %q", recs[1][4])
	}
}

// Every free-text column goes through hardenRowFor, not just actor_id: the
// evidence file is opened in a spreadsheet by auditors.
func TestAuditExportCSVHardensEveryTextField(t *testing.T) {
	f := &exportFake{n: 1, gen: func(int) AuditEntry {
		e := exportRow(0)
		e.Action, e.ActorType, e.ActorID = "=cmd", "+cmd", "-cmd"
		e.ResourceType, e.ResourceID, e.TraceID = "@cmd", "\tcmd", "\rcmd"
		e.Tenant = "=cmd"
		return e
	}}
	rec := httptest.NewRecorder()
	exportMux(t, f).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export", nil))
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil || len(recs) != 2 {
		t.Fatalf("parse: %v, %d records", err, len(recs))
	}
	for _, i := range []int{2, 3, 4, 5, 6, 7, 9} {
		if !strings.HasPrefix(recs[1][i], "'") {
			t.Errorf("%s not neutralised: %q", recs[0][i], recs[1][i])
		}
	}
}

func TestAuditExportBadFormat(t *testing.T) {
	rec := httptest.NewRecorder()
	exportMux(t, &exportFake{n: 1, gen: exportRow}).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/audit/export?format=xml", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestAuditExportUnauthenticatedAndMethod(t *testing.T) {
	mux := exportMux(t, &exportFake{n: 1, gen: exportRow})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/audit/export", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

func exportTenantSetup(t *testing.T) (http.Handler, AuditProvider, string, string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	auth := NewAuthenticatorFromEnv()
	_, acme, _ := auth.CreateAPIKey("acme-adm", "acme-adm", "pki-admin", []string{"*"}, "", "acme", time.Now())
	_, viewer, _ := auth.CreateAPIKey("acme-view", "acme-view", "viewer", []string{"*"}, "", "acme", time.Now())
	p, err := openFileAuditProvider(filepath.Join(t.TempDir(), "audit.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		tenant := []string{"acme", "globex"}[i%2]
		e := exportRow(i)
		e.ID, e.Tenant, e.ResourceID = 0, tenant, "res-"+tenant
		if err := p.AppendEntry(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	RegisterAuditExportHandlers(mux, auth, NewCustomRoleStoreFromEnv(), p)
	return withAuditTenant(mux), p, acme, viewer
}

func exportGet(h http.Handler, path, token, tenant string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant", tenant)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuditExportTenantScoped(t *testing.T) {
	h, _, acme, _ := exportTenantSetup(t)
	for _, format := range []string{"csv", "json"} {
		rec := exportGet(h, "/api/v1/audit/export?format="+format, acme, "acme")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", format, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, "globex") {
			t.Fatalf("%s export leaked globex rows:\n%s", format, body)
		}
		if !strings.Contains(body, "res-acme") {
			t.Fatalf("%s export missing acme rows", format)
		}
	}
}

func TestAuditExportRequiresPermission(t *testing.T) {
	h, p, _, viewer := exportTenantSetup(t)
	rec := exportGet(h, "/api/v1/audit/export", viewer, "acme")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer: got %d", rec.Code)
	}
	res, _ := p.ListEntries(context.Background(), AuditListQuery{Limit: 100, Action: "audit.export"})
	if len(res.Entries) == 0 || res.Entries[0].Outcome != AuditOutcomeDenied {
		t.Fatalf("expected a denied audit.export row, got %+v", res.Entries)
	}
}
