// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/notifications/itsm"
)

const itsmSecret = "itsm-super-secret-password-value"

// itsmStubConnector is a read-only fake; findErr is returned by Find and may
// carry upstream text that must never reach the API response.
type itsmStubConnector struct {
	findErr error
	finds   []string
	creates int
}

func (c *itsmStubConnector) Kind() string { return "servicenow" }
func (c *itsmStubConnector) Find(_ context.Context, id string) (*itsm.TicketRef, error) {
	c.finds = append(c.finds, id)
	return nil, c.findErr
}
func (c *itsmStubConnector) Create(context.Context, itsm.Event) (itsm.TicketRef, error) {
	c.creates++
	return itsm.TicketRef{}, nil
}
func (c *itsmStubConnector) Exists(context.Context, itsm.TicketRef) (bool, error)  { return true, nil }
func (c *itsmStubConnector) Resolve(context.Context, itsm.TicketRef, string) error { return nil }

type itsmHarness struct {
	db              *sql.DB
	mux             *http.ServeMux
	auth            *Authenticator
	svc             *itsm.Service
	creds           *sqliteOutboundCredentialStore
	audit           *scepRecordingAudit
	credID          string
	stub            *itsmStubConnector
	adminKey, opKey string
}

func newITSMHarness(t *testing.T) *itsmHarness {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "itsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	creds := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := creds.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	meta, err := creds.Create(context.Background(), "cred-itsm", "snow", "api_token", "default", []byte(`{"username":"svc","password":"`+itsmSecret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	stub := &itsmStubConnector{}
	svc := itsm.NewService(itsm.Config{
		Store: itsm.NewStore(db, false),
		Conns: func(context.Context, string) (itsm.Connector, error) { return stub, nil },
	})
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	registerITSMHandlers(mux, auth, svc, creds, audit, nil)
	_, opKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &itsmHarness{db: db, stub: stub, mux: mux, auth: auth, svc: svc, creds: creds, audit: audit, credID: meta.ID, adminKey: "test-token", opKey: opKey}
}

func (h *itsmHarness) call(method, path, token string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func (h *itsmHarness) lastAudit(action string) (AuditEntry, bool) {
	for i := len(h.audit.entries) - 1; i >= 0; i-- {
		if h.audit.entries[i].Action == action {
			return h.audit.entries[i], true
		}
	}
	return AuditEntry{}, false
}

func (h *itsmHarness) createConn(t *testing.T, token string) string {
	t.Helper()
	rec := h.call(http.MethodPost, "/api/v1/itsm/connections", token, map[string]any{
		"kind": "servicenow", "name": "prod snow", "base_url": "https://example.service-now.com", "credential_ref": h.credID,
		"event_classes": []map[string]string{{"class": "renewal_failed", "ticket_type": "incident"}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data itsm.Connection }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Data.ID
}

func TestITSMHandlers_AdminOnly(t *testing.T) {
	h := newITSMHarness(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/itsm/connections"},
		{http.MethodPost, "/api/v1/itsm/connections"},
		{http.MethodGet, "/api/v1/itsm/connections/x"},
		{http.MethodDelete, "/api/v1/itsm/connections/x"},
		{http.MethodGet, "/api/v1/itsm/events"},
	} {
		if rec := h.call(tc.method, tc.path, h.opKey, map[string]string{}); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as operator: %d, want 403", tc.method, tc.path, rec.Code)
		}
		if rec := h.call(tc.method, tc.path, "", nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated: %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
	if e, ok := h.lastAudit("itsm.connection.create"); !ok || e.Outcome != AuditOutcomeDenied {
		t.Fatalf("denial not audited: %+v", h.audit.entries)
	}
}

func TestITSMHandlers_CreateGetListDelete_CredentialsNeverEchoed(t *testing.T) {
	h := newITSMHarness(t)
	id := h.createConn(t, h.adminKey)
	if e, ok := h.lastAudit("itsm.connection.create"); !ok || e.Outcome != AuditOutcomeSuccess || e.ResourceID != id {
		t.Fatalf("create not audited: %+v", h.audit.entries)
	}
	for _, path := range []string{"/api/v1/itsm/connections", "/api/v1/itsm/connections/" + id} {
		rec := h.call(http.MethodGet, path, h.adminKey, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), id) {
			t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), itsmSecret) || strings.Contains(rec.Body.String(), "password") {
			t.Fatalf("GET %s leaked credential material: %s", path, rec.Body.String())
		}
	}
	rec := h.call(http.MethodDelete, "/api/v1/itsm/connections/"+id, h.adminKey, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if e, ok := h.lastAudit("itsm.connection.delete"); !ok || e.Outcome != AuditOutcomeSuccess {
		t.Fatalf("delete not audited: %+v", h.audit.entries)
	}
	if rec := h.call(http.MethodGet, "/api/v1/itsm/connections/"+id, h.adminKey, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("after delete: %d", rec.Code)
	}
	for _, e := range h.audit.entries {
		if strings.Contains(e.ChangeSummary, itsmSecret) {
			t.Fatal("audit entry carries credential material")
		}
	}
}

func TestITSMHandlers_ValidationFailuresAreAudited(t *testing.T) {
	h := newITSMHarness(t)
	good := map[string]any{"kind": "jira", "name": "j", "base_url": "https://j.example", "credential_ref": h.credID}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range good {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	for name, body := range map[string]map[string]any{
		"unknown credential_ref": with("credential_ref", "cred-missing"),
		"bad kind":               with("kind", "remedy"),
		"plain http":             with("base_url", "http://j.example"),
		"userinfo in url":        with("base_url", "https://u:p@j.example"),
		"no name":                with("name", " "),
		"no credential_ref":      with("credential_ref", ""),
	} {
		before := len(h.audit.entries)
		rec := h.call(http.MethodPost, "/api/v1/itsm/connections", h.adminKey, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if name == "unknown credential_ref" && !strings.Contains(rec.Body.String(), "unknown credential_ref") {
			t.Errorf("message: %s", rec.Body.String())
		}
		if len(h.audit.entries) != before+1 || h.audit.entries[before].Outcome != AuditOutcomeFailure {
			t.Errorf("%s: failure not audited", name)
		}
	}
	// Loopback http is allowed for local stubs.
	if rec := h.call(http.MethodPost, "/api/v1/itsm/connections", h.adminKey, with("base_url", "http://127.0.0.1:9999")); rec.Code != http.StatusCreated {
		t.Errorf("loopback http: %d %s", rec.Code, rec.Body.String())
	}
}

func TestITSMHandlers_TenantIsolation(t *testing.T) {
	h := newITSMHarness(t)
	t.Setenv("MULTI_TENANCY", "on")
	// The credential belongs to tenant-a so tenant-b cannot reference it.
	if _, err := h.creds.Create(context.Background(), "cred-a", "a", "api_token", "tenant-a", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	_, tokA, err := h.auth.CreateAPIKey("ka", "ka", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, tokB, err := h.auth.CreateAPIKey("kb", "kb", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"kind": "jira", "name": "a", "base_url": "https://a.example", "credential_ref": "cred-a"}
	rec := h.call(http.MethodPost, "/api/v1/itsm/connections", tokA, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("tenant-a create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ Data itsm.Connection }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Data.Tenant != "tenant-a" {
		t.Fatalf("tenant stamp: %q", created.Data.Tenant)
	}
	if rec := h.call(http.MethodPost, "/api/v1/itsm/connections", tokB, body); rec.Code != http.StatusBadRequest {
		t.Errorf("tenant-b must not reference tenant-a's credential: %d", rec.Code)
	}
	if rec := h.call(http.MethodGet, "/api/v1/itsm/connections", tokB, nil); strings.Contains(rec.Body.String(), created.Data.ID) {
		t.Errorf("list leaked across tenants: %s", rec.Body.String())
	}
	if rec := h.call(http.MethodGet, "/api/v1/itsm/connections/"+created.Data.ID, tokB, nil); rec.Code != http.StatusNotFound {
		t.Errorf("get across tenants: %d", rec.Code)
	}
	if rec := h.call(http.MethodDelete, "/api/v1/itsm/connections/"+created.Data.ID, tokB, nil); rec.Code != http.StatusNotFound {
		t.Errorf("delete across tenants: %d", rec.Code)
	}
	// Events: tenant-a submits one; tenant-b sees none.
	if err := h.svc.Submit(context.Background(), created.Data.ID, itsm.Event{ID: "ev-a", Class: "expiry"}); err != nil {
		t.Fatal(err)
	}
	if rec := h.call(http.MethodGet, "/api/v1/itsm/events", tokB, nil); strings.Contains(rec.Body.String(), "ev-a") {
		t.Errorf("events leaked across tenants: %s", rec.Body.String())
	}
	if rec := h.call(http.MethodGet, "/api/v1/itsm/events", tokA, nil); !strings.Contains(rec.Body.String(), "ev-a") {
		t.Errorf("owner cannot see its event: %s", rec.Body.String())
	}
}

func TestITSMHandlers_EventsAndDeleteWithHistory(t *testing.T) {
	h := newITSMHarness(t)
	id := h.createConn(t, h.adminKey)
	for i := 0; i < 3; i++ {
		if err := h.svc.Submit(context.Background(), id, itsm.Event{ID: "ev-" + string(rune('a'+i)), Class: "renewal_failed"}); err != nil {
			t.Fatal(err)
		}
	}
	rec := h.call(http.MethodGet, "/api/v1/itsm/events?status=pending&limit=2", h.adminKey, nil)
	var resp struct {
		Data struct{ Items []itsm.EventRow }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK || len(resp.Data.Items) != 2 {
		t.Fatalf("limit: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"payload"`) {
		t.Fatal("payload must not be exposed")
	}
	for _, q := range []string{"status=bogus", "limit=0", "limit=x"} {
		if rec := h.call(http.MethodGet, "/api/v1/itsm/events?"+q, h.adminKey, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	if rec := h.call(http.MethodDelete, "/api/v1/itsm/connections/"+id, h.adminKey, nil); rec.Code != http.StatusConflict {
		t.Fatalf("delete with history: %d", rec.Code)
	}
	if e, _ := h.lastAudit("itsm.connection.delete"); e.Outcome != AuditOutcomeFailure {
		t.Fatalf("conflict not audited: %+v", e)
	}
}

func TestITSMHandlers_UnconfiguredAnswers503AndAudits(t *testing.T) {
	h := newITSMHarness(t)
	mux := http.NewServeMux()
	registerITSMHandlers(mux, h.auth, nil, nil, h.audit, nil)
	h.mux = mux
	rec := h.call(http.MethodPost, "/api/v1/itsm/connections", h.adminKey, map[string]any{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d", rec.Code)
	}
	if e, ok := h.lastAudit("itsm.connection.create"); !ok || e.Outcome != AuditOutcomeFailure {
		t.Fatalf("%+v", h.audit.entries)
	}
}

func TestValidITSMBaseURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://a.example": true, "http://localhost:8080": true, "http://127.0.0.1": true, "http://[::1]:80": true,
		"http://a.example": false, "ftp://a.example": false, "https://": false, "https://u:p@a.example": false, "": false,
	} {
		if got := validITSMBaseURL(raw); got != want {
			t.Errorf("%q: got %v want %v", raw, got, want)
		}
	}
}

func TestITSMHandlers_EventClassesShapeValidationAndRoundTrip(t *testing.T) {
	h := newITSMHarness(t)
	base := func(kind string, classes any) map[string]any {
		return map[string]any{"kind": kind, "name": "n", "base_url": "https://x.example", "credential_ref": h.credID, "event_classes": classes}
	}
	ec := func(class, tt string) map[string]string { return map[string]string{"class": class, "ticket_type": tt} }
	for name, body := range map[string]map[string]any{
		"legacy string array":        base("servicenow", []string{"renewal_failed"}),
		"not an array":               base("servicenow", "renewal_failed"),
		"unknown field":              base("servicenow", []map[string]string{{"class": "renewal_failed", "ticket_type": "incident", "x": "y"}}),
		"unknown class":              base("servicenow", []any{ec("expiry", "incident")}),
		"duplicate class":            base("servicenow", []any{ec("renewal_failed", "incident"), ec("renewal_failed", "change_request")}),
		"servicenow bad ticket_type": base("servicenow", []any{ec("renewal_failed", "problem")}),
		"jira control char type":     base("jira", []any{ec("renewal_failed", "Bu\x00g")}),
	} {
		before := len(h.audit.entries)
		rec := h.call(http.MethodPost, "/api/v1/itsm/connections", h.adminKey, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if len(h.audit.entries) != before+1 || h.audit.entries[before].Outcome != AuditOutcomeFailure {
			t.Errorf("%s: failure not audited", name)
		}
	}
	want := []any{ec("renewal_failed", "incident"), ec("approval_pending", "change_request"), ec("expiry_no_owner", "incident")}
	rec := h.call(http.MethodPost, "/api/v1/itsm/connections", h.adminKey, base("servicenow", want))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data itsm.Connection }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Data.EventClasses) != 3 || resp.Data.EventClasses[1] != (itsm.EventClass{Class: "approval_pending", TicketType: "change_request"}) {
		t.Fatalf("create response: %+v", resp.Data.EventClasses)
	}
	got := h.call(http.MethodGet, "/api/v1/itsm/connections/"+resp.Data.ID, h.adminKey, nil)
	var back struct{ Data itsm.Connection }
	_ = json.Unmarshal(got.Body.Bytes(), &back)
	if len(back.Data.EventClasses) != 3 || back.Data.EventClasses[2] != (itsm.EventClass{Class: "expiry_no_owner", TicketType: "incident"}) {
		t.Fatalf("round trip: %s", got.Body.String())
	}
	// Jira: omitted ticket_type defaults to Task; a custom name is kept verbatim.
	rec = h.call(http.MethodPost, "/api/v1/itsm/connections", h.adminKey, base("jira", []any{ec("renewal_failed", ""), ec("approval_pending", "Change Request")}))
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusCreated || resp.Data.EventClasses[0].TicketType != "Task" || resp.Data.EventClasses[1].TicketType != "Change Request" {
		t.Fatalf("jira: %d %s", rec.Code, rec.Body.String())
	}
	// Routing: an unsubscribed class is dropped, a subscribed one carries its ticket type.
	if err := h.svc.Submit(context.Background(), resp.Data.ID, itsm.Event{ID: "drop", Class: "expiry_no_owner"}); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Submit(context.Background(), resp.Data.ID, itsm.Event{ID: "keep", Class: "approval_pending"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Store().GetEvent(context.Background(), "drop"); err == nil {
		t.Error("unsubscribed class was queued")
	}
	row, err := h.svc.Store().GetEvent(context.Background(), "keep")
	if err != nil || !strings.Contains(row.Payload, `"ticket_type":"Change Request"`) {
		t.Errorf("ticket type not carried: %q err=%v", row.Payload, err)
	}
}

func TestITSMHandlers_TestConnection(t *testing.T) {
	h := newITSMHarness(t)
	id := h.createConn(t, h.adminKey)
	path := "/api/v1/itsm/connections/" + id + "/test"
	type result struct {
		Data struct {
			OK     bool
			Detail string
		}
	}
	run := func(token string) (*httptest.ResponseRecorder, result) {
		rec := h.call(http.MethodPost, path, token, nil)
		var r result
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return rec, r
	}
	rec, r := run(h.adminKey)
	if rec.Code != http.StatusOK || !r.Data.OK || r.Data.Detail == "" {
		t.Fatalf("ok path: %d %s", rec.Code, rec.Body.String())
	}
	if len(h.stub.finds) != 1 || h.stub.finds[0] != "kk-connection-test" || h.stub.creates != 0 {
		t.Fatalf("must be one read-only Find: finds=%v creates=%d", h.stub.finds, h.stub.creates)
	}
	if e, ok := h.lastAudit("itsm.connection.test"); !ok || e.Outcome != AuditOutcomeSuccess || e.ResourceID != id {
		t.Fatalf("ok not audited: %+v", h.audit.entries)
	}
	for name, findErr := range map[string]error{
		"temporary": fmt.Errorf("%w: upstream body %s", itsm.ErrTemporary, itsmSecret),
		"permanent": fmt.Errorf("%w: upstream body %s", itsm.ErrPermanent, itsmSecret),
		"other":     errors.New("boom " + itsmSecret),
	} {
		h.stub.findErr = findErr
		rec, r = run(h.adminKey)
		if rec.Code != http.StatusOK || r.Data.OK || r.Data.Detail == "" || strings.Contains(rec.Body.String(), itsmSecret) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if e, _ := h.lastAudit("itsm.connection.test"); e.Outcome != AuditOutcomeFailure {
			t.Errorf("%s: failure not audited: %+v", name, e)
		}
	}
	before := len(h.audit.entries)
	if rec := h.call(http.MethodPost, "/api/v1/itsm/connections/itsm-nope/test", h.adminKey, nil); rec.Code != http.StatusNotFound {
		t.Errorf("missing connection: %d", rec.Code)
	}
	if len(h.audit.entries) != before+1 {
		t.Error("404 not audited")
	}
	if rec := h.call(http.MethodPost, path, h.opKey, nil); rec.Code != http.StatusForbidden {
		t.Errorf("operator: %d, want 403", rec.Code)
	}
	if e, _ := h.lastAudit("itsm.connection.test"); e.Outcome != AuditOutcomeDenied {
		t.Errorf("denial not audited: %+v", e)
	}
	if rec := h.call(http.MethodGet, path, h.adminKey, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
}

func TestITSMHandlers_TestConnectionCrossTenant404(t *testing.T) {
	h := newITSMHarness(t)
	t.Setenv("MULTI_TENANCY", "on")
	if _, err := h.creds.Create(context.Background(), "cred-a", "a", "api_token", "tenant-a", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	_, tokA, _ := h.auth.CreateAPIKey("ka", "ka", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	_, tokB, _ := h.auth.CreateAPIKey("kb", "kb", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	rec := h.call(http.MethodPost, "/api/v1/itsm/connections", tokA, map[string]any{"kind": "jira", "name": "a", "base_url": "https://a.example", "credential_ref": "cred-a"})
	var created struct{ Data itsm.Connection }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	path := "/api/v1/itsm/connections/" + created.Data.ID + "/test"
	if rec := h.call(http.MethodPost, path, tokB, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant test: %d", rec.Code)
	}
	if len(h.stub.finds) != 0 {
		t.Fatal("cross-tenant request reached the connector")
	}
	if rec := h.call(http.MethodPost, path, tokA, nil); rec.Code != http.StatusOK {
		t.Fatalf("owner: %d", rec.Code)
	}
}
