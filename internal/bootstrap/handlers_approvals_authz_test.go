// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type approvalAuthzTemplates struct{ stubTemplateProvider }

func (approvalAuthzTemplates) GetTemplate(_ context.Context, id string) (TemplateItem, bool, error) {
	return TemplateItem{ID: id, ApprovalRoles: []string{"pki-operator"}}, true, nil
}

func newApprovalAuthzRig(t *testing.T) (*http.ServeMux, *Authenticator, ApprovalStore, *expiryAudit) {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "appr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteApprovalStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	audit := &expiryAudit{}
	mux := http.NewServeMux()
	registerApprovalHandlers(mux, auth, store, &reportCertProvider{}, approvalAuthzTemplates{}, audit)
	return mux, auth, store, audit
}

func seedAuthzApproval(t *testing.T, s ApprovalStore, id string) {
	t.Helper()
	if err := s.Create(context.Background(), ApprovalRequest{ID: id, TemplateID: "tpl", CAID: "ca", Requester: "req-1",
		Status: "pending", RequestedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
}

// F8: reject needs the role approve needs; the ChatOps bridge bypasses the
// write gate, so the handler itself must refuse a viewer or requester.
func TestApprovalReject_RequiresApproverRole(t *testing.T) {
	mux, auth, store, audit := newApprovalAuthzRig(t)
	seedAuthzApproval(t, store, "apr-1")
	for _, role := range []string{"pki-viewer", "pki-requester"} {
		_, tok, err := auth.CreateAPIKey(role+"-key", role+"-p", role, []string{"*"}, "", "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, bearerReq(tok, http.MethodPost, "/api/v1/approvals/apr-1/reject", []byte(`{"reason":"x"}`)))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s reject: %d %s", role, rec.Code, rec.Body.String())
		}
	}
	if got, _ := store.Get(context.Background(), "apr-1"); got.Status != "pending" {
		t.Fatalf("status %s after refused rejects", got.Status)
	}
	if len(audit.all("approval.reject", AuditOutcomeDenied)) != 2 {
		t.Fatalf("denied audit rows: %+v", audit.entries)
	}
	// A template-listed approver role and an admin may reject.
	_, op, err := auth.CreateAPIKey("op-key", "op-p", "pki-operator", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(op, http.MethodPost, "/api/v1/approvals/apr-1/reject", []byte(`{"reason":"no"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("operator reject: %d %s", rec.Code, rec.Body.String())
	}
	seedAuthzApproval(t, store, "apr-2")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, auth, "adm", ""), http.MethodPost, "/api/v1/approvals/apr-2/reject", []byte(`{"reason":"no"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin reject: %d %s", rec.Code, rec.Body.String())
	}
}

// L-8: an oversized limit is clamped, not honoured.
func TestApprovalList_LimitClamped(t *testing.T) {
	mux, auth, _, _ := newApprovalAuthzRig(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, auth, "adm", ""), http.MethodGet, "/api/v1/approvals?limit=1000000", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Meta struct{ Limit int } `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Meta.Limit != approvalsMaxListLimit {
		t.Fatalf("limit = %d (%s), want %d", body.Meta.Limit, strings.TrimSpace(rec.Body.String()), approvalsMaxListLimit)
	}
}
