// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
)

type listApprovalStore struct {
	ApprovalStore
	pending []ApprovalRequest
}

func (s *listApprovalStore) List(_ context.Context, status string, _, offset int) ([]ApprovalRequest, int, error) {
	if status != "pending" || offset > 0 {
		return nil, len(s.pending), nil
	}
	return s.pending, len(s.pending), nil
}

func (f *templateAPIFixture) put(id, body, ifMatch string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/templates/"+id, strings.NewReader(body))
	req.Header.Set("If-Match", ifMatch)
	req.Header.Set("Authorization", "Bearer "+f.h.key(f.t, "pki-admin"))
	rec := httptest.NewRecorder()
	f.h.gate.ServeHTTP(rec, req)
	return rec
}

func (f *templateAPIFixture) revisions(id string) []TemplateRevision {
	f.t.Helper()
	rec := f.h.do(f.h.key(f.t, "pki-admin"), http.MethodGet, "/api/v1/templates/"+id+"/revisions", nil)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("GET revisions: %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data []TemplateRevision `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		f.t.Fatal(err)
	}
	return env.Data
}

// toRevision3 creates a template and takes it to revision 3 (PUT validity,
// PATCH display_name).
func (f *templateAPIFixture) toRevision3(name string) string {
	f.t.Helper()
	id := f.createTemplate(name, "")
	if rec := f.put(id, strings.Replace(enrollTemplateBody(name, ""), "P1D", "P2D", 1), "1"); rec.Code != http.StatusOK {
		f.t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.h.do(f.h.key(f.t, "pki-admin"), http.MethodPatch, "/api/v1/templates/"+id, []byte(`{"display_name":"renamed"}`)); rec.Code != http.StatusOK {
		f.t.Fatalf("PATCH: %d %s", rec.Code, rec.Body.String())
	}
	return id
}

func TestRevisionsListedWithDiffs(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.toRevision3("hist")
	revs := f.revisions(id)
	if len(revs) != 3 {
		t.Fatalf("got %d revisions, want 3", len(revs))
	}
	for i, r := range revs {
		if r.Revision != i+1 {
			t.Fatalf("revision[%d] = %d, want ascending 1..3", i, r.Revision)
		}
	}
	if len(revs[0].Changes) != 0 {
		t.Errorf("revision 1 changes = %+v, want none", revs[0].Changes)
	}
	var found bool
	for _, c := range revs[1].Changes {
		if c.Field == "validity_period" && c.Old == "P1D" && c.New == "P2D" {
			found = true
		}
	}
	if !found {
		t.Errorf("revision 2 lacks validity_period P1D->P2D: %+v", revs[1].Changes)
	}
	if len(revs[2].Changes) != 1 || revs[2].Changes[0].Field != "display_name" || revs[2].Changes[0].New != "renamed" {
		t.Errorf("revision 3 changes = %+v, want display_name only", revs[2].Changes)
	}
	if revs[1].Snapshot.ValidityPeriod != "P2D" || revs[0].Snapshot.ValidityPeriod != "P1D" {
		t.Errorf("snapshots do not hold each revision's own values")
	}
}

func TestValidityChangeMovesRevision3To4AndAuditsOldNew(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.toRevision3("audit-rev")
	rec := f.put(id, strings.Replace(enrollTemplateBody("audit-rev", ""), "P1D", "P90D", 1), "3")
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != "4" {
		t.Fatalf("PUT If-Match 3: %d etag=%q %s", rec.Code, rec.Header().Get("ETag"), rec.Body.String())
	}
	var row *AuditEntry
	for i, e := range f.h.audit.entries {
		if e.Action == "template.replace" && e.Outcome == AuditOutcomeSuccess && strings.Contains(e.ChangeSummary, `"new":4`) {
			row = &f.h.audit.entries[i]
		}
	}
	if row == nil {
		t.Fatalf("no template.replace audit row: %+v", f.h.audit.entries)
	}
	var detail struct {
		Revision struct{ Old, New int } `json:"revision"`
		Changes  []TemplateFieldChange  `json:"changes"`
	}
	if err := json.Unmarshal([]byte(row.ChangeSummary), &detail); err != nil {
		t.Fatalf("change summary %q: %v", row.ChangeSummary, err)
	}
	if detail.Revision.Old != 3 || detail.Revision.New != 4 {
		t.Errorf("revision move = %+v", detail.Revision)
	}
	var ok bool
	for _, c := range detail.Changes {
		ok = ok || (c.Field == "validity_period" && c.Old == "P2D" && c.New == "P90D")
	}
	if !ok {
		t.Errorf("audit lacks validity old/new: %s", row.ChangeSummary)
	}
}

func TestStaleIfMatchReturns412(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.toRevision3("stale")
	if rec := f.put(id, enrollTemplateBody("stale", `"enrollment_permissions":{"enroll":["pki-admin"]}`), "3"); rec.Code != http.StatusOK {
		t.Fatalf("PUT at 3: %d", rec.Code)
	}
	rec := f.put(id, enrollTemplateBody("stale", ""), "3")
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match: %d %s, want 412", rec.Code, rec.Body.String())
	}
	if n := len(f.revisions(id)); n != 4 {
		t.Errorf("rejected PUT changed history: %d revisions, want 4", n)
	}
}

func TestCloneRestartsHistoryAtRevision1(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.toRevision3("orig")
	f.put(id, enrollTemplateBody("orig", ""), "3") // revision 4
	rec := f.h.do(f.h.key(t, "pki-admin"), http.MethodPost, "/api/v1/templates/"+id+"/clone", []byte(`{"name":"copy","display_name":"copy"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("clone: %d %s", rec.Code, rec.Body.String())
	}
	cloneID := between(rec.Body.String(), `"id":"`, `"`)
	revs := f.revisions(cloneID)
	if len(revs) != 1 || revs[0].Revision != 1 {
		t.Fatalf("clone history = %+v, want exactly revision 1", revs)
	}
	if n := len(f.revisions(id)); n != 4 {
		t.Errorf("source history changed by clone: %d", n)
	}
}

func TestRevisionsUnknownTemplateAndUnsupportedProvider(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	if rec := f.h.do(f.h.key(t, "pki-admin"), http.MethodGet, "/api/v1/templates/nope/revisions", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id: %d", rec.Code)
	}
	// A provider without the optional capability answers 503, not a panic.
	mux := http.NewServeMux()
	h := newWriteGateHarness(t, mux)
	registerTemplateHandlers(mux, h.auth, &fakeTemplateProvider{}, h.audit, nil)
	if rec := h.do(h.key(t, "pki-admin"), http.MethodGet, "/api/v1/templates/x/revisions", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unsupported provider: %d", rec.Code)
	}
}

// A template written before history existed gets a single synthetic entry and
// then real ones as it changes.
func TestLegacyTemplateGetsSyntheticRevision(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	legacy := `[{"id":"tpl-old","name":"old","display_name":"old","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P1D","active":true,"revision":5,"schema_version":1}]`
	if err := os.WriteFile(os.Getenv("APP_TEMPLATE_FILE"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if revs := f.revisions("tpl-old"); len(revs) != 1 || revs[0].Revision != 5 || len(revs[0].Changes) != 0 {
		t.Fatalf("legacy history = %+v", revs)
	}
	f.h.do(f.h.key(t, "pki-admin"), http.MethodPatch, "/api/v1/templates/tpl-old", []byte(`{"display_name":"new"}`))
	revs := f.revisions("tpl-old")
	if len(revs) != 2 || revs[1].Revision != 6 || len(revs[1].Changes) != 1 {
		t.Fatalf("after patch = %+v", revs)
	}
}

func TestIssuedCertificateStoresTemplateRevision(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	tpl := TemplateItem{ID: "tpl-rev", Active: true, AllowedAlgorithms: []string{"ECDSA"}, ValidityPeriod: "24h", Revision: 7}
	templates := &fakeTemplateProvider{templates: map[string]TemplateItem{"tpl-rev": tpl}}
	provider = WithTemplateProvider(provider, templates)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-rev",
		CSRPEM: generateTestCSRPEM(t, "rev.example.com", "rev.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if issued.TemplateRevision != 7 {
		t.Fatalf("issued TemplateRevision = %d, want 7", issued.TemplateRevision)
	}

	// Survives the DB round trip: a fresh provider hydrates it from the row.
	reloaded := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, false), db, false)
	got, found, err := reloaded.GetCertificate(ctx, issued.FingerprintSHA256)
	if err != nil || !found {
		t.Fatalf("reload: found=%v err=%v", found, err)
	}
	if got.TemplateRevision != 7 {
		t.Fatalf("reloaded TemplateRevision = %d, want 7", got.TemplateRevision)
	}

	// No template: nothing recorded.
	plain, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID,
		CSRPEM: generateTestCSRPEM(t, "plain.example.com", "plain.example.com")})
	if err != nil || plain.TemplateRevision != 0 {
		t.Fatalf("no-template issuance: rev=%d err=%v", plain.TemplateRevision, err)
	}
}

func TestDeleteBlockedByInFlightApproval(t *testing.T) {
	store := &listApprovalStore{}
	f := newTemplateAPIFixture(t, store)
	id := f.createTemplate("inflight", "")
	store.pending = []ApprovalRequest{{ID: "apr-1", TemplateID: id, Status: "pending"}}
	admin := f.h.key(t, "pki-admin")

	if rec := f.h.do(admin, http.MethodDelete, "/api/v1/templates/"+id, nil); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "in-flight") {
		t.Fatalf("delete with pending approval: %d %s, want 409", rec.Code, rec.Body.String())
	}
	rec := f.h.do(admin, http.MethodPatch, "/api/v1/templates/"+id, []byte(`{"active":false}`))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"revision":2`) || !strings.Contains(rec.Body.String(), `"active":false`) {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	store.pending = nil // decided
	if rec := f.h.do(admin, http.MethodDelete, "/api/v1/templates/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete after decision: %d %s", rec.Code, rec.Body.String())
	}
	// A request for a different template does not block.
	other := f.createTemplate("other", "")
	store.pending = []ApprovalRequest{{ID: "apr-2", TemplateID: "someone-else", Status: "pending"}}
	if rec := f.h.do(admin, http.MethodDelete, "/api/v1/templates/"+other, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete unrelated: %d", rec.Code)
	}
}

func TestDisableAuditAction(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.createTemplate("disable-me", "")
	admin := f.h.key(t, "pki-admin")
	f.h.do(admin, http.MethodPatch, "/api/v1/templates/"+id, []byte(`{"display_name":"x"}`))
	if rows := f.auditRows("template.disable"); len(rows) != 0 {
		t.Fatalf("non-disabling patch audited as disable: %+v", rows)
	}
	f.h.do(admin, http.MethodPatch, "/api/v1/templates/"+id, []byte(`{"active":false}`))
	rows := f.auditRows("template.disable")
	if len(rows) != 1 || rows[0].ResourceID != id || !strings.Contains(rows[0].ChangeSummary, `"field":"active"`) {
		t.Fatalf("disable rows = %+v", rows)
	}
	if len(f.auditRows("template.update")) != 2 {
		t.Errorf("template.update must still be audited alongside template.disable")
	}
}
