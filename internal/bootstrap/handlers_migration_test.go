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

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/migration"
)

// testMigrationImporter reads a JSON array of {"key","name"} objects.
type testMigrationImporter struct{}

func (testMigrationImporter) Source() string { return "testsrc" }

func (testMigrationImporter) Parse(_ context.Context, in migration.Input) ([]migration.SourceObject, error) {
	var raw []map[string]string
	if err := json.Unmarshal(in.Content, &raw); err != nil {
		return nil, err
	}
	out := []migration.SourceObject{}
	for _, r := range raw {
		out = append(out, migration.SourceObject{Kind: "template", SourceKey: r["key"], Name: r["name"], Raw: map[string]any{"oid": r["oid"]}})
	}
	return out, nil
}

func (testMigrationImporter) Map(o migration.SourceObject) (migration.Mapped, error) {
	oid, _ := o.Raw["oid"].(string)
	return migration.Mapped{
		Template: migration.Template{Name: o.Name, DisplayName: o.Name, OID: oid, KeyUsage: []string{"digitalSignature"},
			ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"RSA"}, MinKeySize: 2048, ValidityPeriod: "P30D"},
		Fields: []migration.FieldReport{{Field: "validity", Status: migration.FieldMapped, Target: "validity_period"}},
	}, nil
}

// fakeApprovals lists a fixed set of approval requests.
type fakeApprovals struct {
	ApprovalStore
	pending []ApprovalRequest
}

func (f *fakeApprovals) List(context.Context, string, int, int) ([]ApprovalRequest, int, error) {
	return f.pending, len(f.pending), nil
}

type migrationHarness struct {
	*pluginHarness
	templates TemplateProvider
	svc       *migration.Service
	approvals *fakeApprovals
	h         *migrationHandlers
	// policies is the real issuance-policy engine (Baseline seeded by the
	// migrations); floorOff stops the migration from reading its floor.
	policies *ca.PolicyEngine
	floorOff *bool
}

func newMigrationHarness(t *testing.T) *migrationHarness {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("APP_TEMPLATE_FILE", filepath.Join(t.TempDir(), "templates.json"))
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migration.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// The real migration, so a drift between it and the store's DDL shows up.
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	actions := &dbPendingActionStore{db: db, ph: sqlitePlaceholder}
	if err := actions.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	templates := NewFileTemplateProviderFromEnv()
	approvals := &fakeApprovals{}
	sink := templateSink{templates: templates, approvals: func() (ApprovalStore, error) { return approvals, nil }}
	pe, err := ca.NewPolicyEngine(db, false)
	if err != nil {
		t.Fatal(err)
	}
	floorOff := new(bool)
	svc := migration.NewService(sink, migration.NewSQLStore(db, false), testMigrationImporter{}).
		WithKeyFloor(policyKeyFloor(func() *ca.PolicyEngine {
			if *floorOff {
				return nil
			}
			return pe
		}))
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	h := mountMigrationHandlers(mux, auth, svc, nil, actions, audit)
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, actions, audit,
		map[string]ActionExecutor{ActionMigrationApply: h.ExecuteApply})
	_, adminKey, err := auth.CreateAPIKey("admin-2", "second-admin", "pki-admin", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, opKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &migrationHarness{
		pluginHarness: &pluginHarness{mux: mux, adminKey: adminKey, opKey: opKey, audit: audit},
		templates:     templates, svc: svc, approvals: approvals, h: h, policies: pe, floorOff: floorOff,
	}
}

func migrationBody(objs ...[2]string) map[string]any {
	list := []map[string]string{}
	for _, o := range objs {
		list = append(list, map[string]string{"key": o[0], "name": o[1]})
	}
	raw, _ := json.Marshal(list)
	return map[string]any{"source": "testsrc", "content": string(raw)}
}

func (h *migrationHarness) templateNames(t *testing.T) []string {
	t.Helper()
	res, err := h.templates.ListTemplates(context.Background(), TemplateListQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, it := range res.Items {
		names = append(names, it.Name)
	}
	return names
}

func (h *migrationHarness) auditActions(action string) []AuditEntry {
	var out []AuditEntry
	for _, e := range h.audit.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (h *migrationHarness) proposeAndApprove(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	id := pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/migration/apply", "test-token", body))
	return h.call(t, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", h.adminKey, nil)
}

func TestDryRunEndpoint(t *testing.T) {
	h := newMigrationHarness(t)
	rec := h.call(t, http.MethodPost, "/api/v1/migration/dryrun", "test-token", migrationBody([2]string{"k1", "Web"}, [2]string{"k2", "Mail"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("dryrun: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data migration.Diff `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Data.Counts[migration.ActionCreate] != 2 || len(out.Data.Entries) != 2 || out.Data.Entries[0].Name != "Mail" {
		t.Fatalf("diff: %+v", out.Data)
	}
	if n := h.templateNames(t); len(n) != 0 {
		t.Fatalf("dry-run created templates: %v", n)
	}
	if got := h.auditActions("migration.dryrun"); len(got) != 1 || got[0].ResourceID != "testsrc" {
		t.Fatalf("audit: %+v", got)
	}
	rec2 := h.call(t, http.MethodPost, "/api/v1/migration/dryrun", "test-token", migrationBody([2]string{"k1", "Web"}, [2]string{"k2", "Mail"}))
	if rec.Body.String() != rec2.Body.String() {
		t.Fatalf("dry-run not byte-identical:\n%s\n%s", rec.Body.String(), rec2.Body.String())
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/migration/dryrun", "test-token", map[string]any{"source": "nope", "content": "[]"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown source: %d", rec.Code)
	}
	if rec := h.call(t, http.MethodGet, "/api/v1/migration/sources", "test-token", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"testsrc"`) {
		t.Fatalf("sources: %d %s", rec.Code, rec.Body.String())
	}
}

func TestApplyProposesAndReturns202(t *testing.T) {
	h := newMigrationHarness(t)
	rec := h.call(t, http.MethodPost, "/api/v1/migration/apply", "test-token", migrationBody([2]string{"k1", "Web"}))
	id := pendingActionID(t, rec)
	if n := h.templateNames(t); len(n) != 0 {
		t.Fatalf("proposal created templates before approval: %v", n)
	}
	if !strings.Contains(rec.Body.String(), `"diff"`) {
		t.Fatalf("202 must carry the diff: %s", rec.Body.String())
	}
	if got := h.auditActions("migration.apply_requested"); len(got) != 1 || !strings.Contains(got[0].ChangeSummary, id) {
		t.Fatalf("audit: %+v", got)
	}
	// Self-approval is refused by the queue.
	if rec := h.call(t, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", "test-token", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("proposer approved own migration: %d", rec.Code)
	}
	if n := h.templateNames(t); len(n) != 0 {
		t.Fatalf("self-approval created templates: %v", n)
	}
}

func TestApplyExecutorCreatesBatchAndAudits(t *testing.T) {
	h := newMigrationHarness(t)
	rec := h.proposeAndApprove(t, migrationBody([2]string{"k1", "Web"}, [2]string{"k2", "Mail"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.templateNames(t); len(n) != 2 {
		t.Fatalf("templates: %v", n)
	}
	res, _ := h.templates.ListTemplates(context.Background(), TemplateListQuery{Limit: 10})
	for _, it := range res.Items {
		if !it.Active {
			t.Fatalf("migrated template %s must be active", it.Name)
		}
	}
	got := h.auditActions("migration.apply")
	if len(got) != 1 || got[0].ActorID != "second-admin" || got[0].Outcome != AuditOutcomeSuccess || !strings.Contains(got[0].ChangeSummary, "created=2") {
		t.Fatalf("audit: %+v", got)
	}
	batchID := strings.TrimPrefix(strings.Fields(got[0].ChangeSummary)[0], "batch=")
	if !strings.HasPrefix(batchID, "mb_") || got[0].ResourceID != batchID {
		t.Fatalf("batch id: %q / %q", batchID, got[0].ResourceID)
	}

	rec = h.call(t, http.MethodGet, "/api/v1/migration/batches", "test-token", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), batchID) || !strings.Contains(rec.Body.String(), `"items":2`) || strings.Contains(rec.Body.String(), "report_json") {
		t.Fatalf("batches: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.call(t, http.MethodGet, "/api/v1/migration/"+batchID+"/report", "test-token", nil)
	var rep struct {
		Data struct {
			Batch  migration.Batch  `json:"batch"`
			Report migration.Report `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("report: %d %v %s", rec.Code, err, rec.Body.String())
	}
	if rep.Data.Report.Created != 2 || rep.Data.Batch.CreatedBy != "second-admin" || rep.Data.Report.Entries[0].TemplateID == "" || len(rep.Data.Report.Entries[0].Fields) == 0 {
		t.Fatalf("report: %+v", rep.Data)
	}
	if rec := h.call(t, http.MethodGet, "/api/v1/migration/mb_missing/report", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing report: %d", rec.Code)
	}
}

func TestApplyRerunCreatesNothing(t *testing.T) {
	h := newMigrationHarness(t)
	body := migrationBody([2]string{"k1", "Web"})
	if rec := h.proposeAndApprove(t, body); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	rec := h.call(t, http.MethodPost, "/api/v1/migration/apply", "test-token", body)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "nothing_to_apply") {
		t.Fatalf("rerun: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.templateNames(t); len(n) != 1 {
		t.Fatalf("rerun changed templates: %v", n)
	}
}

func TestApplyExecutorRefusesChangedState(t *testing.T) {
	h := newMigrationHarness(t)
	id := pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/migration/apply", "test-token", migrationBody([2]string{"k1", "Web"})))
	// Someone creates the same template name between proposal and approval.
	if _, err := h.templates.CreateTemplate(context.Background(), TemplateUpsertRequest{Name: "Web", DisplayName: "Web",
		KeyUsage: []string{"digitalSignature"}, ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"RSA"}, ValidityPeriod: "P30D", Active: true}); err != nil {
		t.Fatal(err)
	}
	rec := h.call(t, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", h.adminKey, nil)
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "propose again") {
		t.Fatalf("stale proposal executed: %d %s", rec.Code, rec.Body.String())
	}
	if got := h.auditActions("migration.apply"); len(got) != 1 || got[0].Outcome != AuditOutcomeFailure {
		t.Fatalf("audit: %+v", got)
	}
}

func TestApplyOversizeRejected(t *testing.T) {
	h := newMigrationHarness(t)
	rec := h.call(t, http.MethodPost, "/api/v1/migration/apply", "test-token",
		map[string]any{"source": "testsrc", "content": strings.Repeat("x", maxMigrationApplyContent+1)})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "split it") {
		t.Fatalf("oversize: %d %s", rec.Code, rec.Body.String())
	}
}

func TestMigrationRequiresAuthAndPermission(t *testing.T) {
	h := newMigrationHarness(t)
	for _, p := range []string{"/api/v1/migration/dryrun", "/api/v1/migration/apply", "/api/v1/migration/batches", "/api/v1/migration/sources"} {
		method := http.MethodPost
		if strings.HasSuffix(p, "batches") || strings.HasSuffix(p, "sources") {
			method = http.MethodGet
		}
		if rec := h.call(t, method, p, "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without token: %d", p, rec.Code)
		}
		if rec := h.call(t, method, p, "wrong-token", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s with bad token: %d", p, rec.Code)
		}
	}
	// The write gate (which fronts the real server) must cover the routes.
	for _, path := range []string{"/api/v1/migration/dryrun", "/api/v1/migration/apply", "/api/v1/migration/mb_1/rollback"} {
		if ok, need := writeDecision(AuthPrincipal{ID: "x", Role: "viewer"}, nil, path); ok || need != "ca.manage" {
			t.Fatalf("%s: viewer allowed=%v need=%q", path, ok, need)
		}
		if ok, _ := writeDecision(AuthPrincipal{ID: "a", Role: "pki-admin"}, nil, path); !ok {
			t.Fatalf("%s: admin refused", path)
		}
	}
	if rec := h.call(t, http.MethodGet, "/api/v1/migration/dryrun", "test-token", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET dryrun: %d", rec.Code)
	}
}

func (h *migrationHarness) appliedBatch(t *testing.T, objs ...[2]string) string {
	t.Helper()
	if rec := h.proposeAndApprove(t, migrationBody(objs...)); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	return strings.TrimPrefix(strings.Fields(h.auditActions("migration.apply")[0].ChangeSummary)[0], "batch=")
}

func (h *migrationHarness) activeByName(t *testing.T) map[string]bool {
	t.Helper()
	res, err := h.templates.ListTemplates(context.Background(), TemplateListQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, it := range res.Items {
		out[it.Name] = it.Active
	}
	return out
}

func TestRollbackEndpointDisablesAndKeepsPending(t *testing.T) {
	h := newMigrationHarness(t)
	batchID := h.appliedBatch(t, [2]string{"k1", "Web"}, [2]string{"k2", "Mail"}, [2]string{"k3", "Vpn"})
	vpn, _, err := (templateSink{templates: h.templates}).FindByName(context.Background(), "Vpn")
	if err != nil || vpn == "" {
		t.Fatalf("find Vpn: %q %v", vpn, err)
	}
	h.approvals.pending = []ApprovalRequest{{ID: "ap1", TemplateID: vpn, Status: "pending"}}

	rec := h.call(t, http.MethodPost, "/api/v1/migration/"+batchID+"/rollback", "test-token", nil)
	var out struct {
		Data migration.RollbackResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("rollback: %d %v %s", rec.Code, err, rec.Body.String())
	}
	if out.Data.Disabled != 2 || out.Data.Kept != 1 {
		t.Fatalf("result: %+v", out.Data)
	}
	active := h.activeByName(t)
	if len(active) != 3 {
		t.Fatalf("rollback must never delete: %v", active)
	}
	if active["Web"] || active["Mail"] || !active["Vpn"] {
		t.Fatalf("Web/Mail must be disabled and Vpn (pending approval) kept active: %v", active)
	}
	if rec := h.call(t, http.MethodGet, "/api/v1/migration/batches", "test-token", nil); !strings.Contains(rec.Body.String(), `"status":"rolled_back"`) || !strings.Contains(rec.Body.String(), "rolled_back_at") {
		t.Fatalf("batches: %s", rec.Body.String())
	}
}

func TestRollbackAuditWrittenOnce(t *testing.T) {
	h := newMigrationHarness(t)
	batchID := h.appliedBatch(t, [2]string{"k1", "Web"})
	path := "/api/v1/migration/" + batchID + "/rollback"
	if rec := h.call(t, http.MethodPost, path, "test-token", nil); rec.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rec.Code, rec.Body.String())
	}
	got := h.auditActions("migration.rollback")
	if len(got) != 1 || got[0].ResourceID != batchID || got[0].Outcome != AuditOutcomeSuccess || got[0].ChangeSummary != "disabled=1 kept=0" {
		t.Fatalf("audit after first: %+v", got)
	}
	rec := h.call(t, http.MethodPost, path, "test-token", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"already_rolled_back":true`) {
		t.Fatalf("second: %d %s", rec.Code, rec.Body.String())
	}
	if got := h.auditActions("migration.rollback"); len(got) != 1 {
		t.Fatalf("second rollback wrote audit rows: %+v", got)
	}
}

func TestRollbackUnknownBatch404(t *testing.T) {
	h := newMigrationHarness(t)
	if rec := h.call(t, http.MethodPost, "/api/v1/migration/mb_nope/rollback", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown batch: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.call(t, http.MethodGet, "/api/v1/migration/mb_nope/rollback", "test-token", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET rollback: %d", rec.Code)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/migration/mb_nope/rollback", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
}

func TestMigrationValidationFailuresAreAudited(t *testing.T) {
	for _, tc := range []struct {
		path, action string
		body         any
	}{
		{"/api/v1/migration/dryrun", "migration.dryrun", nil},
		{"/api/v1/migration/dryrun", "migration.dryrun", map[string]any{"source": " "}},
		{"/api/v1/migration/apply", "migration.apply_requested", nil},
		{"/api/v1/migration/apply", "migration.apply_requested", map[string]any{"source": " "}},
		{"/api/v1/migration/apply", "migration.apply_requested", map[string]any{"source": "testsrc", "content": strings.Repeat("x", maxMigrationApplyContent+1)}},
	} {
		h := newMigrationHarness(t)
		if rec := h.call(t, http.MethodPost, tc.path, "test-token", tc.body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s %v: want 400, got %d", tc.path, tc.body, rec.Code)
		}
		got := h.auditActions(tc.action)
		if len(got) != 1 || got[0].Outcome != AuditOutcomeFailure {
			t.Fatalf("%s %v: want one failure audit row, got %+v", tc.path, tc.body, got)
		}
	}
}
