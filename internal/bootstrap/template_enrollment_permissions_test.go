// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// templateAPIFixture wires the real template + certificate handlers behind the
// write gate, with a real file template provider and a real CA provider, so a
// test exercises the same POST /api/v1/certificates path the wizard uses.
type templateAPIFixture struct {
	t         *testing.T
	h         *writeGateHarness
	templates TemplateProvider
	caID      string
	approvals ApprovalStore
}

func newTemplateAPIFixture(t *testing.T, approvals ApprovalStore) *templateAPIFixture {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "templates.json")
	if err := os.WriteFile(filePath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)
	templates := NewFileTemplateProviderFromEnv()

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-enroll-perms-passphrase-32!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Enroll Root", pkix.Name{CommonName: "Enroll Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certs := WithTemplateProvider(NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false), templates)

	mux := http.NewServeMux()
	h := newWriteGateHarness(t, mux)
	registerTemplateHandlers(mux, h.auth, templates, h.audit, approvals)
	registerCertificateHandlers(mux, h.auth, certs, h.audit, approvals)
	return &templateAPIFixture{t: t, h: h, templates: templates, caID: root.ID, approvals: approvals}
}

func enrollTemplateBody(name, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return `{"name":"` + name + `","display_name":"` + name + `","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P1D","active":true` + extra + `}`
}

func (f *templateAPIFixture) createTemplate(name, extra string) string {
	f.t.Helper()
	rec := f.h.do(f.h.key(f.t, "pki-admin"), http.MethodPost, "/api/v1/templates", []byte(enrollTemplateBody(name, extra)))
	if rec.Code != http.StatusCreated {
		f.t.Fatalf("create template: %d %s", rec.Code, rec.Body.String())
	}
	return between(rec.Body.String(), `"id":"`, `"`)
}

func (f *templateAPIFixture) issue(token, templateID string) *httptest.ResponseRecorder {
	f.t.Helper()
	body, _ := json.Marshal(map[string]string{
		"ca_id": f.caID, "template_id": templateID,
		"csr_pem": generateTestCSRPEM(f.t, "svc.corp.example", "svc.corp.example"),
	})
	return f.h.do(token, http.MethodPost, "/api/v1/certificates", body)
}

func (f *templateAPIFixture) auditRows(action string) []AuditEntry {
	var out []AuditEntry
	for _, e := range f.h.audit.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func TestEnrollmentPermissionsRoundTripPOSTPUTPATCH(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	admin := f.h.key(t, "pki-admin")

	// Mixed case, whitespace and duplicates normalize.
	id := f.createTemplate("rt", `"enrollment_permissions":{"enroll":[" PKI-Admin ","pki-admin",""]}`)
	got := f.h.do(admin, http.MethodGet, "/api/v1/templates/"+id, nil)
	if !strings.Contains(got.Body.String(), `"enrollment_permissions":{"enroll":["pki-admin"]}`) {
		t.Fatalf("GET lacks normalized enroll list: %s", got.Body.String())
	}

	// PUT replaces; absent clears.
	put := f.h.do(admin, http.MethodPut, "/api/v1/templates/"+id, []byte(enrollTemplateBody("rt", "")))
	if put.Code != http.StatusPreconditionFailed {
		t.Fatalf("PUT without If-Match: %d", put.Code)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/templates/"+id, strings.NewReader(enrollTemplateBody("rt", "")))
	req.Header.Set("If-Match", "1")
	req.Header.Set("Authorization", "Bearer "+admin)
	rec := httptest.NewRecorder()
	f.h.gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "enrollment_permissions") {
		t.Fatalf("PUT should clear: %d %s", rec.Code, rec.Body.String())
	}

	// PATCH sets and bumps the revision.
	patch := f.h.do(admin, http.MethodPatch, "/api/v1/templates/"+id, []byte(`{"enrollment_permissions":{"enroll":["pki-operator","pki-admin"]}}`))
	if patch.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", patch.Code, patch.Body.String())
	}
	var env struct {
		Data TemplateItem `json:"data"`
	}
	if err := json.Unmarshal(patch.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Revision != 3 || len(env.Data.EnrollRoles()) != 2 {
		t.Fatalf("PATCH result revision=%d roles=%v, want revision 3 and 2 roles", env.Data.Revision, env.Data.EnrollRoles())
	}

	// PATCH with an empty list clears the restriction.
	clear := f.h.do(admin, http.MethodPatch, "/api/v1/templates/"+id, []byte(`{"enrollment_permissions":{"enroll":[]}}`))
	if clear.Code != http.StatusOK || strings.Contains(clear.Body.String(), "enrollment_permissions") {
		t.Fatalf("PATCH clear: %d %s", clear.Code, clear.Body.String())
	}
}

func TestEnrollmentPermissionsRejectsBadRole(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	admin := f.h.key(t, "pki-admin")
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = `"r` + strconv.Itoa(i) + `"`
	}
	for name, perms := range map[string]string{
		"space inside": `{"enroll":["pki admin"]}`,
		"leading dash": `{"enroll":["-x"]}`,
		"too long":     `{"enroll":["` + strings.Repeat("a", 65) + `"]}`,
		"too many":     `{"enroll":[` + strings.Join(tooMany, ",") + `]}`,
	} {
		rec := f.h.do(admin, http.MethodPost, "/api/v1/templates", []byte(enrollTemplateBody("bad-"+strings.ReplaceAll(name, " ", "-"), `"enrollment_permissions":`+perms)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s: %d, want 400", name, rec.Code)
		}
	}
	id := f.createTemplate("patch-bad", "")
	rec := f.h.do(admin, http.MethodPatch, "/api/v1/templates/"+id, []byte(`{"enrollment_permissions":{"enroll":["no good"]}}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("PATCH bad role: %d, want 400", rec.Code)
	}
}

// The wizard issues through the same POST /api/v1/certificates, so this test
// covers API and wizard (api.issueCertificate in ui/src/lib/api.ts).
func TestIssuanceDeniedForRoleNotInEnroll(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.createTemplate("admin-only", `"enrollment_permissions":{"enroll":["pki-admin"]}`)

	op := f.h.key(t, "pki-operator")
	rec := f.issue(op, id)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "your role may not enroll from this template") {
		t.Fatalf("operator not in enroll: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if ok := f.issue(f.h.key(t, "pki-admin"), id); ok.Code != http.StatusCreated {
		t.Fatalf("admin listed in enroll: %d %s", ok.Code, ok.Body.String())
	}
}

func TestDeniedAttemptAuditedAsIssuanceDeniedTemplateRole(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.createTemplate("audited", `"enrollment_permissions":{"enroll":["pki-admin"]}`)
	if rec := f.issue(f.h.key(t, "pki-operator"), id); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	rows := f.auditRows("issuance.denied_template_role")
	if len(rows) != 1 {
		t.Fatalf("got %d issuance.denied_template_role rows, want 1: %+v", len(rows), f.h.audit.entries)
	}
	e := rows[0]
	if e.Outcome != AuditOutcomeDenied || e.ResourceType != "template" || e.ResourceID != id ||
		!strings.Contains(e.ChangeSummary, `"role":"pki-operator"`) {
		t.Fatalf("audit row = %+v", e)
	}
}

func TestEmptyEnrollIsUnrestricted(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.createTemplate("open", `"enrollment_permissions":{"enroll":[]}`)
	if rec := f.issue(f.h.key(t, "pki-operator"), id); rec.Code != http.StatusCreated {
		t.Fatalf("empty enroll: %d %s", rec.Code, rec.Body.String())
	}
	if rows := f.auditRows("issuance.denied_template_role"); len(rows) != 0 {
		t.Fatalf("unexpected denial rows: %+v", rows)
	}
}

// Template files written before W23-42 have no field: nil must mean unrestricted.
func TestLegacyTemplateWithoutFieldStillIssues(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	legacy := `[{"id":"tpl-legacy","name":"legacy","display_name":"legacy","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P1D","active":true,"revision":1,"schema_version":1}]`
	if err := os.WriteFile(os.Getenv("APP_TEMPLATE_FILE"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := f.issue(f.h.key(t, "pki-operator"), "tpl-legacy"); rec.Code != http.StatusCreated {
		t.Fatalf("legacy template: %d %s", rec.Code, rec.Body.String())
	}
}

// Fail closed: a restricted template with no caller role in ctx (an internal
// caller that never stamped one) is refused, never waved through.
func TestRestrictedTemplateFailsClosedWithoutCallerRole(t *testing.T) {
	f := newTemplateAPIFixture(t, nil)
	id := f.createTemplate("closed", `"enrollment_permissions":{"enroll":["pki-admin"]}`)
	tpl, _, _ := f.templates.GetTemplate(context.Background(), id)
	if err := ca.CheckEnrollment(context.Background(), tpl.ID, tpl.EnrollRoles()); err == nil {
		t.Fatal("restricted template allowed a ctx with no caller role")
	}
	if err := ca.CheckEnrollment(ca.WithCallerRole(context.Background(), ""), tpl.ID, tpl.EnrollRoles()); err == nil {
		t.Fatal("blank role allowed")
	}
	if err := ca.CheckEnrollment(context.Background(), "x", nil); err != nil {
		t.Fatalf("unrestricted template denied: %v", err)
	}
}

// A denied role must not create an approval request on an approval-gated template.
func TestDeniedRoleDoesNotQueueApproval(t *testing.T) {
	store := &createApprovalStore{}
	f := newTemplateAPIFixture(t, store)
	id := f.createTemplate("gated", `"require_approval":true,"enrollment_permissions":{"enroll":["pki-admin"]}`)
	if rec := f.issue(f.h.key(t, "pki-operator"), id); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if len(store.created) != 0 {
		t.Fatalf("denied role queued %d approval(s)", len(store.created))
	}
}
