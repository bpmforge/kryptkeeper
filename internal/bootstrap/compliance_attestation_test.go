// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestAttestationStore(t *testing.T, path string) *dbComplianceAttestationStore {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &dbComplianceAttestationStore{db: db, ph: sqlitePlaceholder}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return s
}

func manualControlsOf(rep ComplianceEvidenceReport) []ComplianceControl {
	var out []ComplianceControl
	for _, c := range rep.Controls {
		if c.Type == manualControlType {
			out = append(out, c)
		}
	}
	return out
}

func TestManualControlPendingByDefault(t *testing.T) {
	store := newTestAttestationStore(t, filepath.Join(t.TempDir(), "a.db"))
	now := time.Now().UTC()
	base := computeComplianceEvidenceAt(nil, nil, "all", now)

	rep := computeComplianceEvidenceAt(nil, nil, "all", now)
	applyManualControls(context.Background(), store, &rep, now)
	manual := manualControlsOf(rep)
	if len(manual) != 3 {
		t.Fatalf("want 3 manual controls, got %d", len(manual))
	}
	for _, c := range manual {
		if c.Status != attestStatusPending || c.Type != manualControlType {
			t.Fatalf("control %s = %q/%q, want pending/manual", c.ID, c.Status, c.Type)
		}
	}
	if rep.Summary != base.Summary {
		t.Fatalf("manual controls moved the summary: %+v vs %+v", rep.Summary, base.Summary)
	}

	dora := computeComplianceEvidenceAt(nil, nil, "dora", now)
	applyManualControls(context.Background(), store, &dora, now)
	if n := len(manualControlsOf(dora)); n != 0 {
		t.Fatalf("dora has no manual controls, got %d", n)
	}

	// A nil store degrades to pending instead of failing the report.
	nilRep := computeComplianceEvidenceAt(nil, nil, "soc2", now)
	applyManualControls(context.Background(), nil, &nilRep, now)
	if m := manualControlsOf(nilRep); len(m) != 1 || m[0].Status != attestStatusPending {
		t.Fatalf("nil store: %+v", m)
	}
}

func TestAttestationStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	ctx := context.Background()
	first := newTestAttestationStore(t, path)
	rec, err := first.Record(ctx, Attestation{ControlID: "SOC2-MAN-CC6.1", AttesterName: "Dana Reviewer", AttestedByPrincipal: "admin-1"})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if !strings.HasPrefix(rec.ID, "att-") || rec.AttestedAt == "" {
		t.Fatalf("record did not assign id/time: %+v", rec)
	}
	if err := first.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second := newTestAttestationStore(t, path)
	got, err := second.Latest(ctx)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if a := got["SOC2-MAN-CC6.1"]; a.ID != rec.ID || a.AttesterName != "Dana Reviewer" {
		t.Fatalf("attestation lost across reopen: %+v", got)
	}
}

func TestApplyManualControlsAttestedAndExpiry(t *testing.T) {
	store := newTestAttestationStore(t, filepath.Join(t.TempDir(), "e.db"))
	ctx := context.Background()
	if _, err := store.Record(ctx, Attestation{ControlID: "PCI-MAN-12.3.3", AttesterName: "Old Name", AttestedByPrincipal: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Record(ctx, Attestation{ControlID: "PCI-MAN-12.3.3", AttesterName: "New Name", AttestedByPrincipal: "a"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	find := func(at time.Time) ComplianceControl {
		rep := computeComplianceEvidenceAt(nil, nil, "pci", at)
		applyManualControls(ctx, store, &rep, at)
		m := manualControlsOf(rep)
		if len(m) != 1 {
			t.Fatalf("want 1 pci manual control, got %d", len(m))
		}
		return m[0]
	}
	c := find(now.Add(time.Hour))
	if c.Status != attestStatusAttested || c.Attester != "New Name" || c.AttestedAt == "" ||
		!strings.Contains(c.Evidence, "New Name") || !strings.Contains(c.Evidence, now.Format("2006-01-02")) {
		t.Fatalf("newest attestation must win and name attester+date: %+v", c)
	}
	if c := find(now.Add(366 * 24 * time.Hour)); c.Status != attestStatusPending || c.Attester != "" {
		t.Fatalf("expired attestation must read pending: %+v", c)
	}
}

type attestHarness struct {
	mux   *http.ServeMux
	audit *recordingAuditProvider
	store *dbComplianceAttestationStore
	auth  *Authenticator
}

func newAttestHarness(t *testing.T) attestHarness {
	t.Helper()
	auth := newTestSCIMAuthenticator()
	auth.config.bootstrapToken = "boot-secret"
	store := newTestAttestationStore(t, filepath.Join(t.TempDir(), "h.db"))
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	RegisterComplianceAttestationHandlers(mux, auth, store, audit)
	return attestHarness{mux, audit, store, auth}
}

func (h attestHarness) do(t *testing.T, method, token, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/v1/reports/compliance-attestations", rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant", tenant)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func (h attestHarness) roleToken(t *testing.T, sub, role string) string {
	t.Helper()
	tok, err := mintHS256JWT(sub, role, h.auth.config.loginSigning, h.auth.config.jwtIssuer, h.auth.config.jwtAudience, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (h attestHarness) auditOutcomes(action string) []AuditOutcome {
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	var out []AuditOutcome
	for _, e := range h.audit.entries {
		if e.Action == action {
			out = append(out, e.Outcome)
		}
	}
	return out
}

func TestAttestHandlerAuthz(t *testing.T) {
	h := newAttestHarness(t)
	good := map[string]string{"control_id": "SOC2-MAN-CC6.1", "attester_name": "  Dana Reviewer "}

	if rec := h.do(t, http.MethodPost, "", "", good); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	for _, role := range []string{"pki-viewer", "auditor"} {
		rec := h.do(t, http.MethodPost, h.roleToken(t, "u-"+role, role), "", good)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: want 403, got %d %s", role, rec.Code, rec.Body)
		}
	}
	if got := h.auditOutcomes("evidence.attest"); len(got) != 3 {
		t.Fatalf("401 + 2x 403 must each audit, got %v", got)
	}
	for _, o := range h.auditOutcomes("evidence.attest") {
		if o != AuditOutcomeDenied {
			t.Fatalf("denials must audit as denied, got %v", o)
		}
	}

	t.Run("tenant-scoped", func(t *testing.T) {
		t.Setenv("MULTI_TENANCY", "true")
		rec := h.do(t, http.MethodPost, "boot-secret", "acme", good)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("tenant-scoped principal: want 403, got %d %s", rec.Code, rec.Body)
		}
	})

	for name, body := range map[string]any{
		"unknown control": map[string]string{"control_id": "NOPE", "attester_name": "x"},
		"empty attester":  map[string]string{"control_id": "SOC2-MAN-CC6.1", "attester_name": "   "},
		"long note":       map[string]string{"control_id": "SOC2-MAN-CC6.1", "attester_name": "x", "note": strings.Repeat("n", 501)},
	} {
		if rec := h.do(t, http.MethodPost, "boot-secret", "", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", name, rec.Code)
		}
	}
	if rec := h.do(t, http.MethodPost, "boot-secret", "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body: want 400, got %d", rec.Code)
	}

	rec := h.do(t, http.MethodPost, "boot-secret", "", good)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin: want 201, got %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Data Attestation `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Data.AttesterName != "Dana Reviewer" || out.Data.ControlID != "SOC2-MAN-CC6.1" || out.Data.ID == "" {
		t.Fatalf("response: %+v", out.Data)
	}
	outcomes := h.auditOutcomes("evidence.attest")
	if len(outcomes) == 0 || outcomes[len(outcomes)-1] != AuditOutcomeSuccess {
		t.Fatalf("success must audit last, got %v", outcomes)
	}

	list := h.do(t, http.MethodGet, "boot-secret", "", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "Dana Reviewer") {
		t.Fatalf("list: %d %s", list.Code, list.Body)
	}
	if rec := h.do(t, http.MethodPut, "boot-secret", "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: %d", rec.Code)
	}
}

func TestPendingControlRendersInPDFAndJSON(t *testing.T) {
	pdfCompression = false
	t.Cleanup(func() { pdfCompression = true })
	store := newTestAttestationStore(t, filepath.Join(t.TempDir(), "p.db"))
	ctx := context.Background()
	now := time.Now().UTC()

	render := func() (ComplianceEvidenceReport, []byte) {
		rep := computeComplianceEvidenceAt(nil, nil, "soc2", now)
		applyManualControls(ctx, store, &rep, now)
		pdf, err := renderComplianceEvidencePDF(rep, 0, now)
		if err != nil {
			t.Fatal(err)
		}
		return rep, pdf
	}

	rep, pdf := render()
	js, _ := json.Marshal(rep)
	if !bytes.Contains(js, []byte(`"status":"pending"`)) || !bytes.Contains(js, []byte(`"type":"manual"`)) {
		t.Fatalf("JSON lacks pending manual control: %s", js)
	}
	if !bytes.Contains(pdf, []byte("PENDING")) || !bytes.Contains(pdf, []byte("Pending attestation")) {
		t.Fatal("PDF must show PENDING and the pending evidence text")
	}

	if _, err := store.Record(ctx, Attestation{ControlID: "SOC2-MAN-CC6.1", AttesterName: "Dana Reviewer", AttestedByPrincipal: "a"}); err != nil {
		t.Fatal(err)
	}
	_, pdf = render()
	if !bytes.Contains(pdf, []byte("Attested by")) || !bytes.Contains(pdf, []byte("Dana Reviewer")) {
		t.Fatal("PDF must show the named attester after attestation")
	}
}
