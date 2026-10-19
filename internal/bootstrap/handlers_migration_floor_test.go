// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/migration"
)

// B2 (ADCS cutover rehearsal): templates migrated from ADCS at RSA-2048 could
// never issue under the default Baseline policy (RSA >= 3072), and there was
// no way to fix them. The policy is not weakened; the mapping raises the
// template to the policy floor and says so, and a re-apply updates in place.

const wsOID = "1.3.6.1.4.1.311.21.8.12189506.10184651.7684799.15371974.11026834.190.1.30"

func wsBody() map[string]any {
	raw, _ := json.Marshal([]map[string]string{{"key": "CN=Workstation", "name": "Workstation", "oid": wsOID}})
	return map[string]any{"source": "testsrc", "content": string(raw)}
}

func (h *migrationHarness) dryRun(t *testing.T, body map[string]any) migration.Diff {
	t.Helper()
	rec := h.call(t, http.MethodPost, "/api/v1/migration/dryrun", "test-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("dryrun: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data migration.Diff `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Data
}

func (h *migrationHarness) template(t *testing.T, name string) TemplateItem {
	t.Helper()
	res, err := h.templates.ListTemplates(context.Background(), TemplateListQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range res.Items {
		if it.Name == name {
			return it
		}
	}
	t.Fatalf("template %q not found", name)
	return TemplateItem{}
}

const raiseNote = `key size raised from 2048 to 3072 to meet policy "Baseline"`

func TestMigrationRaisesKeySizeToPolicyFloor(t *testing.T) {
	h := newMigrationHarness(t)
	d := h.dryRun(t, wsBody())
	if len(d.Entries) != 1 || d.Entries[0].Action != migration.ActionCreate ||
		len(d.Entries[0].Notes) != 1 || d.Entries[0].Notes[0] != raiseNote {
		t.Fatalf("dry-run must report the raise: %+v", d.Entries)
	}
	if rec := h.proposeAndApprove(t, wsBody()); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if got := h.template(t, "Workstation"); got.MinKeySize != 3072 || got.OID != wsOID {
		t.Fatalf("migrated template: min_key_size=%d oid=%s, want 3072 and the ADCS OID", got.MinKeySize, got.OID)
	}

	// The policy itself is unchanged: an RSA-2048 key is still refused.
	pol, ok, err := h.policies.GetPolicy("pol-baseline")
	if err != nil || !ok || pol.Rules.MinRSABits != 3072 || !pol.Enabled {
		t.Fatalf("Baseline changed: %+v %v %v", pol, ok, err)
	}
	v, err := h.policies.Evaluate("", ca.PolicyInput{Algorithm: "RSA-2048", RSABits: 2048})
	if err != nil || v.Allowed {
		t.Fatalf("below-floor key must still be refused: %+v %v", v, err)
	}
	if v, _ := h.policies.Evaluate("", ca.PolicyInput{Algorithm: "RSA-3072", RSABits: 3072}); !v.Allowed {
		t.Fatalf("the raised size must pass the policy: %+v", v.Violations)
	}
}

func TestMigrationReapplyUpdatesMigratedTemplate(t *testing.T) {
	h := newMigrationHarness(t)
	// A batch applied before the floor existed: the template is RSA-2048.
	*h.floorOff = true
	if rec := h.proposeAndApprove(t, wsBody()); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	before := h.template(t, "Workstation")
	if before.MinKeySize != 2048 {
		t.Fatalf("setup: %d", before.MinKeySize)
	}
	*h.floorOff = false

	d := h.dryRun(t, wsBody())
	if d.Counts[migration.ActionUpdate] != 1 || d.Counts[migration.ActionConflict] != 0 || d.Entries[0].Notes[0] != raiseNote {
		t.Fatalf("re-apply must plan an update, not a conflict: %+v", d)
	}
	// Through the approval queue: proposing writes nothing.
	id := pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/migration/apply", "test-token", wsBody()))
	if got := h.template(t, "Workstation"); got.MinKeySize != 2048 {
		t.Fatalf("proposal changed the template: %d", got.MinKeySize)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", h.adminKey, nil); rec.Code != http.StatusOK {
		t.Fatalf("approve update: %d %s", rec.Code, rec.Body.String())
	}
	after := h.template(t, "Workstation")
	if after.ID != before.ID || after.OID != wsOID || after.MinKeySize != 3072 || !after.Active {
		t.Fatalf("update in place: before=%+v after=%+v", before, after)
	}
	if got := h.auditActions("migration.apply"); len(got) != 2 || !strings.Contains(got[1].ChangeSummary, "updated=1") {
		t.Fatalf("audit: %+v", got)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/migration/apply", "test-token", wsBody()); !strings.Contains(rec.Body.String(), "nothing_to_apply") {
		t.Fatalf("rerun after update: %d %s", rec.Code, rec.Body.String())
	}
	// The update batch owns the template now: rolling back the old batch
	// leaves it alone.
	old := strings.TrimPrefix(strings.Fields(h.auditActions("migration.apply")[0].ChangeSummary)[0], "batch=")
	if rec := h.call(t, http.MethodPost, "/api/v1/migration/"+old+"/rollback", "test-token", nil); rec.Code != http.StatusOK {
		t.Fatalf("rollback old batch: %d %s", rec.Code, rec.Body.String())
	}
	if !h.template(t, "Workstation").Active {
		t.Fatal("rolling back the superseded batch disabled the updated template")
	}
}

func TestMigrationReapplyAfterRollbackUpdatesSameOID(t *testing.T) {
	h := newMigrationHarness(t)
	*h.floorOff = true
	if rec := h.proposeAndApprove(t, wsBody()); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	b := strings.TrimPrefix(strings.Fields(h.auditActions("migration.apply")[0].ChangeSummary)[0], "batch=")
	if rec := h.call(t, http.MethodPost, "/api/v1/migration/"+b+"/rollback", "test-token", nil); rec.Code != http.StatusOK {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body.String())
	}
	if h.template(t, "Workstation").Active {
		t.Fatal("rollback left the template active")
	}
	*h.floorOff = false

	d := h.dryRun(t, wsBody())
	if d.Entries[0].Action != migration.ActionUpdate || !strings.Contains(d.Entries[0].Reason, "name and OID") {
		t.Fatalf("same name+OID after rollback must update: %+v", d.Entries[0])
	}
	if rec := h.proposeAndApprove(t, wsBody()); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if got := h.template(t, "Workstation"); !got.Active || got.MinKeySize != 3072 {
		t.Fatalf("re-applied template: %+v", got)
	}

	// Same name, different OID: still a conflict.
	raw, _ := json.Marshal([]map[string]string{{"key": "CN=Workstation2", "name": "Workstation", "oid": "1.2.3.4"}})
	d = h.dryRun(t, map[string]any{"source": "testsrc", "content": string(raw)})
	if d.Entries[0].Action != migration.ActionConflict {
		t.Fatalf("different OID must conflict: %+v", d.Entries[0])
	}
}

// B5: the sink stores a migrated template's restriction, and a re-apply keeps
// an enroll list an admin set afterwards (e.g. granting one DC).
func TestMigrationSinkCarriesEnrollRestriction(t *testing.T) {
	h := newMigrationHarness(t)
	sink := templateSink{templates: h.templates}
	ctx := context.Background()
	tmpl := migration.Template{Name: "KerberosAuthentication", DisplayName: "Kerberos Authentication", OID: "1.2.3.9",
		KeyUsage: []string{"digitalSignature"}, ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"RSA"},
		MinKeySize: 3072, ValidityPeriod: "P365D", EnrollRoles: []string{"pki-admin"}}
	id, err := sink.Create(ctx, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	got, _, _ := h.templates.GetTemplate(ctx, id)
	if r := got.EnrollRoles(); len(r) != 1 || r[0] != "pki-admin" || got.AutoEnroll {
		t.Fatalf("restriction not stored: %+v", got)
	}
	grant := []string{"pki-admin", "protocol:wstep:lab-dc01.corp.example.test"}
	if _, err := h.templates.PatchTemplate(ctx, id, TemplatePatchRequest{EnrollmentPermissions: &EnrollmentPermissions{Enroll: grant}}); err != nil {
		t.Fatal(err)
	}
	tmpl.ValidityPeriod = "P730D"
	if err := sink.Update(ctx, id, tmpl); err != nil {
		t.Fatal(err)
	}
	got, _, _ = h.templates.GetTemplate(ctx, id)
	if r := got.EnrollRoles(); len(r) != 2 || r[1] != grant[1] || got.ValidityPeriod != "P730D" {
		t.Fatalf("re-apply dropped the admin grant: %+v", got)
	}
}
