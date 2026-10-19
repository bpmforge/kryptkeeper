// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"kryptkeeper/internal/migration"
)

// S-05: an import may update only a template a migration made and that nobody
// disabled; rolling an update back restores the template it replaced.

func lastBatchID(t *testing.T, h *migrationHarness) string {
	t.Helper()
	got := h.auditActions("migration.apply")
	if len(got) == 0 {
		t.Fatal("no migration.apply audit row")
	}
	return strings.TrimPrefix(strings.Fields(got[len(got)-1].ChangeSummary)[0], "batch=")
}

func TestMigrationNeverOverwritesHubNativeTemplate(t *testing.T) {
	h := newMigrationHarness(t)
	*h.floorOff = true
	// An admin-authored template that happens to share the ADCS name and OID.
	native, err := h.templates.CreateTemplate(context.Background(), TemplateUpsertRequest{
		Name: "Workstation", DisplayName: "Native", OID: wsOID, KeyUsage: []string{"keyEncipherment"},
		ExtendedKeyUsage: []string{"clientAuth"}, AllowedAlgorithms: []string{"ECDSA"}, ValidityPeriod: "P90D", Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	d := h.dryRun(t, wsBody())
	if e := d.Entries[0]; e.Action != migration.ActionConflict || !strings.Contains(e.Reason, "not created by a migration") {
		t.Fatalf("hub-native template must be a conflict: %+v", e)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/migration/apply", "test-token", wsBody()); !strings.Contains(rec.Body.String(), "nothing_to_apply") {
		t.Fatalf("a conflict-only import must have nothing to apply: %d %s", rec.Code, rec.Body.String())
	}
	after := h.template(t, "Workstation")
	if after.ID != native.ID || after.DisplayName != "Native" || after.ValidityPeriod != "P90D" || after.Revision != native.Revision {
		t.Fatalf("native template was changed: %+v", after)
	}
}

func TestMigrationNeverReactivatesAdminDisabledTemplate(t *testing.T) {
	h := newMigrationHarness(t)
	*h.floorOff = true
	if rec := h.proposeAndApprove(t, wsBody()); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	tpl := h.template(t, "Workstation")
	inactive := false
	if _, err := h.templates.PatchTemplate(context.Background(), tpl.ID, TemplatePatchRequest{Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	*h.floorOff = false // the policy floor changed, so the import now differs

	d := h.dryRun(t, wsBody())
	if e := d.Entries[0]; e.Action != migration.ActionConflict || !strings.Contains(e.Reason, "disabled by an administrator") {
		t.Fatalf("disabled template must be a conflict: %+v", e)
	}
	if got := h.template(t, "Workstation"); got.Active || got.MinKeySize != 2048 {
		t.Fatalf("disabled template changed: %+v", got)
	}
}

func TestMigrationRollbackOfUpdateRestoresTemplate(t *testing.T) {
	h := newMigrationHarness(t)
	*h.floorOff = true
	if rec := h.proposeAndApprove(t, wsBody()); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	before := h.template(t, "Workstation")
	*h.floorOff = false
	if rec := h.proposeAndApprove(t, wsBody()); rec.Code != http.StatusOK {
		t.Fatalf("approve update: %d %s", rec.Code, rec.Body.String())
	}
	if got := h.template(t, "Workstation"); got.MinKeySize != 3072 {
		t.Fatalf("update not applied: %+v", got)
	}

	rec := h.call(t, http.MethodPost, "/api/v1/migration/"+lastBatchID(t, h)+"/rollback", "test-token", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"restored":1`) {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body.String())
	}
	after := h.template(t, "Workstation")
	if after.ID != before.ID || after.MinKeySize != before.MinKeySize || !after.Active ||
		after.ValidityPeriod != before.ValidityPeriod || after.OID != before.OID {
		t.Fatalf("template not restored:\nbefore %+v\nafter  %+v", before, after)
	}
}
