// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"kryptkeeper/internal/acme"
	"kryptkeeper/internal/ctmonitor"
)

// initAllSelfHealingStores runs every store-level EnsureSchema that targets the
// shared kryptkeeper.db, the way a non-ca deployment does at boot. Constructor
// errors are ignored on purpose: the point is the schema they leave behind.
func initAllSelfHealingStores(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("KRYPTKEEPER_DATA_DIR", dir)
	t.Setenv(dbModeEnv, dbModeSQLite)
	constructAllSelfHealingStores(t)

	db, err := sql.Open("sqlite", filepath.Join(dir, "kryptkeeper.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	initAcmeCTStores(t, db, false)
}

func initAcmeCTStores(t *testing.T, db *sql.DB, postgres bool) {
	t.Helper()
	if err := acme.NewSQLiteStore(db, postgres).EnsureSchema(); err != nil {
		t.Fatalf("acme EnsureSchema: %v", err)
	}
	if _, err := ctmonitor.NewStore(db, postgres); err != nil {
		t.Fatalf("ctmonitor store: %v", err)
	}
}

// constructAllSelfHealingStores builds every store that creates or alters
// tables on first use. KEEP THIS LIST EXHAUSTIVE: add any new store whose
// constructor executes CREATE TABLE / ALTER TABLE. The completeness guard
// TestSelfHealingStoreListIsExhaustive fails when a non-test file in
// internal/bootstrap issues DDL without being named in selfHealingDDLFiles.
func constructAllSelfHealingStores(t *testing.T) {
	t.Helper()
	t.Setenv("APP_AUDIT_PROVIDER", "db")

	_ = NewPendingActionStoreFromEnv()
	_ = chatopsRefStoreForActions(NewPendingActionStoreFromEnv())
	_ = NewAgentStoreFromEnv()
	_ = NewConfigStoreFromEnv()
	_ = newUserPrefsStoreFromEnv()
	_ = NewDiscoveryProviderFromEnv()
	_ = newDiscoveryScheduleStoreFromEnv()
	_ = NewEvidenceScheduleStoreFromEnv()
	_ = NewComplianceAttestationStoreFromEnv()
	_ = NewManagedTargetStoreFromEnv()
	_ = newCertTargetBindingStoreFromEnv()
	_ = newTargetGroupStoreFromEnv()
	_ = NewNHIStoreFromEnv()
	_ = NewCodesignTrustStoreFromEnv()
	_ = NewMigrationWaveStoreFromEnv()
	_ = NewTenantStoreFromEnv()
	_, _ = NewPostureSnapshotStoreFromEnv()
	_, _ = newApprovalStoreFromEnv()
	_ = newConnectorStoreFromEnv()
	_ = newDCVStoreFromEnv()
	_ = newAuthorizedIssuerStoreFromEnv()
	_, _ = newFindingExceptionStoreFromEnv()
	_, _ = newFindingIdentityStoreFromEnv()
	_ = newSCIMGroupStoreFromEnv()
	_ = newInventorySourceStoreFromEnv()
	_, _ = newRenewalAlertCooldownStoreFromEnv()
	_, _ = newRenewalFailureStoreFromEnv()
	_, _ = newNotificationSilenceStoreFromEnv()
	_, _ = newDBAuditProviderFromEnv()
	_, _ = newHACoordinatorFromEnv()
	_ = newSSHCertStoreFromEnv()
	_ = NewCustomRoleStoreFromEnv()
	_ = newOutboundCredentialStoreFromEnv()
	_ = newAccessReviewStoreFromEnv()
	_ = newBreakGlassStoreFromEnv()
	constructAuditArchiveSchema(t)
	constructPolicyVersionSchema(t)
	constructTeamPolicySchema(t)
}

// constructPolicyVersionSchema: the policy-version store borrows the core DB
// handle (it is built from the PolicyEngine), so open that file directly.
func constructPolicyVersionSchema(t *testing.T) {
	t.Helper()
	dsn, err := resolveSQLiteDSNFromEnv("APP_CORE_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := (&policyVersionStore{db: db, ph: sqlitePlaceholder}).EnsureSchema(context.Background()); err != nil {
		t.Fatalf("issuance_policy_versions schema: %v", err)
	}
}

// constructTeamPolicySchema: the team-policy store takes the core DB handle
// from main, so open that file directly (W33-20).
func constructTeamPolicySchema(t *testing.T) {
	t.Helper()
	dsn, err := resolveSQLiteDSNFromEnv("APP_CORE_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := newDBTeamPolicyStore(db, false).EnsureSchema(context.Background()); err != nil {
		t.Fatalf("team_policies schema: %v", err)
	}
	if err := newTeamCounterStore(db, false).EnsureSchema(context.Background()); err != nil {
		t.Fatalf("team_request_counters schema: %v", err)
	}
}

// constructAuditArchiveSchema mirrors cmd/kryptkeeper: the archive manager
// shares the database the audit trail lives in and creates audit_archives
// itself, so this exercises that DDL against both migration orders.
func constructAuditArchiveSchema(t *testing.T) {
	t.Helper()
	state := newDBProviderState[*AuditArchiveManager](
		"audit-archive", auditSQLiteDSNFromEnv, auditPostgresDSNFromEnv,
		fmt.Errorf("no audit DSN"),
		func(db *sql.DB) *AuditArchiveManager { return NewAuditArchiveManager(db, false, nil, nil) },
		func(db *sql.DB) *AuditArchiveManager { return NewAuditArchiveManager(db, true, nil, nil) },
	)
	if state.store == nil {
		t.Fatalf("audit archive store: %v", state.openErr)
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("audit_archives schema: %v", err)
	}
}

// A data directory first used with a non-ca provider has every store's
// self-healed tables in kryptkeeper.db before RunMigrations ever executes.
// Switching to ca then runs all pending migrations on top; a blind ALTER TABLE
// ADD COLUMN in any of them (000020 pending_actions.tenant was the reproduced
// one) would fail OpenCoreDB.
func TestOpenCoreDBAfterStoresSelfHealedSchema(t *testing.T) {
	dir := t.TempDir()
	initAllSelfHealingStores(t, dir)

	db, _, err := OpenCoreDB()
	if err != nil {
		t.Fatalf("OpenCoreDB after stores self-healed the schema: %v", err)
	}
	_ = db.Close()
}

// The opposite order (ca from day one, stores attach later) must keep working.
func TestStoresSelfHealAfterMigrations(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KRYPTKEEPER_DATA_DIR", dir)
	t.Setenv(dbModeEnv, dbModeSQLite)
	db, _, err := OpenCoreDB()
	if err != nil {
		t.Fatalf("OpenCoreDB: %v", err)
	}
	_ = db.Close()
	initAllSelfHealingStores(t, dir)
	db, _, err = OpenCoreDB()
	if err != nil {
		t.Fatalf("OpenCoreDB reopen: %v", err)
	}
	_ = db.Close()
}

// selfHealingDDLFiles is every non-test file in this package that issues
// CREATE TABLE / ALTER TABLE at runtime, each covered by
// constructAllSelfHealingStores. The earlier version of this test silently
// missed the ssh-cert, custom-role and outbound-credential stores because
// nothing forced the list to track the code.
var selfHealingDDLFiles = map[string]bool{
	"access_review_campaign.go": true, "agent_store_db.go": true, "approval_store.go": true, "chatops_approval_post.go": true, "breakglass.go": true, "codesign_oidc.go": true, "audit_archive.go": true, "audit_db_provider.go": true, "authorized_issuer_store.go": true,
	"authz_custom_roles_handlers.go": true, "compliance_attestation.go": true, "config_store.go": true, "handlers_user_prefs.go": true, "connector_store.go": true, "dcv_tracker.go": true,
	"discovery_db_provider.go": true, "discovery_schedule_store.go": true, "evidence_schedule_store.go": true, "finding_exception_store.go": true, "finding_identity.go": true, "report_schedule_store.go": true,
	"ha_coordinator.go": true, "handlers_ssh_certs.go": true, "inventory_source.go": true,
	"managed_target_store.go": true, "cert_target_binding_store.go": true, "target_group_store.go": true, "nhi_identity.go": true, "notification_dedup.go": true, "renewal_retry.go": true,
	"notification_rule_store.go": true, "outbound_credential_store.go": true, "pending_action_store.go": true,
	"posture_snapshot_store.go": true, "pqc_wave_store.go": true, "policy_versions.go": true, "scim.go": true, "tenant_store.go": true, "team_policy_store.go": true, "team_policy_enforce.go": true,
	// db_core.go only mentions the phrase in a comment.
	"db_core.go": true,
}

var runtimeDDLRe = regexp.MustCompile(`(?i)(CREATE\s+TABLE|ALTER\s+TABLE)`)

func TestSelfHealingStoreListIsExhaustive(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		if runtimeDDLRe.Match(b) && !selfHealingDDLFiles[n] {
			t.Errorf("%s issues runtime DDL but is not in selfHealingDDLFiles: construct its store in "+
				"constructAllSelfHealingStores (so the migration-collision tests exercise it) and add it here", n)
		}
	}
}

func attachAcmeCTPostgres(t *testing.T, dsn string) {
	t.Helper()
	pg, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	initAcmeCTStores(t, pg, true)
}

// Postgres twin of TestOpenCoreDBAfterStoresSelfHealedSchema: every store
// self-heals first, then the migration runner must still succeed.
func TestOpenCoreDBAfterStoresSelfHealedSchema_Postgres(t *testing.T) {
	dsn := freshPostgresForTest(t)
	constructAllSelfHealingStores(t)
	attachAcmeCTPostgres(t, dsn)

	db, _, err := OpenCoreDB()
	if err != nil {
		t.Fatalf("OpenCoreDB after stores self-healed the schema (postgres): %v", err)
	}
	_ = db.Close()
}

// The opposite order on Postgres: migrations first, stores attach after.
func TestStoresSelfHealAfterMigrations_Postgres(t *testing.T) {
	dsn := freshPostgresForTest(t)
	db, _, err := OpenCoreDB()
	if err != nil {
		t.Fatalf("OpenCoreDB: %v", err)
	}
	_ = db.Close()
	constructAllSelfHealingStores(t)
	attachAcmeCTPostgres(t, dsn)
	db, _, err = OpenCoreDB()
	if err != nil {
		t.Fatalf("OpenCoreDB reopen: %v", err)
	}
	_ = db.Close()
}
