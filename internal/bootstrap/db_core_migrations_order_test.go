// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
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
	_ = NewAgentStoreFromEnv()
	_ = NewConfigStoreFromEnv()
	_ = NewDiscoveryProviderFromEnv()
	_ = NewEvidenceScheduleStoreFromEnv()
	_ = NewManagedTargetStoreFromEnv()
	_ = NewNHIStoreFromEnv()
	_ = NewMigrationWaveStoreFromEnv()
	_ = NewTenantStoreFromEnv()
	_, _ = NewPostureSnapshotStoreFromEnv()
	_, _ = newApprovalStoreFromEnv()
	_ = newConnectorStoreFromEnv()
	_, _ = newFindingExceptionStoreFromEnv()
	_ = newSCIMGroupStoreFromEnv()
	_ = newInventorySourceStoreFromEnv()
	_, _ = newRenewalAlertCooldownStoreFromEnv()
	_, _ = newNotificationSilenceStoreFromEnv()
	_, _ = newDBAuditProviderFromEnv()
	_, _ = newHACoordinatorFromEnv()
	_ = newSSHCertStoreFromEnv()
	_ = NewCustomRoleStoreFromEnv()
	_ = newOutboundCredentialStoreFromEnv()
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
	"agent_store_db.go": true, "approval_store.go": true, "audit_db_provider.go": true,
	"authz_custom_roles_handlers.go": true, "config_store.go": true, "connector_store.go": true,
	"discovery_db_provider.go": true, "evidence_schedule_store.go": true, "finding_exception_store.go": true,
	"ha_coordinator.go": true, "handlers_ssh_certs.go": true, "inventory_source.go": true,
	"managed_target_store.go": true, "nhi_identity.go": true, "notification_dedup.go": true,
	"notification_rule_store.go": true, "outbound_credential_store.go": true, "pending_action_store.go": true,
	"posture_snapshot_store.go": true, "pqc_wave_store.go": true, "scim.go": true, "tenant_store.go": true,
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
