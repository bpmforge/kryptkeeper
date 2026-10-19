// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// archiveEnv is one engine's wired-up fixture.
type archiveEnv struct {
	db       *sql.DB
	postgres bool
	audit    AuditProvider
	store    PendingActionStore
	mgr      *AuditArchiveManager
	cutoff   time.Time // "before" for the job
	oldRows  int
	newRows  int
}

// runOnEngines runs fn on a fresh SQLite database always, and on Postgres
// when KRYPTKEEPER_TEST_POSTGRES_DSN is set (otherwise that half is skipped).
//
// Timestamps are placed relative to a clock shifted ~45 days ahead so every
// row falls inside the Postgres partitions the audit schema pre-creates
// (this month plus two) while still being "older than retention" for the job.
func runOnEngines(t *testing.T, fn func(t *testing.T, e *archiveEnv)) {
	t.Helper()
	for _, engine := range []string{"sqlite", "postgres"} {
		t.Run(engine, func(t *testing.T) {
			t.Setenv("AUDIT_RETENTION_DAYS", "1")
			t.Setenv("AUDIT_ARCHIVE_DIR", filepath.Join(t.TempDir(), "archives"))
			t.Setenv("AUDIT_TRANSPARENCY_SIGNING_SEED", base64.StdEncoding.EncodeToString(make([]byte, 32)))
			t.Setenv("MULTI_TENANCY", "")
			e := &archiveEnv{postgres: engine == "postgres"}
			var auditStore dbAuditStore
			if e.postgres {
				dsn := freshPostgresForTest(t)
				db, err := sql.Open("pgx", dsn)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				e.db = db
				auditStore = &postgresAuditStore{db: db}
				e.store = &dbPendingActionStore{db: db, ph: postgresPlaceholder}
			} else {
				db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "a.db")+sqliteDSNParams)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				e.db = db
				auditStore = &sqliteAuditStore{db: db}
				e.store = &dbPendingActionStore{db: db, ph: sqlitePlaceholder}
			}
			ctx := context.Background()
			if err := auditStore.EnsureSchema(ctx); err != nil {
				t.Fatal(err)
			}
			if err := e.store.EnsureSchema(ctx); err != nil {
				t.Fatal(err)
			}
			e.audit = &dbAuditProvider{store: auditStore}
			e.mgr = NewAuditArchiveManager(e.db, e.postgres, e.store, e.audit)
			clock := time.Now().UTC().Add(45 * 24 * time.Hour)
			e.mgr.now = func() time.Time { return clock }
			if err := e.mgr.EnsureSchema(ctx); err != nil {
				t.Fatal(err)
			}
			e.cutoff = clock.Add(-24 * time.Hour).Truncate(time.Second)
			e.oldRows, e.newRows = 50, 10
			base := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
			for i := 0; i < e.oldRows; i++ {
				e.seed(t, base.Add(time.Duration(i)*12*time.Hour), i)
			}
			for i := 0; i < e.newRows; i++ {
				e.seed(t, clock.Add(-time.Hour+time.Duration(i)*time.Minute), 1000+i)
			}
			fn(t, e)
		})
	}
}

func (e *archiveEnv) seed(t *testing.T, ts time.Time, i int) {
	t.Helper()
	err := e.audit.AppendEntry(context.Background(), AuditEntry{
		Timestamp: ts.Format(time.RFC3339), Action: "cert.issue", ActorType: "user", ActorID: "alice",
		ResourceType: "certificate", ResourceID: fmt.Sprintf("fp-%d", i), Outcome: AuditOutcomeSuccess,
		ChangeSummary: "n=" + fmt.Sprint(i), Tenant: DefaultTenant,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (e *archiveEnv) count(t *testing.T, where string) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM audit_log ` + where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *archiveEnv) run(t *testing.T) json.RawMessage {
	t.Helper()
	params, _ := json.Marshal(map[string]string{"before": e.cutoff.Format(time.RFC3339)})
	res, err := e.mgr.ExecuteArchive(context.Background(), PendingAction{ID: "act1", Params: params}, AuthPrincipal{ID: "approver", Role: "pki-admin"})
	if err != nil {
		t.Fatalf("ExecuteArchive: %v", err)
	}
	return res
}

func TestRetentionDefault2555(t *testing.T) {
	t.Setenv("AUDIT_RETENTION_DAYS", "")
	if got := AuditRetentionDays(); got != 2555 {
		t.Fatalf("default retention = %d, want 2555", got)
	}
	for _, bad := range []string{"abc", "0", "-5", "1.5"} {
		t.Setenv("AUDIT_RETENTION_DAYS", bad)
		if got := AuditRetentionDays(); got != 2555 {
			t.Fatalf("AUDIT_RETENTION_DAYS=%q -> %d, want 2555", bad, got)
		}
	}
	t.Setenv("AUDIT_RETENTION_DAYS", "90")
	if got := AuditRetentionDays(); got != 90 {
		t.Fatalf("got %d", got)
	}
}

func TestProposeRefusesInsideRetentionWindow(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		_, err := e.mgr.Propose(context.Background(), AuthPrincipal{ID: "a"}, e.mgr.now().Add(-time.Hour))
		if err == nil {
			t.Fatal("a cutoff inside the retention window must be refused")
		}
		if _, err := e.mgr.Propose(context.Background(), AuthPrincipal{ID: "a"}, e.cutoff); err != nil {
			t.Fatalf("a cutoff at the window edge must be accepted: %v", err)
		}
	})
}

func TestExecuteArchiveRecordsCheckpointBeforeDelete(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		hookRan := false
		e.mgr.beforeDelete = func() {
			hookRan = true
			var rows int
			var file, root string
			if err := e.db.QueryRow(`SELECT row_count, file_path, merkle_root FROM audit_archives`).Scan(&rows, &file, &root); err != nil {
				t.Errorf("checkpoint must be recorded before delete: %v", err)
				return
			}
			if rows != e.oldRows || root == "" {
				t.Errorf("recorded row_count=%d root=%q", rows, root)
			}
			if _, err := os.Stat(file); err != nil {
				t.Errorf("archive file must exist before delete: %v", err)
			}
			if n := e.count(t, ""); n != e.oldRows+e.newRows {
				t.Errorf("rows were deleted before the hook: %d", n)
			}
		}
		e.run(t)
		if !hookRan {
			t.Fatal("beforeDelete seam never ran")
		}
		if n := e.count(t, `WHERE action = 'cert.issue'`); n != e.newRows {
			t.Fatalf("old rows must be gone and new rows intact: %d cert.issue rows left, want %d", n, e.newRows)
		}
		entries, _ := os.ReadDir(os.Getenv("AUDIT_ARCHIVE_DIR"))
		if len(entries) != 1 {
			t.Fatalf("want exactly the final archive file (no stray .tmp), got %d entries", len(entries))
		}
		for _, de := range entries {
			if info, _ := de.Info(); info != nil && info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("archive file %s is group/world accessible: %v", de.Name(), info.Mode().Perm())
			}
		}
	})
}

func TestTriggersStayAppendOnly(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		e.run(t)
		if _, err := e.db.Exec(`DELETE FROM audit_log WHERE id > 0`); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("a plain DELETE must still fail after the job, got %v", err)
		}
		if _, err := e.db.Exec(`UPDATE audit_log SET action = 'x' WHERE id > 0`); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("UPDATE must still fail after the job, got %v", err)
		}
	})
}

func TestArchiveEmitsAuditArchiveRow(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		e.run(t)
		res, err := e.audit.ListEntries(context.Background(), AuditListQuery{Limit: 10, Action: "audit.archive"})
		if err != nil || len(res.Entries) != 1 {
			t.Fatalf("want one audit.archive row, got %v %+v", err, res.Entries)
		}
		row := res.Entries[0]
		if row.Outcome != AuditOutcomeSuccess || row.ResourceType != "audit_log" || row.ActorID != "approver" {
			t.Fatalf("row %+v", row)
		}
		for _, want := range []string{fmt.Sprintf("rows=%d", e.oldRows), "archive=", "root="} {
			if !strings.Contains(row.ChangeSummary, want) {
				t.Fatalf("summary %q lacks %q", row.ChangeSummary, want)
			}
		}
	})
}

func TestArchiveFailureIsAudited(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		e.mgr.signKey = func() (ed25519.PrivateKey, error) { return nil, fmt.Errorf("no key") }
		params, _ := json.Marshal(map[string]string{"before": e.cutoff.Format(time.RFC3339)})
		if _, err := e.mgr.ExecuteArchive(context.Background(), PendingAction{ID: "act1", Params: params}, AuthPrincipal{ID: "approver", Role: "pki-admin"}); err == nil {
			t.Fatal("expected failure")
		}
		if n := e.count(t, `WHERE action = 'cert.issue'`); n != e.oldRows+e.newRows {
			t.Fatalf("a failed run must delete nothing, %d left", n)
		}
		res, _ := e.audit.ListEntries(context.Background(), AuditListQuery{Limit: 10, Action: "audit.archive"})
		if len(res.Entries) != 1 || res.Entries[0].Outcome != AuditOutcomeFailure {
			t.Fatalf("want one failure row, got %+v", res.Entries)
		}
	})
}

func TestRestoreReproducesRows(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		ctx := context.Background()
		q := AuditListQuery{Limit: 1000, Order: "asc", Action: "cert.issue", Before: e.cutoff.Format(time.RFC3339)}
		before, err := e.audit.ListEntries(ctx, q)
		if err != nil || len(before.Entries) != e.oldRows {
			t.Fatalf("snapshot: %v %d", err, len(before.Entries))
		}
		res := e.run(t)
		var out struct {
			File string `json:"file"`
			Root string `json:"merkle_root"`
		}
		_ = json.Unmarshal(res, &out)
		if gone, _ := e.audit.ListEntries(ctx, q); len(gone.Entries) != 0 {
			t.Fatalf("rows not deleted: %d", len(gone.Entries))
		}
		restored, err := e.mgr.Restore(ctx, out.File)
		if err != nil || restored != e.oldRows {
			t.Fatalf("Restore: %d, %v", restored, err)
		}
		after, _ := e.audit.ListEntries(ctx, q)
		if len(after.Entries) != len(before.Entries) {
			t.Fatalf("restored %d rows, want %d", len(after.Entries), len(before.Entries))
		}
		for i := range before.Entries {
			if before.Entries[i] != after.Entries[i] {
				t.Fatalf("row %d differs after restore:\n%+v\n%+v", i, before.Entries[i], after.Entries[i])
			}
		}
		var stored string
		if err := e.db.QueryRow(`SELECT merkle_root FROM audit_archives`).Scan(&stored); err != nil || stored != out.Root {
			t.Fatalf("stored root %q vs job result %q (%v)", stored, out.Root, err)
		}
		// Restoring twice must not duplicate anything.
		if again, err := e.mgr.Restore(ctx, out.File); err != nil || again != 0 {
			t.Fatalf("second Restore inserted %d (%v)", again, err)
		}
	})
}

func TestRestoreRefusesMismatchedCheckpoint(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		var out struct {
			File string `json:"file"`
		}
		_ = json.Unmarshal(e.run(t), &out)
		if _, err := e.db.Exec(`UPDATE audit_archives SET merkle_root = 'AAAA'`); err != nil {
			t.Fatal(err)
		}
		left := e.count(t, "")
		if _, err := e.mgr.Restore(context.Background(), out.File); err == nil {
			t.Fatal("a checkpoint that differs from the recorded one must refuse")
		}
		if e.count(t, "") != left {
			t.Fatal("nothing may be inserted on refusal")
		}
	})
}

func TestRestoreRefusesTamperedFile(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		var out struct {
			File string `json:"file"`
		}
		_ = json.Unmarshal(e.run(t), &out)
		raw, _ := os.ReadFile(out.File)
		if err := os.WriteFile(out.File, []byte(strings.Replace(string(raw), "fp-3", "fp-X", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := e.mgr.Restore(context.Background(), out.File); err == nil {
			t.Fatal("an edited archive must not restore")
		}
	})
}

func TestArchiveRequiresSecondApprover(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
		t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
		auth := newReportsTestAuth(t)
		mux := http.NewServeMux()
		registerPendingActionHandlers(mux, auth, &recordingCertProvider{reportCertProvider: &reportCertProvider{}}, e.store, stubAuditProvider{},
			map[string]ActionExecutor{ActionAuditArchive: e.mgr.ExecuteArchive})
		RegisterAuditArchiveHandlers(mux, auth, e.mgr, stubAuditProvider{})

		tokA := mintAdminToken(t, auth, "admin-a", "")
		tokB := mintAdminToken(t, auth, "admin-b", "")

		body, _ := json.Marshal(map[string]string{"before": e.cutoff.Format(time.RFC3339)})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, bearerReq(tokA, http.MethodPost, "/api/v1/audit/archive", body))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("propose: %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data PendingAction `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		approve := "/api/v1/pending-actions/" + env.Data.ID + "/approve"
		if n := e.count(t, ""); n != e.oldRows+e.newRows {
			t.Fatalf("proposing must not archive anything (%d rows)", n)
		}

		for name, tok := range map[string]string{"proposer": tokA, "bootstrap": "reports-test-token"} {
			rec = httptest.NewRecorder()
			mux.ServeHTTP(rec, bearerReq(tok, http.MethodPost, approve, nil))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s approving: want 403, got %d", name, rec.Code)
			}
			if n := e.count(t, ""); n != e.oldRows+e.newRows {
				t.Fatalf("%s approval must leave rows intact (%d)", name, n)
			}
		}

		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, bearerReq(tokB, http.MethodPost, approve, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("second admin approving: %d %s", rec.Code, rec.Body.String())
		}
		if n := e.count(t, `WHERE action = 'cert.issue'`); n != e.newRows {
			t.Fatalf("approved run must archive the old rows: %d cert.issue left", n)
		}
	})
}

func TestArchiveProposeEndpointGuards(t *testing.T) {
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
		t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
		auth := newReportsTestAuth(t)
		mux := http.NewServeMux()
		RegisterAuditArchiveHandlers(mux, auth, e.mgr, stubAuditProvider{})
		do := func(method, tok, body string) int {
			var b []byte
			if body != "" {
				b = []byte(body)
			}
			req := bearerReq(tok, method, "/api/v1/audit/archive", b)
			if tok == "" {
				req.Header.Del("Authorization")
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			return rec.Code
		}
		admin := mintAdminToken(t, auth, "admin-a", "")
		if c := do(http.MethodPost, "", ""); c != http.StatusUnauthorized {
			t.Fatalf("anon: %d", c)
		}
		if c := do(http.MethodGet, admin, ""); c != http.StatusMethodNotAllowed {
			t.Fatalf("GET: %d", c)
		}
		if c := do(http.MethodPost, admin, `{"before":"yesterday"}`); c != http.StatusBadRequest {
			t.Fatalf("bad before: %d", c)
		}
		recent := e.mgr.now().Add(-time.Hour).Format(time.RFC3339)
		if c := do(http.MethodPost, admin, `{"before":"`+recent+`"}`); c != http.StatusBadRequest {
			t.Fatalf("inside retention: %d", c)
		}
		if c := do(http.MethodPost, admin, ""); c != http.StatusAccepted {
			t.Fatalf("default before: %d", c)
		}
	})
}

func TestArchiveCrossTenant(t *testing.T) {
	// With multi-tenancy on, a tenant-scoped admin can neither propose nor
	// approve: the log it would rewrite is instance-global.
	runOnEngines(t, func(t *testing.T, e *archiveEnv) {
		t.Setenv("MULTI_TENANCY", "on")
		t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
		t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
		auth := newReportsTestAuth(t)
		_, acme, err := auth.CreateAPIKey("acme-adm", "acme-adm", "pki-admin", []string{"*"}, "", "acme", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		RegisterAuditArchiveHandlers(mux, auth, e.mgr, stubAuditProvider{})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, bearerReq(acme, http.MethodPost, "/api/v1/audit/archive", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("tenant admin proposing: %d", rec.Code)
		}
		params, _ := json.Marshal(map[string]string{"before": e.cutoff.Format(time.RFC3339)})
		_, err = e.mgr.ExecuteArchive(context.Background(), PendingAction{ID: "x", Params: params}, AuthPrincipal{ID: "acme-adm", Role: "pki-admin", Tenant: "acme", TenantScoped: true})
		if err == nil {
			t.Fatal("tenant-scoped approver must be refused")
		}
		if n := e.count(t, ""); n != e.oldRows+e.newRows {
			t.Fatalf("rows touched: %d", n)
		}
	})
}
