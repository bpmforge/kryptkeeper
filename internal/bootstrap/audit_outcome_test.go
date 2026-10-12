// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// RC6 live autopilot run: audit_log.outcome had a CHECK of success/failure/
// denied, the code recorded six more outcomes, and with the DB as the default
// audit store every such append failed with "CHECK constraint failed" and was
// only logged — silent audit loss. These tests pin the vocabulary to the code
// and to the schema, and run every outcome through the real stores.

func outcomeSet(vals []string) string {
	sort.Strings(vals)
	return strings.Join(vals, ",")
}

func vocabularyStrings() []string {
	var out []string
	for _, o := range AllAuditOutcomes() {
		out = append(out, string(o))
	}
	return out
}

// outcomePositions maps each audit-writing function to the index of its
// outcome argument. A string literal (or a concatenation containing one) in
// that position would compile against the string-kinded AuditOutcome, so the
// vocabulary is enforced here instead of by the type checker.
var outcomePositions = map[string]int{
	"emitAuditEvent": 6, "emitAuditEventDetail": 6, "emitAuditEventDetailErr": 6,
	"emitRenewalAudit": 3, "appendPluginAudit": 3, "recordAttest": 2, "appendProtocolAudit": 4,
}

func nonTestGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no go files in %s (err=%v)", dir, err)
	}
	var out []string
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			out = append(out, f)
		}
	}
	return out
}

func hasStringLit(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			found = true
		}
		return !found
	})
	return found
}

func TestAuditOutcomesAreNeverBareLiterals(t *testing.T) {
	calls := 0
	for _, dir := range []string{".", "../../cmd/kryptkeeper"} {
		for _, path := range nonTestGoFiles(t, dir) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					name := ""
					switch fn := x.Fun.(type) {
					case *ast.Ident:
						name = fn.Name
					case *ast.SelectorExpr:
						name = fn.Sel.Name
					}
					if i, ok := outcomePositions[name]; ok && i < len(x.Args) {
						calls++
						if hasStringLit(x.Args[i]) {
							t.Errorf("%s: %s passes a string literal as the audit outcome; use an AuditOutcome constant", fset.Position(x.Pos()), name)
						}
					}
				case *ast.CompositeLit:
					id, ok := x.Type.(*ast.Ident)
					sel, isSel := x.Type.(*ast.SelectorExpr)
					if !(ok && id.Name == "AuditEntry") && !(isSel && sel.Sel.Name == "AuditEntry") {
						return true
					}
					for _, el := range x.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok {
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Outcome" && hasStringLit(kv.Value) {
								t.Errorf("%s: AuditEntry.Outcome set from a string literal; use an AuditOutcome constant", fset.Position(kv.Pos()))
							}
						}
					}
				}
				return true
			})
		}
	}
	if calls < 200 {
		t.Fatalf("scanned only %d audit calls; the scan is no longer finding the call sites", calls)
	}
}

// The protocol and key-custody packages cannot import bootstrap, so they carry
// their own Outcome strings and the hub adapts them. Whatever literals they
// use must still be in the vocabulary, or the adapted row would be refused.
func TestLeafPackageOutcomeLiteralsAreInVocabulary(t *testing.T) {
	valid := map[string]bool{}
	for _, v := range vocabularyStrings() {
		valid[v] = true
	}
	leafCalls := map[string]int{"byokRecord": 3, "record": 4}
	seen := 0
	for _, dir := range []string{"../est", "../scep", "../wstep", "../keystore"} {
		for _, path := range nonTestGoFiles(t, dir) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			check := func(e ast.Expr) {
				bl, ok := e.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					return
				}
				seen++
				if v, _ := strconv.Unquote(bl.Value); !valid[v] {
					t.Errorf("%s: outcome %q is not an AuditOutcome", fset.Position(bl.Pos()), v)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.KeyValueExpr:
					if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Outcome" {
						check(x.Value)
					}
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok {
						if i, ok := leafCalls[id.Name]; ok && i < len(x.Args) {
							check(x.Args[i])
						}
					}
				}
				return true
			})
		}
	}
	if seen < 10 {
		t.Fatalf("found only %d outcome literals in the leaf packages; the scan is stale", seen)
	}
}

var (
	outcomeCheckRe    = regexp.MustCompile(`(?s)outcome\s+(?:VARCHAR\(\d+\)|TEXT)\s+NOT NULL DEFAULT 'success'\s+CHECK\s*\(outcome IN \(([^)]*)\)\)`)
	outcomeCheckAltRe = regexp.MustCompile(`(?s)CHECK\s*\(outcome IN \(([^)]*)\)\)`)
	quotedRe          = regexp.MustCompile(`'([a-z_]+)'`)
)

func quotedValues(s string) []string {
	var out []string
	for _, m := range quotedRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func TestAuditOutcomeVocabularyMatchesSchemas(t *testing.T) {
	want := outcomeSet(vocabularyStrings())
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, p := range []string{
		"../db/migrations/sqlite/000076_audit_outcome_vocabulary.up.sql",
		"../db/migrations/postgres/000076_audit_outcome_vocabulary.up.sql",
	} {
		m := outcomeCheckAltRe.FindStringSubmatch(read(p))
		if m == nil {
			t.Fatalf("%s: no outcome CHECK found", p)
		}
		if got := outcomeSet(quotedValues(m[1])); got != want {
			t.Errorf("%s: CHECK allows %s, AuditOutcome is %s", p, got, want)
		}
	}
	for name, ddl := range map[string]string{"sqliteAuditSchema": sqliteAuditSchema, "postgresAuditSchema": postgresAuditSchema} {
		m := outcomeCheckRe.FindStringSubmatch(ddl)
		if m == nil {
			t.Fatalf("%s: no outcome CHECK found", name)
		}
		if got := outcomeSet(quotedValues(m[1])); got != want {
			t.Errorf("%s: CHECK allows %s, AuditOutcome is %s", name, got, want)
		}
	}
	if !strings.Contains(postgresAuditSchema, "outcome                   VARCHAR(32)") {
		t.Error("postgresAuditSchema outcome column must be wide enough for the longest outcome")
	}
	longest := 0
	for _, v := range vocabularyStrings() {
		longest = max(longest, len(v))
	}
	if longest > 32 {
		t.Errorf("longest outcome is %d chars, the Postgres column holds 32", longest)
	}
}

func TestAuditOutcomeClassification(t *testing.T) {
	for _, o := range AllAuditOutcomes() {
		if !o.Valid() {
			t.Errorf("%q must be valid", o)
		}
	}
	if AuditOutcome("renewed_install_failed").Valid() || AuditOutcome("").Valid() {
		t.Error("values outside the vocabulary must not be valid")
	}
	for _, o := range []AuditOutcome{AuditOutcomeFailure, AuditOutcomeDenied, AuditOutcomeIssuanceFailed, AuditOutcomePartial} {
		if !o.Adverse() {
			t.Errorf("%q must be adverse", o)
		}
	}
	for _, o := range []AuditOutcome{AuditOutcomeSuccess, AuditOutcomeSkipped, AuditOutcomePendingApproval, AuditOutcomeProposed, AuditOutcomeExecuted} {
		if o.Adverse() {
			t.Errorf("%q must not be adverse", o)
		}
	}
}

// appendEveryOutcome writes one row per AuditOutcome through p and reads every
// one back. An append that fails is a test failure: this is exactly the loss
// that used to be only logged.
func appendEveryOutcome(t *testing.T, p AuditProvider) {
	t.Helper()
	ctx := context.Background()
	for _, o := range AllAuditOutcomes() {
		err := p.AppendEntry(ctx, AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "outcome.roundtrip", ActorType: "user",
			ActorID: "alice", ResourceType: "test", ResourceID: string(o), Outcome: o, Tenant: "default",
			ChangeSummary: "outcome vocabulary round trip",
		})
		if err != nil {
			t.Errorf("append outcome %q: %v", o, err)
		}
	}
	res, err := p.ListEntries(ctx, AuditListQuery{Limit: 100, Action: "outcome.roundtrip", Order: "asc"})
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}
	got := map[AuditOutcome]bool{}
	for _, e := range res.Entries {
		got[e.Outcome] = true
		if string(e.Outcome) != e.ResourceID {
			t.Errorf("row for %q read back as outcome %q", e.ResourceID, e.Outcome)
		}
	}
	for _, o := range AllAuditOutcomes() {
		if !got[o] {
			t.Errorf("outcome %q was not stored", o)
		}
	}
	// spiffe.workload_attest records actor_type "workload".
	if err := p.AppendEntry(ctx, AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "spiffe.workload_attest", ActorType: "workload",
		ActorID: "spiffe://example/wl", ResourceType: "svid", ResourceID: "spiffe://example/wl", Outcome: AuditOutcomeSuccess,
	}); err != nil {
		t.Errorf("append actor_type workload: %v", err)
	}
}

func realSQLiteAuditProvider(t *testing.T) AuditProvider {
	t.Helper()
	t.Setenv("APP_AUDIT_PROVIDER", "db")
	t.Setenv(dbModeEnv, dbModeSQLite)
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("APP_CORE_DB_DSN", "")
	p, err := newDBAuditProviderFromEnv()
	if err != nil {
		t.Fatalf("newDBAuditProviderFromEnv: %v", err)
	}
	return p
}

func TestDBAuditStore_SQLite_StoresEveryOutcome(t *testing.T) {
	appendEveryOutcome(t, realSQLiteAuditProvider(t))
}

func TestDBAuditStore_Postgres_StoresEveryOutcome_StoreCreatedSchema(t *testing.T) {
	freshPostgresForTest(t)
	t.Setenv("APP_AUDIT_PROVIDER", "db")
	p, err := newDBAuditProviderFromEnv()
	if err != nil {
		t.Fatalf("newDBAuditProviderFromEnv: %v", err)
	}
	appendEveryOutcome(t, p)
}

func TestDBAuditStore_Postgres_StoresEveryOutcome_MigratedSchema(t *testing.T) {
	migratedPostgresForTest(t)
	t.Setenv("APP_AUDIT_PROVIDER", "db")
	p, err := newDBAuditProviderFromEnv()
	if err != nil {
		t.Fatalf("newDBAuditProviderFromEnv: %v", err)
	}
	appendEveryOutcome(t, p)
}

// A table created by an older hub (original CHECK) must be widened when the
// audit store opens it, even when no migration will ever run against it
// (APP_AUDIT_DB_DSN pointing at its own database), without losing a row.
func TestDBAuditStore_SQLite_WidensPreExistingNarrowTable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_AUDIT_PROVIDER", "db")
	t.Setenv(dbModeEnv, dbModeSQLite)
	t.Setenv("KRYPTKEEPER_DATA_DIR", dir)
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("APP_CORE_DB_DSN", "")

	old, err := sql.Open("sqlite", filepath.Join(dir, "kryptkeeper.db"))
	if err != nil {
		t.Fatal(err)
	}
	narrow := strings.Replace(sqliteAuditSchema,
		"CHECK (outcome IN ('success', 'failure', 'denied', 'skipped', 'pending_approval', 'proposed', 'executed', 'issuance_failed', 'partial'))",
		"CHECK (outcome IN ('success', 'failure', 'denied'))", 1)
	if narrow == sqliteAuditSchema {
		t.Fatal("test setup: failed to narrow the CHECK")
	}
	if _, err := old.Exec(narrow); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO audit_log (action, actor_type, actor_id, resource_type, resource_id, outcome)
		VALUES ('legacy.row', 'user', 'bob', 'test', 'r1', 'denied')`); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()

	p, err := newDBAuditProviderFromEnv()
	if err != nil {
		t.Fatalf("newDBAuditProviderFromEnv: %v", err)
	}
	appendEveryOutcome(t, p)
	res, err := p.ListEntries(context.Background(), AuditListQuery{Limit: 100, Action: "legacy.row"})
	if err != nil || len(res.Entries) != 1 || res.Entries[0].Outcome != AuditOutcomeDenied {
		t.Fatalf("legacy row lost or altered by the widening: %+v err=%v", res, err)
	}
}

// The file (JSONL) provider has no outcome restriction.
func TestFileAuditProvider_StoresEveryOutcome(t *testing.T) {
	t.Setenv("APP_AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))
	p := mustFileAudit(t)
	appendEveryOutcome(t, p)
}

// RC5 A1 audited skipped alerts, but only ever against an in-memory capture,
// so the real store's CHECK never saw the outcome. Same scenario, real store.
func TestSchedulerSkippedAlertIsStoredByRealAuditStore(t *testing.T) {
	audit := realSQLiteAuditProvider(t)
	s := &RenewalScheduler{
		notifProvider: newFileNotificationProvider(), auditProvider: audit,
		cooldown: time.Hour, cooldownStore: newFreshRenewalAlertCooldownStore(t),
	}
	now := time.Now().UTC()
	cert := CertificateItem{FingerprintSHA256: "fp-real-store", OwnerEmail: "owner@example.com"}
	if s.handleRenewalCandidate(context.Background(), cert, now.Add(10*24*time.Hour), now, time.Hour) {
		t.Fatal("reminder reported notified through a non-delivering provider")
	}
	res, err := audit.ListEntries(context.Background(), AuditListQuery{Limit: 10, Action: "renewal_notification_sent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 || res.Entries[0].Outcome != AuditOutcomeSkipped ||
		!strings.Contains(res.Entries[0].ChangeSummary, "does not deliver") {
		t.Fatalf("want one stored skipped row naming the non-delivering provider, got %+v", res.Entries)
	}
}
