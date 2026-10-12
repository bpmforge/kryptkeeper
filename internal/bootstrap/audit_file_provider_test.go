// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// mustFileAudit opens the file audit provider named by APP_AUDIT_FILE and
// closes it with the test.
func mustFileAudit(t testing.TB) AuditProvider {
	t.Helper()
	p, err := NewFileAuditProviderFromEnv()
	if err != nil {
		t.Fatalf("open file audit provider: %v", err)
	}
	if c, ok := p.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = c.Close() })
	}
	return p
}

func openTestFileAudit(t *testing.T, path string) *fileAuditProvider {
	t.Helper()
	p, err := openFileAuditProvider(path, fileAuditSyncInterval)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func listAll(t *testing.T, p AuditProvider, q AuditListQuery) AuditListResult {
	t.Helper()
	if q.Limit == 0 {
		q.Limit = 1 << 20
	}
	res, err := p.ListEntries(context.Background(), q)
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}
	return res
}

func testEntry(action, resource string) AuditEntry {
	return AuditEntry{Action: action, ActorType: "system", ActorID: "test", ResourceType: "certificate", ResourceID: resource, Outcome: "success"}
}

func TestFileAuditConcurrentAppendsLoseNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	p := openTestFileAudit(t, path)

	const workers, per = 8, 500
	var wg sync.WaitGroup
	errs := make(chan error, workers*per)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := p.AppendEntry(context.Background(), testEntry("certificate.issue", fmt.Sprintf("w%d-%d", w, i))); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	// A reader running alongside the writers must never see a torn record.
	stop := make(chan struct{})
	var rg sync.WaitGroup
	rg.Add(1)
	go func() {
		defer rg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if _, err := p.ListEntries(context.Background(), AuditListQuery{Limit: 10}); err != nil {
					errs <- err
					return
				}
			}
		}
	}()
	wg.Wait()
	close(stop)
	rg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent audit: %v", err)
	}

	res := listAll(t, p, AuditListQuery{})
	if res.Total != workers*per {
		t.Fatalf("want %d entries, got %d", workers*per, res.Total)
	}
	seen := map[int64]bool{}
	for _, e := range res.Entries {
		if seen[e.ID] {
			t.Fatalf("duplicate id %d", e.ID)
		}
		seen[e.ID] = true
	}
	if n := p.corruptLines.Load(); n != 0 {
		t.Fatalf("corrupt lines counted: %d", n)
	}
	body, _ := os.ReadFile(path)
	if body[0] != '{' || strings.Count(string(body), "\n") != workers*per {
		t.Fatalf("file is not one JSON object per line")
	}
}

func TestFileAuditCorruptLineIsSkippedAndAppendsContinue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	good1 := `{"id":1,"timestamp":"2026-01-01T00:00:00Z","action":"a","actor_type":"system","actor_id":"x","resource_type":"r","resource_id":"1","outcome":"success"}`
	good2 := `{"id":2,"timestamp":"2026-01-01T00:00:01Z","action":"b","actor_type":"system","actor_id":"x","resource_type":"r","resource_id":"2","outcome":"success"}`
	if err := os.WriteFile(path, []byte(good1+"\n{this is not json\n"+good2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := openTestFileAudit(t, path)
	if n := p.corruptLines.Load(); n != 1 {
		t.Fatalf("want 1 corrupt line counted at open, got %d", n)
	}
	if res := listAll(t, p, AuditListQuery{}); res.Total != 2 {
		t.Fatalf("want 2 readable entries around the corrupt line, got %d", res.Total)
	}
	if err := p.AppendEntry(context.Background(), testEntry("c", "3")); err != nil {
		t.Fatal(err)
	}
	res := listAll(t, p, AuditListQuery{Order: "asc"})
	if res.Total != 3 || res.Entries[2].ID != 3 {
		t.Fatalf("append after corrupt line: %+v", res.Entries)
	}
	body, _ := os.ReadFile(path)
	if !bytes.Contains(body, []byte("{this is not json\n")) {
		t.Fatal("corrupt line was removed; history must never be rewritten")
	}
}

func TestFileAuditTornTailDoesNotGlueNextRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	good := `{"id":1,"timestamp":"2026-01-01T00:00:00Z","action":"a","actor_type":"system","actor_id":"x","resource_type":"r","resource_id":"1","outcome":"success"}`
	if err := os.WriteFile(path, []byte(good+"\n"+`{"id":2,"timest`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := openTestFileAudit(t, path)
	if err := p.AppendEntry(context.Background(), testEntry("b", "2")); err != nil {
		t.Fatal(err)
	}
	res := listAll(t, p, AuditListQuery{})
	if res.Total != 2 {
		t.Fatalf("want the good record and the new one, got %d", res.Total)
	}
}

func TestFileAuditReopenContinuesIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	p := openTestFileAudit(t, path)
	for i := 0; i < 3; i++ {
		if err := p.AppendEntry(context.Background(), testEntry("a", "x")); err != nil {
			t.Fatal(err)
		}
	}
	_ = p.Close()
	p2 := openTestFileAudit(t, path)
	if err := p2.AppendEntry(context.Background(), testEntry("a", "y")); err != nil {
		t.Fatal(err)
	}
	res := listAll(t, p2, AuditListQuery{Order: "asc"})
	if res.Total != 4 || res.Entries[3].ID != 4 {
		t.Fatalf("ids did not continue after reopen: %+v", res.Entries)
	}
}

func TestFileAuditMigratesLegacyArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	// Legacy files are newest first.
	legacy := `[{"id":2,"timestamp":"2026-01-02T00:00:00Z","action":"second","actor_type":"system","actor_id":"x","resource_type":"r","resource_id":"2","outcome":"success"},` +
		`{"id":1,"timestamp":"2026-01-01T00:00:00Z","action":"first","actor_type":"system","actor_id":"x","resource_type":"r","resource_id":"1","outcome":"success"}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	p := openTestFileAudit(t, path)

	bak, err := os.ReadFile(path + ".bak")
	if err != nil || string(bak) != legacy {
		t.Fatalf("original must be kept byte-for-byte as .bak (err=%v)", err)
	}
	if _, err := os.Stat(path + ".migrating"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temp file left behind")
	}
	body, _ := os.ReadFile(path)
	if body[0] != '{' || strings.Count(string(body), "\n") != 2 {
		t.Fatalf("not JSONL: %q", body)
	}
	res := listAll(t, p, AuditListQuery{Order: "asc"})
	if res.Total != 2 || res.Entries[0].Action != "first" || res.Entries[1].Action != "second" {
		t.Fatalf("migrated entries wrong: %+v", res.Entries)
	}
	if err := p.AppendEntry(context.Background(), testEntry("third", "3")); err != nil {
		t.Fatal(err)
	}
	if res := listAll(t, p, AuditListQuery{Order: "asc"}); res.Total != 3 || res.Entries[2].ID != 3 {
		t.Fatalf("append after migration: %+v", res.Entries)
	}

	// Reopening an already-migrated file is a no-op.
	_ = p.Close()
	p2 := openTestFileAudit(t, path)
	if res := listAll(t, p2, AuditListQuery{}); res.Total != 3 {
		t.Fatalf("reopen lost entries: %d", res.Total)
	}
}

func TestFileAuditUnparseableLegacyArrayRefusesToOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	orig := `[{"id":1,"timestamp":"2026`
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openFileAuditProvider(path, 0); err == nil {
		t.Fatal("expected an error for a truncated legacy array")
	}
	if body, _ := os.ReadFile(path); string(body) != orig {
		t.Fatal("unparseable legacy file must be left untouched")
	}
}

func TestFileAuditListErrorIsNotEmptyHistory(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should be: readable as nothing, but an error.
	p := &fileAuditProvider{filePath: dir}
	if _, err := p.ListEntries(context.Background(), AuditListQuery{}); err == nil {
		t.Fatal("an unreadable audit store must be an error, not zero entries")
	}
}

func TestFileAuditSyncPerWrite(t *testing.T) {
	p, err := openFileAuditProvider(filepath.Join(t.TempDir(), "a.json"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.AppendEntry(context.Background(), testEntry("a", "x")); err != nil {
		t.Fatal(err)
	}
	if p.syncTimer != nil || p.dirty {
		t.Fatal("sync-per-write must not leave a pending sync")
	}
}

func TestFileAuditAppendAfterCloseFails(t *testing.T) {
	p, err := openFileAuditProvider(filepath.Join(t.TempDir(), "a.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	if err := p.AppendEntry(context.Background(), testEntry("a", "x")); err == nil {
		t.Fatal("append to a closed store must fail, not vanish")
	}
}

func TestResolveAuditProviderDefaultsToDBWhenCoreDBExists(t *testing.T) {
	t.Setenv("APP_AUDIT_PROVIDER", "")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("APP_AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))

	p, desc, err := ResolveAuditProvider(true)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := p.(*dbAuditProvider); !ok || !strings.HasPrefix(desc, "db") {
		t.Fatalf("want DB provider by default with a core DB, got %T (%s)", p, desc)
	}

	p, desc, err = ResolveAuditProvider(false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := p.(*fileAuditProvider); !ok || !strings.HasPrefix(desc, "file") {
		t.Fatalf("want file provider without a core DB, got %T (%s)", p, desc)
	}
	_ = p.(*fileAuditProvider).Close()
}

func TestResolveAuditProviderExplicitFileWinsOverCoreDB(t *testing.T) {
	t.Setenv("APP_AUDIT_PROVIDER", "file")
	t.Setenv("APP_AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))
	p, desc, err := ResolveAuditProvider(true)
	if err != nil {
		t.Fatal(err)
	}
	fp, ok := p.(*fileAuditProvider)
	if !ok || !strings.Contains(desc, "APP_AUDIT_PROVIDER") {
		t.Fatalf("explicit file must be honoured, got %T (%s)", p, desc)
	}
	_ = fp.Close()
}

func TestResolveAuditProviderFailsClosedOnUnopenableStore(t *testing.T) {
	// The parent of the audit path is a regular file, so it can never be opened.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_AUDIT_PROVIDER", "file")
	t.Setenv("APP_AUDIT_FILE", filepath.Join(blocker, "sub", "audit.json"))
	if p, _, err := ResolveAuditProvider(false); err == nil {
		t.Fatalf("want a startup error, got provider %T", p)
	}

	// And a DB audit store that cannot be opened is also an error.
	t.Setenv("APP_AUDIT_PROVIDER", "db")
	t.Setenv("APP_AUDIT_DB_DSN", "file:"+filepath.Join(blocker, "x", "a.db"))
	if p, _, err := ResolveAuditProvider(true); err == nil {
		t.Fatalf("want a startup error for an unopenable audit DB, got %T", p)
	}
}

// --- renewal retry history (N-01, N-02) ---

type scriptedAudit struct {
	entries []AuditEntry
	err     error
}

func (s scriptedAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: s.entries, Total: len(s.entries)}, s.err
}
func (scriptedAudit) AppendEntry(context.Context, AuditEntry) error { return nil }

func TestInstallStateSurfacesUnreadableHistory(t *testing.T) {
	s := &RenewalScheduler{auditProvider: scriptedAudit{err: errors.New("disk gone")}}
	if _, err := s.installState(context.Background(), CertificateItem{FingerprintSHA256: "fp"}); err == nil {
		t.Fatal("an unreadable store must surface as an error, not as zero failures")
	}
}

func TestInstallStateOverFileProviderReportsReadError(t *testing.T) {
	s := &RenewalScheduler{auditProvider: &fileAuditProvider{filePath: t.TempDir()}}
	if _, err := s.installState(context.Background(), CertificateItem{FingerprintSHA256: "fp"}); err == nil {
		t.Fatal("file provider read failure must reach the scheduler")
	}
}

func TestInstallStateUnparseableTimestampStillBacksOff(t *testing.T) {
	s := &RenewalScheduler{auditProvider: scriptedAudit{entries: []AuditEntry{
		{ID: 1, Action: "certificate.renew_execute_failed", Timestamp: "not-a-time"},
	}}}
	st, err := s.installState(context.Background(), CertificateItem{FingerprintSHA256: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	if st.failures != 1 || st.lastFailure.IsZero() {
		t.Fatalf("bad timestamp must count as a failure that just happened: %+v", st)
	}
	out := s.tryAutoRenew(context.Background(), CertificateItem{FingerprintSHA256: "fp"}, ManagedTarget{}, time.Now().UTC(), st, time.Minute)
	if !out.pending || out.attempted {
		t.Fatalf("expected backoff (pending, not attempted), got %+v", out)
	}
}

func TestAuditDBDSNFollowsCoreDBWhenUnset(t *testing.T) {
	core := "file:" + filepath.Join(t.TempDir(), "core.db")
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("APP_CORE_DB_DSN", core)
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir()) // must not be used
	if got, err := auditSQLiteDSNFromEnv(); err != nil || got != core {
		t.Fatalf("sqlite audit DSN = %q (%v), want the core DSN %q", got, err, core)
	}

	pg := "postgres://core.example/kk"
	t.Setenv("APP_CORE_DB_DSN", "")
	t.Setenv("KRYPTKEEPER_DB_DSN", "")
	t.Setenv("DATABASE_URL", pg)
	if got := auditPostgresDSNFromEnv(); got != pg {
		t.Fatalf("postgres audit DSN = %q, want DATABASE_URL %q", got, pg)
	}
	t.Setenv("APP_CORE_DB_DSN", "postgres://core-specific/kk")
	if got := auditPostgresDSNFromEnv(); got != "postgres://core-specific/kk" {
		t.Fatalf("APP_CORE_DB_DSN must win like it does for the core DB, got %q", got)
	}
	t.Setenv("APP_AUDIT_DB_DSN", "postgres://audit-only/kk")
	if got := auditPostgresDSNFromEnv(); got != "postgres://audit-only/kk" {
		t.Fatalf("explicit audit DSN must win, got %q", got)
	}
}

func TestAuditDBPostgresModeWithoutDSNFailsClosed(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DB_MODE", "postgres")
	for _, k := range []string{"APP_AUDIT_DB_DSN", "APP_CORE_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL"} {
		t.Setenv(k, "")
	}
	t.Setenv("APP_AUDIT_PROVIDER", "")
	if p, _, err := ResolveAuditProvider(true); err == nil {
		t.Fatalf("postgres mode with no DSN must not fall back to sqlite, got %T", p)
	}
}
