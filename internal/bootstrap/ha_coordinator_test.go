// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestHADB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ha.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestHACoordinatorAt builds a coordinator pinned to a fixed clock and
// replica ID, sharing db across instances to simulate multiple replicas
// contending for the same lock rows.
func newTestHACoordinatorAt(t *testing.T, db *sql.DB, replicaID string, at time.Time) *HACoordinator {
	t.Helper()
	c := &HACoordinator{
		db:        db,
		ph:        sqlitePlaceholder,
		replicaID: replicaID,
		now:       func() time.Time { return at },
	}
	if err := c.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return c
}

func TestHACoordinatorTryAcquire(t *testing.T) {
	base := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		run  func(t *testing.T, db *sql.DB)
	}{
		{
			name: "first_acquire_succeeds",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				ok, err := a.TryAcquire(context.Background(), "lock-x", time.Minute)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if !ok {
					t.Fatal("expected first acquire of an unheld lock to succeed")
				}
			},
		},
		{
			name: "peer_with_live_lease_is_excluded",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a.TryAcquire(context.Background(), "lock-x", 5*time.Minute); err != nil || !ok {
					t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
				}
				b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(time.Second))
				ok, err := b.TryAcquire(context.Background(), "lock-x", 5*time.Minute)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if ok {
					t.Fatal("expected a peer to be excluded while the current holder's lease is still live")
				}
			},
		},
		{
			name: "same_holder_renews_its_own_lease",
			run: func(t *testing.T, db *sql.DB) {
				a1 := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a1.TryAcquire(context.Background(), "lock-x", 5*time.Minute); err != nil || !ok {
					t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
				}
				a2 := newTestHACoordinatorAt(t, db, "replica-a", base.Add(time.Minute))
				ok, err := a2.TryAcquire(context.Background(), "lock-x", 5*time.Minute)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if !ok {
					t.Fatal("expected the existing holder to renew its own lease before it lapses")
				}
			},
		},
		{
			name: "failover_after_lease_expiry",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a.TryAcquire(context.Background(), "lock-x", time.Minute); err != nil || !ok {
					t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
				}
				// replica-a never renews (simulated crash); replica-b tries
				// after the lease has lapsed.
				b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(2*time.Minute))
				ok, err := b.TryAcquire(context.Background(), "lock-x", time.Minute)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if !ok {
					t.Fatal("expected failover once the previous leader's lease had lapsed")
				}
			},
		},
		{
			name: "independent_lock_names_do_not_interfere",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a.TryAcquire(context.Background(), "lock-x", 5*time.Minute); err != nil || !ok {
					t.Fatalf("setup acquire lock-x: ok=%v err=%v", ok, err)
				}
				b := newTestHACoordinatorAt(t, db, "replica-b", base)
				ok, err := b.TryAcquire(context.Background(), "lock-y", 5*time.Minute)
				if err != nil {
					t.Fatalf("acquire lock-y: %v", err)
				}
				if !ok {
					t.Fatal("expected a distinct lock name to be independently acquirable by another replica")
				}
			},
		},
		{
			name: "non_positive_lease_duration_is_floored",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a.TryAcquire(context.Background(), "lock-x", 0); err != nil || !ok {
					t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
				}
				b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(time.Second))
				ok, err := b.TryAcquire(context.Background(), "lock-x", 0)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if ok {
					t.Fatal("expected a non-positive lease duration to be floored, not to expire immediately")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestHADB(t)
			tc.run(t, db)
		})
	}
}

func TestHACoordinatorRelease(t *testing.T) {
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	t.Run("release_lets_a_peer_acquire_without_waiting_for_the_lease", func(t *testing.T) {
		db := newTestHADB(t)
		a := newTestHACoordinatorAt(t, db, "replica-a", base)
		if ok, err := a.TryAcquire(context.Background(), "lock-x", time.Hour); err != nil || !ok {
			t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
		}
		if err := a.Release(context.Background(), "lock-x"); err != nil {
			t.Fatalf("release: %v", err)
		}
		// Same instant, well before the hour-long lease would have lapsed.
		b := newTestHACoordinatorAt(t, db, "replica-b", base)
		ok, err := b.TryAcquire(context.Background(), "lock-x", time.Hour)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		if !ok {
			t.Fatal("expected a peer to acquire immediately after Release, not wait out the lease")
		}
	})

	t.Run("release_only_deletes_a_row_this_replica_holds", func(t *testing.T) {
		db := newTestHADB(t)
		a := newTestHACoordinatorAt(t, db, "replica-a", base)
		if ok, err := a.TryAcquire(context.Background(), "lock-x", time.Hour); err != nil || !ok {
			t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
		}
		// replica-b never held this lock; its Release must not touch
		// replica-a's live lease.
		b := newTestHACoordinatorAt(t, db, "replica-b", base)
		if err := b.Release(context.Background(), "lock-x"); err != nil {
			t.Fatalf("release: %v", err)
		}
		c := newTestHACoordinatorAt(t, db, "replica-c", base.Add(time.Second))
		ok, err := c.TryAcquire(context.Background(), "lock-x", time.Hour)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		if ok {
			t.Fatal("expected replica-a's lease to still be live after an unrelated replica's Release")
		}
	})

	t.Run("release_of_a_lock_never_held_is_a_safe_no_op", func(t *testing.T) {
		db := newTestHADB(t)
		a := newTestHACoordinatorAt(t, db, "replica-a", base)
		if err := a.Release(context.Background(), "never-acquired"); err != nil {
			t.Fatalf("expected release of a nonexistent lock to be a no-op, got: %v", err)
		}
	})
}

// --- W23-27: readiness gate ---

type haRecordingAudit struct {
	AuditProvider
	entries []AuditEntry
}

func (r *haRecordingAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	r.entries = append(r.entries, e)
	return nil
}

func TestHAReadinessProbeFailsWhenDBClosed(t *testing.T) {
	db := newTestHADB(t)
	c := newTestHACoordinatorAt(t, db, "replica-a", time.Now().UTC())
	probe := c.ReadinessProbe(nil)
	if err := probe(context.Background()); err != nil {
		t.Fatalf("healthy DB should be ready: %v", err)
	}
	db.Close()
	if err := probe(context.Background()); err == nil {
		t.Fatal("closed DB must fail the probe")
	}
	mux := http.NewServeMux()
	registerMetaHandlers(mux, probe)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503", rec.Code)
	}
}

func TestHAReadinessAlertFiresOncePerOutage(t *testing.T) {
	db := newTestHADB(t)
	c := newTestHACoordinatorAt(t, db, "replica-a", time.Now().UTC())
	probe := c.ReadinessProbe(nil)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	db.Close()
	for i := 0; i < 3; i++ {
		_ = probe(context.Background())
	}
	if n := strings.Count(buf.String(), "ALERT ha.replica_not_ready"); n != 1 {
		t.Fatalf("alert lines = %d, want 1; log: %s", n, buf.String())
	}
}

func TestHAReadinessRecoveryWritesAuditEntry(t *testing.T) {
	db := newTestHADB(t)
	c := newTestHACoordinatorAt(t, db, "replica-a", time.Now().UTC())
	audit := &haRecordingAudit{}
	probe := c.ReadinessProbe(audit)
	db.Close()
	if err := probe(context.Background()); err == nil {
		t.Fatal("expected failure while closed")
	}
	if len(audit.entries) != 0 {
		t.Fatal("no audit row may be written during the outage")
	}
	c.db = newTestHADB(t)
	if err := c.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := probe(context.Background()); err != nil {
		t.Fatalf("recovered DB should be ready: %v", err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "ha.replica_not_ready" {
		t.Fatalf("audit entries = %+v", audit.entries)
	}
	// A further healthy probe must not re-audit.
	_ = probe(context.Background())
	if len(audit.entries) != 1 {
		t.Fatalf("recovery audited more than once: %d", len(audit.entries))
	}
}

func TestIssuanceFailsClosedOnDBLossLeavesNoPartialRow(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)
	count := func() int {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM certificates`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if _, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "ok.example.com", "ok.example.com"),
	}); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	before := count()

	c := newTestHACoordinatorAt(t, db, "replica-a", time.Now().UTC())
	probe := c.ReadinessProbe(nil)
	mux := http.NewServeMux()
	registerMetaHandlers(mux, probe)

	// Outage: the certificates table is unwritable (as in the persist test).
	if _, err := db.Exec(`ALTER TABLE certificates RENAME TO certificates_lost`); err != nil {
		t.Fatal(err)
	}
	_, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "lost.example.com", "lost.example.com"),
	})
	if err == nil || !strings.Contains(err.Error(), "could not be recorded") {
		t.Fatalf("issuance must fail closed during the outage, got %v", err)
	}
	if _, err := db.Exec(`ALTER TABLE certificates_lost RENAME TO certificates`); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != before {
		t.Fatalf("partial rows: count %d, want %d", got, before)
	}

	// And /readyz reports 503 once the DB handle itself is gone.
	db.Close()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503", rec.Code)
	}
}
