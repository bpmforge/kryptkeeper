// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ha_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	chaosIssuances = 400
	chaosWorkers   = 8
	renewalLock    = "renewal-scheduler"
)

func leaseRow(db *sql.DB) (holder, expires string, err error) {
	err = db.QueryRow(`SELECT holder_id, lease_expires_at FROM ha_scheduler_locks WHERE lock_name=$1`, renewalLock).Scan(&holder, &expires)
	return holder, expires, err
}

// TestHAConcurrentIssuanceNoDuplicateSerials issues through both replicas at
// once and asserts the shared database holds no duplicate (ca_id, serial).
func TestHAConcurrentIssuanceNoDuplicateSerials(t *testing.T) {
	e := loadEnv(t, "KK_LIVE_HA")
	a, b := newHub("A", e.aURL, e.token, 30*time.Second), newHub("B", e.bURL, e.token, 30*time.Second)
	f := setupFixture(t, a, b)
	db := openDB(t, e.dsn)

	var created, other, transport atomic.Int64
	var mu sync.Mutex
	nonCreated := map[string]int{}
	sampleBody := map[int][]byte{}
	var wg sync.WaitGroup
	jobs := make(chan int)
	for w := 0; w < chaosWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				h := a
				if i%2 == 1 {
					h = b
				}
				_, st, body, err := f.issue(h, fmt.Sprintf("ha-chaos-%d", i))
				if err == nil && st == http.StatusCreated {
					created.Add(1)
					continue
				}
				other.Add(1)
				if st == 0 {
					transport.Add(1)
				}
				mu.Lock()
				key := fmt.Sprintf("HTTP %d", st)
				if err != nil {
					key = fmt.Sprintf("HTTP %d: %v", st, err)
				}
				nonCreated[key]++
				if _, seen := sampleBody[st]; !seen {
					sampleBody[st] = body
				}
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < chaosIssuances; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	t.Logf("issuances: %d requested, %d created (201), %d other %v", chaosIssuances, created.Load(), other.Load(), nonCreated)
	for st, body := range sampleBody {
		t.Logf("sample non-201 body (HTTP %d): %.200s", st, body)
	}
	if got := float64(created.Load()) / chaosIssuances; got < 0.99 {
		t.Errorf("only %.1f%% of issuances returned 201, want at least 99%%", got*100)
	}
	if transport.Load() > 0 {
		t.Errorf("%d transport-level failures with both replicas up: %v", transport.Load(), nonCreated)
	}

	dups, err := queryDups(db, qDupSerials)
	if err != nil {
		t.Fatalf("duplicate-serial query: %v", err)
	}
	if len(dups) != 0 {
		t.Errorf("duplicate (ca_id, serial) rows: %v", dups)
	}
	n, err := queryCount(db, `SELECT COUNT(*) FROM certificates WHERE ca_id=$1`, f.caID)
	if err != nil {
		t.Fatal(err)
	}
	if int64(n) < created.Load() {
		t.Errorf("only %d certificates rows for %d created responses", n, created.Load())
	}
	idx, err := queryCount(db, `SELECT COUNT(*) FROM pg_indexes WHERE indexname='idx_cert_serial_ca'`)
	if err != nil || idx != 1 {
		t.Errorf("unique index idx_cert_serial_ca present = %d (err %v)", idx, err)
	}
	t.Logf("certificates rows for the CA: %d, duplicate (ca_id, serial) groups: %d", n, len(dups))
}

// TestHALeaseTakeoverAfterKill SIGKILLs the replica that started first (the
// renewal-scheduler lease holder) and waits for the other replica to take the
// lease over. Each scheduler in a process has its own coordinator id, so the
// victim is chosen by start order, which run.sh guarantees.
func TestHALeaseTakeoverAfterKill(t *testing.T) {
	e := loadEnv(t, "KK_LIVE_HA")
	a, b := newHub("A", e.aURL, e.token, 30*time.Second), newHub("B", e.bURL, e.token, 30*time.Second)
	f := setupFixture(t, a, b)
	db := openDB(t, e.dsn)

	holder, expires, err := leaseRow(db)
	if err != nil {
		t.Fatalf("no %s lease row before the kill: %v", renewalLock, err)
	}
	t.Logf("before kill: holder %s, lease expires %s", holder, expires)

	poll := time.Duration(e.pollMinutes) * time.Minute
	// DECISION (W23-28): the lease is max(2*poll, 1 min) and the standby only
	// retries on its own tick, so the worst case is lease + one poll = 3x poll.
	bound := 3*poll + 10*time.Second

	killedAt := time.Now()
	if out, err := podman("kill", "-s", "KILL", e.container("kk-a")); err != nil {
		t.Fatalf("podman kill %s: %v %s", e.container("kk-a"), err, out)
	}
	t.Logf("SIGKILL sent to %s", e.container("kk-a"))

	// While the lease is orphaned, B must keep serving.
	served := 0
	for i := 0; i < 5; i++ {
		if _, st, _, err := f.issue(b, fmt.Sprintf("ha-during-takeover-%d", i)); err == nil && st == http.StatusCreated {
			served++
		}
	}
	if served != 5 {
		t.Errorf("B served %d/5 issuances while A was dead", served)
	}

	ctx, cancel := context.WithTimeout(context.Background(), bound+30*time.Second)
	defer cancel()
	var newHolder string
	err = waitFor(ctx, 2*time.Second, func() (bool, error) {
		h, _, err := leaseRow(db)
		if err != nil {
			return false, nil
		}
		newHolder = h
		return h != holder, nil
	})
	elapsed := time.Since(killedAt)
	if err != nil {
		t.Fatalf("lease still held by %s %s after the kill (bound %s): %v", holder, elapsed.Round(time.Second), bound, err)
	}
	t.Logf("takeover: %s -> %s after %s (poll %s, lease %s, bound %s)", holder, newHolder, elapsed.Round(time.Second), poll, 2*poll, bound)
	if elapsed > bound {
		t.Errorf("takeover took %s, bound is %s (2*poll lease + one poll + 10s)", elapsed.Round(time.Second), bound)
	}
	if !b.ready() {
		t.Errorf("B is not ready after A was killed")
	}
}

// TestHANoDuplicateRenewalsOrAlerts runs after the kill test. It logs how many
// rows the two queries examined: in a 20-minute harness with 30-day
// certificates they can legitimately be zero, and the README says so.
func TestHANoDuplicateRenewalsOrAlerts(t *testing.T) {
	e := loadEnv(t, "KK_LIVE_HA")
	db := openDB(t, e.dsn)
	renewals, alerts := assertNoDuplicateRenewalsOrAlerts(t, db)
	t.Logf("rows examined: %d certificates with a predecessor, %d non-rule renewal_notification_sent successes", renewals, alerts)
	dups, err := queryDups(db, qDupSerials)
	if err != nil || len(dups) != 0 {
		t.Errorf("duplicate serials after the kill: %v (err %v)", dups, err)
	}
}
