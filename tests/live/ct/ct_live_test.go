// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package ct_test drives the real ctmonitor (real crt.sh source, real SQLite
// store, real ChannelNotifier over a recording channel) against a domain the
// operator controls. Gated by KK_LIVE_CT=1; see README.md for the env contract
// and how to issue the test certificate from a CA that is not this hub.
package ct_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/ctmonitor"
	"kryptkeeper/internal/notifications/delivery"
)

type recordingChannel struct {
	mu     sync.Mutex
	events []delivery.Event
}

func (r *recordingChannel) Name() string { return "live-ct" }
func (r *recordingChannel) Send(_ context.Context, ev delivery.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}
func (r *recordingChannel) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// knownInventory knows exactly one serial (the pretend-inventoried cert).
type knownInventory struct{ serial string }

func (k knownInventory) HasSerial(_ context.Context, serial string) (bool, error) {
	return k.serial != "" && ctmonitor.NormalizeSerial(serial) == k.serial, nil
}

func envDuration(t *testing.T, key, def string) time.Duration {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		v = def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		t.Fatalf("%s=%q is not a positive duration", key, v)
	}
	return d
}

func TestCTLive(t *testing.T) {
	if os.Getenv("KK_LIVE_CT") != "1" {
		t.Skip("set KK_LIVE_CT=1 and KK_LIVE_CT_DOMAIN=<domain you control> (see tests/live/ct/README.md) to run against crt.sh")
	}
	domain := strings.TrimSpace(os.Getenv("KK_LIVE_CT_DOMAIN"))
	if domain == "" {
		t.Fatal("KK_LIVE_CT_DOMAIN is required: a domain you control with a cert issued by a CA that is not this hub")
	}
	wait := envDuration(t, "KK_LIVE_CT_WAIT", "30m")
	poll := envDuration(t, "KK_LIVE_CT_POLL", "60s")
	expectIssuer := os.Getenv("KK_LIVE_CT_EXPECT_ISSUER")
	knownSerial := ""
	if v := os.Getenv("KK_LIVE_CT_KNOWN_SERIAL"); v != "" {
		knownSerial = ctmonitor.NormalizeSerial(v)
	}

	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ct-live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := ctmonitor.NewStore(db, false)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingChannel{}
	notifier := &ctmonitor.ChannelNotifier{Channel: rec, Target: "live-ct-test"}

	mon, err := ctmonitor.NewMonitor(ctmonitor.NewCrtShSource(""), knownInventory{serial: knownSerial}, store, notifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	sources := []string{"crtsh"}
	// Same default as production: Cert Spotter as a second source unless off.
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_CT_SECOND_SOURCE")), "off") {
		mon.AddSource(ctmonitor.NewCertSpotterSource("", strings.TrimSpace(os.Getenv("KRYPTKEEPER_CT_CERTSPOTTER_KEY"))))
		sources = append(sources, "certspotter")
	}
	mon.SetDomainProvider(func(context.Context) []string { return []string{domain} })

	start := time.Now()
	deadline := start.Add(wait)
	var report ctmonitor.ScanReport
	errorCount := 0
	for polls := 1; ; polls++ {
		report, err = mon.Scan(ctx)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		errorCount += len(report.Errors)
		t.Logf("poll %d after %s: entries=%d new_findings=%d errors=%v", polls, time.Since(start).Round(time.Second), report.Entries, len(report.NewFindings), report.Errors)
		if len(report.NewFindings) > 0 {
			break
		}
		if time.Now().Add(poll).After(deadline) {
			t.Fatalf("no finding for %s within %s; last errors: %v", domain, wait, report.Errors)
		}
		time.Sleep(poll)
	}
	elapsed := time.Since(start).Round(time.Second)

	// 4. one notification per new finding; fields populated.
	if got := rec.count(); got != len(report.NewFindings) {
		t.Errorf("notifications=%d, new findings=%d: want one notification per finding", got, len(report.NewFindings))
	}
	var first ctmonitor.Finding
	for i, id := range report.NewFindings {
		f, err := store.Get(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if i == 0 {
			first = f
		}
		if f.ID == "" || f.Issuer == "" || f.Serial == "" || f.NotBefore.IsZero() {
			t.Errorf("finding %s has empty fields: %+v", id, f)
		}
		if knownSerial != "" && ctmonitor.NormalizeSerial(f.Serial) == knownSerial {
			t.Errorf("finding %s is for the inventoried serial", id)
		}
		if expectIssuer != "" && !strings.Contains(f.Issuer, expectIssuer) {
			t.Errorf("finding %s issuer %q lacks %q", id, f.Issuer, expectIssuer)
		}
	}
	notified := rec.count()

	// 5. immediate re-scan: nothing new, nobody re-notified.
	again, err := mon.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	errorCount += len(again.Errors)
	if len(again.NewFindings) != 0 {
		t.Errorf("re-scan raised %v, want none", again.NewFindings)
	}
	if rec.count() != notified {
		t.Errorf("re-scan renotified: %d -> %d", notified, rec.count())
	}

	// 6. a cert in inventory never produces a finding.
	if knownSerial != "" {
		all, err := store.List(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range all {
			if ctmonitor.NormalizeSerial(f.Serial) == knownSerial {
				t.Errorf("inventoried serial produced finding %s", f.ID)
			}
		}
	}

	// 7. acknowledged findings never renotify.
	for _, id := range report.NewFindings {
		if err := store.Acknowledge(ctx, id); err != nil {
			t.Fatalf("acknowledge %s: %v", id, err)
		}
	}
	acked, err := mon.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	errorCount += len(acked.Errors)
	if len(acked.NewFindings) != 0 || rec.count() != notified {
		t.Errorf("after acknowledge: new=%v notifications %d -> %d, want silence", acked.NewFindings, notified, rec.count())
	}

	// 8. result block for run.sh / docs/release/LIVE_RESULTS_CT_v0.12.md.
	fmt.Println("=== CT LIVE RESULT ===")
	fmt.Printf("date: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("domain: %s\n", domain)
	fmt.Printf("sources: %s\n", strings.Join(sources, ","))
	fmt.Printf("elapsed_to_first_finding: %s\n", elapsed)
	fmt.Printf("finding: id=%s issuer=%q serial=%s\n", first.ID, first.Issuer, first.Serial)
	fmt.Printf("new_findings: %d\n", len(report.NewFindings))
	fmt.Printf("notifications: %d\n", notified)
	fmt.Printf("source_errors_seen: %d\n", errorCount)
	fmt.Println("rescan_silent: true")
	fmt.Println("acknowledged_silent: true")
	fmt.Println("=== END ===")
}
