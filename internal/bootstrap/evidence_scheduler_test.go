// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

func newTestEnabledMailer(t *testing.T) (*EvidenceMailer, *int) {
	t.Helper()
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "noreply@example.com")
	m := NewEvidenceMailerFromEnv()
	sent := 0
	m.send = func(_ string, _ smtp.Auth, _ string, _ []string, _ []byte) error {
		sent++
		return nil
	}
	return m, &sent
}

func TestEvidenceSchedulerScanSendsDueSchedule(t *testing.T) {
	store := newTestScheduleStore(t)
	if _, err := store.Create(context.Background(), EvidenceSchedule{
		Framework: "pci", Cadence: "weekly", Recipients: []string{"a@x.com"}, Enabled: true,
	}); err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	mailer, sent := newTestEnabledMailer(t)
	certs := &reportCertProvider{}

	s := &EvidenceScheduler{certProvider: certs, store: store, mailer: mailer, pollInterval: time.Hour}
	s.scan()

	if *sent != 1 {
		t.Fatalf("expected 1 send, got %d", *sent)
	}
}

func TestEvidenceSchedulerScanSkipsWhenNotLeader(t *testing.T) {
	store := newTestScheduleStore(t)
	if _, err := store.Create(context.Background(), EvidenceSchedule{
		Framework: "pci", Cadence: "weekly", Recipients: []string{"a@x.com"}, Enabled: true,
	}); err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	mailer, sent := newTestEnabledMailer(t)
	certs := &reportCertProvider{}

	db := newTestHADB(t)
	now := time.Now().UTC()
	peer := newTestHACoordinatorAt(t, db, "replica-peer", now)
	if ok, err := peer.TryAcquire(context.Background(), haLockEvidenceScheduler, 5*time.Minute); err != nil || !ok {
		t.Fatalf("setup: peer acquire ok=%v err=%v", ok, err)
	}
	self := newTestHACoordinatorAt(t, db, "replica-self", now)

	s := &EvidenceScheduler{certProvider: certs, store: store, mailer: mailer, pollInterval: time.Hour, haCoordinator: self}
	s.scan()

	if *sent != 0 {
		t.Fatalf("expected non-leader scan to skip sending, got %d send(s)", *sent)
	}
}

func TestEvidenceSchedulerScanRunsWhenLeader(t *testing.T) {
	store := newTestScheduleStore(t)
	if _, err := store.Create(context.Background(), EvidenceSchedule{
		Framework: "pci", Cadence: "weekly", Recipients: []string{"a@x.com"}, Enabled: true,
	}); err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	mailer, sent := newTestEnabledMailer(t)
	certs := &reportCertProvider{}

	db := newTestHADB(t)
	self := newTestHACoordinatorAt(t, db, "replica-self", time.Now().UTC())

	s := &EvidenceScheduler{certProvider: certs, store: store, mailer: mailer, pollInterval: time.Hour, haCoordinator: self}
	s.scan()

	if *sent != 1 {
		t.Fatalf("expected leader scan to send, got %d", *sent)
	}
}

type retryHarness struct {
	s      *EvidenceScheduler
	store  *dbEvidenceScheduleStore
	id     string
	sends  int
	sleeps []time.Duration
	alerts []string
	failN  int // fail the first failN sends (-1 = always)
}

func newRetryHarness(t *testing.T, failN int) *retryHarness {
	t.Helper()
	store := newTestScheduleStore(t)
	sc, err := store.Create(context.Background(), EvidenceSchedule{
		Framework: "pci", Cadence: "weekly", Recipients: []string{"a@x.com"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	mailer, _ := newTestEnabledMailer(t)
	h := &retryHarness{store: store, id: sc.ID, failN: failN}
	h.s = &EvidenceScheduler{
		certProvider: &reportCertProvider{}, store: store, mailer: mailer,
		pollInterval: time.Hour, retryDelay: 7 * time.Second, stop: make(chan struct{}),
		send: func([]string, string, string, []byte, string) error {
			h.sends++
			if h.failN < 0 || h.sends <= h.failN {
				return errors.New("smtp down")
			}
			return nil
		},
		sleep: func(_ context.Context, d time.Duration) bool { h.sleeps = append(h.sleeps, d); return true },
		alerts: func(_ context.Context, event, detail string) {
			h.alerts = append(h.alerts, event+"|"+detail)
		},
	}
	return h
}

func (h *retryHarness) lastSent(t *testing.T) string {
	t.Helper()
	list, err := h.store.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	return list[0].LastSentAt
}

func TestEvidenceSchedulerRetriesThenAlerts(t *testing.T) {
	buf := captureLog(t)
	h := newRetryHarness(t, -1)
	h.s.scan()

	if h.sends != 3 {
		t.Fatalf("sends=%d want 3", h.sends)
	}
	if len(h.sleeps) != 2 || h.sleeps[0] != 7*time.Second || h.sleeps[1] != 7*time.Second {
		t.Fatalf("sleeps=%v want 2x7s", h.sleeps)
	}
	if h.lastSent(t) != "" {
		t.Fatalf("MarkSent called on failure")
	}
	if len(h.alerts) != 1 || !strings.HasPrefix(h.alerts[0], AlertEventEvidenceDeliveryFailed+"|schedule="+h.id) {
		t.Fatalf("alerts=%v", h.alerts)
	}
	if n := strings.Count(buf.String(), "evidence scheduler: send "+h.id+" failed"); n != 3 {
		t.Fatalf("failure log lines=%d want 3\n%s", n, buf.String())
	}
}

func TestEvidenceSchedulerRetrySucceedsOnSecondAttempt(t *testing.T) {
	h := newRetryHarness(t, 1)
	h.s.scan()
	if h.sends != 2 || len(h.alerts) != 0 || h.lastSent(t) == "" {
		t.Fatalf("sends=%d alerts=%v lastSent=%q", h.sends, h.alerts, h.lastSent(t))
	}
}

func TestEvidenceSchedulerRecoversOnNextPoll(t *testing.T) {
	h := newRetryHarness(t, 3)
	h.s.scan()
	if h.lastSent(t) != "" || len(h.alerts) != 1 {
		t.Fatalf("first scan: lastSent=%q alerts=%v", h.lastSent(t), h.alerts)
	}
	h.s.scan() // mailer has recovered (only first 3 sends fail)
	if h.sends != 4 || h.lastSent(t) == "" || len(h.alerts) != 1 {
		t.Fatalf("second scan: sends=%d lastSent=%q alerts=%v", h.sends, h.lastSent(t), h.alerts)
	}
}

func TestEvidenceSchedulerInterruptedSleepSkipsAlert(t *testing.T) {
	h := newRetryHarness(t, -1)
	h.s.sleep = func(context.Context, time.Duration) bool { return false }
	h.s.scan()
	if h.sends != 1 || len(h.alerts) != 0 {
		t.Fatalf("sends=%d alerts=%v", h.sends, h.alerts)
	}
}

func TestEvidenceSchedulerDefaultSinkWritesAudit(t *testing.T) {
	h := newRetryHarness(t, -1)
	h.s.alerts = nil
	aud := &memAuditProvider{}
	h.s.WithAudit(aud)
	h.s.scan()

	if len(aud.entries) != 1 {
		t.Fatalf("audit entries=%d want 1", len(aud.entries))
	}
	e := aud.entries[0]
	if e.Action != "evidence.delivery_failed" || e.ResourceID != h.id || e.ResourceType != "evidence_schedule" || e.Outcome != AuditOutcomeFailure {
		t.Fatalf("entry=%+v", e)
	}
	if strings.Contains(e.ChangeSummary, "@") {
		t.Fatalf("detail leaks address: %q", e.ChangeSummary)
	}
}

func TestEvidenceRetryDelayFromEnv(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 30 * time.Second, "2": 2 * time.Second, "0": 30 * time.Second, "x": 30 * time.Second} {
		t.Setenv("EVIDENCE_RETRY_DELAY_SECONDS", in)
		if got := evidenceRetryDelayFromEnv(); got != want {
			t.Errorf("%q => %v want %v", in, got, want)
		}
	}
}
