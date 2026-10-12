// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/smtp"
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
