// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"net/smtp"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// --- mailer ---

func TestEvidenceMailer_BuildMIMEHasAttachment(t *testing.T) {
	msg := buildEvidenceMIME("from@x.com", []string{"a@x.com", "b@x.com"},
		"Subject Line", "body text", []byte("%PDF-1.4 fake"), "pack.pdf")
	s := string(msg)
	for _, want := range []string{
		"To: a@x.com, b@x.com",
		"multipart/mixed",
		"Content-Type: application/pdf",
		"Content-Transfer-Encoding: base64",
		`filename="pack.pdf"`,
		"body text",
	} {
		if !bytes.Contains(msg, []byte(want)) {
			t.Errorf("MIME missing %q\n---\n%s", want, s)
		}
	}
}

func TestEvidenceMailer_SendCapturesRecipients(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "noreply@example.com")
	m := NewEvidenceMailerFromEnv()
	if !m.Enabled() {
		t.Fatal("expected mailer enabled")
	}
	var gotTo []string
	var gotMsg []byte
	m.send = func(_ string, _ smtp.Auth, _ string, to []string, msg []byte) error {
		gotTo = to
		gotMsg = msg
		return nil
	}
	if err := m.Send([]string{"x@y.com"}, "subj", "body", []byte("%PDF-"), "p.pdf"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(gotTo) != 1 || gotTo[0] != "x@y.com" {
		t.Errorf("recipients wrong: %v", gotTo)
	}
	if !bytes.Contains(gotMsg, []byte("p.pdf")) {
		t.Error("message missing attachment filename")
	}
}

func TestEvidenceMailer_DisabledFailsClearly(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_FROM", "")
	m := NewEvidenceMailerFromEnv()
	if m.Enabled() {
		t.Fatal("expected disabled")
	}
	if err := m.Send([]string{"x@y.com"}, "s", "b", nil, "f.pdf"); err == nil {
		t.Fatal("expected error when SMTP not configured")
	}
}

// --- schedule store ---

func newTestScheduleStore(t *testing.T) *dbEvidenceScheduleStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sched.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &dbEvidenceScheduleStore{db: db, ph: sqlitePlaceholder}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return s
}

func TestEvidenceScheduleStore_CRUD(t *testing.T) {
	s := newTestScheduleStore(t)
	ctx := context.Background()
	created, err := s.Create(ctx, EvidenceSchedule{
		Framework: "pci", Cadence: "monthly", Recipients: []string{"a@x.com", "b@x.com"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected generated id")
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	if len(list[0].Recipients) != 2 || !list[0].Enabled {
		t.Errorf("round-trip wrong: %+v", list[0])
	}
	if err := s.MarkSent(ctx, created.ID, "2026-06-17T00:00:00Z"); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	list, _ = s.List(ctx)
	if list[0].LastSentAt != "2026-06-17T00:00:00Z" {
		t.Errorf("last_sent_at not persisted: %q", list[0].LastSentAt)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if list, _ := s.List(ctx); len(list) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(list))
	}
}

func TestEvidenceSchedule_IsDue(t *testing.T) {
	now := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	// Never sent → due.
	if !(EvidenceSchedule{Enabled: true, Recipients: []string{"x"}, Cadence: "weekly"}).isDue(now) {
		t.Error("never-sent schedule should be due")
	}
	// Sent 8 days ago, weekly → due.
	old := now.Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	if !(EvidenceSchedule{Enabled: true, Recipients: []string{"x"}, Cadence: "weekly", LastSentAt: old}).isDue(now) {
		t.Error("weekly schedule sent 8d ago should be due")
	}
	// Sent 2 days ago, weekly → not due.
	recent := now.Add(-2 * 24 * time.Hour).Format(time.RFC3339)
	if (EvidenceSchedule{Enabled: true, Recipients: []string{"x"}, Cadence: "weekly", LastSentAt: recent}).isDue(now) {
		t.Error("weekly schedule sent 2d ago should NOT be due")
	}
	// Disabled → not due.
	if (EvidenceSchedule{Enabled: false, Recipients: []string{"x"}}).isDue(now) {
		t.Error("disabled schedule should not be due")
	}
}
