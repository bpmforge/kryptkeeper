// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newFreshNotificationSilenceStore(t *testing.T) *sqliteNotificationSilenceStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "silences-fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteNotificationSilenceStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}
	return s
}

func mustSilenceID(t *testing.T) string {
	t.Helper()
	id, err := newNotificationSilenceID()
	if err != nil {
		t.Fatalf("newNotificationSilenceID: %v", err)
	}
	return id
}

// TestNotificationSilenceStore_SelfHealsSchemaOnFreshDB is the W1-06/G-33
// regression: a brand-new database with no pre-existing
// notification_silences table must still work, and EnsureSchema must be
// idempotent.
func TestNotificationSilenceStore_SelfHealsSchemaOnFreshDB(t *testing.T) {
	s := newFreshNotificationSilenceStore(t)
	ctx := context.Background()

	silenced, err := s.IsSilenced(ctx, SilenceTargetCertificate, "fp-unknown")
	if err != nil {
		t.Fatalf("IsSilenced on fresh db: %v", err)
	}
	if silenced {
		t.Fatal("expected an unknown target to not be silenced on a fresh db")
	}

	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema again: %v", err)
	}
}

// TestNotificationSilenceStore_RejectsInvalidTargetType proves the
// CHECK-constrained target_type enum is actually enforced.
func TestNotificationSilenceStore_RejectsInvalidTargetType(t *testing.T) {
	s := newFreshNotificationSilenceStore(t)
	ctx := context.Background()

	bad := NotificationSilence{
		ID: mustSilenceID(t), TargetType: "endpoint", TargetID: "x",
		CreatedBy: "alice", CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.Create(ctx, bad); err == nil {
		t.Error("expected an error for an invalid target_type, got none")
	}
}

// TestNotificationSilenceStore_IsSilencedScopedPerTarget proves silences
// don't leak across unrelated targets, and Delete removes one.
func TestNotificationSilenceStore_IsSilencedScopedPerTarget(t *testing.T) {
	s := newFreshNotificationSilenceStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	certSilence := NotificationSilence{
		ID: mustSilenceID(t), TargetType: SilenceTargetCertificate, TargetID: "fp-legacy",
		CreatedBy: "bob", CreatedAt: now,
	}
	if err := s.Create(ctx, certSilence); err != nil {
		t.Fatalf("create cert silence: %v", err)
	}
	caSilence := NotificationSilence{
		ID: mustSilenceID(t), TargetType: SilenceTargetCA, TargetID: "ca-decommissioning",
		CreatedBy: "bob", CreatedAt: now,
	}
	if err := s.Create(ctx, caSilence); err != nil {
		t.Fatalf("create ca silence: %v", err)
	}

	if silenced, err := s.IsSilenced(ctx, SilenceTargetCertificate, "fp-legacy"); err != nil || !silenced {
		t.Fatalf("expected fp-legacy to be silenced: silenced=%v err=%v", silenced, err)
	}
	if silenced, err := s.IsSilenced(ctx, SilenceTargetCertificate, "fp-other"); err != nil || silenced {
		t.Fatalf("expected fp-other to NOT be silenced: silenced=%v err=%v", silenced, err)
	}
	if silenced, err := s.IsSilenced(ctx, SilenceTargetCA, "ca-decommissioning"); err != nil || !silenced {
		t.Fatalf("expected ca-decommissioning to be silenced: silenced=%v err=%v", silenced, err)
	}
	// Same ID string, different target_type — must not cross-match.
	if silenced, err := s.IsSilenced(ctx, SilenceTargetTemplate, "fp-legacy"); err != nil || silenced {
		t.Fatalf("expected target_type to scope matches (no cross-type leak): silenced=%v err=%v", silenced, err)
	}

	if err := s.Delete(ctx, certSilence.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if silenced, err := s.IsSilenced(ctx, SilenceTargetCertificate, "fp-legacy"); err != nil || silenced {
		t.Fatalf("expected fp-legacy to no longer be silenced after delete: silenced=%v err=%v", silenced, err)
	}
	if err := s.Delete(ctx, "sil-does-not-exist"); err != errNotificationSilenceNotFound {
		t.Fatalf("expected errNotificationSilenceNotFound deleting an unknown id, got %v", err)
	}
}

// TestRenewalScheduler_SilenceSuppressesNotificationByCertCAOrTemplate is the
// W1-06 acceptance regression for "a rule can target/silence a specific
// cert/CA/template": each of the three target types independently suppresses
// the reminder for a matching certificate.
func TestRenewalScheduler_SilenceSuppressesNotificationByCertCAOrTemplate(t *testing.T) {
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)

	cases := []struct {
		name       string
		targetType string
		targetID   string
		cert       CertificateItem
	}{
		{
			name: "silenced by certificate fingerprint", targetType: SilenceTargetCertificate, targetID: "fp-silenced",
			cert: CertificateItem{FingerprintSHA256: "fp-silenced", CommonName: "a", ValidUntil: soon, OwnerEmail: "o@example.com"},
		},
		{
			name: "silenced by CA", targetType: SilenceTargetCA, targetID: "ca-silenced",
			cert: CertificateItem{FingerprintSHA256: "fp-b", CommonName: "b", ValidUntil: soon, OwnerEmail: "o@example.com", CAID: "ca-silenced"},
		},
		{
			name: "silenced by template", targetType: SilenceTargetTemplate, targetID: "tpl-silenced",
			cert: CertificateItem{FingerprintSHA256: "fp-c", CommonName: "c", ValidUntil: soon, OwnerEmail: "o@example.com", TemplateID: "tpl-silenced"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			silenceStore := newFreshNotificationSilenceStore(t)
			if err := silenceStore.Create(context.Background(), NotificationSilence{
				ID: mustSilenceID(t), TargetType: tc.targetType, TargetID: tc.targetID,
				CreatedBy: "carol", CreatedAt: time.Now().UTC().Format(time.RFC3339),
			}); err != nil {
				t.Fatalf("create silence: %v", err)
			}

			s := &RenewalScheduler{
				certProvider:  &reportCertProvider{items: []CertificateItem{tc.cert}},
				notifProvider: succeedingTestDeliveryNotificationProvider{},
				auditProvider: stubAuditProvider{},
				thresholdDays: 30, pollInterval: 24 * time.Hour,
				silenceStore: silenceStore,
			}
			s.runScan()
			if st := s.Status(); st.LastNotifications != 0 {
				t.Fatalf("expected the silenced target to suppress the notification, got %d notifications", st.LastNotifications)
			}
		})
	}
}

// TestRenewalScheduler_UnsilencedCertStillNotifies is the discriminating
// counterpart — a cert with no matching silence must still be notified,
// proving the silence check doesn't over-suppress.
func TestRenewalScheduler_UnsilencedCertStillNotifies(t *testing.T) {
	silenceStore := newFreshNotificationSilenceStore(t)
	if err := silenceStore.Create(context.Background(), NotificationSilence{
		ID: mustSilenceID(t), TargetType: SilenceTargetCertificate, TargetID: "fp-someone-elses-cert",
		CreatedBy: "carol", CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("create silence: %v", err)
	}

	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	s := &RenewalScheduler{
		certProvider: &reportCertProvider{items: []CertificateItem{
			{FingerprintSHA256: "fp-unrelated", CommonName: "u", ValidUntil: soon, OwnerEmail: "o@example.com"},
		}},
		notifProvider: succeedingTestDeliveryNotificationProvider{},
		auditProvider: stubAuditProvider{},
		thresholdDays: 30, pollInterval: 24 * time.Hour,
		silenceStore: silenceStore,
	}
	s.runScan()
	if st := s.Status(); st.LastNotifications != 1 {
		t.Fatalf("expected the unrelated cert to still be notified, got %d", st.LastNotifications)
	}
}
