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
)

// countingFixture: 2 active (one of them expired by date), 2 revoked (one by
// timestamp, one by status only) and 1 renewed predecessor.
func countingFixture() []CertificateItem {
	now := time.Now().UTC()
	revokedAt := now.Add(-time.Hour).Format(time.RFC3339)
	mk := func(fp, status string, until time.Duration, revoked *string) CertificateItem {
		return CertificateItem{
			FingerprintSHA256:  fp,
			CAID:               "ca-1",
			ValidUntil:         now.Add(until).Format(time.RFC3339),
			RenewalStatus:      status,
			RevokedAt:          revoked,
			PQCReadiness:       "vulnerable",
			PublicKeyAlgorithm: "RSA",
		}
	}
	return []CertificateItem{
		mk("active-1", "active", 20*24*time.Hour, nil),
		mk("active-expired", "active", -24*time.Hour, nil),
		mk("revoked-ts", "revoked", 30*24*time.Hour, &revokedAt),
		mk("revoked-status-only", "revoked", -48*time.Hour, nil),
		mk("renewed-pred", "renewed", 10*24*time.Hour, nil),
	}
}

func TestActiveCertificates_Rule(t *testing.T) {
	got := activeCertificates(countingFixture())
	if len(got) != 2 || got[0].FingerprintSHA256 != "active-1" || got[1].FingerprintSHA256 != "active-expired" {
		t.Fatalf("active = %+v, want [active-1 active-expired]", got)
	}
	same := countingFixture()[:1]
	if out := activeCertificates(same); len(out) != 1 {
		t.Fatalf("all-active input changed: %d", len(out))
	}
}

func TestCountingRule_PostureAndTimelineIgnoreRevoked(t *testing.T) {
	certs := countingFixture()

	posture := computeCryptoPostureReport(certs, nil)
	if posture.TotalCerts != 2 {
		t.Errorf("posture total = %d, want 2", posture.TotalCerts)
	}
	if posture.PQCReadiness.Vulnerable != 2 {
		t.Errorf("posture vulnerable = %d, want 2 (revoked/renewed excluded)", posture.PQCReadiness.Vulnerable)
	}
	if posture.ExpiryBuckets.Expired != 1 {
		t.Errorf("posture expired = %d, want 1 (revoked expiry must not count)", posture.ExpiryBuckets.Expired)
	}

	tl := computeExpiryTimeline(certs)
	if tl.TotalCerts != 2 || tl.ByCA["ca-1"] != 2 {
		t.Errorf("timeline total=%d by_ca=%v, want 2 / ca-1:2", tl.TotalCerts, tl.ByCA)
	}

	if sunset := computeAlgorithmSunset(certs); sunset.TotalCerts != 2 {
		t.Errorf("sunset total = %d, want 2", sunset.TotalCerts)
	}

	members := 0
	for _, w := range derivePQCWaves(certs) {
		members += len(w.Members)
	}
	if members != 2 {
		t.Errorf("wave members = %d, want 2", members)
	}

	// Executive summary and PQC countdown derive from posture.
	if es := computeExecutiveSummary(context.Background(), certs, nil, nil); es.TotalCerts != 2 {
		t.Errorf("executive total = %d, want 2", es.TotalCerts)
	}
	if pc := computePQCCountdown(context.Background(), certs, nil, nil, time.Now().UTC(), nil); pc.TotalCerts != 2 {
		t.Errorf("pqc countdown total = %d, want 2", pc.TotalCerts)
	}
}

// The dashboard SQL must agree with the Go rule over the same rows.
func TestCountingRule_DashboardSummarySQL(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "rule.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE certificates (valid_until TEXT NOT NULL, management_state TEXT, revoked_at TEXT, renewal_status TEXT, owner_team TEXT, is_ca INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		`(datetime('now', '+20 day'), 'managed', NULL, 'active')`,
		`(datetime('now', '-1 day'), 'managed', NULL, 'active')`,
		`(datetime('now', '+30 day'), 'managed', datetime('now'), 'revoked')`,
		`(datetime('now', '-2 day'), 'external', NULL, 'revoked')`,
		`(datetime('now', '+10 day'), 'managed', NULL, 'renewed')`,
	} {
		if _, err := db.Exec(`INSERT INTO certificates(valid_until, management_state, revoked_at, renewal_status) VALUES ` + row); err != nil {
			t.Fatal(err)
		}
	}
	s, err := (&sqliteCertSummaryStore{db: db}).LoadSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != 2 || s.Revoked != 2 || s.Expired != 1 || s.Expiring30Days != 1 || s.Managed != 2 || s.External != 0 {
		t.Errorf("summary = %+v, want total 2 revoked 2 expired 1 expiring 1 managed 2 external 0", s)
	}
}
