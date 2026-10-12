// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

// Certs with an empty or unparseable ValidUntil used to vanish from the
// expiry buckets, so a malformed record read as "nothing to worry about".
func TestExpiryReports_CountUnparseableValidUntilAsUnknown(t *testing.T) {
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	certs := []CertificateItem{
		{FingerprintSHA256: "ok", ValidUntil: soon, CAID: "ca1"},
		{FingerprintSHA256: "garbled", ValidUntil: "not-a-date", CAID: "ca1"},
		{FingerprintSHA256: "empty", ValidUntil: ""},
	}

	posture := computeCryptoPostureReport(certs, nil)
	if posture.ExpiryBuckets.Unknown != 2 {
		t.Fatalf("posture unknown=%d, want 2", posture.ExpiryBuckets.Unknown)
	}
	if posture.ExpiryBuckets.Expiring47d != 1 {
		t.Fatalf("posture expiring_47d=%d, want 1", posture.ExpiryBuckets.Expiring47d)
	}

	exec := computeExecutiveSummary(context.Background(), certs, nil, nil)
	if exec.ExpiryUnknown != 2 {
		t.Fatalf("executive summary expiry_unknown=%d, want 2", exec.ExpiryUnknown)
	}

	tl := computeExpiryTimeline(certs)
	if tl.UnknownExpiry != 2 {
		t.Fatalf("timeline unknown_expiry=%d, want 2", tl.UnknownExpiry)
	}
	counted := 0
	for _, b := range tl.Buckets {
		counted += b.Count
	}
	if counted != 1 {
		t.Fatalf("timeline bucketed %d certs, want only the parseable one", counted)
	}
}
