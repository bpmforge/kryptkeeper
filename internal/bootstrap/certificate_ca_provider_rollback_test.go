// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
)

// A failed persist must leave memory matching the database, not ahead of it
// until the next restart reverts the change silently.
func TestFailedPersistLeavesEstateAndOwnershipUnchanged(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	res, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, CSRPEM: generateTestCSRPEM(t, "rb.example.com", "rb.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	fp := res.FingerprintSHA256
	before, _, _ := provider.GetCertificate(ctx, fp)

	if _, err := db.Exec(`DROP TABLE certificates`); err != nil {
		t.Fatal(err)
	}

	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{ManagementState: "external", RenewalStatus: "reissue_required", RenewalMethod: "manual"}); err == nil {
		t.Fatal("UpdateEstate must fail when the row cannot be written")
	}
	if _, err := provider.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{OwnerEmail: "x@example.com", OwnerTeam: "t", ServiceName: "svc"}); err == nil {
		t.Fatal("UpdateOwnership must fail when the row cannot be written")
	}
	// A rejected value mid-request must not leave earlier fields applied.
	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{ManagementState: "external", Origin: "bogus"}); err == nil {
		t.Fatal("invalid origin must be rejected")
	}

	after, _, _ := provider.GetCertificate(ctx, fp)
	if after.ManagementState != before.ManagementState || after.RenewalStatus != before.RenewalStatus ||
		after.RenewalMethod != before.RenewalMethod || after.OwnerEmail != before.OwnerEmail ||
		after.OwnerTeam != before.OwnerTeam || after.ServiceName != before.ServiceName || after.Origin != before.Origin {
		t.Fatalf("memory diverged from the database after failed writes:\nbefore=%+v\nafter=%+v", before, after)
	}
}
