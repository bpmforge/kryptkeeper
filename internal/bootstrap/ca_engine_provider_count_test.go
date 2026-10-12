// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
)

// S-72: ActiveIssuedCertificates was only ever populated by the file CA
// provider, so ca mode showed "0 certs" on every CA card regardless of
// inventory. The count goes through the production issuance path, never a
// hand-written INSERT (the S-66 lesson), so it counts what issuance wrote.
func TestEngineCAProviderCountsIssuedCertificates(t *testing.T) {
	db := setupIntegrationDB(t)
	certProvider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	caProvider := NewEngineCAProviderWithCounts(engine, NewDBActiveCertCountByCA(db))

	// Before issuance: listed, with zero certs.
	before, err := caProvider.ListCAs(ctx, CAListQuery{})
	if err != nil {
		t.Fatalf("list CAs: %v", err)
	}
	if len(before.Items) != 1 || before.Items[0].ActiveIssuedCertificates != 0 {
		t.Fatalf("expected one CA with 0 certs before issuance, got %+v", before.Items)
	}

	csrPEM := generateTestCSRPEM(t, "count-test.example.com", "count-test.example.com")
	if _, err := certProvider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     csrPEM,
		TemplateID: "file-backed-default",
		TeamID:     "team-count-test",
	}); err != nil {
		t.Fatalf("issue cert: %v", err)
	}

	after, err := caProvider.ListCAs(ctx, CAListQuery{})
	if err != nil {
		t.Fatalf("list CAs after issuance: %v", err)
	}
	if got := after.Items[0].ActiveIssuedCertificates; got != 1 {
		t.Fatalf("expected the issued certificate to be counted, got %d", got)
	}

	item, ok, err := caProvider.GetCA(ctx, caID)
	if err != nil || !ok {
		t.Fatalf("get CA: ok=%v err=%v", ok, err)
	}
	if item.ActiveIssuedCertificates != 1 {
		t.Fatalf("GetCA count = %d, want 1", item.ActiveIssuedCertificates)
	}
}

// Without a count source (the legacy constructor) the listing still works
// and reports zero — a missing inventory must never break the CA list.
func TestEngineCAProviderWithoutCountsListsZero(t *testing.T) {
	db := setupIntegrationDB(t)
	_, engine := newIntegrationCAProvider(t, db)

	caProvider := NewEngineCAProvider(engine)
	result, err := caProvider.ListCAs(context.Background(), CAListQuery{})
	if err != nil {
		t.Fatalf("list CAs: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].ActiveIssuedCertificates != 0 {
		t.Fatalf("expected one CA with 0 certs, got %+v", result.Items)
	}
}

// The ca-mode boot path tolerates an unavailable core DB; the counter must
// degrade to no counts, not an error that breaks the listing.
func TestDBActiveCertCountByCANilDB(t *testing.T) {
	counts, err := NewDBActiveCertCountByCA(nil)(context.Background())
	if err != nil {
		t.Fatalf("nil db must not error, got %v", err)
	}
	if len(counts) != 0 {
		t.Fatalf("nil db must report no counts, got %v", counts)
	}
}
