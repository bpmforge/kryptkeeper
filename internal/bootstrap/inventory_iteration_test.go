// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// These tests pin H2/H3/M1/M3: ListCertificates clamps to one HTTP page of
// 100, so every internal caller that wants the whole inventory must see all
// of it. 250 > 2 pages, and the CreatedAt values are deliberately tied across
// page boundaries (S-62).
const inventoryFixtureSize = 250

func seededInventoryProvider(t *testing.T) *caCertificateProvider {
	t.Helper()
	p := NewCACertificateProvider(nil, nil, nil, false).(*caCertificateProvider)
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	for i := 0; i < inventoryFixtureSize; i++ {
		fp := fmt.Sprintf("fp-%03d", i)
		p.mu.Lock()
		p.addLocked(fp, &storedCert{item: CertificateItem{
			FingerprintSHA256: fp,
			SerialNumber:      fmt.Sprintf("%d", i+1),
			CommonName:        fmt.Sprintf("host-%03d.example.com", i),
			CAID:              "ca-A",
			CreatedAt:         fmt.Sprintf("2026-08-19T10:00:%02dZ", i/7),
			ValidFrom:         "2026-08-19T10:00:00Z",
			ValidUntil:        soon,
			RenewalStatus:     "active",
			PQCReadiness:      "vulnerable",
			OwnerEmail:        "owner@example.com",
		}})
		p.mu.Unlock()
	}
	return p
}

func TestForEachCertificate_SeesEverythingInListOrder(t *testing.T) {
	p := seededInventoryProvider(t)

	var got []string
	if err := ForEachCertificate(context.Background(), p, CertificateListQuery{}, func(c CertificateItem) error {
		got = append(got, c.FingerprintSHA256)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != inventoryFixtureSize {
		t.Fatalf("ForEachCertificate saw %d, want %d", len(got), inventoryFixtureSize)
	}

	// Paged HTTP-style walk must return the identical sequence: same total
	// order, nothing skipped or repeated across the tied-second boundaries.
	var paged []string
	for offset := 0; ; {
		page, err := p.ListCertificates(context.Background(), CertificateListQuery{Limit: 100, Offset: offset})
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != inventoryFixtureSize {
			t.Fatalf("Total=%d", page.Total)
		}
		for _, c := range page.Items {
			paged = append(paged, c.FingerprintSHA256)
		}
		offset += len(page.Items)
		if len(page.Items) == 0 || offset >= page.Total {
			break
		}
	}
	if !slices.Equal(got, paged) {
		t.Fatalf("paged order differs from full-pass order")
	}
}

func TestListCertificates_HTTPPageStaysCapped(t *testing.T) {
	p := seededInventoryProvider(t)
	page, err := p.ListCertificates(context.Background(), CertificateListQuery{Limit: 50000})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 100 || page.Total != inventoryFixtureSize {
		t.Fatalf("items=%d total=%d, want the HTTP contract of 100 of %d", len(page.Items), page.Total, inventoryFixtureSize)
	}
}

func TestListCertificates_FilteredPagesStable(t *testing.T) {
	p := seededInventoryProvider(t)
	q := CertificateListQuery{CAID: "ca-A", Q: "HOST-1", Limit: 10}
	var seen []string
	for offset := 0; ; {
		q.Offset = offset
		page, err := p.ListCertificates(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range page.Items {
			seen = append(seen, c.FingerprintSHA256)
		}
		offset += len(page.Items)
		if len(page.Items) == 0 || offset >= page.Total {
			break
		}
	}
	// host-100..host-199 (100) plus host-1xx only: "host-1" matches 100-199.
	if len(seen) != 100 {
		t.Fatalf("filtered walk saw %d, want 100", len(seen))
	}
	if len(slices.Compact(slices.Clone(seen))) != len(seen) {
		t.Fatal("filtered walk repeated a certificate")
	}
}

func TestForEachCertificate_CallbackMayReenterProvider(t *testing.T) {
	p := seededInventoryProvider(t)
	n := 0
	err := p.ForEachCertificate(context.Background(), CertificateListQuery{}, func(c CertificateItem) error {
		// Would deadlock if a read lock were held across fn and a writer queued.
		if _, err := p.UpdateOwnership(context.Background(), c.FingerprintSHA256, CertificateOwnershipRequest{OwnerEmail: "new@example.com"}); err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil || n != inventoryFixtureSize {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestRenewalScheduler_SeesAllCandidates(t *testing.T) {
	p := seededInventoryProvider(t)
	t.Setenv("RENEWAL_THRESHOLD_DAYS", "30")
	s := NewRenewalSchedulerFromEnv(p, nil, stubAuditProvider{})
	s.haCoordinator = nil
	s.targetStore = nil
	s.runScan()
	if got := s.Status().LastCandidates; got != inventoryFixtureSize {
		t.Fatalf("renewal scheduler saw %d candidates, want %d", got, inventoryFixtureSize)
	}
}

func TestReportVisibleCertificates_SeesAll(t *testing.T) {
	p := seededInventoryProvider(t)
	got, err := reportVisibleCertificates(context.Background(), AuthPrincipal{ID: "bootstrap", Role: "pki-admin"}, p, reportCertificateCeiling)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != inventoryFixtureSize {
		t.Fatalf("report saw %d, want %d", len(got), inventoryFixtureSize)
	}
}

func TestExecutiveSummary_TotalCertsIsRealCount(t *testing.T) {
	p := seededInventoryProvider(t)
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerExecutiveSummaryHandler(mux, auth, p, &reportCAProvider{}, nil, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/executive-summary", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			TotalCerts int `json:"total_certs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.TotalCerts != inventoryFixtureSize {
		t.Fatalf("total_certs=%d, want %d", resp.Data.TotalCerts, inventoryFixtureSize)
	}
}

func TestBulkRevoke_ReachesEveryCertificateOfTheCA(t *testing.T) {
	p := seededInventoryProvider(t)
	a := PendingAction{ActionType: "bulk_revoke", Params: json.RawMessage(`{"ca_id":"ca-A","reason_code":4}`)}
	res, err := executePendingAction(context.Background(), p, a)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(res, &m)
	if m["revoked"].(float64) != inventoryFixtureSize {
		t.Fatalf("bulk revoke result %v, want %d revoked", m, inventoryFixtureSize)
	}
	if _, truncated := m["truncated_at"]; truncated {
		t.Fatalf("250 < maxBulkRevoke must not report truncation: %v", m)
	}
	revoked, _ := p.ListCertificates(context.Background(), CertificateListQuery{Status: "revoked", Limit: 1})
	if revoked.Total != inventoryFixtureSize {
		t.Fatalf("revoked total=%d", revoked.Total)
	}
}

// flaggingProvider records reissue_required flags and still runs the real
// provider's UpdateEstate, so its validation is exercised.
type flaggingProvider struct {
	*caCertificateProvider
	flagged map[string]bool
}

func (f *flaggingProvider) UpdateEstate(_ context.Context, fp string, u EstateUpdate) (CertificateItem, error) {
	item, err := f.caCertificateProvider.UpdateEstate(context.Background(), fp, u)
	if err == nil && u.RenewalStatus == "reissue_required" {
		f.flagged[fp] = true
	}
	return item, err
}

type countingReissuer struct{ n int }

func (r *countingReissuer) ReissueCertificate(context.Context, string) error { r.n++; return nil }

func TestCAKeyCompromise_AffectsEveryCertificate(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("burned", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: "ca-A", KeyID: "burned", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	certs := &flaggingProvider{caCertificateProvider: seededInventoryProvider(t), flagged: map[string]bool{}}
	reissuer := &countingReissuer{}
	m, _ := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(&recordingRotator{}, caStore),
		WithLifecycleReissue(certs, reissuer))
	if err := m.SetPolicy("burned", "alice", nil, 0); err != nil {
		t.Fatal(err)
	}
	report, err := m.MarkCompromised(context.Background(), "burned")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Affected) != inventoryFixtureSize || len(certs.flagged) != inventoryFixtureSize || reissuer.n != inventoryFixtureSize {
		t.Fatalf("affected=%d flagged=%d reissued=%d, want %d each (errors: %v)",
			len(report.Affected), len(certs.flagged), reissuer.n, inventoryFixtureSize, report.Errors)
	}
}

func TestAnomalyAndSLOSweeps_SeeEverything(t *testing.T) {
	p := seededInventoryProvider(t)
	events, err := (&AnomalyScheduler{certProvider: p}).issuanceEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != inventoryFixtureSize {
		t.Fatalf("anomaly events=%d, want %d", len(events), inventoryFixtureSize)
	}
}

func TestCBOM_IncludesEveryCertificate(t *testing.T) {
	p := seededInventoryProvider(t)
	doc, err := BuildCBOM(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != inventoryFixtureSize {
		t.Fatalf("CBOM components=%d, want %d", len(doc.Components), inventoryFixtureSize)
	}
}

// csrPEMWithKey builds a CSR over a caller-supplied key so two issuances can
// share a public key.
func csrPEMWithKey(t *testing.T, key *ecdsa.PrivateKey, cn string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestKeyReuse_DetectedIncrementally(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	p := provider.(*caCertificateProvider)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	shared, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issue := func(key *ecdsa.PrivateKey, cn string) CertificateItem {
		res, err := p.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "", CSRPEM: csrPEMWithKey(t, key, cn)})
		if err != nil {
			t.Fatal(err)
		}
		return res.CertificateItem
	}
	flagged := func(fp string) bool {
		d, _, _ := p.GetCertificate(ctx, fp)
		return slices.Contains(d.RiskFlags, "KEY_REUSE")
	}

	a := issue(shared, "a.example.com")
	o := issue(other, "o.example.com")
	if flagged(a.FingerprintSHA256) || flagged(o.FingerprintSHA256) {
		t.Fatal("no key shared yet; nothing may be flagged")
	}
	b := issue(shared, "b.example.com")
	if !flagged(a.FingerprintSHA256) || !flagged(b.FingerprintSHA256) {
		t.Fatal("both holders of the shared key must be flagged once the second is issued")
	}
	if flagged(o.FingerprintSHA256) {
		t.Fatal("unrelated certificate flagged")
	}
	if d, _, _ := p.GetCertificate(ctx, a.FingerprintSHA256); d.RiskScore < 20 {
		t.Fatalf("KEY_REUSE must add risk score, got %d", d.RiskScore)
	}
}

func TestActiveCertCounts_TrackIssueRevokeRenew(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	p := provider.(*caCertificateProvider)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	var fps []string
	for i := 0; i < 3; i++ {
		res, err := p.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, CSRPEM: generateTestCSRPEM(t, fmt.Sprintf("c%d.example.com", i))})
		if err != nil {
			t.Fatal(err)
		}
		fps = append(fps, res.FingerprintSHA256)
	}
	count := func() int {
		m, err := p.ActiveCertCountsByCA(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return m[caID]
	}
	if got := count(); got != 3 {
		t.Fatalf("after 3 issues: %d, want 3", got)
	}
	if _, err := p.RevokeCertificate(ctx, fps[0], CertificateRevokeRequest{ReasonCode: 1}); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 2 {
		t.Fatalf("after revoke: %d, want 2", got)
	}
	// Renewal retires the predecessor and adds the successor: net zero.
	if _, err := p.RenewCertificate(ctx, fps[1], CertificateRenewRequest{CSRPEM: generateTestCSRPEM(t, "c1.example.com")}); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 2 {
		t.Fatalf("after renew: %d, want 2", got)
	}
	// An expired-status cert still needs replacing, so it stays active
	// (certificate_active.go); only revoked and superseded ones leave the count.
	if _, err := p.UpdateEstate(ctx, fps[2], EstateUpdate{RenewalStatus: "expired"}); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 2 {
		t.Fatalf("after expiring one: %d, want 2", got)
	}
	if _, err := p.UpdateEstate(ctx, fps[2], EstateUpdate{RenewalStatus: "revoked"}); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 1 {
		t.Fatalf("after status-revoking one: %d, want 1", got)
	}
}

func TestSilenceMemo_AsksOncePerTarget(t *testing.T) {
	store := &countingSilenceStore{}
	ctx := withSilenceMemo(context.Background())
	for i := 0; i < 50; i++ {
		if _, err := memoizedIsSilenced(ctx, store, SilenceTargetCA, "ca-A"); err != nil {
			t.Fatal(err)
		}
	}
	if store.calls != 1 {
		t.Fatalf("store consulted %d times for one target in one tick, want 1", store.calls)
	}
	// No memo on the context: every call goes to the store.
	_, _ = memoizedIsSilenced(context.Background(), store, SilenceTargetCA, "ca-A")
	_, _ = memoizedIsSilenced(context.Background(), store, SilenceTargetCA, "ca-A")
	if store.calls != 3 {
		t.Fatalf("calls=%d, want 3", store.calls)
	}
}

type countingSilenceStore struct {
	NotificationSilenceStore
	calls int
}

func (s *countingSilenceStore) IsSilenced(context.Context, string, string) (bool, error) {
	s.calls++
	return false, nil
}
