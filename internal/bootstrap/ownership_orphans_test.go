// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

type fakeOrphanChannel struct {
	mu     sync.Mutex
	events []delivery.Event
}

func (c *fakeOrphanChannel) Name() string { return "fake" }
func (c *fakeOrphanChannel) Send(_ context.Context, e delivery.Event) error {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
	return nil
}

func orphanSeedCert(p *caCertificateProvider, fp, owner string, revoked bool) {
	status := "active"
	if revoked {
		status = "revoked"
	}
	p.mu.Lock()
	p.addLocked(fp, &storedCert{item: CertificateItem{
		FingerprintSHA256: fp, SerialNumber: fp, CommonName: fp + ".example.com", CAID: "ca-A",
		CreatedAt: "2026-08-19T10:00:00Z", ValidUntil: "2030-01-01T00:00:00Z",
		RenewalStatus: status, OwnerEmail: owner, OwnerTeam: "old-team", ServiceName: "svc-" + fp,
	}})
	p.mu.Unlock()
}

func orphanUsers() *fileUserProvider {
	return &fileUserProvider{users: []UserRecord{
		{ID: "u-active", Email: "alive@example.com", Role: "pki-admin", Status: "active"},
		{ID: "u-deact", Email: "Gone@Example.com", Role: "pki-operator", Status: "deactivated"},
		{ID: "u-inact", Email: "idle@example.com", Role: "pki-viewer", Status: "inactive"},
		{ID: "u-empty", Email: "empty@example.com", Role: "pki-viewer", Status: "deactivated"},
	}}
}

func orphanCerts() *caCertificateProvider {
	p := NewCACertificateProvider(nil, nil, nil, false).(*caCertificateProvider)
	orphanSeedCert(p, "fp-1", "gone@example.com ", false) // case/whitespace differ
	orphanSeedCert(p, "fp-2", "GONE@example.com", false)
	orphanSeedCert(p, "fp-3", "gone@example.com", true) // revoked: ignored
	orphanSeedCert(p, "fp-4", "idle@example.com", false)
	orphanSeedCert(p, "fp-5", "alive@example.com", false)
	return p
}

func TestFindOrphanedOwners(t *testing.T) {
	got, err := findOrphanedOwners(context.Background(), orphanUsers(), orphanCerts())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"gone@example.com": 2, "idle@example.com": 1}
	if len(got) != len(want) {
		t.Fatalf("orphans = %+v, want %v", got, want)
	}
	for _, o := range got {
		if want[o.OwnerEmail] != o.CertCount {
			t.Errorf("%s: count %d, want %d", o.OwnerEmail, o.CertCount, want[o.OwnerEmail])
		}
		if o.UserID == "" {
			t.Errorf("%s: missing user id", o.OwnerEmail)
		}
	}
}

func TestOrphanScannerAlertsWithin15Minutes(t *testing.T) {
	if defaultOrphanSweep > 5*time.Minute {
		t.Fatalf("defaultOrphanSweep = %s, must be <= 5m", defaultOrphanSweep)
	}
	users := &fileUserProvider{users: []UserRecord{{ID: "u1", Email: "gone@example.com", Role: "pki-viewer", Status: "active"}}}
	certs := orphanCerts()
	audit := &recordingAuditProvider{}
	ch := &fakeOrphanChannel{}
	s := NewOrphanScannerFromEnv(certs, users, audit, ch, "ops@example.com")
	s.haCoordinator = nil

	t0 := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	s.tick(context.Background(), t0)
	if audit.count("ownership.orphan_detected") != 0 || len(ch.events) != 0 {
		t.Fatal("active owner must not alert")
	}
	if err := users.DeactivateUser(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), t0.Add(defaultOrphanSweep))
	if audit.count("ownership.orphan_detected") != 1 || len(ch.events) != 1 {
		t.Fatalf("audit=%d events=%d, want 1/1", audit.count("ownership.orphan_detected"), len(ch.events))
	}
	if !strings.HasPrefix(ch.events[0].Subject, "ownership.orphan: ") || ch.events[0].Target != "ops@example.com" {
		t.Fatalf("event = %+v", ch.events[0])
	}
	s.tick(context.Background(), t0.Add(2*defaultOrphanSweep))
	if audit.count("ownership.orphan_detected") != 1 || len(ch.events) != 1 {
		t.Fatal("latch failed: second tick alerted again")
	}
}

func TestOrphanScannerRearmsAfterCleared(t *testing.T) {
	users := orphanUsers()
	certs := orphanCerts()
	audit := &recordingAuditProvider{}
	s := NewOrphanScannerFromEnv(certs, users, audit, nil, "")
	s.haCoordinator = nil
	now := time.Now()
	s.tick(context.Background(), now)
	first := audit.count("ownership.orphan_detected")
	if first != 2 {
		t.Fatalf("first sweep rows = %d, want 2", first)
	}
	for _, fp := range []string{"fp-4"} {
		if _, err := certs.UpdateOwnership(context.Background(), fp, CertificateOwnershipRequest{OwnerTeam: "t", OwnerEmail: "alive@example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	s.tick(context.Background(), now.Add(time.Minute)) // idle@ cleared, latch drops it
	if _, err := certs.UpdateOwnership(context.Background(), "fp-5", CertificateOwnershipRequest{OwnerTeam: "t", OwnerEmail: "idle@example.com"}); err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), now.Add(2*time.Minute))
	if got := audit.count("ownership.orphan_detected"); got != first+1 {
		t.Fatalf("re-orphan rows = %d, want %d", got, first+1)
	}
}

type failingUsers struct{ UserProvider }

func (failingUsers) ListUsers(context.Context) ([]UserRecord, error) {
	return nil, context.DeadlineExceeded
}

func TestOrphanScannerSoftFailsOnUserOutage(t *testing.T) {
	audit := &recordingAuditProvider{}
	s := NewOrphanScannerFromEnv(orphanCerts(), failingUsers{}, audit, nil, "")
	s.haCoordinator = nil
	s.tick(context.Background(), time.Now()) // must not panic
	if audit.count("ownership.orphan_detected") != 0 {
		t.Fatal("alerted despite user outage")
	}
}

func TestScimDeactivationRaisesOrphan(t *testing.T) {
	users := &fileUserProvider{users: []UserRecord{{ID: "user-1", Email: "gone@example.com", Role: "pki-operator", Status: "active"}}}
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, newTestSCIMAuthenticator(), users, stubAuditProvider{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPatch, "/scim/v2/Users/user-1", `{"Operations":[{"op":"replace","path":"active","value":false}]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("scim deactivate: %d %s", rec.Code, rec.Body.String())
	}
	audit := &recordingAuditProvider{}
	ch := &fakeOrphanChannel{}
	s := NewOrphanScannerFromEnv(orphanCerts(), users, audit, ch, "t")
	s.haCoordinator = nil
	s.tick(context.Background(), time.Now())
	if audit.count("ownership.orphan_detected") != 1 || len(ch.events) != 1 {
		t.Fatalf("scim deactivation not detected: audit=%d events=%d", audit.count("ownership.orphan_detected"), len(ch.events))
	}
}

func orphanEnv(t *testing.T) (*http.ServeMux, *caCertificateProvider, *recordingAuditProvider) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	certs := orphanCerts()
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	RegisterOwnershipOrphanHandlers(mux, NewAuthenticatorFromEnv(), certs, orphanUsers(), audit)
	return mux, certs, audit
}

func orphanCall(mux *http.ServeMux, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestBulkReassign(t *testing.T) {
	mux, certs, audit := orphanEnv(t)

	rec := orphanCall(mux, http.MethodGet, "/api/v1/ownership/orphans", "test-token", "")
	var list struct {
		Data []orphanedOwner `json:"data"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Data) != 2 {
		t.Fatalf("orphans: %d %s", rec.Code, rec.Body.String())
	}

	if rec := orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", "test-token", `{"from_email":"alive@example.com","to_team":"x"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("active owner: %d, want 400", rec.Code)
	}
	if rec := orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", "test-token", `{"from_email":"gone@example.com"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing to_team: %d, want 400", rec.Code)
	}
	if rec := orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", "bad", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
	if rec := orphanCall(mux, http.MethodGet, "/api/v1/ownership/reassign", "test-token", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET reassign: %d", rec.Code)
	}

	rec = orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", "test-token", `{"from_email":"GONE@example.com","to_team":"platform","to_email":"new@example.com"}`)
	var out struct {
		Data struct {
			Reassigned int `json:"reassigned"`
		} `json:"data"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Data.Reassigned != 2 {
		t.Fatalf("reassign: %d %s", rec.Code, rec.Body.String())
	}
	for _, fp := range []string{"fp-1", "fp-2"} {
		it, _, _ := certs.GetCertificate(context.Background(), fp)
		if it.OwnerTeam != "platform" || it.OwnerEmail != "new@example.com" || it.ServiceName != "svc-"+fp {
			t.Errorf("%s: %+v", fp, it.CertificateItem)
		}
	}
	if audit.count("certificate.ownership_update") != 2 || audit.count("ownership.reassign") < 1 {
		t.Fatalf("audit rows: per-cert=%d summary=%d", audit.count("certificate.ownership_update"), audit.count("ownership.reassign"))
	}
	// Re-running finds nothing left to move.
	if rec := orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", "test-token", `{"from_email":"gone@example.com","to_team":"platform"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("repeat reassign: %d, want 400", rec.Code)
	}
}

// Tenant isolation: each tenant sees and moves only the orphans whose
// certificates its CAs issued; a foreign tenant's orphan reads as "none".
func TestOrphansAreTenantScoped(t *testing.T) {
	setupTenantWritePathTest(t)
	auth := NewAuthenticatorFromEnv()
	acme := cmdbAPIKey(t, auth, "pki-admin", "acme")
	globex := cmdbAPIKey(t, auth, "pki-admin", "globex")
	viewer := cmdbAPIKey(t, auth, "viewer", "acme")
	certs := NewFileCertificateProviderFromEnv()
	ctx := context.Background()
	for fp, owner := range map[string]string{"fp-acme-cert": "gone@example.com", "fp-globex-cert": "gone@example.com"} {
		if _, err := certs.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{OwnerTeam: "old", OwnerEmail: owner}); err != nil {
			t.Fatal(err)
		}
	}
	users := &fileUserProvider{users: []UserRecord{{ID: "u1", Email: "gone@example.com", Status: "deactivated"}}}
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	RegisterOwnershipOrphanHandlers(mux, auth, certs, users, audit)

	count := func(token string) int {
		rec := orphanCall(mux, http.MethodGet, "/api/v1/ownership/orphans", token, "")
		var l struct {
			Data []orphanedOwner `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &l)
		if rec.Code != http.StatusOK {
			t.Fatalf("list: %d", rec.Code)
		}
		if len(l.Data) == 0 {
			return 0
		}
		return l.Data[0].CertCount
	}
	if got := count(acme); got != 1 {
		t.Fatalf("acme sees %d certs, want 1 (its own)", got)
	}
	if got := count("root-token"); got != 2 {
		t.Fatalf("super-admin sees %d, want 2", got)
	}
	if rec := orphanCall(mux, http.MethodGet, "/api/v1/ownership/orphans", viewer, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer list: %d, want 403", rec.Code)
	}
	if rec := orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", viewer, `{"from_email":"gone@example.com","to_team":"x"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer reassign: %d, want 403", rec.Code)
	}

	rec := orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", acme, `{"from_email":"gone@example.com","to_team":"acme-new"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"reassigned":1`) {
		t.Fatalf("acme reassign: %d %s", rec.Code, rec.Body.String())
	}
	g, _, _ := certs.GetCertificate(ctx, "fp-globex-cert")
	if g.OwnerTeam != "old" {
		t.Fatalf("acme reassign touched globex cert: %q", g.OwnerTeam)
	}
	// acme has nothing left; globex still has its own.
	if rec := orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", acme, `{"from_email":"gone@example.com","to_team":"again"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("acme second reassign: %d, want 400", rec.Code)
	}
	if rec := orphanCall(mux, http.MethodPost, "/api/v1/ownership/reassign", globex, `{"from_email":"gone@example.com","to_team":"globex-new"}`); rec.Code != http.StatusOK {
		t.Fatalf("globex reassign: %d", rec.Code)
	}
	a, _, _ := certs.GetCertificate(ctx, "fp-acme-cert")
	if a.OwnerTeam != "acme-new" {
		t.Fatalf("globex reassign touched acme cert: %q", a.OwnerTeam)
	}
}
