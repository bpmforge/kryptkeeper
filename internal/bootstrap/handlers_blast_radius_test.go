// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
)

// W17-05: what-breaks-if over the live inventory.

func blastRadiusFixture() []CertificateItem {
	return []CertificateItem{
		{FingerprintSHA256: "fp1", CommonName: "shop.example.com", CAID: "ca-prod",
			PublicKeyAlgorithm: "RSA", KeySizeBits: 2048,
			SubjectAltNames: []string{"shop.example.com", "www.shop.example.com"}},
		{FingerprintSHA256: "fp2", CommonName: "api.example.com", CAID: "ca-prod",
			PublicKeyAlgorithm: "RSA", KeySizeBits: 2048,
			SubjectAltNames: []string{"api.example.com"}},
		{FingerprintSHA256: "fp3", CommonName: "pqc.example.com", CAID: "ca-lab",
			PublicKeyAlgorithm: "ML-DSA", KeySizeBits: 0,
			SubjectAltNames: []string{"pqc.example.com"}},
	}
}

func blastRadiusMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerBlastRadiusHandler(mux, newReportsTestAuth(t),
		&reportCertProvider{items: blastRadiusFixture()}, nil, stubAuditProvider{})
	return mux
}

func blastRadiusQuery(t *testing.T, mux *http.ServeMux, action, target string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/blast-radius?action="+action+"&target="+target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s/%s: expected 200, got %d: %s", action, target, rec.Code, rec.Body.String())
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Data
}

func affectedKind(data map[string]any, kind string) []string {
	byKind, _ := data["affected_by_kind"].(map[string]any)
	raw, _ := byKind[kind].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

// Revoking one cert takes down exactly the services it serves — and
// nothing else.
func TestBlastRadiusRevokeHitsOnlyThatCertsServices(t *testing.T) {
	data := blastRadiusQuery(t, blastRadiusMux(t), "revoke", "fp1")
	services := affectedKind(data, "service")
	if len(services) != 2 {
		t.Fatalf("fp1 serves 2 names, got %v", services)
	}
	for _, s := range services {
		if s == "api.example.com" {
			t.Fatal("revoking fp1 must not implicate a service served by a different cert")
		}
	}
}

// Retiring a CA propagates TRANSITIVELY: CA -> its certs -> their
// services. That transitive hop is the whole point.
func TestBlastRadiusRetireCAPropagatesTransitively(t *testing.T) {
	data := blastRadiusQuery(t, blastRadiusMux(t), "retire_ca", "ca-prod")
	certs := affectedKind(data, "cert")
	if len(certs) != 2 {
		t.Fatalf("ca-prod issued 2 certs, got %v", certs)
	}
	services := affectedKind(data, "service")
	if len(services) != 3 {
		t.Fatalf("both certs' services must be reached transitively, got %v", services)
	}
}

// The 2030 question: what breaks when RSA-2048 is disallowed. The PQC
// cert must NOT be implicated.
func TestBlastRadiusDeprecateAlgorithmSparesQuantumSafeCerts(t *testing.T) {
	data := blastRadiusQuery(t, blastRadiusMux(t), "deprecate_algorithm", "RSA-2048")
	certs := affectedKind(data, "cert")
	if len(certs) != 2 {
		t.Fatalf("only the two RSA-2048 certs break, got %v", certs)
	}
	for _, c := range certs {
		if c == "fp3" {
			t.Fatal("the ML-DSA cert must not be affected by an RSA-2048 deprecation")
		}
	}
	if data["severity"] == "none" {
		t.Fatal("breaking three services must not score as no impact")
	}
}

func TestBlastRadiusRejectsUnknownActionAndRequiresAuth(t *testing.T) {
	mux := blastRadiusMux(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/blast-radius?action=nuke&target=fp1", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action must be refused, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/blast-radius?action=revoke", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing target must be refused, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/blast-radius?action=revoke&target=fp1", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// blastAuditRecorder keeps every audit entry (capturingAuditProvider keeps only the last).
type blastAuditRecorder struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (p *blastAuditRecorder) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (p *blastAuditRecorder) AppendEntry(_ context.Context, e AuditEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, e)
	return nil
}

func (p *blastAuditRecorder) has(action string, outcome AuditOutcome) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		if e.Action == action && e.Outcome == outcome {
			return true
		}
	}
	return false
}

// blastCAStub serves a fixed CA list; every other CAProvider method is unused.
type blastCAStub struct {
	CAProvider
	cas     []CAListItem
	listErr error
}

func (s blastCAStub) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{Items: s.cas}, s.listErr
}

func (s blastCAStub) GetCA(_ context.Context, id string) (CAListItem, bool, error) {
	for _, c := range s.cas {
		if c.ID == id {
			return c, true, nil
		}
	}
	return CAListItem{}, false, nil
}

func blastMuxWith(t *testing.T, items []CertificateItem, cas CAProvider) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerBlastRadiusHandler(mux, newReportsTestAuth(t), &reportCertProvider{items: items}, cas, stubAuditProvider{})
	return mux
}

func blastStatus(mux *http.ServeMux, action, target string) int {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/blast-radius?action="+action+"&target="+target, nil))
	return rec.Code
}

func TestBlastRadiusUnknownTarget404(t *testing.T) {
	mux := blastRadiusMux(t)
	for action, target := range map[string]string{"revoke": "no-such-fp", "retire_ca": "no-such-ca", "deprecate_algorithm": "RSA-9999"} {
		if code := blastStatus(mux, action, target); code != http.StatusNotFound {
			t.Errorf("%s/%s: expected 404, got %d", action, target, code)
		}
	}
}

func TestBlastRadiusRealCAWithNoCertsIs200Zero(t *testing.T) {
	cas := blastCAStub{cas: []CAListItem{{ID: "ca-empty"}}}
	mux := blastMuxWith(t, blastRadiusFixture(), cas)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/blast-radius?action=retire_ca&target=ca-empty", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			TotalAffected int    `json:"total_affected"`
			Severity      string `json:"severity"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.TotalAffected != 0 || resp.Data.Severity != "none" {
		t.Fatalf("expected zero impact, got %+v", resp.Data)
	}
}

func TestBlastRadiusSubCAChainsThroughCAProvider(t *testing.T) {
	parent := "ca-root"
	cas := blastCAStub{cas: []CAListItem{{ID: "ca-root"}, {ID: "ca-prod", ParentCAID: &parent}}}
	mux := blastMuxWith(t, blastRadiusFixture(), cas)
	data := blastRadiusQuery(t, mux, "retire_ca", "ca-root")
	if got := affectedKind(data, "ca"); len(got) != 1 || got[0] != "ca-prod" {
		t.Fatalf("child CA must be reached, got %v", got)
	}
	if len(affectedKind(data, "cert")) != 2 || len(affectedKind(data, "service")) != 3 {
		t.Fatalf("chained certs/services missed: %v", data["affected_by_kind"])
	}
}

func TestBlastRadiusListCAsErrorFallsBackToCertOnly(t *testing.T) {
	cas := blastCAStub{listErr: fmt.Errorf("boom")}
	mux := blastMuxWith(t, blastRadiusFixture(), cas)
	data := blastRadiusQuery(t, mux, "retire_ca", "ca-prod")
	if len(affectedKind(data, "cert")) != 2 {
		t.Fatalf("cert-only edges must still work: %v", data)
	}
}

func TestBlastRadiusCrossTenant403(t *testing.T) {
	_, acmeToken, globexToken := setupTenantWritePathTest(t)
	rec := &blastAuditRecorder{}
	bmux := http.NewServeMux()
	registerBlastRadiusHandler(bmux, lastTenantWritePathAuth, NewFileCertificateProviderFromEnv(), NewFileCAProviderFromEnv(), rec)

	get := func(token, tenant, action, target string) int {
		return doTenantReq(bmux, http.MethodGet, "/api/v1/blast-radius?action="+action+"&target="+target, token, tenant).Code
	}
	for _, c := range []struct{ token, tenant, action, target string }{
		{acmeToken, "acme", "retire_ca", "ca-globex"},
		{acmeToken, "acme", "revoke", "fp-globex-cert"},
		{globexToken, "globex", "retire_ca", "ca-acme"},
		{globexToken, "globex", "revoke", "fp-acme-cert"},
	} {
		if code := get(c.token, c.tenant, c.action, c.target); code != http.StatusForbidden {
			t.Errorf("%s %s as %s: expected 403, got %d", c.action, c.target, c.tenant, code)
		}
	}
	if code := get(acmeToken, "acme", "retire_ca", "ca-acme"); code != http.StatusOK {
		t.Errorf("own CA: expected 200, got %d", code)
	}
	if code := get(acmeToken, "acme", "revoke", "fp-acme-cert"); code != http.StatusOK {
		t.Errorf("own cert: expected 200, got %d", code)
	}
	if code := get(globexToken, "globex", "retire_ca", "ca-globex"); code != http.StatusOK {
		t.Errorf("globex own CA: expected 200, got %d", code)
	}
	if code := get(acmeToken, "acme", "retire_ca", "ca-nowhere"); code != http.StatusNotFound {
		t.Errorf("unknown CA: expected 404, got %d", code)
	}
	if !rec.has("blast_radius.simulate", AuditOutcomeDenied) {
		t.Fatal("cross-tenant denial must be audited as denied")
	}
}

func TestBlastRadiusTenantSeesOnlyOwnAlgorithmImpact(t *testing.T) {
	_, acmeToken, _ := setupTenantWritePathTest(t)
	bmux := http.NewServeMux()
	registerBlastRadiusHandler(bmux, lastTenantWritePathAuth, NewFileCertificateProviderFromEnv(), NewFileCAProviderFromEnv(), stubAuditProvider{})
	rec := doTenantReq(bmux, http.MethodGet, "/api/v1/blast-radius?action=deprecate_algorithm&target=ECDSA-256", acmeToken, "acme")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	certs := affectedKind(resp.Data, "cert")
	if len(certs) != 1 || certs[0] != "fp-acme-cert" {
		t.Fatalf("acme must see only its own cert, got %v", certs)
	}
}

func TestBlastRadiusEdgeCoverageInResponse(t *testing.T) {
	data := blastRadiusQuery(t, blastRadiusMux(t), "retire_ca", "ca-prod")
	cov, _ := data["edge_coverage"].(map[string]any)
	if cov == nil {
		t.Fatal("edge_coverage missing")
	}
	for _, k := range []string{"certs_total", "certs_with_ca_edge", "certs_with_service_edge"} {
		if v, _ := cov[k].(float64); v != 3 {
			t.Errorf("%s = %v, want 3", k, cov[k])
		}
	}
	if b, _ := cov["basis"].(string); b == "" {
		t.Error("basis must be non-empty")
	}
}

func TestBlastRadiusP95At100kCerts(t *testing.T) {
	// Timing bound is meaningless under PR CI's -race; nightly runs it (W31-18).
	if testing.Short() || os.Getenv("KRYPTKEEPER_SCALE_TESTS") != "1" {
		t.Skip("100k-cert p95 test: set KRYPTKEEPER_SCALE_TESTS=1 (nightly)")
	}
	const nCerts, nCAs = 100000, 1000
	items := make([]CertificateItem, nCerts)
	for i := range items {
		items[i] = CertificateItem{
			FingerprintSHA256:  fmt.Sprintf("fp-%d", i),
			CommonName:         fmt.Sprintf("host-%d.example.com", i),
			CAID:               fmt.Sprintf("ca-%d", i%nCAs),
			PublicKeyAlgorithm: "RSA", KeySizeBits: 2048,
			SubjectAltNames: []string{fmt.Sprintf("a-%d.example.com", i), fmt.Sprintf("b-%d.example.com", i)},
		}
	}
	mux := blastMuxWith(t, items, nil)
	const n = 40
	durs := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		var action, target string
		switch i % 3 {
		case 0:
			action, target = "revoke", fmt.Sprintf("fp-%d", i*997)
		case 1:
			action, target = "retire_ca", fmt.Sprintf("ca-%d", i)
		default:
			action, target = "deprecate_algorithm", "RSA-2048"
		}
		start := time.Now()
		code := blastStatus(mux, action, target)
		durs = append(durs, time.Since(start))
		if code != http.StatusOK {
			t.Fatalf("%s/%s: %d", action, target, code)
		}
	}
	sort.Slice(durs, func(a, b int) bool { return durs[a] < durs[b] })
	t.Logf("p50=%v p95=%v max=%v", durs[n/2], durs[37], durs[n-1])
	if durs[37] >= 2*time.Second {
		t.Fatalf("p95 %v >= 2s", durs[37])
	}
}
