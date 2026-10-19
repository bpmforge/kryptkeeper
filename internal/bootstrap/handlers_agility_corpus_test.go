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
	"sort"
	"strings"
	"testing"
	"time"
)

// W31-13: the same 500-cert corpus through the HTTP handler.

type agilityKind struct {
	alg  string
	bits int
}

var agilityKinds = [10]agilityKind{
	{"RSA", 1024}, {"RSA", 2048}, {"RSA", 3072}, {"RSA", 4096},
	{"ECDSA", 256}, {"ECDSA", 384}, {"Ed25519", 256}, {"ML-DSA", 0},
	{"RSA", 0}, {"ECDSA", 0},
}

func agilityCorpusItems(caID string) []CertificateItem {
	future := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	items := make([]CertificateItem, 0, 520)
	for i := 0; i < 500; i++ {
		k := agilityKinds[i%10]
		cn := fmt.Sprintf("www%d.example.com", i)
		switch i % 3 {
		case 0:
			cn = fmt.Sprintf("test-%d.example.com", i)
		case 1:
			cn = fmt.Sprintf("svc%d.corp", i)
		}
		items = append(items, CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp%03d", i), CommonName: cn,
			PublicKeyAlgorithm: k.alg, KeySizeBits: k.bits, ValidUntil: future, CAID: caID,
		})
	}
	return items
}

func agilityInactiveItems() []CertificateItem {
	revokedAt := time.Now().Add(-time.Hour).Format(time.RFC3339)
	var out []CertificateItem
	for i := 0; i < 10; i++ {
		out = append(out,
			CertificateItem{FingerprintSHA256: fmt.Sprintf("rev%02d", i), CommonName: "rev.example.com",
				PublicKeyAlgorithm: "RSA", KeySizeBits: 2048, RevokedAt: &revokedAt},
			CertificateItem{FingerprintSHA256: fmt.Sprintf("ren%02d", i), CommonName: "ren.example.com",
				PublicKeyAlgorithm: "RSA", KeySizeBits: 2048, RenewalStatus: "renewed"})
	}
	return out
}

// agilityOracle is written from the policy doc, not from pqc.Matches.
func agilityOracle(i int, algs []string, maxBits int) bool {
	k := agilityKinds[i%10]
	if len(algs) == 0 {
		return maxBits > 0 && k.bits > 0 && k.bits <= maxBits
	}
	hit := false
	for _, a := range algs {
		if strings.Contains(strings.ToLower(k.alg), strings.ToLower(a)) {
			hit = true
		}
	}
	if !hit {
		return false
	}
	return !(maxBits > 0 && k.bits > 0 && k.bits > maxBits)
}

func agilityFingerprints(t *testing.T, data map[string]any) []string {
	t.Helper()
	var got []string
	for _, items := range data["roadmap"].(map[string]any)["by_wave"].(map[string]any) {
		for _, it := range items.([]any) {
			got = append(got, it.(map[string]any)["fingerprint"].(string))
		}
	}
	sort.Strings(got)
	return got
}

func TestAgilityHandlerCorpusMembershipExact(t *testing.T) {
	items := append(agilityCorpusItems(""), agilityInactiveItems()...)
	mux := http.NewServeMux()
	registerAgilityHandler(mux, newReportsTestAuth(t), &reportCertProvider{items: items}, stubAuditProvider{})

	cases := []struct {
		body string
		algs []string
		bits int
	}{
		{`{"name":"P1","algorithms":["RSA"],"max_key_bits":2048}`, []string{"RSA"}, 2048},
		{`{"name":"P2","algorithms":["RSA"]}`, []string{"RSA"}, 0},
		{`{"name":"P3","algorithms":["ECDSA"],"max_key_bits":256}`, []string{"ECDSA"}, 256},
		{`{"name":"P4","algorithms":["ECDSA","ML-DSA"]}`, []string{"ECDSA", "ML-DSA"}, 0},
		{`{"name":"P5","max_key_bits":2048}`, nil, 2048},
	}
	for _, c := range cases {
		var want []string
		for i := 0; i < 500; i++ {
			if agilityOracle(i, c.algs, c.bits) {
				want = append(want, fmt.Sprintf("fp%03d", i))
			}
		}
		sort.Strings(want)
		code, data := postAgility(t, mux, c.body)
		if code != http.StatusOK {
			t.Fatalf("%s: %d", c.body, code)
		}
		got := agilityFingerprints(t, data)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %d certs want %d", c.body, len(got), len(want))
		}
		if tot := int(data["progress"].(map[string]any)["total_inventory"].(float64)); tot != 500 {
			t.Errorf("%s: total_inventory=%d, inactive certs must be excluded", c.body, tot)
		}
	}
}

func TestAgilityHandlerEmptyPolicy400(t *testing.T) {
	mux := agilityMux(t)
	for _, body := range []string{`{}`, `{"name":"x"}`, `{"algorithms":[],"max_key_bits":0}`} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/crypto-agility/roadmap", []byte(body)))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "must constrain") {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestAgilityHandlerAuditEvent(t *testing.T) {
	items := agilityCorpusItems("")
	audit := &captureAudit{}
	mux := http.NewServeMux()
	registerAgilityHandler(mux, newReportsTestAuth(t), &reportCertProvider{items: items}, audit)

	if code, _ := postAgility(t, mux, `{"name":"P1","algorithms":["RSA"],"max_key_bits":2048}`); code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d", len(audit.entries))
	}
	e := audit.entries[0]
	if e.Action != "crypto_agility.roadmap" || e.Outcome != AuditOutcomeSuccess {
		t.Fatalf("entry = %+v", e)
	}
	var cs struct {
		Matched int `json:"matched"`
	}
	if err := json.Unmarshal([]byte(e.ChangeSummary), &cs); err != nil {
		t.Fatalf("change summary %q: %v", e.ChangeSummary, err)
	}
	want := 0
	for i := 0; i < 500; i++ {
		if agilityOracle(i, []string{"RSA"}, 2048) {
			want++
		}
	}
	if cs.Matched != want {
		t.Fatalf("audited matched=%d want %d", cs.Matched, want)
	}

	audit.entries = nil
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/crypto-agility/roadmap", nil))
	if rec.Code != http.StatusUnauthorized || len(audit.entries) != 1 || audit.entries[0].Outcome != AuditOutcomeDenied {
		t.Fatalf("unauthenticated: code=%d entries=%+v", rec.Code, audit.entries)
	}
}

func TestAgilityHandlerTenantScoped(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv(dbModeEnv, dbModeSQLite)
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)

	ts := NewTenantStoreFromEnv()
	if ts == nil {
		t.Fatal("tenant store unavailable")
	}
	ctx := context.Background()
	for _, id := range []string{"t1", "t2"} {
		if _, err := ts.CreateTenant(ctx, id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.SetCATenant(ctx, "ca-a", "t1"); err != nil {
		t.Fatal(err)
	}
	if err := ts.SetCATenant(ctx, "ca-b", "t2"); err != nil {
		t.Fatal(err)
	}
	prev := activeTenantStore
	setActiveTenantStore(ts)
	t.Cleanup(func() { setActiveTenantStore(prev) })

	_, tok, err := auth.CreateAPIKey("t1-key", "t1-admin", "pki-admin", []string{"*"}, "", "t1", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	var items []CertificateItem
	for i := 0; i < 40; i++ {
		ca := "ca-a"
		if i%2 == 1 {
			ca = "ca-b"
		}
		items = append(items, CertificateItem{FingerprintSHA256: fmt.Sprintf("t%02d", i), CommonName: "x.example.com",
			PublicKeyAlgorithm: "RSA", KeySizeBits: 2048, CAID: ca})
	}
	mux := http.NewServeMux()
	registerAgilityHandler(mux, auth, &reportCertProvider{items: items}, stubAuditProvider{})

	req := bearerReq(tok, http.MethodPost, "/api/v1/crypto-agility/roadmap", []byte(`{"name":"x","algorithms":["RSA"]}`))
	req.Header.Set("X-Tenant", "t1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	got := agilityFingerprints(t, resp.Data)
	if len(got) != 20 {
		t.Fatalf("t1 should see only its 20 ca-a certs, got %d", len(got))
	}
	for _, fp := range got {
		var n int
		fmt.Sscanf(fp, "t%d", &n)
		if n%2 != 0 {
			t.Fatalf("leaked ca-b cert %s", fp)
		}
	}
	if tot := int(resp.Data["progress"].(map[string]any)["total_inventory"].(float64)); tot != 20 {
		t.Fatalf("total_inventory=%d", tot)
	}
}
