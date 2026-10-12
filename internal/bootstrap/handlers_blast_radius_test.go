// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
		&reportCertProvider{items: blastRadiusFixture()}, stubAuditProvider{})
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
