// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// W17-06: the 2030 question as a query — "what do we migrate, in what
// order, before RSA-2048 is disallowed".

func agilityMux(t *testing.T) *http.ServeMux {
	t.Helper()
	future := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	items := []CertificateItem{
		{FingerprintSHA256: "fp1", CommonName: "test-api.example.com", PublicKeyAlgorithm: "RSA", KeySizeBits: 2048, ValidUntil: future},
		{FingerprintSHA256: "fp2", CommonName: "shop.example.com", PublicKeyAlgorithm: "RSA", KeySizeBits: 2048, ValidUntil: future},
		{FingerprintSHA256: "fp3", CommonName: "pqc.example.com", PublicKeyAlgorithm: "ML-DSA", KeySizeBits: 0, ValidUntil: future},
	}
	mux := http.NewServeMux()
	registerAgilityHandler(mux, newReportsTestAuth(t), &reportCertProvider{items: items}, stubAuditProvider{})
	return mux
}

func postAgility(t *testing.T, mux *http.ServeMux, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/crypto-agility/roadmap", []byte(body)))
	var resp struct {
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp.Data
}

func TestAgilityRoadmapDerivesWavesForRSATransition(t *testing.T) {
	code, data := postAgility(t, agilityMux(t),
		`{"name":"RSA-2048 sunset","algorithms":["RSA"],"max_key_bits":2048,"deadline":"2030-01-01T00:00:00Z"}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	roadmap := data["roadmap"].(map[string]any)
	if int(roadmap["total_matched"].(float64)) != 2 {
		t.Fatalf("only the two RSA-2048 certs are subject to the policy: %v", roadmap["total_matched"])
	}
	// The ML-DSA cert must not appear anywhere in the plan.
	byWave := roadmap["by_wave"].(map[string]any)
	for wave, items := range byWave {
		for _, it := range items.([]any) {
			if it.(map[string]any)["fingerprint"] == "fp3" {
				t.Fatalf("a quantum-safe cert must not be in an RSA sunset roadmap (wave %s)", wave)
			}
		}
	}
	progress := data["progress"].(map[string]any)
	if int(progress["percent_migrated"].(float64)) != 33 {
		t.Fatalf("1 of 3 migrated = 33%%, got %v", progress["percent_migrated"])
	}
}

// A past deadline must report overdue — that flag is the whole point of
// tracking a transition against a regulation.
func TestAgilityReportsOverduePastDeadline(t *testing.T) {
	_, data := postAgility(t, agilityMux(t),
		`{"name":"already late","algorithms":["RSA"],"max_key_bits":2048,"deadline":"2020-01-01T00:00:00Z"}`)
	if !data["progress"].(map[string]any)["overdue"].(bool) {
		t.Fatal("a transition past its deadline with unmigrated certs must report overdue")
	}
}

// A policy constraining nothing would match nothing, report 100%
// migrated and a clean roadmap — a false all-clear. It must be refused.
func TestAgilityRefusesUnconstrainedPolicy(t *testing.T) {
	code, _ := postAgility(t, agilityMux(t), `{"name":"empty","deadline":"2030-01-01T00:00:00Z"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("an unconstrained policy must be refused, got %d", code)
	}
}

func TestAgilityRejectsBadDeadlineAndRequiresAuth(t *testing.T) {
	mux := agilityMux(t)
	code, _ := postAgility(t, mux, `{"name":"x","algorithms":["RSA"],"deadline":"January 2030"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("a non-RFC3339 deadline must be refused, got %d", code)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/crypto-agility/roadmap", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
