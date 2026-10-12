// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W7-01: join-token workload attestation — register → attest → SVID,
// single-use, expiry, and no-identity-choice guarantees.

func TestWorkloadRegistryAttestLifecycle(t *testing.T) {
	reg := NewWorkloadRegistry()
	now := time.Now()
	entry, token, err := reg.Register("spiffe://example.org/ns/prod/sa/agent", "admin-1", 0, now)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if token == "" || len(token) != 64 {
		t.Fatalf("expected 32-byte hex token, got %q", token)
	}

	// Wrong token refused.
	if _, err := reg.Attest("deadbeef", now); err == nil {
		t.Fatal("unknown token must be refused")
	}
	// Right token attests to the REGISTERED identity.
	got, err := reg.Attest(token, now)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if got.SPIFFEID != entry.SPIFFEID || got.ID != entry.ID {
		t.Fatalf("attested entry mismatch: %+v", got)
	}
	// Single-use: a second redemption is refused.
	if _, err := reg.Attest(token, now); err == nil {
		t.Fatal("replayed join token must be refused")
	}
}

func TestWorkloadRegistryExpiryAndTTLCap(t *testing.T) {
	reg := NewWorkloadRegistry()
	now := time.Now()
	_, token, err := reg.Register("spiffe://example.org/x", "admin-1", time.Minute, now)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := reg.Attest(token, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired join token must be refused")
	}
	if _, _, err := reg.Register("spiffe://example.org/y", "admin-1", 30*24*time.Hour, now); err == nil {
		t.Fatal("ttl above the cap must be refused")
	}
}

// workloadTestSetup wires the SPIFFE engine plus the workload handlers.
func workloadTestSetup(t *testing.T) (*http.ServeMux, *WorkloadRegistry) {
	t.Helper()
	mux := spiffeTestSetup(t)
	reg := NewWorkloadRegistry()
	registerSPIFFEWorkloadHandlers(mux, newReportsTestAuth(t), reg, stubAuditProvider{})
	return mux, reg
}

func registerWorkloadEntry(t *testing.T, mux *http.ServeMux, spiffeID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"spiffe_id": spiffeID})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/spiffe/workload-entries", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			JoinToken string `json:"join_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.JoinToken == "" {
		t.Fatal("registration must return the join token once")
	}
	return resp.Data.JoinToken
}

func TestWorkloadAttestMintsSVIDWithoutPrincipalAuth(t *testing.T) {
	mux, _ := workloadTestSetup(t)
	token := registerWorkloadEntry(t, mux, "spiffe://example.org/ns/prod/sa/checkout")

	// The workload call carries NO Authorization header — the join
	// token is the attestation evidence.
	body, _ := json.Marshal(map[string]string{"join_token": token})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spiffe/workload-svid", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			SPIFFEID string `json:"spiffe_id"`
			SVIDPEM  string `json:"svid_pem"`
			KeyPEM   string `json:"key_pem"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.SPIFFEID != "spiffe://example.org/ns/prod/sa/checkout" {
		t.Fatalf("SVID must carry the REGISTERED identity, got %q", resp.Data.SPIFFEID)
	}
	block, _ := pem.Decode([]byte(resp.Data.SVIDPEM))
	if block == nil {
		t.Fatal("svid_pem is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("svid parse: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != resp.Data.SPIFFEID {
		t.Fatalf("SVID URI SAN mismatch: %v", cert.URIs)
	}
	// Short-lived: default TTL is 1h; allow slack but refuse long-lived.
	if until := time.Until(cert.NotAfter); until > 2*time.Hour {
		t.Fatalf("SVID not short-lived: NotAfter %v", cert.NotAfter)
	}

	// Replay of the consumed token is refused with 401.
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/api/v1/spiffe/workload-svid", bytes.NewReader(body)))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replayed token: expected 401, got %d", rec2.Code)
	}
}

func TestWorkloadEntryRegistrationRequiresAdminAndValidID(t *testing.T) {
	mux, _ := workloadTestSetup(t)

	// Unauthenticated registration refused.
	body, _ := json.Marshal(map[string]string{"spiffe_id": "spiffe://example.org/x"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/spiffe/workload-entries", bytes.NewReader(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// Foreign trust domain refused at registration time.
	body2, _ := json.Marshal(map[string]string{"spiffe_id": "spiffe://evil.org/x"})
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, authedReq(http.MethodPost, "/api/v1/spiffe/workload-entries", body2))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for foreign trust domain, got %d", rec2.Code)
	}
}

// RC1-B-03: the unauthenticated redeem route must cap its body.
func TestWorkloadSVIDRejectsOversizedBody(t *testing.T) {
	mux, _ := workloadTestSetup(t)
	big := `{"join_token":"` + strings.Repeat("a", maxAuthBodyBytes*2) + `"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/spiffe/workload-svid", strings.NewReader(big)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestWorkloadEntryListNeverLeaksTokens(t *testing.T) {
	mux, _ := workloadTestSetup(t)
	registerWorkloadEntry(t, mux, "spiffe://example.org/ns/prod/sa/api")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/spiffe/workload-entries", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Neither the token nor its hash may appear anywhere in the body.
	if s := rec.Body.String(); len(s) > 0 && (strings.Contains(s, "join_token") || strings.Contains(s, "token_hash") || strings.Contains(s, "tokenHash")) {
		t.Fatalf("entry listing leaks token material: %s", s)
	}
}
