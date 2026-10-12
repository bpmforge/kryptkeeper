// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W13-02: CertCentral write path — order→poll→download against a
// recorded fixture, auto-approve short path, pending-budget error,
// and rate-limit visibility through Health.

func digicertLeafPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type digicertFixture struct {
	srv       *httptest.Server
	requests  []string
	orderBody map[string]any
	// pollsUntilIssued: how many status polls before certificate.id appears.
	pollsUntilIssued int
	polls            int
	rateLimit        bool
	leafPEM          []byte
}

func newDigiCertFixture(t *testing.T, pollsUntilIssued int) *digicertFixture {
	t.Helper()
	f := &digicertFixture{pollsUntilIssued: pollsUntilIssued, leafPEM: digicertLeafPEM(t, "upstream.example.com")}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-DC-DEVKEY") != "devkey-123" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if f.rateLimit {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/services/v2/order/certificate/"):
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &f.orderBody)
			resp := map[string]any{"id": 777, "status": "pending"}
			if f.pollsUntilIssued == 0 {
				resp["certificate"] = map[string]any{"id": 4242}
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodGet && r.URL.Path == "/services/v2/order/certificate/777":
			f.polls++
			resp := map[string]any{"id": 777, "status": "pending"}
			if f.polls >= f.pollsUntilIssued {
				resp["certificate"] = map[string]any{"id": 4242}
				resp["status"] = "issued"
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodGet && r.URL.Path == "/services/v2/certificate/4242/download/format/pem_all":
			_, _ = w.Write(f.leafPEM)
		case r.URL.Path == "/services/v2/user/me":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func digicertConnectorFor(f *digicertFixture) *DigiCertConnector {
	return NewDigiCertConnector("dc-1", DigiCertConfig{
		BaseURL: f.srv.URL, APIKey: "devkey-123", OrganizationID: 99,
		PollAttempts: 3, PollInterval: time.Millisecond,
	}, f.srv.Client())
}

func TestDigiCertOrderPollDownloadFlow(t *testing.T) {
	f := newDigiCertFixture(t, 2) // approval-gated: cert id on the 2nd poll
	c := digicertConnectorFor(f)

	res, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "upstream.example.com")})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(res.FingerprintSHA256) != 64 || !strings.Contains(res.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("result shape: %+v", res)
	}
	// Request shapes pinned: product path, org id, CSR, sha256.
	if f.requests[0] != "POST /services/v2/order/certificate/ssl_basic" {
		t.Fatalf("order path: %v", f.requests)
	}
	cert := f.orderBody["certificate"].(map[string]any)
	if cert["common_name"] != "upstream.example.com" || cert["signature_hash"] != "sha256" {
		t.Fatalf("order certificate body: %v", cert)
	}
	if !strings.Contains(cert["csr"].(string), "CERTIFICATE REQUEST") {
		t.Fatal("order must carry the CSR PEM")
	}
	org := f.orderBody["organization"].(map[string]any)
	if org["id"].(float64) != 99 {
		t.Fatalf("organization id: %v", org)
	}
	last := f.requests[len(f.requests)-1]
	if last != "GET /services/v2/certificate/4242/download/format/pem_all" {
		t.Fatalf("download must be the final step: %v", f.requests)
	}
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("post-success health: %+v", h)
	}
}

func TestDigiCertAutoApproveShortPath(t *testing.T) {
	f := newDigiCertFixture(t, 0) // certificate.id on the order response
	c := digicertConnectorFor(f)
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "fast.example.com")}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	for _, r := range f.requests {
		if strings.HasPrefix(r, "GET /services/v2/order/certificate/777") {
			t.Fatalf("auto-approve must not poll: %v", f.requests)
		}
	}
}

func TestDigiCertPendingPastBudgetNamesOrder(t *testing.T) {
	f := newDigiCertFixture(t, 99) // never issues within the 3-poll budget
	c := digicertConnectorFor(f)
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "slow.example.com")})
	if err == nil || !strings.Contains(err.Error(), "order 777 still pending") {
		t.Fatalf("pending budget must name the order: %v", err)
	}
}

func TestDigiCertRateLimitSurfacesInHealth(t *testing.T) {
	f := newDigiCertFixture(t, 0)
	c := digicertConnectorFor(f)
	f.rateLimit = true
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "x.example.com")})
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("429 must surface as a rate-limit error: %v", err)
	}
	h := c.Health(context.Background())
	if h.Status != "degraded" || !strings.Contains(h.Detail, "rate limited") {
		t.Fatalf("throttling must show in Health: %+v", h)
	}
}
