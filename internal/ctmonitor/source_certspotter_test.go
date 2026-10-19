// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testCertDER mints a throwaway self-signed cert; the key is generated
// in-test and discarded.
func testCertDER(t *testing.T, serial int64, cn string, sans ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return der
}

func issuance(id string, der []byte, sans ...string) map[string]any {
	return map[string]any{
		"id": id, "dns_names": sans,
		"not_before": "2026-10-15T00:00:00Z", "not_after": "2026-12-15T00:00:00Z",
		"issuer":   map[string]any{"name": "CN=Some CA,O=Some"},
		"cert_der": base64.StdEncoding.EncodeToString(der),
	}
}

func TestCertSpotterParsesIssuances(t *testing.T) {
	der := testCertDER(t, 0x0abc12, "svc.example.com", "svc.example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/issuances" || r.URL.Query().Get("domain") != "example.com" ||
			r.URL.Query().Get("include_subdomains") != "true" {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		if r.URL.Query().Get("after") == "" {
			_ = json.NewEncoder(w).Encode([]any{issuance("77", der, "svc.example.com")})
			return
		}
		_ = json.NewEncoder(w).Encode([]any{})
	}))
	defer srv.Close()
	entries, err := NewCertSpotterSource(srv.URL, "").Search(context.Background(), "example.com")
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	e := entries[0]
	// crt.sh style: lowercase hex, no leading zeros; matches NormalizeSerial.
	if e.EntryID != "77" || e.Serial != "abc12" || e.CommonName != "svc.example.com" ||
		len(e.DNSNames) != 1 || e.Issuer != "CN=Some CA,O=Some" ||
		e.NotAfter.Format(time.RFC3339) != "2026-12-15T00:00:00Z" {
		t.Fatalf("bad entry: %+v", e)
	}
	if e.Serial != NormalizeSerial("0A:BC:12") {
		t.Fatalf("serial not comparable to crt.sh style: %q", e.Serial)
	}
	if NewCertSpotterSource(srv.URL, "").Name() != "certspotter" {
		t.Fatal("name")
	}
}

func TestCertSpotterPaginates(t *testing.T) {
	d1, d2 := testCertDER(t, 1, "a.example.com"), testCertDER(t, 2, "b.example.com")
	var afters []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		afters = append(afters, after)
		switch after {
		case "":
			_ = json.NewEncoder(w).Encode([]any{issuance("1", d1)})
		case "1":
			_ = json.NewEncoder(w).Encode([]any{issuance("2", d2)})
		default:
			_ = json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()
	entries, err := NewCertSpotterSource(srv.URL, "").Search(context.Background(), "example.com")
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	if strings.Join(afters, ",") != ",1,2" {
		t.Fatalf("after cursors = %v", afters)
	}
}

func TestCertSpotterRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := NewCertSpotterSource(srv.URL, "").Search(context.Background(), "example.com")
	if err == nil || err.Error() != "certspotter rate limited" {
		t.Fatalf("err = %v", err)
	}
}

func TestCertSpotterSendsBearerWhenKeySet(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode([]any{})
	}))
	defer srv.Close()
	_, _ = NewCertSpotterSource(srv.URL, "k-123").Search(context.Background(), "example.com")
	_, _ = NewCertSpotterSource(srv.URL, "").Search(context.Background(), "example.com")
	if len(got) != 2 || got[0] != "Bearer k-123" || got[1] != "" {
		t.Fatalf("auth headers = %q", got)
	}
}
