// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W36-05: EJBCA inventory source against an mTLS fixture pinning the
// search request shape.

func ejbcaTestCert(t *testing.T, cn string, serial int64, client bool) (der []byte, certPEM, keyPEM string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return der, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

func TestEJBCASourceSearchShapeAndSkips(t *testing.T) {
	a, _, _ := ejbcaTestCert(t, "a.example.com", 1, false)
	b, _, _ := ejbcaTestCert(t, "b.example.com", 2, false)
	_, cliCert, cliKey := ejbcaTestCert(t, "kk-client", 3, true)
	enc := base64.StdEncoding.EncodeToString

	var gotBody map[string]any
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/ejbca/ejbca-rest-api/v1/certificate/search" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]string{
				{"certificate": enc(a), "response_format": "DER"},
				{"certificate": "!!!not base64!!!"},
				{"certificate": enc([]byte("not a cert"))},
				{"base64Cert": enc(b)},
			},
			"more_results": false,
		})
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	srvPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	cfg, _ := json.Marshal(map[string]any{"base_url": srv.URL + "/ejbca/ejbca-rest-api", "ca_cert_pem": srvPEM})
	cred, _ := json.Marshal(map[string]string{"client_cert_pem": cliCert, "client_key_pem": cliKey})
	src, err := newEJBCASource(context.Background(), string(cfg), "cred-e", commercialCreds(t, string(cred)))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	certs, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("want 2 parseable certs (2 bad items skipped), got %d", len(certs))
	}
	for _, c := range certs {
		if c.UpstreamStatus != "active" || !strings.Contains(c.PEM, "BEGIN CERTIFICATE") {
			t.Fatalf("bad item: %+v", c)
		}
	}
	if gotBody["max_number_of_results"] != float64(defaultEJBCASearchLimit) {
		t.Errorf("max_number_of_results = %v", gotBody["max_number_of_results"])
	}
	crit, _ := gotBody["criteria"].([]any)
	want := map[string]any{"property": "STATUS", "value": "CERT_ACTIVE", "operation": "EQUAL"}
	if len(crit) != 1 || fmt.Sprint(crit[0]) != fmt.Sprint(want) {
		t.Errorf("criteria = %v", crit)
	}
}

func TestEJBCASourceErrors(t *testing.T) {
	ctx := context.Background()
	_, cliCert, cliKey := ejbcaTestCert(t, "kk-client", 3, true)
	good, _ := json.Marshal(map[string]string{"client_cert_pem": cliCert, "client_key_pem": cliKey})
	badKey, _ := json.Marshal(map[string]string{"client_cert_pem": cliCert, "client_key_pem": "garbage-SECRETKEY"})

	if _, err := newEJBCASource(ctx, `{}`, "c", commercialCreds(t, string(good))); err == nil {
		t.Error("missing base_url must fail")
	}
	if _, err := newEJBCASource(ctx, `{"base_url":"https://x"}`, "", nil); err == nil {
		t.Error("missing credential_ref must fail")
	}
	if _, err := newEJBCASource(ctx, `{"base_url":"https://x"}`, "c", commercialCreds(t, `{"client_cert_pem":"x"}`)); err == nil {
		t.Error("incomplete credential must fail")
	}
	_, err := newEJBCASource(ctx, `{"base_url":"https://x"}`, "c", commercialCreds(t, string(badKey)))
	if err == nil || strings.Contains(err.Error(), "SECRETKEY") {
		t.Errorf("bad key err = %v", err)
	}
	if _, err := newEJBCASource(ctx, `{"base_url":"https://x","ca_cert_pem":"junk"}`, "c", commercialCreds(t, string(good))); err == nil {
		t.Error("junk ca_cert_pem must fail")
	}

	// HTTP error surfaces from Fetch.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	srvPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	cfg, _ := json.Marshal(map[string]any{"base_url": srv.URL, "ca_cert_pem": srvPEM})
	src, err := newEJBCASource(ctx, string(cfg), "c", commercialCreds(t, string(good)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("fetch err = %v", err)
	}
}
