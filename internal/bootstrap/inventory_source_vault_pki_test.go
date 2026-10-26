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
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func vaultInvTestCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestVaultPKISourceListsAndMarksRevoked(t *testing.T) {
	live, gone := vaultInvTestCertPEM(t, "live.example.test"), vaultInvTestCertPEM(t, "gone.example.test")
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Vault-Token") != "tok" || r.Header.Get("X-Vault-Namespace") != "ns1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/v1/pki-int/certs":
			_, _ = fmt.Fprint(w, `{"data":{"keys":["01:aa","02:bb"]}}`)
		case "/v1/pki-int/cert/01:aa":
			b, _ := json.Marshal(map[string]any{"data": map[string]any{"certificate": live, "revocation_time": 0}})
			_, _ = w.Write(b)
		case "/v1/pki-int/cert/02:bb":
			b, _ := json.Marshal(map[string]any{"data": map[string]any{"certificate": gone, "revocation_time": 1667400107}})
			_, _ = w.Write(b)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)

	old := egressAllowLoopback
	egressAllowLoopback = true
	oldPlain := upstreamAllowPlainHTTP
	upstreamAllowPlainHTTP = true
	t.Cleanup(func() { upstreamAllowPlainHTTP = oldPlain })
	t.Cleanup(func() { egressAllowLoopback = old })

	src, err := newVaultPKISource(context.Background(),
		fmt.Sprintf(`{"base_url":%q,"mount":"pki-int","namespace":"ns1"}`, srv.URL),
		"cred-v", commercialCreds(t, `{"token":"tok"}`))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	certs, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(certs) != 2 || certs[0].UpstreamStatus != "active" || certs[1].UpstreamStatus != "revoked" {
		t.Fatalf("status mapping: %+v", certs)
	}
	if certs[0].PEM != live || certs[1].PEM != gone {
		t.Fatal("PEM passthrough")
	}
	if methods[0] != "LIST /v1/pki-int/certs" {
		t.Fatalf("first call must be LIST certs, got %v", methods)
	}
	for _, m := range methods {
		if strings.HasPrefix(m, "POST") || strings.HasPrefix(m, "PUT") || strings.HasPrefix(m, "DELETE") {
			t.Fatalf("source must be read-only, saw %s", m)
		}
	}
}

func TestVaultPKISourceConfigAndCredentialValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := newVaultPKISource(ctx, `{}`, "c", commercialCreds(t, `{"token":"t"}`)); err == nil {
		t.Error("base_url required")
	}
	if _, err := newVaultPKISource(ctx, `{"base_url":"https://v"}`, "", nil); err == nil {
		t.Error("credential_ref required")
	}
	if _, err := newVaultPKISource(ctx, `{"base_url":"https://v"}`, "c", commercialCreds(t, `{"role_id":"r"}`)); err == nil {
		t.Error("approle needs secret_id")
	}
	if _, err := newVaultPKISource(ctx, `{"base_url":"https://v"}`, "c", commercialCreds(t, `{"role_id":"r","secret_id":"s"}`)); err != nil {
		t.Errorf("approle payload should be accepted: %v", err)
	}
}
