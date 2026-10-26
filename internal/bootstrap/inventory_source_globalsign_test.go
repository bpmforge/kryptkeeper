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
	"strings"
	"testing"
)

func TestGlobalSignSourceListsAndMarksRevoked(t *testing.T) {
	live, gone := vaultInvTestCertPEM(t, "live.example.test"), vaultInvTestCertPEM(t, "gone.example.test")
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/v2/login" {
			_, _ = fmt.Fprint(w, `{"access_token":"tok"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/stats/issued":
			_, _ = fmt.Fprint(w, `[{"serial_number":"11"}]`)
		case "/v2/stats/revoked":
			_, _ = fmt.Fprint(w, `[{"serial_number":"22"}]`)
		case "/v2/certificates/11":
			b, _ := json.Marshal(map[string]any{"certificate": live, "status": "ISSUED"})
			_, _ = w.Write(b)
		case "/v2/certificates/22":
			b, _ := json.Marshal(map[string]any{"certificate": gone, "status": "REVOKED"})
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

	src, err := newGlobalSignSource(context.Background(),
		fmt.Sprintf(`{"base_url":%q}`, srv.URL+"/v2"), "cred-g",
		commercialCreds(t, `{"api_key":"k","api_secret":"s"}`))
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
	for _, c := range calls {
		if !strings.HasPrefix(c, "GET") && c != "POST /v2/login" {
			t.Fatalf("source must be read-only, saw %s", c)
		}
	}
}

func TestGlobalSignSourceCredentialValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := newGlobalSignSource(ctx, `{}`, "", nil); err == nil {
		t.Error("credential_ref required")
	}
	if _, err := newGlobalSignSource(ctx, `{}`, "c", commercialCreds(t, `{"api_key":"k"}`)); err == nil {
		t.Error("api_secret required")
	}
	if _, err := newGlobalSignSource(ctx, `{}`, "c", commercialCreds(t, `{"api_key":"k","api_secret":"s"}`)); err != nil {
		t.Errorf("minimal payload should be accepted: %v", err)
	}
}
