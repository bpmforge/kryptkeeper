// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func opsGet(h http.Handler, method, path, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestOpsHandlerHealthzReadyz(t *testing.T) {
	h := OpsHandler(OpsConfig{})
	if r := opsGet(h, "GET", "/healthz", ""); r.Code != 200 {
		t.Fatalf("healthz = %d", r.Code)
	}
	if r := opsGet(h, "GET", "/readyz", ""); r.Code != 200 {
		t.Fatalf("readyz = %d", r.Code)
	}
	before := ReadyzFailures.Load()
	h = OpsHandler(OpsConfig{Ready: func(context.Context) error { return errors.New("secret-db-dsn down") }})
	if r := opsGet(h, "GET", "/healthz", ""); r.Code != 200 {
		t.Fatalf("healthz with failing ready = %d", r.Code)
	}
	r := opsGet(h, "GET", "/readyz", "")
	if r.Code != 503 {
		t.Fatalf("readyz = %d, want 503", r.Code)
	}
	if strings.Contains(r.Body.String(), "secret-db-dsn") || !strings.Contains(r.Body.String(), "dependency check failed") {
		t.Fatalf("body must be generic: %s", r.Body.String())
	}
	if ReadyzFailures.Load() != before+1 {
		t.Fatal("readyz failure not counted")
	}
}

func TestOpsMetricsBearer(t *testing.T) {
	h := OpsHandler(OpsConfig{Bearer: func() string { return "tok-123" }})
	if r := opsGet(h, "GET", "/metrics", ""); r.Code != 401 || r.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("no token = %d", r.Code)
	}
	if r := opsGet(h, "GET", "/metrics", "Bearer wrong"); r.Code != 401 {
		t.Fatalf("wrong token = %d", r.Code)
	}
	if r := opsGet(h, "GET", "/metrics", "Bearer tok-123"); r.Code != 200 {
		t.Fatalf("right token = %d", r.Code)
	}
	if r := opsGet(h, "GET", "/healthz", ""); r.Code != 200 {
		t.Fatalf("healthz must stay open: %d", r.Code)
	}
	if r := opsGet(h, "GET", "/readyz", ""); r.Code != 200 {
		t.Fatalf("readyz must stay open: %d", r.Code)
	}
	open := OpsHandler(OpsConfig{Bearer: func() string { return "" }})
	if r := opsGet(open, "GET", "/metrics", ""); r.Code != 200 {
		t.Fatalf("empty bearer = open, got %d", r.Code)
	}
}

func TestBearerMatches(t *testing.T) {
	for _, tc := range []struct {
		hdr  string
		want bool
	}{{"Bearer abc", true}, {"bearer abc", true}, {"Bearer abcd", false}, {"Bearer ", false}, {"abc", false}, {"", false}} {
		if got := BearerMatches(tc.hdr, "abc"); got != tc.want {
			t.Errorf("BearerMatches(%q) = %v", tc.hdr, got)
		}
	}
}

func TestOpsMethodNotAllowed(t *testing.T) {
	h := OpsHandler(OpsConfig{})
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		if r := opsGet(h, "POST", p, ""); r.Code != 405 {
			t.Errorf("POST %s = %d", p, r.Code)
		}
	}
}

func TestOpsAddrFromEnv(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if got := OpsAddrFromEnv(get, "127.0.0.1:9101"); got != "127.0.0.1:9101" {
		t.Fatal(got)
	}
	env[OpsAddrEnv] = "  0.0.0.0:9000 "
	if got := OpsAddrFromEnv(get, "x"); got != "0.0.0.0:9000" {
		t.Fatal(got)
	}
	env[OpsAddrEnv] = "off"
	if got := OpsAddrFromEnv(get, "x"); got != "off" {
		t.Fatal(got)
	}
}

func TestServeOpsDisabledReturnsNil(t *testing.T) {
	for _, a := range []string{"", "off", "OFF"} {
		if err := ServeOps(context.Background(), OpsConfig{Addr: a}); err != nil {
			t.Fatalf("addr %q: %v", a, err)
		}
	}
}

func TestServeOpsServesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- ServeOps(ctx, OpsConfig{Addr: "127.0.0.1:0"}) }()
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
