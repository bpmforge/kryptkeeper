// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMountProtocolHandlers_AllProtocolPathsReachable is the G-64/S-10
// regression: cmd/kryptkeeper/main.go registers CMP, WSTEP, XCEP, and
// /metrics directly on protocolMux, but for a while mountProtocolHandlers
// (formerly inlined in RunWithProtocols) only forwarded the original 5
// protocols' prefixes -- http.ServeMux has no wildcard/catch-all fallback,
// so anything registered on protocolMux but missing from this list was
// entirely unreachable (404), not merely unrouted to some default handler.
// This test exercises the REAL mountProtocolHandlers function against every
// path it's supposed to cover, proving each one actually reaches
// protocolMux through the exact hub-mux topology the running binary builds.
func TestMountProtocolHandlers_AllProtocolPathsReachable(t *testing.T) {
	protocolMux := http.NewServeMux()
	hit := map[string]bool{}
	mount := func(pattern string) {
		p := pattern
		protocolMux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			hit[p] = true
			w.WriteHeader(http.StatusOK)
		})
	}
	mount("/acme/")
	mount("/ocsp")
	mount("/ocsp/")
	mount("/crl/")
	mount("/.well-known/est/")
	mount("/scep")
	mount("/scep/")
	mount("/cmp")
	mount("/wstep")
	mount("/xcep")
	mount("/metrics")

	mux := http.NewServeMux()
	mountProtocolHandlers(mux, protocolMux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{
		"/acme/directory",
		"/ocsp",
		"/ocsp/MEIwQDA-MDwwOjAJBgUrDgMCGgUABBQ", // RFC 5019 GET form
		"/crl/some-ca",
		"/.well-known/est/simpleenroll",
		"/scep",
		"/scep/pkiclient.exe",
		"/cmp",
		"/wstep",
		"/xcep",
		"/metrics",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("%s: got 404 -- unreachable through the mounted mux", path)
		}
	}

	for _, p := range []string{"/acme/", "/ocsp", "/ocsp/", "/crl/", "/.well-known/est/", "/scep", "/scep/", "/cmp", "/wstep", "/xcep", "/metrics"} {
		if !hit[p] {
			t.Errorf("protocolMux handler for %s was never actually invoked", p)
		}
	}
}

// TestMountProtocolHandlers_NilProtocolMuxIsNoop proves a nil protocolMux
// (protocols disabled, e.g. APP_CERTIFICATE_PROVIDER != "ca") doesn't panic
// and mounts nothing.
func TestMountProtocolHandlers_NilProtocolMuxIsNoop(t *testing.T) {
	mux := http.NewServeMux()
	mountProtocolHandlers(mux, nil)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ocsp")
	if err != nil {
		t.Fatalf("GET /ocsp: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 with a nil protocolMux, got %d", resp.StatusCode)
	}
}
