// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The plaintext listener must serve CRL and OCSP and nothing else: no API,
// UI or enrollment endpoint may become reachable without TLS.
func TestRevocationHTTPHandlerServesOnlyCRLAndOCSP(t *testing.T) {
	tag := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Served-By", name)
		})
	}
	h := revocationHTTPHandler(tag("crl"), tag("ocsp"))
	for path, want := range map[string]string{
		"/crl/ca-1.crl":            "crl",
		"/ocsp":                    "ocsp",
		"/ocsp/MEIwQDA-MDwwOjAJBg": "ocsp",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if got := w.Header().Get("X-Served-By"); got != want {
			t.Errorf("%s served by %q, want %q", path, got, want)
		}
	}
	for _, path := range []string{"/", "/api/v1/certificates", "/wstep", "/xcep", "/acme/directory", "/.well-known/est/simpleenroll", "/scep", "/metrics", "/healthz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound || w.Header().Get("X-Served-By") != "" {
			t.Errorf("%s reachable over plaintext: %d", path, w.Code)
		}
	}
}

func TestRevocationBaseURL(t *testing.T) {
	t.Setenv("KRYPTKEEPER_REVOCATION_BASE_URL", "")
	if got := revocationBaseURL("https://hub.corp.example:8443/"); got != "https://hub.corp.example:8443" {
		t.Fatalf("fallback %q", got)
	}
	t.Setenv("KRYPTKEEPER_REVOCATION_BASE_URL", "http://hub.corp.example:8081/")
	if got := revocationBaseURL("https://hub.corp.example:8443"); got != "http://hub.corp.example:8081" {
		t.Fatalf("override %q", got)
	}
}
