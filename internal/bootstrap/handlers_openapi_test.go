// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"kryptkeeper/docs"
)

func serveOpenAPI(t *testing.T, method string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerOpenAPIHandlers(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/openapi.yaml", nil))
	return rec
}

func TestOpenAPIServed(t *testing.T) {
	rec := serveOpenAPI(t, http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	want, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Error("served body is not byte-identical to docs/openapi.yaml")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestOpenAPIMethodNotAllowed(t *testing.T) {
	rec := serveOpenAPI(t, http.MethodPost)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Errorf("Allow = %q, want GET", got)
	}
}

func TestOpenAPIVersionMatchesBuild(t *testing.T) {
	rec := serveOpenAPI(t, http.MethodGet)
	m := regexp.MustCompile(`(?m)^  version: "([^"]+)"`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("info.version not found")
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+`).MatchString(m[1]) {
		t.Errorf("info.version %q is not semver", m[1])
	}
	if v := os.Getenv("APP_VERSION"); v != "" && v != "dev" {
		if want := strings.TrimPrefix(v, "v"); m[1] != want {
			t.Errorf("info.version = %q, want APP_VERSION %q", m[1], want)
		}
	}
}

func TestOpenAPIEmbedNonEmpty(t *testing.T) {
	if len(docs.OpenAPI) <= 1000 {
		t.Fatalf("embedded spec too small: %d bytes", len(docs.OpenAPI))
	}
	if !bytes.HasPrefix(docs.OpenAPI, []byte(`openapi: "3.1.0"`)) {
		t.Error(`embedded spec does not begin with openapi: "3.1.0"`)
	}
}
