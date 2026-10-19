// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tenantidor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const fakeBootstrap = "fake-bootstrap"

// newLeakyHub is a minimal in-process hub with ONE deliberate cross-tenant
// read: GET /api/v1/cas returns every tenant's CAs. Everything else it
// serves (single-resource reads and deletes) is correctly tenant-checked, so
// the harness must find exactly the seeded leak and nothing more.
func newLeakyHub(t testing.TB) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	type ca struct{ ID, Name, Owner string }
	keys := map[string]string{} // token -> tenant
	var cas []ca
	n := 0
	write := func(w http.ResponseWriter, st int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_ = json.NewEncoder(w).Encode(v)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/tenants" && tok == fakeBootstrap:
			write(w, 201, map[string]any{"data": body})
		case r.Method == "POST" && r.URL.Path == "/api/v1/api-keys" && tok == fakeBootstrap:
			n++
			tenant, _ := body["tenant"].(string)
			tk := fmt.Sprintf("kk_fake_%d", n)
			keys[tk] = tenant
			write(w, 201, map[string]any{"data": map[string]any{"token": tk, "kid": fmt.Sprintf("kid%d", n)}})
		case keys[tok] == "":
			write(w, 401, map[string]any{"error": "unauthorized"})
		case r.Method == "POST" && r.URL.Path == "/api/v1/cas":
			n++
			name, _ := body["name"].(string)
			c := ca{ID: fmt.Sprintf("ca-%d", n), Name: name, Owner: keys[tok]}
			cas = append(cas, c)
			write(w, 201, map[string]any{"data": map[string]any{"id": c.ID}})
		case r.Method == "GET" && r.URL.Path == "/api/v1/cas":
			write(w, 200, map[string]any{"data": cas}) // the seeded leak: no tenant filter
		case strings.HasPrefix(r.URL.Path, "/api/v1/cas/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/cas/")
			for _, c := range cas {
				if c.ID == id && c.Owner == keys[tok] {
					write(w, 200, map[string]any{"data": c})
					return
				}
			}
			write(w, 403, map[string]any{"error": "forbidden"})
		default:
			write(w, 404, map[string]any{"error": "not found"})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runAgainstLeakyHub runs the full harness against the leaky hub.
func runAgainstLeakyHub(t testing.TB) Result {
	t.Helper()
	srv := newLeakyHub(t)
	routes := filepath.Join(t.TempDir(), "routes.tsv")
	spec := "GET\t/api/v1/cas\nGET\t/api/v1/cas/{id}\nDELETE\t/api/v1/cas/{id}\n"
	if err := os.WriteFile(routes, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadRoutes(routes)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(srv.URL)
	f, err := Seed(c, fakeBootstrap)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return Run(c, f, rs, Allowlist{}, t.Logf)
}
