// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// W17-09: the listener + the operator API that fills the registry it
// consults. Either alone is inert.

func selectorMux(t *testing.T, registry *SelectorRegistry) *http.ServeMux {
	t.Helper()
	t.Setenv("SPIFFE_TRUST_DOMAIN", "example.org")
	mux := http.NewServeMux()
	registerWorkloadSelectorHandlers(mux, newReportsTestAuth(t), registry, stubAuditProvider{})
	return mux
}

func TestWorkloadSelectorBindAndList(t *testing.T) {
	registry := NewSelectorRegistry()
	mux := selectorMux(t, registry)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/spiffe/workload-selectors",
		[]byte(`{"uid":1001,"spiffe_id":"spiffe://example.org/ns/prod/sa/checkout"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	// The binding must actually reach the registry the ATTESTOR reads —
	// an operator API that writes somewhere else would be inert.
	if id, ok := registry.lookup(1001); !ok || id != "spiffe://example.org/ns/prod/sa/checkout" {
		t.Fatalf("binding did not reach the attestor's registry: %q %v", id, ok)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/spiffe/workload-selectors", nil))
	var resp struct {
		Data struct {
			Selectors []SelectorBinding `json:"selectors"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Selectors) != 1 || resp.Data.Selectors[0].UID != 1001 {
		t.Fatalf("list must show the binding: %+v", resp.Data.Selectors)
	}
}

// Binding a UID to ANOTHER trust domain's identity would mint an SVID
// this CA has no authority to assert.
func TestWorkloadSelectorRejectsForeignTrustDomain(t *testing.T) {
	mux := selectorMux(t, NewSelectorRegistry())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/spiffe/workload-selectors",
		[]byte(`{"uid":1002,"spiffe_id":"spiffe://someone-else.example/ns/x/sa/y"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a foreign trust domain must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestWorkloadSelectorRequiresApprover(t *testing.T) {
	mux := selectorMux(t, NewSelectorRegistry())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/spiffe/workload-selectors", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// The listener is OFF unless a socket is configured — a gRPC endpoint
// handing out SVIDs must never start by accident.
func TestWorkloadAPIDoesNotStartWithoutSocket(t *testing.T) {
	t.Setenv(SPIFFEWorkloadSocketEnv, "")
	if srv := startWorkloadAPIIfConfigured(NewSelectorRegistry(), stubAuditProvider{}); srv != nil {
		srv.Stop()
		t.Fatal("the Workload API must not start when no socket is configured")
	}
}

func TestWorkloadAPIStartsWhenSocketConfigured(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kkwl9")
	if err != nil {
		t.Fatalf("tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := dir + "/w.sock"
	t.Setenv(SPIFFEWorkloadSocketEnv, sock)

	srv := startWorkloadAPIIfConfigured(NewSelectorRegistry(), stubAuditProvider{})
	if srv == nil {
		t.Fatal("a configured socket must start the listener")
	}
	t.Cleanup(srv.Stop)
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("the socket must exist: %v", err)
	}
}
