// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W24-45: GET /api/v1/agents/{id}/inventory.

func pushAgentInventory(t *testing.T, mux *http.ServeMux, id, token string, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/inventory", bytes.NewReader(b))
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("push inventory: %d %s", w.Code, w.Body.String())
	}
}

func getAgentInventory(mux *http.ServeMux, id, query, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+id+"/inventory"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func inventoryCerts(n int) []map[string]any {
	out := make([]map[string]any, n)
	for i := range out {
		out[i] = map[string]any{
			"fingerprint": fmt.Sprintf("fp-%02d", i), "subject": fmt.Sprintf("CN=svc-%02d.example.com", i), "issuer": "CN=Test CA",
			"not_before": time.Now().Add(-time.Hour).Format(time.RFC3339), "not_after": time.Now().Add(48 * time.Hour).Format(time.RFC3339),
			"source": fmt.Sprintf("/etc/ssl/svc-%02d.pem", i),
		}
	}
	return out
}

func TestAgentInventoryAPIReturnsCertificatesAndFilesPaginated(t *testing.T) {
	mux, _ := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "inv-api", AgentTypeLinux)
	pushAgentInventory(t, mux, id, token, map[string]any{
		"certs":        inventoryCerts(5),
		"host_scanned": true,
		"files": []map[string]any{
			{"path": "/etc/ssl/svc-00.pem", "kind": "pem", "owner": "root", "group": "root", "mode": "0644"},
			{"path": "/etc/ssl/private/svc-00.key", "kind": "key", "owner": "root", "group": "root", "mode": "0600"},
		},
	})

	w := getAgentInventory(mux, id, "?limit=2&offset=1", agentTestToken)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	var page AgentInventoryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.AgentID != id || page.TotalCertificates != 5 || len(page.Certificates) != 2 || page.Limit != 2 || page.Offset != 1 {
		t.Fatalf("paging wrong: %+v", page)
	}
	if page.Certificates[0].Fingerprint != "fp-01" || page.Certificates[1].Fingerprint != "fp-02" {
		t.Fatalf("pages must be in a stable order: %+v", page.Certificates)
	}
	counted := 0
	for _, n := range page.FilePostureCounts {
		counted += n
	}
	if !page.FilesKnown || counted != 2 || page.TotalFiles > counted || len(page.Files) > page.TotalFiles {
		t.Fatalf("files wrong (every statted file is counted, only flagged ones listed): %+v", page)
	}

	last := getAgentInventory(mux, id, "?limit=2&offset=4", agentTestToken)
	var tail AgentInventoryResponse
	_ = json.Unmarshal(last.Body.Bytes(), &tail)
	if len(tail.Certificates) != 1 || tail.Certificates[0].Fingerprint != "fp-04" {
		t.Fatalf("last page: %+v", tail.Certificates)
	}
	past := getAgentInventory(mux, id, "?offset=99", agentTestToken)
	var empty AgentInventoryResponse
	_ = json.Unmarshal(past.Body.Bytes(), &empty)
	if past.Code != http.StatusOK || len(empty.Certificates) != 0 || empty.TotalCertificates != 5 || strings.Contains(past.Body.String(), "null") {
		t.Fatalf("an offset past the end is an empty page, not an error or null: %d %s", past.Code, past.Body.String())
	}
}

func TestAgentInventoryAPIShowsNoKeyMaterialAndIsPerAgent(t *testing.T) {
	mux, _ := newAgentMux(t)
	idA, tokA := registerTestAgent(t, mux, "a", AgentTypeLinux)
	idB, tokB := registerTestAgent(t, mux, "b", AgentTypeLinux)
	pushAgentInventory(t, mux, idA, tokA, map[string]any{"certs": inventoryCerts(1)})
	pushAgentInventory(t, mux, idB, tokB, map[string]any{"certs": inventoryCerts(3)})

	a := getAgentInventory(mux, idA, "", agentTestToken)
	var ra, rb AgentInventoryResponse
	_ = json.Unmarshal(a.Body.Bytes(), &ra)
	_ = json.Unmarshal(getAgentInventory(mux, idB, "", agentTestToken).Body.Bytes(), &rb)
	if ra.TotalCertificates != 1 || rb.TotalCertificates != 3 {
		t.Fatalf("an agent sees only its own rows: %d / %d", ra.TotalCertificates, rb.TotalCertificates)
	}
	if ra.FilesKnown || len(ra.Files) != 0 {
		t.Fatalf("an agent with no host pass has unknown files, not empty ones: %+v", ra)
	}
	for _, banned := range []string{"PRIVATE KEY", "BEGIN", "key_bytes"} {
		if strings.Contains(a.Body.String(), banned) {
			t.Fatalf("response carries %q", banned)
		}
	}
}

func TestAgentInventoryAPIAuthAndErrors(t *testing.T) {
	mux, _ := newAgentMux(t)
	id, _ := registerTestAgent(t, mux, "e", AgentTypeLinux)
	if w := getAgentInventory(mux, id, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials: %d", w.Code)
	}
	if w := getAgentInventory(mux, "no-such-agent", "", agentTestToken); w.Code != http.StatusNotFound {
		t.Fatalf("unknown agent: %d", w.Code)
	}
	for _, q := range []string{"?limit=0", "?limit=501", "?limit=x", "?offset=-1", "?offset=x"} {
		if w := getAgentInventory(mux, id, q, agentTestToken); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", q, w.Code)
		}
	}
}

// D-203: agents carry no tenant, so a tenant-scoped principal is refused, and
// the refusal is audited, exactly as for GET /agents and /agents/{id}/tasks.
func TestAgentInventoryAPIRefusesTenantScopedPrincipals(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	w := getAgentInventory(mux, "any-agent", "", acmeToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped principal: %d %s", w.Code, w.Body.String())
	}
}
