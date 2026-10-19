// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const agentTestToken = "agent-test-token"

// newAgentTestAuth creates a bootstrap-mode authenticator for agent tests.
func newAgentTestAuth(t *testing.T) *Authenticator {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", agentTestToken)
	return NewAuthenticatorFromEnv()
}

// newAgentMux sets up only the agent routes.
func newAgentMux(t *testing.T) (*http.ServeMux, AgentStore) {
	t.Helper()
	// W5-07: these tests exercise the legacy open-registration mode
	// explicitly — the documented migration flag, not the default.
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	store := NewAgentStore()
	mux := http.NewServeMux()
	auth := newAgentTestAuth(t)
	registerAgentHandlers(mux, auth, store, stubAuditProvider{})
	return mux, store
}

func TestAgentRegister_CreatesAgentAndReturnsToken(t *testing.T) {
	mux, store := newAgentMux(t)

	body := `{"name":"test-agent","type":"linux"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["agent_id"] == "" {
		t.Error("expected agent_id in response")
	}
	if resp["token"] == "" {
		t.Error("expected token in response")
	}

	agents := store.list()
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent in store, got %d", len(agents))
	}
	if agents[0].Name != "test-agent" {
		t.Errorf("expected name 'test-agent', got %q", agents[0].Name)
	}
	if agents[0].Type != AgentTypeLinux {
		t.Errorf("expected type linux, got %q", agents[0].Type)
	}
}

func TestAgentRegister_MissingNameRejects(t *testing.T) {
	mux, _ := newAgentMux(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAgentHeartbeat_UpdatesLastSeen(t *testing.T) {
	mux, store := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "hb-agent", AgentTypeLinux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", nil)
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	agents := store.list()
	if len(agents) == 0 || agents[0].LastSeen == nil {
		t.Fatal("expected LastSeen to be set after heartbeat")
	}
	if agents[0].Status != AgentStatusActive {
		t.Errorf("expected status active, got %q", agents[0].Status)
	}
}

func TestAgentHeartbeat_WrongTokenRejects(t *testing.T) {
	mux, _ := newAgentMux(t)
	id, _ := registerTestAgent(t, mux, "hb-agent", AgentTypeLinux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", nil)
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", "wrong-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAgentInventory_StoresAndCountsCerts(t *testing.T) {
	mux, store := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "inv-agent", AgentTypeMac)

	inv := map[string]any{
		"certs": []map[string]any{
			{
				"fingerprint":    "aa:bb:cc",
				"subject":        "CN=example.com",
				"issuer":         "CN=Test CA",
				"not_before":     time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
				"not_after":      time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
				"source":         "/etc/ssl/example.crt",
				"auto_renewable": true,
			},
			{
				"fingerprint": "dd:ee:ff",
				"subject":     "CN=other.example.com",
				"issuer":      "CN=Test CA",
				"not_before":  time.Now().Add(-48 * time.Hour).Format(time.RFC3339),
				"not_after":   time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
				"source":      "/etc/ssl/other.crt",
			},
		},
	}
	b, _ := json.Marshal(inv)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/inventory", bytes.NewReader(b))
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]int
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["accepted"] != 2 {
		t.Errorf("expected accepted=2, got %d", resp["accepted"])
	}

	agents := store.list()
	if agents[0].InventoryCount != 2 {
		t.Errorf("expected inventory_count=2, got %d", agents[0].InventoryCount)
	}
}

func TestAgentInventory_StoresEndpoints(t *testing.T) {
	mux, store := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "ep-agent", AgentTypeLinux)

	inv := map[string]any{
		"certs": []map[string]any{},
		"endpoints": []map[string]any{
			{
				"server_type": "nginx",
				"cert_path":   "/etc/nginx/ssl/shop.crt",
				"key_path":    "/etc/nginx/ssl/shop.key",
				"server_name": "shop.example.com",
				"listen_port": 443,
				"config_path": "/etc/nginx/sites-enabled/shop.conf",
			},
		},
	}
	b, _ := json.Marshal(inv)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/inventory", bytes.NewReader(b))
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	eps := store.endpointsFor(id)
	if len(eps) != 1 {
		t.Fatalf("expected 1 stored endpoint, got %d", len(eps))
	}
	if eps[0].CertPath != "/etc/nginx/ssl/shop.crt" || eps[0].KeyPath != "/etc/nginx/ssl/shop.key" {
		t.Errorf("endpoint not stored correctly: %+v", eps[0])
	}
	if eps[0].ServerType != "nginx" || eps[0].ListenPort != 443 {
		t.Errorf("endpoint fields wrong: %+v", eps[0])
	}
}

func TestAgentInventory_UnauthorizedRejects(t *testing.T) {
	mux, _ := newAgentMux(t)
	registerTestAgent(t, mux, "inv-agent", AgentTypeLinux)

	body := `{"certs":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/inventory", bytes.NewBufferString(body))
	req.Header.Set("X-Agent-ID", "unknown-id")
	req.Header.Set("X-Agent-Token", "bad-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAgentTasks_EmptyByDefault(t *testing.T) {
	mux, _ := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "task-agent", AgentTypeWindows)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/tasks", nil)
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string][]AgentRenewalTask
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp["tasks"]) != 0 {
		t.Errorf("expected empty tasks, got %d", len(resp["tasks"]))
	}
}

func TestAgentTasks_UnauthorizedRejects(t *testing.T) {
	mux, _ := newAgentMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/tasks", nil)
	req.Header.Set("X-Agent-ID", "nobody")
	req.Header.Set("X-Agent-Token", "bad")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAgentList_RequiresAuth(t *testing.T) {
	mux, _ := newAgentMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAgentList_AdminSeesAllAgents(t *testing.T) {
	mux, _ := newAgentMux(t)
	registerTestAgent(t, mux, "agent-a", AgentTypeLinux)
	registerTestAgent(t, mux, "agent-b", AgentTypeMac)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+agentTestToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string][]AgentInfo
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp["agents"]) != 2 {
		t.Errorf("expected 2 agents, got %d", len(resp["agents"]))
	}
}

func TestAgentStatus_OfflineWithoutHeartbeat(t *testing.T) {
	store := NewAgentStore()
	id, _, _ := store.register("no-hb", AgentTypeLinux)
	agents := store.list()
	var found AgentInfo
	for _, a := range agents {
		if a.ID == id {
			found = a
		}
	}
	if found.Status != AgentStatusOffline {
		t.Errorf("expected offline before first heartbeat, got %q", found.Status)
	}
}

func TestAgentStatus_StaleAfterDelay(t *testing.T) {
	store := NewAgentStore()
	id, token, _ := store.register("stale-agent", AgentTypeLinux)
	_ = store.heartbeat(id, token)

	// Backdate last_seen by 10 minutes to trigger stale status (reach into the
	// in-memory store's internals for the test).
	mem := store.(*memAgentStore)
	mem.mu.Lock()
	stale := time.Now().UTC().Add(-10 * time.Minute)
	mem.records[id].info.LastSeen = &stale
	mem.mu.Unlock()

	agents := store.list()
	var found AgentInfo
	for _, a := range agents {
		if a.ID == id {
			found = a
		}
	}
	if found.Status != AgentStatusStale {
		t.Errorf("expected stale, got %q", found.Status)
	}
}

// registerTestAgent registers an agent via the HTTP endpoint and returns id + token.
func registerTestAgent(t *testing.T, mux *http.ServeMux, name string, agentType AgentType) (id, token string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name, "type": string(agentType)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("registerTestAgent: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	return resp["agent_id"], resp["token"]
}

func TestAgentRenewalResult_RecordsOutcome(t *testing.T) {
	mux, store := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "result-agent", AgentTypeLinux)

	body := map[string]any{
		"task_id":            "task-9",
		"fingerprint":        "abcd1234",
		"outcome":            "installed_verified",
		"served_fingerprint": "abcd1234",
		"rolled_back":        false,
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/renewal-result", bytes.NewReader(b))
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	results := store.resultsFor(id)
	if len(results) != 1 {
		t.Fatalf("expected 1 stored result, got %d", len(results))
	}
	if results[0].Outcome != "installed_verified" || results[0].TaskID != "task-9" {
		t.Errorf("stored result wrong: %+v", results[0])
	}
	if results[0].ReportedAt == "" {
		t.Error("expected ReportedAt to be set by the hub")
	}
}

// TestAgentTaskResults_ReturnsResultAfterSubmit covers W19-26's acceptance
// bar: the audit log used to be the only durable evidence of a renewal
// outcome; this proves it's now visible through the API too.
func TestAgentTaskResults_ReturnsResultAfterSubmit(t *testing.T) {
	mux, _ := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "results-agent", AgentTypeLinux)

	body := map[string]any{
		"task_id":     "task-42",
		"fingerprint": "fp-42",
		"outcome":     "installed_verified",
		"detail":      "renewed and verified over TLS",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/renewal-result", bytes.NewReader(b))
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("submit result: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+id+"/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+agentTestToken)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get task results: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string][]AgentTaskResult
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp["tasks"]) != 1 {
		t.Fatalf("expected 1 task/result row, got %d: %+v", len(resp["tasks"]), resp["tasks"])
	}
	got := resp["tasks"][0]
	if got.Status != "completed" || got.Outcome != "installed_verified" || got.Detail != "renewed and verified over TLS" {
		t.Errorf("result row wrong: %+v", got)
	}
	if got.TaskID != "task-42" || got.Fingerprint != "fp-42" {
		t.Errorf("result identity wrong: %+v", got)
	}
	if got.CompletedAt.IsZero() {
		t.Error("expected CompletedAt to be set")
	}
}

// TestAgentTaskResults_UnknownAgent404s covers the 404 acceptance case.
func TestAgentTaskResults_UnknownAgent404s(t *testing.T) {
	mux, _ := newAgentMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/no-such-agent/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+agentTestToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAgentTaskResults_RequiresAuth mirrors TestAgentList_RequiresAuth.
func TestAgentTaskResults_RequiresAuth(t *testing.T) {
	mux, _ := newAgentMux(t)
	id, _ := registerTestAgent(t, mux, "auth-agent", AgentTypeLinux)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+id+"/tasks", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestAgentTaskResults_IsolatedPerAgent proves one agent's result never
// leaks into another agent's GET /agents/{id}/tasks view -- the only
// isolation dimension that exists for agents today, since the schema has no
// tenant column (see the handler's doc comment).
func TestAgentTaskResults_IsolatedPerAgent(t *testing.T) {
	mux, _ := newAgentMux(t)
	idA, tokenA := registerTestAgent(t, mux, "agent-a-iso", AgentTypeLinux)
	idB, tokenB := registerTestAgent(t, mux, "agent-b-iso", AgentTypeLinux)

	submit := func(id, token, taskID, fp string) {
		b, _ := json.Marshal(map[string]any{"task_id": taskID, "fingerprint": fp, "outcome": "installed"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/renewal-result", bytes.NewReader(b))
		req.Header.Set("X-Agent-ID", id)
		req.Header.Set("X-Agent-Token", token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("submit for %s: expected 200, got %d", id, w.Code)
		}
	}
	submit(idA, tokenA, "task-a", "fp-a")
	submit(idB, tokenB, "task-b", "fp-b")

	fetch := func(id string) []AgentTaskResult {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+id+"/tasks", nil)
		req.Header.Set("Authorization", "Bearer "+agentTestToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("fetch for %s: expected 200, got %d", id, w.Code)
		}
		var resp map[string][]AgentTaskResult
		_ = json.NewDecoder(w.Body).Decode(&resp)
		return resp["tasks"]
	}

	tasksA := fetch(idA)
	if len(tasksA) != 1 || tasksA[0].TaskID != "task-a" {
		t.Fatalf("agent A view wrong: %+v", tasksA)
	}
	tasksB := fetch(idB)
	if len(tasksB) != 1 || tasksB[0].TaskID != "task-b" {
		t.Fatalf("agent B view wrong: %+v", tasksB)
	}
}

func TestAgentRenewalResult_UnauthorizedRejects(t *testing.T) {
	mux, _ := newAgentMux(t)
	_, _ = registerTestAgent(t, mux, "result-agent2", AgentTypeLinux)

	b, _ := json.Marshal(map[string]any{"task_id": "x", "outcome": "installed"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/renewal-result", bytes.NewReader(b))
	req.Header.Set("X-Agent-ID", "bogus")
	req.Header.Set("X-Agent-Token", "bogus")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// agentAuditLog records every audit entry (capturingAuditProvider keeps only
// the last one).
type agentAuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (p *agentAuditLog) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (p *agentAuditLog) AppendEntry(_ context.Context, e AuditEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, e)
	return nil
}

func (p *agentAuditLog) has(action, resourceID string, outcome AuditOutcome) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		if e.Action == action && e.ResourceID == resourceID && e.Outcome == outcome {
			return true
		}
	}
	return false
}

func newAgentAdminMux(t *testing.T) (*http.ServeMux, AgentStore, *agentAuditLog, *Authenticator) {
	t.Helper()
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	store := NewAgentStore()
	audit := &agentAuditLog{}
	auth := newAgentTestAuth(t)
	mux := http.NewServeMux()
	registerAgentHandlers(mux, auth, store, audit)
	return mux, store, audit, auth
}

func agentCall(mux *http.ServeMux, method, path, bearer string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func agentHeartbeat(mux *http.ServeMux, id, token, version string) *httptest.ResponseRecorder {
	h := map[string]string{"X-Agent-ID": id, "X-Agent-Token": token}
	if version != "" {
		h["X-Agent-Version"] = version
	}
	return agentCall(mux, http.MethodPost, "/api/v1/agent/heartbeat", "", h)
}

func listAgentsVia(t *testing.T, mux *http.ServeMux) map[string]AgentInfo {
	t.Helper()
	w := agentCall(mux, http.MethodGet, "/api/v1/agents", agentTestToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list agents: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Agents []AgentInfo `json:"agents"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := map[string]AgentInfo{}
	for _, a := range resp.Agents {
		out[a.ID] = a
	}
	return out
}

func TestAgentList_ReturnsVersion(t *testing.T) {
	mux, _, _, _ := newAgentAdminMux(t)
	withID, withTok := registerTestAgent(t, mux, "versioned", AgentTypeLinux)
	noID, noTok := registerTestAgent(t, mux, "silent-version", AgentTypeLinux)

	if w := agentHeartbeat(mux, withID, withTok, "1.2.3"); w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d", w.Code)
	}
	if w := agentHeartbeat(mux, noID, noTok, ""); w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d", w.Code)
	}
	got := listAgentsVia(t, mux)
	if got[withID].Version != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", got[withID].Version)
	}
	if got[noID].Version != "" {
		t.Errorf("version = %q, want empty for agent that never reported", got[noID].Version)
	}
	w := agentCall(mux, http.MethodGet, "/api/v1/agents", agentTestToken, nil)
	if !strings.Contains(w.Body.String(), `"version":"1.2.3"`) || !strings.Contains(w.Body.String(), `"version":""`) {
		t.Errorf("wire JSON lacks version field: %s", w.Body.String())
	}
}

func TestAgentVersion_RejectedTokenDoesNotSetVersionAndIsCapped(t *testing.T) {
	mux, _, _, _ := newAgentAdminMux(t)
	id, tok := registerTestAgent(t, mux, "v", AgentTypeLinux)
	if w := agentHeartbeat(mux, id, "wrong-token", "6.6.6"); w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if v := listAgentsVia(t, mux)[id].Version; v != "" {
		t.Fatalf("unauthenticated heartbeat set version %q", v)
	}
	agentHeartbeat(mux, id, tok, strings.Repeat("v", 200))
	if v := listAgentsVia(t, mux)[id].Version; len(v) != maxAgentVersionLen {
		t.Fatalf("version length = %d, want capped at %d", len(v), maxAgentVersionLen)
	}
}

func TestAgentStatusAt_FakeClock(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		now  time.Time
		want AgentStatus
	}{
		{"4m59s", t0.Add(4*time.Minute + 59*time.Second), AgentStatusActive},
		{"5m", t0.Add(5 * time.Minute), AgentStatusStale},
		{"29m59s", t0.Add(29*time.Minute + 59*time.Second), AgentStatusStale},
		{"30m", t0.Add(30 * time.Minute), AgentStatusOffline},
	}
	for _, c := range cases {
		if got := computeAgentStatusAt(&t0, c.now); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if got := computeAgentStatusAt(nil, t0); got != AgentStatusOffline {
		t.Errorf("nil lastSeen: got %q, want offline", got)
	}
}

func TestAgentDelete_RevokesToken(t *testing.T) {
	mux, _, audit, _ := newAgentAdminMux(t)
	id, tok := registerTestAgent(t, mux, "doomed", AgentTypeLinux)
	if w := agentHeartbeat(mux, id, tok, ""); w.Code != http.StatusOK {
		t.Fatalf("heartbeat before delete: %d", w.Code)
	}
	if w := agentCall(mux, http.MethodDelete, "/api/v1/agents/"+id, agentTestToken, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d %s", w.Code, w.Body.String())
	}
	if w := agentHeartbeat(mux, id, tok, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("heartbeat after delete: want 401, got %d", w.Code)
	}
	if !audit.has("agent.remove", id, AuditOutcomeSuccess) {
		t.Error("missing agent.remove audit entry")
	}
	if _, ok := listAgentsVia(t, mux)[id]; ok {
		t.Error("removed agent still listed")
	}
}

func TestAgentDelete_RequiresAdmin(t *testing.T) {
	mux, store, audit, auth := newAgentAdminMux(t)
	id, tok := registerTestAgent(t, mux, "kept", AgentTypeLinux)
	_, viewer, err := auth.CreateAPIKey("viewer-key", "viewer-1", "pki-viewer", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if w := agentCall(mux, http.MethodDelete, "/api/v1/agents/"+id, viewer, nil); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin delete: want 403, got %d", w.Code)
	}
	if w := agentHeartbeat(mux, id, tok, ""); w.Code != http.StatusOK {
		t.Fatalf("agent must survive a denied delete, heartbeat = %d", w.Code)
	}
	if len(store.list()) != 1 {
		t.Fatal("agent was removed by non-admin")
	}
	if !audit.has("agent.remove", id, AuditOutcomeDenied) {
		t.Error("missing denied audit entry")
	}
}

func TestAgentDelete_UnknownIs404(t *testing.T) {
	mux, _, audit, _ := newAgentAdminMux(t)
	if w := agentCall(mux, http.MethodDelete, "/api/v1/agents/nope", agentTestToken, nil); w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if !audit.has("agent.remove", "nope", AuditOutcomeFailure) {
		t.Error("404 must leave a failure audit row")
	}
}

func TestAgentDelete_Unauthenticated401(t *testing.T) {
	mux, store, _, _ := newAgentAdminMux(t)
	id, _ := registerTestAgent(t, mux, "x", AgentTypeLinux)
	if w := agentCall(mux, http.MethodDelete, "/api/v1/agents/"+id, "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if len(store.list()) != 1 {
		t.Fatal("unauthenticated delete removed the agent")
	}
}

func TestAgentPruneSilent(t *testing.T) {
	store := NewAgentStore()
	oldID, oldTok, _ := store.register("old", AgentTypeLinux)
	newID, newTok, _ := store.register("new", AgentTypeLinux)
	neverID, _, _ := store.register("never-seen-old", AgentTypeLinux)
	_ = store.heartbeat(oldID, oldTok)
	_ = store.heartbeat(newID, newTok)

	mem := store.(*memAgentStore)
	mem.mu.Lock()
	old := time.Now().UTC().Add(-48 * time.Hour)
	mem.records[oldID].info.LastSeen = &old
	mem.records[oldID].info.RegisteredAt = old
	mem.records[neverID].info.RegisteredAt = old
	mem.mu.Unlock()

	removed := store.pruneSilent(time.Now().Add(-24 * time.Hour))
	sort.Strings(removed)
	want := []string{oldID, neverID}
	sort.Strings(want)
	if strings.Join(removed, ",") != strings.Join(want, ",") {
		t.Fatalf("removed %v, want %v", removed, want)
	}
	if l := store.list(); len(l) != 1 || l[0].ID != newID {
		t.Fatalf("survivors = %+v, want only %s", l, newID)
	}
}

func TestAgentList_PrunesOnlyWhenEnabled(t *testing.T) {
	mux, store, audit, _ := newAgentAdminMux(t)
	id, tok := registerTestAgent(t, mux, "stale-one", AgentTypeLinux)
	agentHeartbeat(mux, id, tok, "")
	old := time.Now().UTC().Add(-72 * time.Hour)
	store.(*memAgentStore).mu.Lock()
	store.(*memAgentStore).records[id].info.LastSeen = &old
	store.(*memAgentStore).records[id].info.RegisteredAt = old
	store.(*memAgentStore).mu.Unlock()

	if _, ok := listAgentsVia(t, mux)[id]; !ok {
		t.Fatal("agent pruned although KRYPTKEEPER_AGENT_PRUNE_AFTER is unset")
	}
	t.Setenv("KRYPTKEEPER_AGENT_PRUNE_AFTER", "24h")
	if _, ok := listAgentsVia(t, mux)[id]; ok {
		t.Fatal("silent agent not pruned with prune enabled")
	}
	if !audit.has("agent.prune", id, AuditOutcomeSuccess) {
		t.Error("missing agent.prune audit entry")
	}
}

func TestAgentPruneAfterFromEnv(t *testing.T) {
	cases := map[string]time.Duration{
		"": 0, "garbage": 0, "-5h": 0, "0": 0,
		"10m": time.Hour, "1h": time.Hour, "72h": 72 * time.Hour,
	}
	for in, want := range cases {
		t.Setenv("KRYPTKEEPER_AGENT_PRUNE_AFTER", in)
		if got := agentPruneAfterFromEnv(); got != want {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
	}
}

func pushInventory(t *testing.T, mux *http.ServeMux, id, token string, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/inventory", bytes.NewReader(b))
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("inventory: %d %s", w.Code, w.Body)
	}
}

func hostPushFixture() map[string]any {
	return map[string]any{
		"certs":            []any{},
		"host_scanned":     true,
		"privilege_mode":   "none",
		"scan_user":        "kryptkeeper-agent",
		"unreadable_paths": []map[string]string{{"path": "/opt/tomcat/conf/keystore.jks", "error": "permission denied"}},
		"unreadable_total": 1,
		"files": []map[string]any{
			{"path": "/opt/tomcat/conf/keystore.jks", "kind": "jks", "owner": "root", "group": "root", "mode": "600", "uid": 0, "gid": 0},
			{"path": "/etc/nginx/ssl/a.key", "kind": "key", "owner": "root", "group": "root", "mode": "644", "uid": 0, "gid": 0},
		},
		"listeners": []map[string]any{
			{"port": 8443, "pid": 9, "uid": 1001, "gid": 1001, "comm": "java", "tech": "tomcat", "app_dirs": []string{"/opt/tomcat"}},
		},
	}
}

func TestAgentInventoryHostPassComputesPostureAndRecordsInsufficientPrivilege(t *testing.T) {
	mux, store := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "host-agent", AgentTypeLinux)
	pushInventory(t, mux, id, token, hostPushFixture())

	hr := store.list()[0].HostReport
	if hr == nil || !hr.PostureKnown || hr.PrivilegeMode != "none" || hr.UnreadableCount != 1 || len(hr.UnreadablePaths) != 1 {
		t.Fatalf("report: %+v", hr)
	}
	joined := strings.Join(hr.Findings, "\n")
	for _, want := range []string{"INSUFFICIENT_PRIVILEGE: uid=unknown; user=kryptkeeper-agent; mode=none; unreadable=1", "KEY_WORLD_READABLE:", "PRIVILEGED_INSTALL_PATH:"} {
		if !strings.Contains(joined, want) {
			t.Errorf("findings lack %q:\n%s", want, joined)
		}
	}
	byPath := map[string]AgentHostFile{}
	for _, f := range hr.Files {
		byPath[f.Path] = f
	}
	if byPath["/opt/tomcat/conf/keystore.jks"].Posture != "privileged" || byPath["/opt/tomcat/conf/keystore.jks"].ServiceTech != "tomcat" {
		t.Fatalf("the same posture as an SSH target: %+v", byPath)
	}
	if hr.ListenerCount != 1 || hr.PostureCounts["privileged"] != 1 {
		t.Fatalf("%+v", hr)
	}
	// The API's agent list carries it for the detail page.
	list := doAgentList(t, mux)
	if !strings.Contains(list, `"host_report"`) || !strings.Contains(list, `"unreadable_count":1`) {
		t.Fatalf("list lacks the report: %s", list)
	}

	// After the helper rule is added the agent reports nothing unreadable.
	ok := hostPushFixture()
	ok["unreadable_paths"], ok["unreadable_total"], ok["privilege_mode"] = []any{}, 0, "helper"
	pushInventory(t, mux, id, token, ok)
	hr = store.list()[0].HostReport
	if hr.UnreadableCount != 0 || strings.Contains(strings.Join(hr.Findings, "\n"), "INSUFFICIENT_PRIVILEGE") || hr.PrivilegeMode != "helper" {
		t.Fatalf("%+v", hr)
	}
}

func TestAgentInventoryPreW34AgentIsUnknownPostureNotStandard(t *testing.T) {
	mux, store := newAgentMux(t)
	id, token := registerTestAgent(t, mux, "old-agent", AgentTypeLinux)
	pushInventory(t, mux, id, token, map[string]any{"certs": []any{}, "endpoints": []any{}})
	hr := store.list()[0].HostReport
	if hr == nil || hr.PostureKnown || len(hr.Files) != 0 || len(hr.PostureCounts) != 0 || len(hr.Findings) != 0 {
		t.Fatalf("a pre-W34 agent must read as unknown posture: %+v", hr)
	}
}

func TestBuildAgentHostReportCapsAndHiddenListeners(t *testing.T) {
	var paths []AgentUnreadablePath
	for i := 0; i < 80; i++ {
		paths = append(paths, AgentUnreadablePath{Path: fmt.Sprintf("/srv/k/%d.jks", i), Error: "permission denied"})
	}
	minus := -1
	rep := buildAgentHostReport(agentHostPush{HostScanned: true, PrivilegeMode: "nopasswd", ScanUser: "a", UnreadablePaths: paths, UnreadableTotal: 120,
		Listeners: []agentPushListener{{Port: 25, UID: &minus}, {Port: 80, PID: 1, Comm: "nginx", Tech: "nginx"}}}, time.Now())
	if rep.UnreadableCount != 120 || len(rep.UnreadablePaths) != maxAgentReportPaths {
		t.Fatalf("count/cap: %d %d", rep.UnreadableCount, len(rep.UnreadablePaths))
	}
	if !strings.Contains(rep.Findings[0], "unreadable=120") || !strings.Contains(rep.Findings[0], "(+110 more)") {
		t.Fatalf("%s", rep.Findings[0])
	}
	if rep.ListenersHidden != 2 {
		// A listener sent without a uid reads as unknown; an explicit -1 as well.
		t.Fatalf("hidden = %d", rep.ListenersHidden)
	}
}

func TestDBAgentStoreKeepsHostReport(t *testing.T) {
	s := newTestDBAgentStore(t)
	id, token, err := s.register("n", AgentTypeLinux)
	if err != nil {
		t.Fatal(err)
	}
	_ = token
	s.setHostReport(id, AgentHostReport{PostureKnown: true, UnreadableCount: 3, PrivilegeMode: "helper"})
	got := s.list()[0].HostReport
	if got == nil || !got.PostureKnown || got.UnreadableCount != 3 || got.PrivilegeMode != "helper" {
		t.Fatalf("%+v", got)
	}
}

func doAgentList(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	w := agentCall(mux, http.MethodGet, "/api/v1/agents", agentTestToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	return w.Body.String()
}
