// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
