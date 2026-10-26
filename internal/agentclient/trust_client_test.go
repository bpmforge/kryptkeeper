// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/agentclient"
)

func TestClient_TrustTasksAndResult(t *testing.T) {
	var got agentclient.TrustResult
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/agent/trust-tasks", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-ID") != "a1" || r.Header.Get("X-Agent-Token") != "tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []agentclient.TrustTask{{BundleID: "b1", Name: "n", Action: "add", CertPEM: "pem"}}})
	})
	mux.HandleFunc("POST /api/v1/agent/trust-result", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := agentclient.New(srv.URL, "a1", "tok", nil)
	tasks, err := c.GetTrustTasks(context.Background())
	if err != nil || len(tasks) != 1 || tasks[0].BundleID != "b1" || tasks[0].Action != "add" {
		t.Fatalf("tasks = %+v err=%v", tasks, err)
	}
	if err := c.PostTrustResult(context.Background(), agentclient.TrustResult{BundleID: "b1", Outcome: "applied", Detail: "ok"}); err != nil {
		t.Fatal(err)
	}
	if got.BundleID != "b1" || got.Outcome != "applied" {
		t.Fatalf("hub saw %+v", got)
	}

	bad := agentclient.New(srv.URL, "a1", "wrong", nil)
	if _, err := bad.GetTrustTasks(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token must surface the hub's refusal: %v", err)
	}
}
