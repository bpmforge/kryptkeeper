// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// stubhub is the smallest hub the real kryptkeeper-agent can talk to: it
// answers the agent loop and serves one scripted trust bundle, so the live
// trust store run proves the AGENT half (opt-in, sudo helper, OS commands)
// against real distributions without standing a whole hub up in each. The hub
// half (approval gating, validation) is covered by the bootstrap tests.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "listen address")
	bundle := flag.String("bundle", "", "PEM file served as the bundle")
	actionFile := flag.String("action-file", "", "file holding add, remove or none, read on every poll")
	results := flag.String("results", "", "file the agent's trust results are appended to")
	flag.Parse()

	var mu sync.Mutex
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
	mux.HandleFunc("/api/v1/agent/heartbeat", func(w http.ResponseWriter, _ *http.Request) { ok(w, `{"status":"ok"}`) })
	mux.HandleFunc("/api/v1/agent/inventory", func(w http.ResponseWriter, _ *http.Request) { ok(w, `{"accepted":0}`) })
	mux.HandleFunc("/api/v1/agent/tasks", func(w http.ResponseWriter, _ *http.Request) { ok(w, `{"tasks":[]}`) })
	mux.HandleFunc("/api/v1/agent/trust-tasks", func(w http.ResponseWriter, _ *http.Request) {
		raw, _ := os.ReadFile(*actionFile)
		action := strings.TrimSpace(string(raw))
		if action != "add" && action != "remove" {
			ok(w, `{"tasks":[]}`)
			return
		}
		pem, err := os.ReadFile(*bundle)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out, _ := json.Marshal(map[string]any{"tasks": []map[string]string{{
			"bundle_id": "live-" + action, "name": "live " + action, "action": action, "cert_pem": string(pem),
		}}})
		ok(w, string(out))
	})
	mux.HandleFunc("/api/v1/agent/trust-result", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		line, _ := json.Marshal(body)
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(*results, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			_, _ = f.Write(append(line, '\n'))
			_ = f.Close()
		}
		ok(w, `{"status":"recorded"}`)
	})
	log.Fatal(http.ListenAndServe(*addr, mux))
}
