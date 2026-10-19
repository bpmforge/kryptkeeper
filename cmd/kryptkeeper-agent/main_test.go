// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/agentclient"
)

// TestRenewalIdentifiers_UsesHubIdentifiers covers W19-13: when the hub sends
// Identifiers, the renewer must use those verbatim rather than parsing
// Subject at all.
func TestRenewalIdentifiers_UsesHubIdentifiers(t *testing.T) {
	task := agentclient.RenewalTask{Subject: "CN=localhost", Identifiers: []string{"shop.example.com"}}
	got := renewalIdentifiers(task)
	if len(got) != 1 || got[0] != "shop.example.com" {
		t.Fatalf("renewalIdentifiers = %v, want [shop.example.com]", got)
	}
}

// TestRenewalIdentifiers_FallsBackToSubjectCN covers the compatibility path:
// a pre-W19-13 hub sends no Identifiers, so the agent parses a hostname out
// of Subject's CN -- never uses Subject itself.
func TestRenewalIdentifiers_FallsBackToSubjectCN(t *testing.T) {
	task := agentclient.RenewalTask{Subject: "CN=localhost"}
	got := renewalIdentifiers(task)
	if len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("renewalIdentifiers = %v, want [localhost]", got)
	}
}

// TestRenewalIdentifiers_UnparsableSubjectYieldsNone covers the case where
// neither Identifiers nor a hostname-shaped CN is available: the renewer
// must not fall back to the raw RDN string.
func TestRenewalIdentifiers_UnparsableSubjectYieldsNone(t *testing.T) {
	task := agentclient.RenewalTask{Subject: "CN=My Service"}
	got := renewalIdentifiers(task)
	if len(got) != 0 {
		t.Fatalf("renewalIdentifiers = %v, want none for a non-hostname CN", got)
	}
}

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"shop.example.com", true},
		{"my-service.example.com", true},
		{"", false},
		{"My Service", false},
		{"192.168.1.1", false},
		{"-bad.example.com", false},
		{"bad-.example.com", false},
	}
	for _, tt := range tests {
		if got := isValidHostname(tt.host); got != tt.want {
			t.Errorf("isValidHostname(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestStartupBanner_IncludesVersion(t *testing.T) {
	old := version
	version = "9.8.7-test"
	defer func() { version = old }()
	if got := startupBanner(); !strings.Contains(got, "9.8.7-test") {
		t.Fatalf("startupBanner() = %q, want it to contain the version", got)
	}
}

// enrollHub is a minimal hub: it records register calls and heartbeats and
// answers every other agent route with an empty JSON object.
type enrollHub struct {
	srv        *httptest.Server
	registers  atomic.Int32
	heartbeats atomic.Int32
	body       atomic.Value // map[string]any of the last register body
}

func newEnrollHub(t *testing.T) *enrollHub {
	t.Helper()
	h := &enrollHub{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/register", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		h.body.Store(m)
		h.registers.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"agent_id":"a1","token":"t1"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/heartbeat") {
			h.heartbeats.Add(1)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

// runUntilHeartbeat runs the agent until the hub has seen a heartbeat.
func runUntilHeartbeat(t *testing.T, h *enrollHub, want int32) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { run(ctx); close(done) }()
	deadline := time.After(20 * time.Second)
	for h.heartbeats.Load() < want {
		select {
		case <-deadline:
			cancel()
			t.Fatal("agent never heartbeated")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func enrollEnv(t *testing.T, hubURL, credFile string) {
	t.Helper()
	serviceEnvFile = ""
	empty := t.TempDir()
	t.Setenv("KRYPTKEEPER_HUB_URL", hubURL)
	t.Setenv("KRYPTKEEPER_AGENT_NAME", "web-01")
	t.Setenv("KRYPTKEEPER_AGENT_CREDENTIALS_FILE", credFile)
	t.Setenv("KRYPTKEEPER_SCAN_PATHS", empty)
	t.Setenv("KRYPTKEEPER_CONFIG_PATHS", filepath.Join(empty, "none"))
	t.Setenv("KRYPTKEEPER_POLL_INTERVAL", "1")
	t.Setenv("KRYPTKEEPER_AGENT_ID", "")
	t.Setenv("KRYPTKEEPER_AGENT_TOKEN", "")
	os.Unsetenv("KRYPTKEEPER_AGENT_ID")
	os.Unsetenv("KRYPTKEEPER_AGENT_TOKEN")
}

func TestRun_ExchangesEnrollTokenAndPersistsCredentials(t *testing.T) {
	h := newEnrollHub(t)
	cred := filepath.Join(t.TempDir(), "cred.env")
	enrollEnv(t, h.srv.URL, cred)
	t.Setenv("KRYPTKEEPER_ENROLL_TOKEN", "tok-1")
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRET", "should-not-be-sent")

	runUntilHeartbeat(t, h, 1)

	if n := h.registers.Load(); n != 1 {
		t.Fatalf("register calls = %d, want 1", n)
	}
	body := h.body.Load().(map[string]any)
	if body["enrollment_token"] != "tok-1" {
		t.Fatalf("enrollment_token = %v", body["enrollment_token"])
	}
	if _, ok := body["enrollment_secret"]; ok {
		t.Fatal("enrollment_secret must not be sent alongside a token")
	}
	info, err := os.Stat(cred)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(cred)
	if !strings.Contains(string(data), "KRYPTKEEPER_AGENT_ID=a1") || !strings.Contains(string(data), "KRYPTKEEPER_AGENT_TOKEN=t1") {
		t.Fatalf("credentials file = %q", data)
	}
	if strings.Contains(string(data), "tok-1") {
		t.Fatal("enrollment token must not be persisted")
	}
	if os.Getenv("KRYPTKEEPER_ENROLL_TOKEN") != "" {
		t.Fatal("enrollment token must be unset from the environment")
	}
}

func TestRun_ReusesPersistedCredentials_NoSecondExchange(t *testing.T) {
	h := newEnrollHub(t)
	cred := filepath.Join(t.TempDir(), "cred.env")
	enrollEnv(t, h.srv.URL, cred)
	if err := writeCredentialsFile(cred, "a1", "t1"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRYPTKEEPER_ENROLL_TOKEN", "tok-spent")

	runUntilHeartbeat(t, h, 1)

	if n := h.registers.Load(); n != 0 {
		t.Fatalf("register calls = %d, want 0", n)
	}
}

func TestScrubEnrollToken_RemovesOnlyThatLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.env")
	in := "KRYPTKEEPER_HUB_URL=https://hub\nKRYPTKEEPER_ENROLL_TOKEN=kke_secret\n# note\nKRYPTKEEPER_AGENT_ID=a1\nKRYPTKEEPER_AGENT_TOKEN=t1\n"
	if err := os.WriteFile(path, []byte(in), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := scrubEnrollToken(path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	want := "KRYPTKEEPER_HUB_URL=https://hub\n# note\nKRYPTKEEPER_AGENT_ID=a1\nKRYPTKEEPER_AGENT_TOKEN=t1\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	if err := scrubEnrollToken(path); err != nil { // no such line -> no-op
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); string(again) != want {
		t.Fatal("no-op scrub changed the file")
	}
	if err := scrubEnrollToken(filepath.Join(dir, "missing.env")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestGenerateSudoersUsesPrivexecRenderer(t *testing.T) {
	raw, err := generateSudoers(sudoersModeFlag(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kryptkeeper-agent ALL=(root) NOPASSWD:", "/usr/bin/install -m * /etc/nginx/ssl/*", "'*' matches '/' too"} {
		if !strings.Contains(raw, want) {
			t.Errorf("raw drop-in lacks %q", want)
		}
	}
	if strings.Contains(raw, "do not span") {
		t.Error("the wrong 'wildcards do not span /' claim is back")
	}
	h, err := generateSudoers(sudoersModeFlag([]string{"--generate-sudoers", "--sudoers-mode=helper"}))
	if err != nil || !strings.Contains(h, "/usr/local/sbin/kryptkeeper-helper") || strings.Contains(h, "KK_READ") {
		t.Fatalf("helper drop-in: %v\n%s", err, h)
	}
	if _, err := generateSudoers("bogus"); err == nil {
		t.Error("unknown mode accepted")
	}
}
