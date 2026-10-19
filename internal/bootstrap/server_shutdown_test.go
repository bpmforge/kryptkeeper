// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type drainHarness struct {
	cancel context.CancelFunc
	url    string
	done   chan error
}

func startDrainServer(t *testing.T, drain time.Duration, onDrain func()) *drainHarness {
	return startDrainServerT(t, drain, 5*time.Second, onDrain, nil)
}

func startDrainServerT(t *testing.T, drain, shutdownTimeout time.Duration, onDrain func(), extra func(*http.ServeMux)) *drainHarness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	draining := new(atomic.Bool)
	mux := http.NewServeMux()
	registerMetaHandlers(mux, withDrainProbe(draining, nil))
	if extra != nil {
		extra(mux)
	}
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	h := &drainHarness{cancel: cancel, url: "http://" + addr, done: make(chan error, 1)}
	go func() { h.done <- runServerCtx(ctx, srv, draining, onDrain, drain, shutdownTimeout) }()
	t.Cleanup(cancel)

	deadline := time.Now().Add(3 * time.Second)
	for {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return h
}

func get(t *testing.T, url string) (int, string, error) {
	t.Helper()
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func TestShutdownDrain_ReadyzTurns503WhileStillServing(t *testing.T) {
	h := startDrainServer(t, 600*time.Millisecond, nil)
	if code, _, err := get(t, h.url+"/readyz"); err != nil || code != 200 {
		t.Fatalf("before shutdown: code=%d err=%v", code, err)
	}
	h.cancel()
	time.Sleep(150 * time.Millisecond) // inside the drain window

	code, body, err := get(t, h.url+"/readyz")
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("readyz during drain: code=%d err=%v", code, err)
	}
	if want := `{"status":"unready","error":"shutting down"}`; body != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	if code, _, err := get(t, h.url+"/healthz"); err != nil || code != 200 {
		t.Fatalf("healthz during drain: code=%d err=%v", code, err)
	}
	if code, _, err := get(t, h.url+"/"); err != nil || code != 200 {
		t.Fatalf("regular request during drain: code=%d err=%v", code, err)
	}
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("runServerCtx: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop after drain")
	}
	if _, _, err := get(t, h.url+"/healthz"); err == nil {
		t.Fatal("listener still open after shutdown")
	}
}

func TestShutdownDrain_ZeroKeepsOldBehaviour(t *testing.T) {
	h := startDrainServer(t, 0, nil)
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("runServerCtx: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("drain=0 should shut down immediately")
	}
	if _, _, err := get(t, h.url+"/healthz"); err == nil {
		t.Fatal("listener should be closed immediately with drain=0")
	}
}

func TestShutdownDrainFromEnv_Bounds(t *testing.T) {
	cases := map[string]time.Duration{"": 0, "5": 5 * time.Second, "-3": 0, "9999": 120 * time.Second, "junk": 0}
	for in, want := range cases {
		t.Setenv("KRYPTKEEPER_READINESS_DRAIN_SECONDS", in)
		if got := readinessDrainFromEnv(); got != want {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
}

// A draining replica must hand back its leases at the START of the drain,
// while still serving, not after the listener closed.
func TestShutdownDrain_HookRunsFirstWhileStillServing(t *testing.T) {
	var order []string
	var mu sync.Mutex
	rec := func(e string) { mu.Lock(); order = append(order, e); mu.Unlock() }
	hookStarted := make(chan struct{})
	var h *drainHarness
	h = startDrainServer(t, 500*time.Millisecond, func() {
		close(hookStarted)
		// Listener must still accept connections while the hook runs.
		if code, _, err := get(t, h.url+"/healthz"); err == nil && code == 200 {
			rec("hook:serving")
		}
		rec("hook:done")
	})
	h.cancel()
	select {
	case <-hookStarted:
	case <-time.After(time.Second):
		t.Fatal("hook did not start promptly after shutdown signal")
	}
	if err := <-h.done; err != nil {
		t.Fatal(err)
	}
	rec("stopped")
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 || order[0] != "hook:serving" || order[1] != "hook:done" || order[2] != "stopped" {
		t.Fatalf("order = %v", order)
	}
}

// A hung connection (SSE-like) outlives the shutdown timeout. The signalled
// shutdown must still return nil so main's deferred Stop/lease release runs.
func TestShutdown_TimeoutWithStuckConnectionReturnsNil(t *testing.T) {
	started := make(chan struct{})
	h := startDrainServerT(t, 0, 200*time.Millisecond, nil, func(mux *http.ServeMux) {
		mux.HandleFunc("/hang", func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		})
	})
	go func() { _, _, _ = get(t, h.url+"/hang") }()
	<-started
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("signalled shutdown with stuck connection returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown hung")
	}
}
