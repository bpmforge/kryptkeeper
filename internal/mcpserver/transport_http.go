// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"kryptkeeper/internal/logging"
)

// MinHTTPTokenLen is the minimum length of KRYPTKEEPER_MCP_HTTP_TOKEN.
const MinHTTPTokenLen = 32

// MaxRequestBodyBytes caps every request body on the MCP HTTP transport.
const MaxRequestBodyBytes = 1 << 20

// HTTPConfig configures the MCP HTTP transport's access controls (LLM-004).
type HTTPConfig struct {
	// Token is the bearer token every /mcp caller must present (>= MinHTTPTokenLen).
	Token string
	// BindAddr is the listen address; its host (plus localhost forms when it
	// is a loopback address) is always an acceptable Host header.
	BindAddr string
	// AllowedHosts are extra acceptable Host header values (host or host:port).
	AllowedHosts []string
	// AllowedOrigins are the acceptable Origin header values. A request with
	// no Origin header (non-browser client) is accepted.
	AllowedOrigins []string
}

// Validate refuses a config that would leave the transport unauthenticated.
func (c HTTPConfig) Validate() error {
	if len(c.Token) < MinHTTPTokenLen {
		return fmt.Errorf("KRYPTKEEPER_MCP_HTTP_TOKEN is required for the http transport and must be at least %d characters", MinHTTPTokenLen)
	}
	return nil
}

// hostOnly strips an optional :port and IPv6 brackets, lowercased.
func hostOnly(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}

func (c HTTPConfig) allowedHostSet() map[string]bool {
	set := map[string]bool{}
	if c.BindAddr != "" {
		h := hostOnly(c.BindAddr)
		if h != "" && h != "0.0.0.0" && h != "::" {
			set[h] = true
		}
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			set["localhost"], set["127.0.0.1"], set["::1"] = true, true, true
		}
	}
	for _, h := range c.AllowedHosts {
		if h = hostOnly(h); h != "" {
			set[h] = true
		}
	}
	return set
}

// guard enforces body cap, Host/Origin allowlists (DNS-rebinding defence)
// and constant-time bearer-token auth in front of next.
func (c HTTPConfig) guard(next http.Handler) http.Handler {
	hosts := c.allowedHostSet()
	origins := map[string]bool{}
	for _, o := range c.AllowedOrigins {
		origins[strings.ToLower(strings.TrimRight(strings.TrimSpace(o), "/"))] = true
	}
	want := []byte(c.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hosts[hostOnly(r.Host)] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !origins[strings.ToLower(strings.TrimRight(o, "/"))] {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.ContentLength > MaxRequestBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// NewHTTPHandler returns an http.Handler serving srv over the MCP
// StreamableHTTP transport at /mcp, plus a liveness-only, unauthenticated
// /healthz endpoint so a container orchestrator can probe the process
// without speaking MCP. /mcp requires cfg's bearer token, an allowed Host
// and (if sent) an allowed Origin, and bodies are capped at 1 MiB.
func NewHTTPHandler(srv *server.MCPServer, cfg HTTPConfig) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/mcp", cfg.guard(server.NewStreamableHTTPServer(srv)))
	mux.HandleFunc("/healthz", healthzHandler)
	return mux
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// ServeHTTP starts srv over the MCP StreamableHTTP transport on addr,
// blocking until an interrupt/SIGTERM is received, then shuts down
// gracefully. Shape matches internal/bootstrap's server run loop so the MCP
// server's HTTP transport behaves the same way under orchestration.
func ServeHTTP(srv *server.MCPServer, addr string, cfg HTTPConfig) error {
	cfg.BindAddr = addr
	if err := cfg.Validate(); err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           NewHTTPHandler(srv, cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logging.Infof("kryptkeeper-mcp: serving StreamableHTTP on %s (endpoint /mcp)", addr)
		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		shutdownErr := httpServer.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			logging.Warnf("graceful shutdown failed: %v", shutdownErr)
			if closeErr := httpServer.Close(); closeErr != nil {
				logging.Warnf("force close failed: %v", closeErr)
			}
		}
		if err := <-errCh; err != nil {
			return fmt.Errorf("server exited with error: %w", err)
		}
		if shutdownErr != nil {
			return fmt.Errorf("graceful shutdown failed: %w", shutdownErr)
		}
		logging.Info("mcp http server stopped")
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server exited with error: %w", err)
		}
		return nil
	}
}
