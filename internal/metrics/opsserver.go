// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// OpsAddrEnv selects the satellite ops listener ("off" disables it).
	OpsAddrEnv       = "KRYPTKEEPER_OPS_ADDR"
	opsReadyTimeout  = 2 * time.Second
	opsOffValue      = "off"
	opsShutdownGrace = 5 * time.Second
)

// OpsConfig configures the small probe/metrics listener the satellite
// binaries (agent, MCP, certmanager) expose.
type OpsConfig struct {
	Addr   string                          // "" or "off" => disabled
	Ready  func(ctx context.Context) error // nil => always ready
	Bearer func() string                   // nil or "" => /metrics is open
}

// OpsAddrFromEnv returns the trimmed KRYPTKEEPER_OPS_ADDR, or def when unset.
func OpsAddrFromEnv(getenv func(string) string, def string) string {
	if v := strings.TrimSpace(getenv(OpsAddrEnv)); v != "" {
		return v
	}
	return def
}

// BearerMatches reports whether the Authorization header carries want as a
// Bearer token. The comparison is constant time over fixed-length digests so
// neither the token value nor its length leaks through timing.
func BearerMatches(header, want string) bool {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	got := strings.TrimSpace(header[len(prefix):])
	return constantTimeEqual(got, want)
}

func constantTimeEqual(a, b string) bool {
	// Digesting first makes both sides equal length, so the compare is
	// constant time in the token's length as well as its content.
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// OpsHandler serves /healthz, /readyz and /metrics (GET only).
func OpsHandler(cfg OpsConfig) http.Handler {
	mux := http.NewServeMux()
	get := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/healthz", get(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"status":"ok"}`)
	}))
	mux.HandleFunc("/readyz", get(func(w http.ResponseWriter, r *http.Request) {
		if cfg.Ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), opsReadyTimeout)
			defer cancel()
			if err := cfg.Ready(ctx); err != nil {
				ReadyzFailures.Inc()
				slog.WarnContext(r.Context(), "ops readyz: dependency check failed", "error", err)
				writeJSON(w, http.StatusServiceUnavailable, `{"status":"unready","error":"dependency check failed"}`)
				return
			}
		}
		writeJSON(w, http.StatusOK, `{"status":"ready"}`)
	}))
	mux.HandleFunc("/metrics", get(func(w http.ResponseWriter, r *http.Request) {
		if cfg.Bearer != nil {
			if tok := cfg.Bearer(); tok != "" && !BearerMatches(r.Header.Get("Authorization"), tok) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeJSON(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		Default.WritePrometheus(w)
	}))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// ServeOps listens on cfg.Addr until ctx is done. It returns nil when the
// listener is disabled.
func ServeOps(ctx context.Context, cfg OpsConfig) error {
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" || strings.EqualFold(addr, opsOffValue) {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           OpsHandler(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), opsShutdownGrace)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			slog.Warn("ops listener shutdown", "error", err)
		}
	}()
	slog.Info("ops listener started", "addr", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-done
	return nil
}
