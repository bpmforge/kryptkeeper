// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/metrics"
)

// ServerOption extends Run/RunWithProtocols without breaking their
// signatures — optional handler groups (W9-06 ceremonies) register through
// WithExtraHandlers instead of growing the parameter lists further.
type ServerOption func(*ServerConfig)

// ServerConfig is what options configure: the API mux, executors for
// pending-action types the core does not know (W20-20), and the delivery
// plugin manager.
type ServerConfig struct {
	Mux             *http.ServeMux
	actionExecutors map[string]ActionExecutor
	plugins         *DeliveryPluginManager
	siem            *SIEMRouter
}

// ActionExecutor carries out an approved pending action of one type for
// approver. It runs only after the queue's approver-role and
// no-self-approval checks.
type ActionExecutor func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error)

// WithExtraHandlers registers additional handlers on the API mux.
func WithExtraHandlers(register func(mux *http.ServeMux)) ServerOption {
	return func(c *ServerConfig) { register(c.Mux) }
}

// WithActionExecutor lets the approval queue carry out actionType.
func WithActionExecutor(actionType string, exec ActionExecutor) ServerOption {
	return func(c *ServerConfig) {
		if c.actionExecutors == nil {
			c.actionExecutors = map[string]ActionExecutor{}
		}
		c.actionExecutors[actionType] = exec
	}
}

// WithDeliveryPlugins gives renewal execution and the plugin API the
// process's one plugin manager. Nil (plugins off) is valid.
func WithDeliveryPlugins(m *DeliveryPluginManager) ServerOption {
	return func(c *ServerConfig) { c.plugins = m }
}

// WithSIEMRouter hands registerHandlers the router the audit provider was
// wrapped with (WithSIEMForwarding), so the integrations Status/Test
// endpoints report on the live instance.
func WithSIEMRouter(r *SIEMRouter) ServerOption {
	return func(c *ServerConfig) { c.siem = r }
}

func applyServerOptions(mux *http.ServeMux, opts []ServerOption) *ServerConfig {
	cfg := &ServerConfig{Mux: mux}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return cfg
}

// RunWithProtocols starts the server with protocol handlers (ACME, OCSP, CRL, EST, SCEP, CMP,
// WSTEP, XCEP) mounted, plus the Prometheus /metrics scrape endpoint.
//
// tlsConfig nil means plain HTTP (cmd/kryptkeeper/main.go's resolveTLSMode
// decides this from KRYPTKEEPER_TLS_* env -- W19-14/UAT W19-05: this used to
// be the only option, which meant every protocol client, including EST
// (RFC 7030 mandates TLS), spoke cleartext to a PKI).
func RunWithProtocols(addr string, tlsConfig *tls.Config, auth *Authenticator, certSummaryProvider CertSummaryProvider, auditProvider AuditProvider, caProvider CAProvider, templateProvider TemplateProvider, certificateProvider CertificateProvider, protocolProvider ProtocolProvider, discoveryProvider DiscoveryProvider, notificationProvider NotificationProvider, dashboardActionProvider DashboardActionProvider, protocolMux *http.ServeMux, keys keystore.Store, keyBackend string, opts ...ServerOption) error {
	mux := http.NewServeMux()
	cfg := applyServerOptions(mux, opts)
	registerHandlers(cfg, auth, certSummaryProvider, auditProvider, caProvider, templateProvider, certificateProvider, protocolProvider, discoveryProvider, notificationProvider, dashboardActionProvider, keys)
	RegisterKeyHandlers(mux, auth, keys, auditProvider, keyBackend)
	RegisterBackupHandlers(mux, auth, keys, auditProvider)
	// W11-07: the SSH certificate authority.
	RegisterSSHCertHandlers(mux, auth, keys, templateProvider, auditProvider)
	mountProtocolHandlers(mux, protocolMux)

	srv := &http.Server{
		Addr:              addr,
		Handler:           withSecurityHeaders(withRequestID(withAPIRateLimiting(withWriteAuthorization(mux, auth, NewCustomRoleStoreFromEnv(), auditProvider), auth))),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return runServer(srv)
}

// Run starts the server without protocol handlers (APP_CERTIFICATE_PROVIDER
// != "ca", e.g. a hub using an external cert provider rather than acting as
// its own CA). FR-P60: /metrics is registered directly here too, not only
// via protocolMux in RunWithProtocols -- Prometheus scraping must not
// depend on the crypto engine being active, since request/auth/HTTP-level
// counters are meaningful regardless of whether this instance issues certs.
func Run(addr string, tlsConfig *tls.Config, auth *Authenticator, certSummaryProvider CertSummaryProvider, auditProvider AuditProvider, caProvider CAProvider, templateProvider TemplateProvider, certificateProvider CertificateProvider, protocolProvider ProtocolProvider, discoveryProvider DiscoveryProvider, notificationProvider NotificationProvider, dashboardActionProvider DashboardActionProvider, keys keystore.Store, keyBackend string, opts ...ServerOption) error {
	mux := http.NewServeMux()
	cfg := applyServerOptions(mux, opts)
	registerHandlers(cfg, auth, certSummaryProvider, auditProvider, caProvider, templateProvider, certificateProvider, protocolProvider, discoveryProvider, notificationProvider, dashboardActionProvider, keys)
	RegisterKeyHandlers(mux, auth, keys, auditProvider, keyBackend)
	RegisterBackupHandlers(mux, auth, keys, auditProvider)
	// W11-07: the SSH certificate authority.
	RegisterSSHCertHandlers(mux, auth, keys, templateProvider, auditProvider)
	mux.HandleFunc("/metrics", metricsHandler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           withSecurityHeaders(withRequestID(withAPIRateLimiting(withWriteAuthorization(mux, auth, NewCustomRoleStoreFromEnv(), auditProvider), auth))),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return runServer(srv)
}

// metricsHandler serves the Prometheus text exposition format, matching the
// handler cmd/kryptkeeper/main.go registers on protocolMux.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.Default.WritePrometheus(w)
}

// mountProtocolHandlers mounts protocolMux (ACME, OCSP, CRL, EST, SCEP, CMP,
// WSTEP, XCEP, and the Prometheus /metrics scrape endpoint -- all registered
// on protocolMux by cmd/kryptkeeper/main.go) onto the serving hub mux.
//
// G-64: this list only covered the original 5 protocols' prefixes for a
// while after CMP/WSTEP/XCEP/metrics were added elsewhere -- since
// http.ServeMux has no wildcard/catch-all fallback, anything registered on
// protocolMux but missing from this list is entirely unreachable, not just
// unrouted to a 404 handler. Every literal path/prefix protocolMux might
// have a handler for must appear here, or it silently 404s forever.
func mountProtocolHandlers(mux *http.ServeMux, protocolMux *http.ServeMux) {
	if protocolMux == nil {
		return
	}
	mux.Handle("/acme/", protocolMux)
	mux.Handle("/ocsp", protocolMux)
	mux.Handle("/ocsp/", protocolMux) // RFC 5019 GET: /ocsp/<base64 request>; Windows CryptoAPI uses it
	mux.Handle("/crl/", protocolMux)
	mux.Handle("/.well-known/est/", protocolMux)
	mux.Handle("/scep", protocolMux)
	mux.Handle("/scep/", protocolMux) // sub-paths some clients append, e.g. /scep/pkiclient.exe
	mux.Handle("/cmp", protocolMux)
	mux.Handle("/wstep", protocolMux)
	mux.Handle("/xcep", protocolMux)
	mux.Handle("/metrics", protocolMux)
}

func runServer(srv *http.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("starting kryptkeeper on %s (tls=%v)", srv.Addr, srv.TLSConfig != nil)
		var err error
		if srv.TLSConfig != nil {
			// Cert/key are already embedded in srv.TLSConfig.Certificates
			// (see cmd/kryptkeeper's resolveTLSMode) -- empty paths here
			// tell ListenAndServeTLS to use that config as-is rather than
			// loading a pair from disk itself.
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
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

		shutdownErr := srv.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			log.Printf("graceful shutdown failed: %v", shutdownErr)
			if closeErr := srv.Close(); closeErr != nil {
				log.Printf("force close failed: %v", closeErr)
			}
		}
		if err := <-errCh; err != nil {
			return fmt.Errorf("server exited with error: %w", err)
		}
		if shutdownErr != nil {
			return fmt.Errorf("graceful shutdown failed: %w", shutdownErr)
		}
		log.Print("server stopped")
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server exited with error: %w", err)
		}
		return nil
	}
}
