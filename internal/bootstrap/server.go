// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/metrics"
	"kryptkeeper/internal/notifications/itsm"
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
	itsm            *itsm.Service
	siem            *SIEMRouter
	scepOffReason   string
	extraReadiness  []ReadinessProbe
	// draining flips true when shutdown begins; /readyz reports 503 from then on.
	draining *atomic.Bool
	// onDrain runs at the start of the drain window (see WithDrainStartHook).
	onDrain func()
	// policyEngine is set by WithPolicyAdmin; nil means no migration key floor.
	policyEngine *ca.PolicyEngine
}

// WithReadinessProbe adds a probe /readyz runs after the built-in dependency
// checks (W23-27). /readyz cannot be re-registered from outside (duplicate
// mux pattern panics), so this is the seam.
func WithReadinessProbe(p ReadinessProbe) ServerOption {
	return func(c *ServerConfig) {
		if p != nil {
			c.extraReadiness = append(c.extraReadiness, p)
		}
	}
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

// WithSCEPOffReason tells the integrations status why SCEP is not serving on
// this hub ("" when it is, or when it was never asked for). The cause is only
// known to the process wiring, so it is passed in rather than re-derived.
func WithSCEPOffReason(reason string) ServerOption {
	return func(c *ServerConfig) { c.scepOffReason = reason }
}

// WithDrainStartHook registers fn to run as soon as shutdown begins, before
// the drain wait. A draining replica must not keep leading: fn is where the
// process hands back HA scheduler leases so a peer takes over in seconds
// instead of waiting for expiry. fn must be idempotent (deferred stops run
// again later) and is waited for, bounded, before the listener closes.
func WithDrainStartHook(fn func()) ServerOption {
	return func(c *ServerConfig) { c.onDrain = fn }
}

func applyServerOptions(mux *http.ServeMux, opts []ServerOption) *ServerConfig {
	cfg := &ServerConfig{Mux: mux, draining: new(atomic.Bool)}
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
	logging.EnsureDefault()
	mux := http.NewServeMux()
	cfg := applyServerOptions(mux, opts)
	installExceptions(cfg, auth, certificateProvider, caProvider, auditProvider) // W22-28: before registerHandlers, which reads cfg.actionExecutors
	registerHandlers(cfg, auth, certSummaryProvider, auditProvider, caProvider, templateProvider, certificateProvider, protocolProvider, discoveryProvider, notificationProvider, dashboardActionProvider, keys)
	RegisterKeyHandlers(mux, auth, keys, auditProvider, keyBackend)
	RegisterBackupHandlers(mux, auth, keys, auditProvider)
	// W11-07: the SSH certificate authority.
	RegisterSSHCertHandlers(mux, auth, keys, templateProvider, auditProvider)
	RegisterOwnershipCMDBHandlers(mux, auth, certificateProvider, auditProvider)
	chatopsActions := NewPendingActionStoreFromEnv()
	chatopsIDs := chatopsIdentityStoreForActions(chatopsActions)
	RegisterChatopsHandlers(mux, auth, chatopsIDs, auditProvider)
	RegisterChatopsTeamsHandlers(mux, chatopsUserProvider(auth), auditProvider, chatopsIDs, nil, nil)
	startChatopsApprovalPosting(chatopsActions)
	registerGovernanceHandlers(mux, auth, auditProvider)
	RegisterOwnershipOrphanHandlers(mux, auth, certificateProvider, auth.userProvider, auditProvider)
	RegisterAuditExportHandlers(mux, auth, NewCustomRoleStoreFromEnv(), auditProvider)
	RegisterApprovalInbox(mux, auth, auditProvider, templateProvider)
	mountProtocolHandlers(mux, protocolMux)

	srv := &http.Server{
		Addr:              addr,
		Handler:           withAuditTenant(withSecurityHeaders(withRequestID(withAccessLog(withMetricsAuth(withHTTPMetrics(withAPIRateLimiting(withWriteAuthorization(mux, auth, NewCustomRoleStoreFromEnv(), auditProvider), auth))))))),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return runServer(srv, cfg.draining, cfg.onDrain)
}

// Run starts the server without protocol handlers (APP_CERTIFICATE_PROVIDER
// != "ca", e.g. a hub using an external cert provider rather than acting as
// its own CA). FR-P60: /metrics is registered directly here too, not only
// via protocolMux in RunWithProtocols -- Prometheus scraping must not
// depend on the crypto engine being active, since request/auth/HTTP-level
// counters are meaningful regardless of whether this instance issues certs.
func Run(addr string, tlsConfig *tls.Config, auth *Authenticator, certSummaryProvider CertSummaryProvider, auditProvider AuditProvider, caProvider CAProvider, templateProvider TemplateProvider, certificateProvider CertificateProvider, protocolProvider ProtocolProvider, discoveryProvider DiscoveryProvider, notificationProvider NotificationProvider, dashboardActionProvider DashboardActionProvider, keys keystore.Store, keyBackend string, opts ...ServerOption) error {
	logging.EnsureDefault()
	mux := http.NewServeMux()
	cfg := applyServerOptions(mux, opts)
	installExceptions(cfg, auth, certificateProvider, caProvider, auditProvider) // W22-28: before registerHandlers, which reads cfg.actionExecutors
	registerHandlers(cfg, auth, certSummaryProvider, auditProvider, caProvider, templateProvider, certificateProvider, protocolProvider, discoveryProvider, notificationProvider, dashboardActionProvider, keys)
	RegisterKeyHandlers(mux, auth, keys, auditProvider, keyBackend)
	RegisterBackupHandlers(mux, auth, keys, auditProvider)
	// W11-07: the SSH certificate authority.
	RegisterSSHCertHandlers(mux, auth, keys, templateProvider, auditProvider)
	RegisterOwnershipCMDBHandlers(mux, auth, certificateProvider, auditProvider)
	chatopsActions := NewPendingActionStoreFromEnv()
	chatopsIDs := chatopsIdentityStoreForActions(chatopsActions)
	RegisterChatopsHandlers(mux, auth, chatopsIDs, auditProvider)
	RegisterChatopsTeamsHandlers(mux, chatopsUserProvider(auth), auditProvider, chatopsIDs, nil, nil)
	startChatopsApprovalPosting(chatopsActions)
	registerGovernanceHandlers(mux, auth, auditProvider)
	RegisterOwnershipOrphanHandlers(mux, auth, certificateProvider, auth.userProvider, auditProvider)
	RegisterAuditExportHandlers(mux, auth, NewCustomRoleStoreFromEnv(), auditProvider)
	RegisterApprovalInbox(mux, auth, auditProvider, templateProvider)
	mux.HandleFunc("/metrics", metricsHandler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           withAuditTenant(withSecurityHeaders(withRequestID(withAccessLog(withMetricsAuth(withHTTPMetrics(withAPIRateLimiting(withWriteAuthorization(mux, auth, NewCustomRoleStoreFromEnv(), auditProvider), auth))))))),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return runServer(srv, cfg.draining, cfg.onDrain)
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

const (
	defaultReadinessDrainSeconds = 0 // chart and image set 5; 0 keeps the pre-drain behaviour for dev and tests
	maxReadinessDrainSeconds     = 120
	httpShutdownTimeout          = 10 * time.Second
	drainHookTimeout             = 15 * time.Second
)

// readinessDrainFromEnv is the window between SIGTERM and closing the
// listener. Kubernetes removes a terminating pod from Service endpoints
// asynchronously, so for a few seconds new connections can still arrive.
func readinessDrainFromEnv() time.Duration {
	return time.Duration(envClampedInt("KRYPTKEEPER_READINESS_DRAIN_SECONDS", defaultReadinessDrainSeconds, 0, maxReadinessDrainSeconds)) * time.Second
}

func runServer(srv *http.Server, draining *atomic.Bool, onDrain func()) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runServerCtx(ctx, srv, draining, onDrain, readinessDrainFromEnv(), httpShutdownTimeout)
}

// runServerCtx serves until ctx is done, then (1) marks the hub not-ready,
// (2) keeps serving for drain so the endpoint removal propagates, (3) calls
// http.Server.Shutdown. Background schedulers are stopped by the caller's
// defers once this returns, so they are not touched here.
func runServerCtx(ctx context.Context, srv *http.Server, draining *atomic.Bool, onDrain func(), drain, shutdownTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		logging.Infof("starting kryptkeeper on %s (tls=%v)", srv.Addr, srv.TLSConfig != nil)
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
		if draining != nil {
			draining.Store(true)
		}
		hookDone := make(chan struct{})
		go func() {
			defer close(hookDone)
			if onDrain != nil {
				onDrain()
			}
		}()
		if drain > 0 {
			logging.Infof("shutdown signal received: /readyz now 503, draining for %s", drain)
			select {
			case <-time.After(drain):
			case err := <-errCh:
				// Serve loop died during the drain; nothing left to shut down.
				if err != nil {
					return fmt.Errorf("server exited with error: %w", err)
				}
				return nil
			}
		}
		select {
		case <-hookDone:
		case <-time.After(drainHookTimeout):
			logging.Warnf("drain-start hook still running after %s; continuing shutdown", drainHookTimeout)
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		shutdownErr := srv.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			logging.Warnf("graceful shutdown failed: %v", shutdownErr)
			if closeErr := srv.Close(); closeErr != nil {
				logging.Warnf("force close failed: %v", closeErr)
			}
		}
		if err := <-errCh; err != nil {
			return fmt.Errorf("server exited with error: %w", err)
		}
		// Connections that outlive the timeout (long-lived SSE streams) were
		// force-closed above. That is a normal end of a signalled shutdown, not
		// a failure: returning an error makes main call logging.Fatal, which
		// exits 1 and skips every deferred scheduler Stop/lease release.
		logging.Info("server stopped")
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server exited with error: %w", err)
		}
		return nil
	}
}
