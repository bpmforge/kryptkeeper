// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"kryptkeeper/internal/discovery/scanner"
	"kryptkeeper/internal/logging"
	"os"
	"strings"
	"sync"
	"time"
)

const discoveryProviderEnv = "APP_DISCOVERY_PROVIDER"

const (
	discoveryProviderFile = "file"
	discoveryProviderDB   = "db"
)

var discoveryProviderWarnf = logging.Warnf

type DiscoverySummary struct {
	DiscoveredEndpoints int `json:"discovered_endpoints"`
	MappedCertificates  int `json:"mapped_certificates"`
	RiskyEndpoints      int `json:"risky_endpoints"`
	ActiveScanJobs      int `json:"active_scan_jobs"`
	// Findings is the finding funnel (raw/deduped/in-scope/effective/
	// suppressed; five stages since W22-29), sourced from
	// EndpointTLSConfig.Issues (internal/cipheraudit) per
	// docs/design/FINDING_ECONOMICS.md — see FindingFunnelSummary's doc
	// comment in handlers_reports.go for what this is (and isn't). Only
	// dbDiscoveryProvider (the "db"-mode APP_DISCOVERY_PROVIDER) populates
	// this; the file/scanner-backed providers leave it zero-valued.
	Findings FindingFunnelSummary `json:"findings"`
	// TrustClasses breaks discovery-found leaf certificates down by whose
	// they are. Zero on providers without a certificate table.
	TrustClasses TrustClassCounts `json:"trust_classes"`
	// InventoryClasses is the same population by inventory_class (W34-06).
	InventoryClasses InventoryClassCounts `json:"inventory_classes"`
}

type DiscoveryEndpoint struct {
	// Tenant is the stored tenant ("" = DefaultTenant); never serialized.
	Tenant    string `json:"-"`
	ID        string `json:"id"`
	Hostname  string `json:"hostname"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	RiskScore int    `json:"risk_score"`
	// Risky is the documented risky-endpoint rule (discovery_risk.go): the
	// score threshold OR a high-severity flag or finding. It is what the
	// risky_only filter and risky_endpoints count are built from, so a UI
	// badge reading it cannot disagree with them the way a bare risk_score
	// comparison did.
	Risky      bool   `json:"risky"`
	LastSeenAt string `json:"last_seen_at"`
	// ServerTech is the fingerprinted web/server technology (iis, apache,
	// nginx, …) or "" if none was read; RecommendedInstallMode is the
	// install_mode that fingerprint (or the service protocol) implies, so
	// Target Setup can suggest the right automation instead of assuming.
	ServerTech             string `json:"server_tech,omitempty"`
	RecommendedInstallMode string `json:"recommended_install_mode,omitempty"`
	// Tech/TechConfidence/Platform/TLSStack/TechEvidence are the W34-01
	// fingerprint (scanner.Fingerprint): the technology behind the endpoint,
	// how sure the scan is, and the evidence rows that voted. Empty for an
	// endpoint no network scan has fingerprinted.
	// InventoryClass is the headline classification of the endpoint's leaf
	// certificates (managed|ours_unmanaged|authorized_external|unknown_issuer|
	// self_signed); the least-trusted class among them when it presents several.
	InventoryClass string             `json:"inventory_class,omitempty"`
	Tech           string             `json:"tech,omitempty"`
	TechConfidence string             `json:"tech_confidence,omitempty"`
	Platform       string             `json:"platform,omitempty"`
	TLSStack       string             `json:"tls_stack,omitempty"`
	TechEvidence   []scanner.Evidence `json:"tech_evidence,omitempty"`
	// InstallPosture is the W34-08 posture of the discovered file holding this
	// endpoint's served leaf; nil when no host scan has seen that file.
	InstallPosture *DiscoveryInstallPosture `json:"install_posture,omitempty"`
	// SSH endpoints carry no certificate; the banner and advertised
	// host-key algorithms are the discoverable material (and feed
	// algorithm-sunset/PQC tracking).
	SSHBanner            string   `json:"ssh_banner,omitempty"`
	SSHHostKeyAlgorithms []string `json:"ssh_host_key_algorithms,omitempty"`
	// CryptoPosture is the on-the-wire TLS posture (negotiated version/
	// cipher/group + ML-KEM hybrid detection).
	CryptoPosture *scanner.CryptoPosture `json:"crypto_posture,omitempty"`
	// MappedCerts are the currently-active certificate_endpoints rows for
	// this endpoint — the actual join, not a hostname text search (which
	// could never surface a discovered cert whose CN differs from the
	// scanned address).
	MappedCerts []DiscoveryMappedCert `json:"mapped_certs,omitempty"`
	// Issues are the endpoints.issues column's cipheraudit findings for a
	// real (port != 0) TLS endpoint, or -- W19-22 -- a port-less source's
	// discovery-error entries (discoveryErrorIssuesJSON) recording a
	// reachability/permission failure (e.g. a K8s RBAC 403 reading a mesh
	// secret) so a caller of this endpoint, not only a scheduler log
	// line, can see it.
	Issues []string `json:"issues,omitempty"`
}

type DiscoveryMappedCert struct {
	Fingerprint string   `json:"fingerprint"`
	CommonName  string   `json:"common_name,omitempty"`
	ValidUntil  string   `json:"valid_until,omitempty"`
	RiskScore   int      `json:"risk_score"`
	RiskFlags   []string `json:"risk_flags,omitempty"`
	// TrustClass is whose certificate this is (managed|public|private_other|
	// self_signed|unknown), from a real x509 verification of the served chain.
	// ChainCA marks an intermediate/root the endpoint served alongside its leaf.
	//
	// RiskScore/RiskFlags are the certificate's own plus what THIS endpoint's
	// serving of it adds (HOSTNAME_MISMATCH, INCOMPLETE_CHAIN, UNTRUSTED_ROOT):
	// the same certificate on another endpoint carries its own set.
	// ChainComplete is nil when completeness could not be judged (a private
	// chain whose issuer the hub does not hold); only a proven missing
	// intermediate is false.
	TrustClass string `json:"trust_class,omitempty"`
	// IssuerClass and InventoryClass are the W34-06 refinements of TrustClass
	// with the operator's authorized issuers.
	IssuerClass    string `json:"issuer_class,omitempty"`
	InventoryClass string `json:"inventory_class,omitempty"`
	// IssuerDN is the issuer as observed, so the UI can declare it authorized.
	IssuerDN      string `json:"issuer_dn,omitempty"`
	ChainCA       bool   `json:"chain_ca,omitempty"`
	ChainComplete *bool  `json:"chain_complete,omitempty"`
	ChainTrusted  bool   `json:"chain_trusted"`
	// SourcePath is the file the certificate was read from on the scanned host
	// (agentless SSH discovery); empty for network-scanned links.
	SourcePath string `json:"source_path,omitempty"`
}

type DiscoveryEndpointQuery struct {
	Protocol  string
	RiskyOnly bool
	// TrustClass keeps endpoints currently presenting a leaf of this class.
	TrustClass string
	// InventoryClass keeps endpoints currently presenting a leaf of this inventory class.
	InventoryClass string
	Limit          int
	Cursor         int
}

type DiscoveryEndpointResult struct {
	Endpoints  []DiscoveryEndpoint
	Total      int
	Limit      int
	NextCursor *int
	PrevCursor *int
}

type DiscoveryScanJob struct {
	// Tenant is the stored tenant ("" = DefaultTenant); never serialized.
	Tenant   string `json:"-"`
	ID       string `json:"id"`
	ScanType string `json:"scan_type"`
	Target   string `json:"target"`
	Status   string `json:"status"`
	QueuedAt string `json:"queued_at"`
	// Error explains a failed job, or summarizes what a completed_with_errors
	// job could not read (which hosts answered but failed, how many ports were
	// closed). Empty for a clean run.
	Error string `json:"error,omitempty"`
}

type DiscoveryScanJobQuery struct {
	Status string
	Q      string
	Limit  int
	Cursor int
}

type DiscoveryScanJobResult struct {
	ScanJobs   []DiscoveryScanJob
	Total      int
	Limit      int
	NextCursor *int
	PrevCursor *int
}

type DiscoveryScanCreateResult struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	ScanType string `json:"scan_type"`
	Target   string `json:"target"`
	QueuedAt string `json:"queued_at"`
}

type DiscoveryScanJobActionResult struct {
	ScanJobID  string `json:"scan_job_id"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	UpdatedAt  string `json:"updated_at"`
	PreviousID string `json:"previous_scan_job_id,omitempty"`
	QueuedAt   string `json:"queued_at,omitempty"`
}

type DiscoveryProvider interface {
	GetSummary(context.Context) (DiscoverySummary, error)
	ListEndpoints(context.Context, DiscoveryEndpointQuery) (DiscoveryEndpointResult, error)
	ListScanJobs(context.Context, DiscoveryScanJobQuery) (DiscoveryScanJobResult, error)
	CreateScan(ctx context.Context, scanType string, target string, extraPorts []int) (DiscoveryScanCreateResult, error)
	CancelScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error)
	RequeueScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error)
}

// NewConfigStoreFromEnv exposes the W8-03 runtime config store outside this
// package (W8-13): cmd/kryptkeeper/main.go needs a ConfigStore instance for
// its own notification-channel wiring, but the real constructor
// (newConfigStoreFromEnv, config_store.go) is package-private and
// config_store.go is outside this ticket's write_scope. This is a one-line
// proxy, not a second store.
func NewConfigStoreFromEnv() ConfigStore {
	return newConfigStoreFromEnv()
}

// discoveryProviderModeTTL bounds how often configuredDiscoveryProvider
// re-checks the config store for a mode override. Discovery endpoints are
// all authenticated (registerDiscoveryHandlers requires
// AuthenticatePrincipalDetails first) but still a request hot path -- a DB
// read on every single call would violate acceptance #3's "no added DB read
// sits on a request hot path without a bound", so this is a poll, not a
// per-call read.
const discoveryProviderModeTTL = 30 * time.Second

// configuredDiscoveryProvider re-resolves APP_DISCOVERY_PROVIDER's DB
// override (config key "discovery.provider") on a bounded poll interval and
// lazily constructs+caches each mode's underlying provider the first time
// that mode is actually selected -- never both eagerly, so a file-mode
// deployment that never has a DB override never opens the discovery DB
// connection newDBDiscoveryProviderFromEnv would otherwise attempt. The
// config store itself is constructed lazily too (storeFactory), so a caller
// that constructs a DiscoveryProvider but never calls a method on it (common
// across this package's tests) never touches the DB at all.
//
// "scanner" mode (main.go:187's APP_DISCOVERY_PROVIDER=="scanner" branch) is
// selected upstream of NewDiscoveryProviderFromEnv and bypasses this type
// entirely -- it stays a startup-only env selection. Only the file/db split
// documented in configRegistry ("discovery.provider") is live-reloadable
// here; widening scanner mode into the same rotation is out of this
// ticket's scope.
type configuredDiscoveryProvider struct {
	storeFactory func() ConfigStore
	fileFactory  func() DiscoveryProvider
	dbFactory    func() DiscoveryProvider
	ttl          time.Duration
	now          func() time.Time

	mu          sync.Mutex
	storeLoaded bool
	store       ConfigStore

	checkedAt    time.Time
	active       DiscoveryProvider
	fileProvider DiscoveryProvider
	dbProvider   DiscoveryProvider
	winrmScan    winRMTargetScanner
	sshScan      sshTargetScanner
	hubCAs       hubCASource
	// scanDiffNotifier is handed to the DB provider when it is built (W24-06).
	scanDiffNotifier ScanDiffNotifier
}

func NewDiscoveryProviderFromEnv() DiscoveryProvider {
	return &configuredDiscoveryProvider{
		storeFactory: newConfigStoreFromEnv,
		fileFactory:  newFileDiscoveryProvider,
		dbFactory:    newDBDiscoveryProviderFromEnv,
		ttl:          discoveryProviderModeTTL,
		now:          time.Now,
	}
}

// resolveDiscoveryMode returns the effective discovery provider mode: store's
// DB override for "discovery.provider" when present, else APP_DISCOVERY_PROVIDER,
// else "db" (the full-featured provider; "file" is a read-only dev stub) -- the
// same DB-override/env-default precedence as EffectiveSettings
// (config_store.go), for exactly the one key this needs.
func resolveDiscoveryMode(ctx context.Context, store ConfigStore) string {
	raw := ""
	if store != nil {
		if entry, ok, err := store.Get(ctx, "discovery.provider"); err == nil && ok && entry.HasValue {
			raw = entry.Value
		}
	}
	if raw == "" {
		raw = os.Getenv(discoveryProviderEnv)
	}
	switch mode := strings.ToLower(strings.TrimSpace(raw)); mode {
	case "", discoveryProviderDB:
		return discoveryProviderDB
	case discoveryProviderFile:
		return discoveryProviderFile
	default:
		discoveryProviderWarnf("warning: unknown discovery provider mode %q; falling back to db", mode)
		return discoveryProviderDB
	}
}

// current returns the active DiscoveryProvider, re-resolving mode from the
// config store at most once per ttl (see discoveryProviderModeTTL).
func (c *configuredDiscoveryProvider) current(ctx context.Context) DiscoveryProvider {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.storeLoaded {
		if c.storeFactory != nil {
			c.store = c.storeFactory()
		}
		c.storeLoaded = true
	}

	now := c.now()
	if c.active != nil && now.Sub(c.checkedAt) < c.ttl {
		return c.active
	}
	c.checkedAt = now

	if resolveDiscoveryMode(ctx, c.store) == discoveryProviderDB {
		if c.dbProvider == nil {
			c.dbProvider = c.dbFactory()
			if s, ok := c.dbProvider.(winRMScanSetter); ok && c.winrmScan != nil {
				s.SetWinRMScanner(c.winrmScan)
			}
			if s, ok := c.dbProvider.(sshScanSetter); ok && c.sshScan != nil {
				s.SetSSHScanner(c.sshScan)
			}
			if s, ok := c.dbProvider.(hubCASetter); ok && c.hubCAs != nil {
				s.SetHubCASource(c.hubCAs)
			}
			if s, ok := c.dbProvider.(scanDiffNotifierSetter); ok && c.scanDiffNotifier != nil {
				s.SetScanDiffNotifier(c.scanDiffNotifier)
			}
		}
		c.active = c.dbProvider
	} else {
		if c.fileProvider == nil {
			c.fileProvider = c.fileFactory()
		}
		c.active = c.fileProvider
	}
	return c.active
}

func (c *configuredDiscoveryProvider) GetSummary(ctx context.Context) (DiscoverySummary, error) {
	return c.current(ctx).GetSummary(ctx)
}

func (c *configuredDiscoveryProvider) ListEndpoints(ctx context.Context, q DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	return c.current(ctx).ListEndpoints(ctx, q)
}

func (c *configuredDiscoveryProvider) ListScanJobs(ctx context.Context, q DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	return c.current(ctx).ListScanJobs(ctx, q)
}

func (c *configuredDiscoveryProvider) CreateScan(ctx context.Context, scanType string, target string, extraPorts []int) (DiscoveryScanCreateResult, error) {
	return c.current(ctx).CreateScan(ctx, scanType, target, extraPorts)
}

func (c *configuredDiscoveryProvider) CancelScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	return c.current(ctx).CancelScanJob(ctx, scanJobID, reason)
}

func (c *configuredDiscoveryProvider) RequeueScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	return c.current(ctx).RequeueScanJob(ctx, scanJobID, reason)
}
