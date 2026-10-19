// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"kryptkeeper/internal/logging"
	_ "modernc.org/sqlite"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/cipheraudit"
	"kryptkeeper/internal/discovery/scanner"
)

// discoveredCertRow flattens a scanner.DiscoveredCert into the argument
// list both stores' certificate upserts share. The real certificates table
// (000002 onward) declares serial_number, subject_dn, issuer_dn,
// valid_from, valid_until, public_key_algorithm and signature_algorithm
// NOT NULL, and public_key_algorithm carries a CHECK — the previous
// two-column insert could never satisfy it, so every scan that found a
// certificate failed to persist. The unit-test schema was a two-column
// stand-in and hid that; it now mirrors the migration.
//
// Postgres types subject_alt_names and risk_flags TEXT[] (migration 000002);
// sqlite has no array type and keeps JSON text. Sending sqlite's JSON string to
// a TEXT[] column is rejected as a malformed array literal -- the same trap
// writeCertToDB documents (S-66) -- so the postgres argument list carries
// real slices.
func discoveredCertRow(cert scanner.DiscoveredCert, now string, postgres bool) (args []any, ok bool) {
	// The raw DER is the authority for the key facts the certificates table
	// stores (issuer CN, key size, stored algorithm name). Sources that build a
	// DiscoveredCert by hand (service mesh, WinRM) never set them, so deriving
	// here keeps every source's row complete; an unparseable Raw (tests, a
	// truncated capture) degrades to NULLs rather than dropping the cert.
	keyAlg := cert.PublicKeyAlgorithm
	var issuerCN any
	var keyBits any
	if parsed, err := x509.ParseCertificate(cert.Raw); err == nil {
		keyAlg = ca.StoredPublicKeyAlgorithm(parsed)
		if cn := parsed.Issuer.CommonName; cn != "" {
			issuerCN = cn
		}
		if bits := ca.PublicKeyBits(parsed.PublicKey); bits > 0 {
			keyBits = bits
		}
	}
	alg, ok := normalizeDiscoveredKeyAlgorithm(keyAlg)
	if !ok {
		// The CHECK constraint would reject the row; skipping one exotic
		// certificate beats failing the whole scan transaction.
		logging.Infof("discovery: skipping cert %s: unsupported public key algorithm %q", cert.Fingerprint, cert.PublicKeyAlgorithm)
		return nil, false
	}
	// Endpoint-scoped flags (HOSTNAME_MISMATCH, INCOMPLETE_CHAIN,
	// UNTRUSTED_ROOT) belong to the certificate_endpoints link, so the shared
	// row carries only what is true of the certificate wherever it is served.
	// The score subtraction is approximate only when the scanner's own sum hit
	// its 100 cap, where both values are far past any threshold.
	flags, _, endpointScore := scanner.SplitEndpointFlags(cert.RiskFlags)
	if flags == nil {
		flags = []string{}
	}
	certScore := max(cert.RiskScore-endpointScore, 0)
	dnsNames := cert.DNSNames
	if dnsNames == nil {
		dnsNames = []string{}
	}
	var sansArg, flagsArg any = dnsNames, flags
	if !postgres {
		sans, _ := json.Marshal(dnsNames)
		flagsJSON, _ := json.Marshal(flags)
		sansArg, flagsArg = string(sans), string(flagsJSON)
	}
	return []any{
		cert.Fingerprint,
		cert.SerialNumber,
		cert.SubjectDN,
		cert.CommonName,
		sansArg,
		cert.IssuerDN,
		cert.ValidFrom.UTC().Format(time.RFC3339),
		cert.ValidUntil.UTC().Format(time.RFC3339),
		alg,
		cert.SignatureAlgorithm,
		certScore,
		flagsArg,
		base64.StdEncoding.EncodeToString(cert.Raw),
		now,
		issuerCN,
		keyBits,
		boolArg(false, postgres), // chain completeness is per endpoint: certificate_endpoints.chain_complete
		boolArg(cert.ChainTrusted, postgres),
		nullString(cert.TrustClass),
		boolArg(cert.ChainCA, postgres),
		nullString(cert.IssuerClass),
	}, true
}

// boolArg renders a flag for the certificates column: native BOOLEAN on
// postgres, 0/1 on sqlite (which has no boolean type).
func boolArg(v, postgres bool) any {
	switch {
	case postgres:
		return v
	case v:
		return 1
	default:
		return 0
	}
}

// normalizeDiscoveredKeyAlgorithm maps crypto/x509's
// PublicKeyAlgorithm.String() onto the values the certificates CHECK
// constraint admits. DSA and unknown algorithms have no legal value and
// are reported unsupported rather than mislabeled.
func normalizeDiscoveredKeyAlgorithm(raw string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "RSA":
		return "RSA", true
	case "ECDSA":
		return "ECDSA", true
	case "ED25519":
		return "Ed25519", true
	case "ML-DSA":
		return "ML-DSA", true
	default:
		return "", false
	}
}

// scanScopeJSON builds the scan_jobs.scope envelope. Extra ports are stored
// alongside the target so a requeue re-runs the same custom sweep.
func scanScopeJSON(target string, extraPorts []int) string {
	payload := struct {
		Target string `json:"target"`
		Ports  []int  `json:"ports,omitempty"`
	}{Target: target, Ports: extraPorts}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"target":%q}`, target)
	}
	return string(b)
}

// scanScopeTarget unwraps the scan_jobs.scope JSON ({"target":"host"})
// back into the plain target the API promised. Rows written before the
// scope envelope existed hold the bare target and pass through unchanged.
func scanScopeTarget(scope string) string {
	if !strings.HasPrefix(strings.TrimSpace(scope), "{") {
		return scope
	}
	var payload struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal([]byte(scope), &payload); err != nil || payload.Target == "" {
		return scope
	}
	return payload.Target
}

// source/origin/management_state are literals, not parameters: a cert that
// arrived via a network scan is discovered and unmanaged until someone
// claims it — letting the columns default to 'api'/'internal'/'managed'
// would fabricate provenance.
// scanScopePorts pulls any custom ports out of a scan_jobs.scope envelope
// so a requeue replays them.
func scanScopePorts(scope string) []int {
	if !strings.HasPrefix(strings.TrimSpace(scope), "{") {
		return nil
	}
	var payload struct {
		Ports []int `json:"ports"`
	}
	if err := json.Unmarshal([]byte(scope), &payload); err != nil {
		return nil
	}
	return payload.Ports
}

const discoveredCertUpsertColumns = `(fingerprint_sha256, serial_number, subject_dn, common_name,
 subject_alt_names, issuer_dn, valid_from, valid_until,
 public_key_algorithm, signature_algorithm, risk_score, risk_flags, raw_cert_b64, updated_at,
 issuer_cn, key_size_bits, chain_complete, chain_trusted, trust_class, is_ca, issuer_class, source, origin, management_state)`

// discoveredCertConflictUpdate{SQLite,Postgres} are the ON CONFLICT bodies. It refreshes
// only discovery-owned facts and is gated off for managed certificates: the
// hub scores those with its own rules, and a scan (whose verdict depends on
// whether it targeted an IP or a name) must not rewrite them. issuer_cn and
// key_size_bits backfill rows discovery wrote before those columns existed.
//
// The issuer verdict (trust_class, chain_trusted) is only overwritten by a scan
// that produced one: a WinRM or mesh sighting of the same cert carries no
// trust_class and must not erase what a network scan established. Everything
// endpoint-specific (hostname match, served-chain completeness, the chain
// flags) is written to certificate_endpoints instead, never here. is_ca is "leaf wins": a cert seen as a served
// leaf anywhere stays in the leaf inventory even if another endpoint also
// serves it as part of its chain.
const discoveredCertConflictUpdateSQLite = `
    risk_score = excluded.risk_score, risk_flags = excluded.risk_flags,
    issuer_cn = COALESCE(certificates.issuer_cn, excluded.issuer_cn),
    key_size_bits = COALESCE(certificates.key_size_bits, excluded.key_size_bits),
    chain_trusted = CASE WHEN excluded.trust_class IS NULL THEN certificates.chain_trusted ELSE excluded.chain_trusted END,
    trust_class = COALESCE(excluded.trust_class, certificates.trust_class),
    issuer_class = COALESCE(excluded.issuer_class, certificates.issuer_class),
    is_ca = MIN(excluded.is_ca, certificates.is_ca),
    updated_at = excluded.updated_at
WHERE certificates.management_state <> 'managed'
`

const discoveredCertConflictUpdatePostgres = `
    risk_score = excluded.risk_score, risk_flags = excluded.risk_flags,
    issuer_cn = COALESCE(certificates.issuer_cn, excluded.issuer_cn),
    key_size_bits = COALESCE(certificates.key_size_bits, excluded.key_size_bits),
    chain_trusted = CASE WHEN excluded.trust_class IS NULL THEN certificates.chain_trusted ELSE excluded.chain_trusted END,
    trust_class = COALESCE(excluded.trust_class, certificates.trust_class),
    issuer_class = COALESCE(excluded.issuer_class, certificates.issuer_class),
    is_ca = (excluded.is_ca AND certificates.is_ca),
    updated_at = excluded.updated_at
WHERE certificates.management_state <> 'managed'
`

type dbDiscoveryStore interface {
	EnsureSchema(ctx context.Context) error
	GetSummary(context.Context) (DiscoverySummary, error)
	ListEndpoints(context.Context, DiscoveryEndpointQuery) (DiscoveryEndpointResult, error)
	ListScanJobs(context.Context, DiscoveryScanJobQuery) (DiscoveryScanJobResult, error)
	CreateScan(ctx context.Context, scanType string, target string, extraPorts []int) (DiscoveryScanCreateResult, error)
	CancelScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error)
	RequeueScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error)
	// ListEndpointFindings returns, per endpoint, the cipheraudit issues
	// persisted at scan time (see auditEndpointTLSIssues) plus the
	// fingerprints of certificates that endpoint is currently presenting —
	// the finding funnel's raw source for discovery (W2-11).
	ListEndpointFindings(ctx context.Context) ([]discoveryEndpointFindings, error)
}

// discoveryEndpointFindings is one endpoint's raw cipheraudit issues plus
// the certificates it currently presents. Issues are attributed to those
// certificates (target_type=certificate) for suppression purposes because
// finding_exceptions.target_type is fixed to certificate|ca — there is no
// endpoint-scoped exception in this design (docs/design/FINDING_ECONOMICS.md).
type discoveryEndpointFindings struct {
	// Tenant is the endpoint's stored tenant ("" = default); it is part of a
	// finding's identity because endpoints are per-tenant rows.
	Tenant           string
	Issues           []string
	CertFingerprints []string
}

// listDiscoveryEndpointFindings is the sqlite/postgres-shared implementation
// behind ListEndpointFindings: two plain queries (endpoints' persisted
// issues, and currently-active certificate_endpoints mappings) combined in
// Go rather than one join, since JSON aggregation syntax diverges between
// sqlite and postgres in exactly the way this package's other schema
// comments already warn about — a plain loop here avoids that trap
// entirely, matching the "don't build a second funnel abstraction" scope
// for discovery (its numbers don't reach the wire this ticket regardless —
// see the W2-11 SCOPE GAP note in docs/board/plan.json).
func listDiscoveryEndpointFindings(ctx context.Context, db *sql.DB, endpointsQuery, certEndpointsQuery string, scopeArgs ...any) ([]discoveryEndpointFindings, error) {
	certsByEndpoint := make(map[string][]string)
	flagFindingsByEndpoint := make(map[string][]string)
	certRows, err := db.QueryContext(ctx, certEndpointsQuery, scopeArgs...)
	if err != nil {
		return nil, err
	}
	for certRows.Next() {
		var endpointID, fingerprint, flagsText, linkFlagsText string
		if err := certRows.Scan(&endpointID, &fingerprint, &flagsText, &linkFlagsText); err != nil {
			certRows.Close()
			return nil, err
		}
		certsByEndpoint[endpointID] = append(certsByEndpoint[endpointID], fingerprint)
		// Each link contributes the certificate's own flags plus what THIS
		// endpoint's serving of it adds, so a mismatch on one endpoint is one
		// finding there and none on the endpoint where the name matches.
		flagFindingsByEndpoint[endpointID] = append(flagFindingsByEndpoint[endpointID],
			certFlagFindings(mergeLinkFlags(parseRiskFlagsText(flagsText), parseRiskFlagsText(linkFlagsText)))...)
	}
	if err := certRows.Err(); err != nil {
		certRows.Close()
		return nil, err
	}
	certRows.Close()

	rows, err := db.QueryContext(ctx, endpointsQuery, scopeArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []discoveryEndpointFindings
	for rows.Next() {
		var endpointID, issuesJSON, tenant string
		if err := rows.Scan(&endpointID, &issuesJSON, &tenant); err != nil {
			return nil, err
		}
		var issues []string
		if issuesJSON != "" {
			if err := json.Unmarshal([]byte(issuesJSON), &issues); err != nil {
				return nil, fmt.Errorf("unmarshal issues for endpoint %s: %w", endpointID, err)
			}
		}
		// The certificate's own risk flags (EXPIRED, SELF_SIGNED, WEAK_KEY, ...)
		// are findings too. Before this the widget counted only cipheraudit's
		// issues, so it read 0 on a hub full of expired and self-signed
		// certificates. Like cipheraudit's, they are counted per endpoint with
		// no dedup (see FindingFunnelSummary), and suppressed by an exception
		// whose issue string is the flag code on that certificate.
		issues = append(issues, flagFindingsByEndpoint[endpointID]...)
		if len(issues) == 0 {
			continue
		}
		findings = append(findings, discoveryEndpointFindings{
			Tenant:           tenant,
			Issues:           issues,
			CertFingerprints: certsByEndpoint[endpointID],
		})
	}
	return findings, rows.Err()
}

type dbDiscoveryProvider struct {
	store                 dbDiscoveryStore
	openErr               error
	findingExceptionStore FindingExceptionStore
	findingIdentityStore  FindingIdentityStore
}

// sqliteDiscoverySchema/postgresDiscoverySchema mirror migration
// 000003_discovery_endpoints (scan_jobs, endpoints, certificate_endpoints)
// — see W2-05/G-33: this store, like every
// other DB-backed store before this ticket, never created its own tables and
// depended entirely on that migration actually running, which never happens
// against a live deployment. Two deliberate deviations from the migration:
//
//   - sni_name is NOT NULL DEFAULT (empty string), not nullable, so the
//     dedup unique index is a plain column index rather than an expression
//     index on COALESCE(sni_name, default). ON CONFLICT conflict-target
//     matching for expression indexes diverges between sqlite and postgres,
//     exactly the class of bug that bit audit_log's schema (S-07); a NOT
//     NULL default sidesteps it entirely while keeping the same dedup
//     semantics.
//   - certificate_endpoints.certificate_fingerprint has NO FK to a
//     certificates table: certificates are file-based in this codebase
//     (fileCertificateProvider is the only CertificateProvider), so no
//     genuine certificates DB table is ever populated from real cert data.
//     A minimal mirror table is created below and kept in sync by
//     upsertScanResults itself, which writes each observed cert's
//     fingerprint/risk_score (computed by the scanner at TLS-handshake time)
//     so the pre-existing risk-score JOINs in GetSummary/ListEndpoints
//     resolve against real, scan-derived data rather than an empty table —
//     see G-55 in DESIGN_REVIEW.md for the one remaining edge this doesn't
//     cover (certs never seen by a discovery scan, e.g. file-store-only
//     certs with no matching endpoint).
//   - endpoints.issues (W2-11) is a JSON array of cipheraudit issue strings,
//     added via best-effort ALTER TABLE in EnsureSchema (the agent_store_db.go/
//     pending_action_store.go precedent) rather than only the CREATE TABLE IF
//     NOT EXISTS below, since a deployment that already ran this migration
//     before W2-11 has an endpoints table with no such column.
const sqliteDiscoverySchema = `
CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    connector TEXT NOT NULL DEFAULT 'api',
    scope TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued',
    error_message TEXT,
    tenant TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tls',
    sni_name TEXT NOT NULL DEFAULT '',
    issues TEXT NOT NULL DEFAULT '[]',
    tenant TEXT NOT NULL DEFAULT '',
    last_scanned TEXT,
    first_discovered TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_endpoint_hostname ON endpoints(hostname);
CREATE TABLE IF NOT EXISTS certificate_endpoints (
    certificate_fingerprint TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    currently_active INTEGER NOT NULL DEFAULT 1,
    endpoint_flags TEXT NOT NULL DEFAULT '[]',
    endpoint_risk_score INTEGER NOT NULL DEFAULT 0,
    chain_complete INTEGER,
    chain_trusted INTEGER,
    source_path TEXT,
    PRIMARY KEY (certificate_fingerprint, endpoint_id)
);
CREATE INDEX IF NOT EXISTS idx_ce_endpoint ON certificate_endpoints(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_ce_active ON certificate_endpoints(currently_active);
CREATE TABLE IF NOT EXISTS certificates (
    fingerprint_sha256 TEXT PRIMARY KEY,
    serial_number TEXT NOT NULL DEFAULT '',
    subject_dn TEXT NOT NULL DEFAULT '',
    common_name TEXT,
    subject_alt_names TEXT,
    issuer_dn TEXT NOT NULL DEFAULT '',
    valid_from TEXT NOT NULL DEFAULT '',
    valid_until TEXT NOT NULL DEFAULT '',
    public_key_algorithm TEXT NOT NULL DEFAULT '',
    signature_algorithm TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_flags TEXT NOT NULL DEFAULT '[]',
    raw_cert_b64 TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    source TEXT NOT NULL DEFAULT 'discovery_network',
    origin TEXT NOT NULL DEFAULT 'discovered',
    management_state TEXT NOT NULL DEFAULT 'unmanaged',
    issuer_cn TEXT,
    key_size_bits INTEGER,
    chain_complete INTEGER NOT NULL DEFAULT 0,
    chain_trusted INTEGER NOT NULL DEFAULT 0,
    trust_class TEXT,
    issuer_class TEXT,
    is_ca INTEGER NOT NULL DEFAULT 0
);`

const postgresDiscoverySchema = `
CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    connector TEXT NOT NULL DEFAULT 'api',
    scope TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued',
    error_message TEXT,
    tenant TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tls',
    sni_name TEXT NOT NULL DEFAULT '',
    issues TEXT NOT NULL DEFAULT '[]',
    tenant TEXT NOT NULL DEFAULT '',
    last_scanned TIMESTAMPTZ,
    first_discovered TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_endpoint_hostname ON endpoints(hostname);
CREATE TABLE IF NOT EXISTS certificate_endpoints (
    certificate_fingerprint TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    currently_active BOOLEAN NOT NULL DEFAULT TRUE,
    endpoint_flags TEXT NOT NULL DEFAULT '[]',
    endpoint_risk_score INTEGER NOT NULL DEFAULT 0,
    chain_complete BOOLEAN,
    chain_trusted BOOLEAN,
    source_path TEXT,
    PRIMARY KEY (certificate_fingerprint, endpoint_id)
);
CREATE INDEX IF NOT EXISTS idx_ce_endpoint ON certificate_endpoints(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_ce_active ON certificate_endpoints(currently_active);
CREATE TABLE IF NOT EXISTS certificates (
    fingerprint_sha256 TEXT PRIMARY KEY,
    serial_number TEXT NOT NULL DEFAULT '',
    subject_dn TEXT NOT NULL DEFAULT '',
    common_name TEXT,
    subject_alt_names TEXT,
    issuer_dn TEXT NOT NULL DEFAULT '',
    valid_from TEXT NOT NULL DEFAULT '',
    valid_until TEXT NOT NULL DEFAULT '',
    public_key_algorithm TEXT NOT NULL DEFAULT '',
    signature_algorithm TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_flags TEXT NOT NULL DEFAULT '[]',
    raw_cert_b64 TEXT,
    updated_at TEXT NOT NULL DEFAULT NOW()::TEXT,
    source TEXT NOT NULL DEFAULT 'discovery_network',
    origin TEXT NOT NULL DEFAULT 'discovered',
    management_state TEXT NOT NULL DEFAULT 'unmanaged',
    issuer_cn TEXT,
    key_size_bits INTEGER,
    chain_complete BOOLEAN NOT NULL DEFAULT FALSE,
    chain_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    trust_class TEXT,
    issuer_class TEXT,
    is_ca BOOLEAN NOT NULL DEFAULT FALSE
);`

// runDiscoveryScan actually executes a network scan. Overridable in tests
// (matching the discoveryProviderWarnf/auditProviderWarnf seam pattern
// already used elsewhere in this package) so unit tests exercising CreateScan
// don't trigger real outbound network connections.
var runDiscoveryScan = func(ctx context.Context, jobID, target, scanType string, extraPorts []int) *scanner.ScanResult {
	cfg := scanner.ScanConfig{Targets: []string{target}, Concurrency: 50, Timeout: 10 * time.Second}
	// A bare host or CIDR (no explicit port) sweeps the scan-type's TLS
	// port list, so a "full" scan of one host finds certs on 8443/636/3389/
	// 5986/… not just 443. A target the user pinned to a specific port
	// (host:port) is honored exactly — expandTargets leaves it alone.
	if scanType == "deep" {
		// Deep mode does its OWN full port sweep per host, so no catalogue
		// port list — but a two-value custom-ports pair [lo,hi] narrows the
		// range (stored separately from Ports so target expansion does not
		// mistake the bounds for literal ports).
		cfg.Deep = true
		if len(extraPorts) == 2 && extraPorts[0] <= extraPorts[1] {
			cfg.DeepPortLo, cfg.DeepPortHi = extraPorts[0], extraPorts[1]
		}
	} else if _, _, err := net.SplitHostPort(target); err != nil {
		// Merge, in order: the scan-type catalogue, per-scan custom ports,
		// and the org's standing custom ports (env). An org that runs HTTPS
		// on 8443-and-9999 gets 9999 swept without editing the catalogue.
		cfg.Ports = mergePorts(scanner.PortsForScanType(scanType), extraPorts, standingCustomPorts())
	}
	// Full (and its alias network) scans run the active fingerprint probes;
	// deep implies them, fast and targeted never do (D-206).
	cfg.ActiveProbes = scanType == "full" || scanType == "network"
	sc := scanner.New(cfg)
	return sc.Scan(ctx, jobID)
}

// mergePorts unions port lists, dropping duplicates and out-of-range values,
// preserving first-seen order.
func mergePorts(lists ...[]int) []int {
	seen := make(map[int]bool)
	out := make([]int, 0)
	for _, list := range lists {
		for _, p := range list {
			if p < 1 || p > 65535 || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// standingCustomPorts reads the org's permanent extra ports from
// APP_DISCOVERY_CUSTOM_PORTS (comma-separated) — for a shop that
// standardized on non-default ports and wants every scan to include them.
func standingCustomPorts() []int {
	raw := strings.TrimSpace(os.Getenv("APP_DISCOVERY_CUSTOM_PORTS"))
	if raw == "" {
		return nil
	}
	return parsePortList(raw)
}

// parsePortList parses a comma-separated port list, silently dropping any
// token that is not a valid 1–65535 port.
func parsePortList(raw string) []int {
	var out []int
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if n, err := strconv.Atoi(tok); err == nil && n >= 1 && n <= 65535 {
			out = append(out, n)
		}
	}
	return out
}

// afterDiscoveryScanPersist is a no-op production hook, overridable in tests
// to synchronize on the background scan-and-persist goroutine's full
// completion (not just runDiscoveryScan returning) before a test's own
// cleanup (e.g. closing the DB) runs.
var afterDiscoveryScanPersist = func(jobID string) {}

// auditEndpointTLSIssues computes cipheraudit's raw findings for a
// discovered endpoint at scan-persist time (W2-11) — before this ticket,
// cipheraudit had zero callers anywhere in bootstrap. This runs once per
// scan, alongside the scanner's own TLS dial, rather than on every
// GetSummary read, so a busy discovery-summary/dashboard endpoint doesn't
// re-audit every endpoint on every request. Overridable in tests (matches
// runDiscoveryScan's seam) so unit tests exercising upsertScanResults don't
// make live TLS connections.
var auditEndpointTLSIssues = func(host string, port int) []string {
	return cipheraudit.NewAuditor(0).AuditEndpoint(host, port).Issues
}

// auditEndpointTLSIssuesBatch runs auditEndpointTLSIssues for every reachable
// endpoint in results and marshals each to JSON, all before any DB
// transaction opens. upsertScanResults used to dial cipheraudit per endpoint
// from inside its write tx — a second, redundant TLS dial to the same
// host:port the scanner package already dialed during discovery, now
// serialized behind a DB write lock. A slow or unreachable endpoint could
// hold that tx (and, on sqlite, the single writer lock) open for up to the
// auditor's dial timeout. Doing every dial here, ahead of BeginTx, keeps the
// transaction itself to pure INSERT/UPDATE work.
func auditEndpointTLSIssuesBatch(results []scanner.DiscoveredEndpoint) ([]string, error) {
	issuesByEndpoint := make([]string, len(results))
	for i, ep := range results {
		if ep.Error != "" || len(ep.Findings) > 0 {
			continue // an endpoint finding already says what is wrong; a second dial would only add "connection failed" noise
		}
		// W12-04: port 0 means no socket to audit (mesh/K8s-secret
		// sources) — a forced dial would stamp a false Grade-F
		// "connection failed" finding on a perfectly healthy secret.
		if ep.Port == 0 {
			issuesByEndpoint[i] = "[]"
			continue
		}
		issuesJSON, err := json.Marshal(auditEndpointTLSIssues(ep.Host, ep.Port))
		if err != nil {
			return nil, fmt.Errorf("marshal cipheraudit issues for %s:%d: %w", ep.Host, ep.Port, err)
		}
		issuesByEndpoint[i] = string(issuesJSON)
	}
	return issuesByEndpoint, nil
}

func newDiscoveryEndpointID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read never partially fills without error; ID only, not key material
	return "ep-" + hex.EncodeToString(b)
}

// discoveryProtocolOrDefault falls back to the endpoints table's own
// default when the scanner didn't report a protocol.
// cryptoPostureJSON marshals the on-the-wire posture for storage, or "" so
// nullString stores NULL when there is none.
func cryptoPostureJSON(cp *scanner.CryptoPosture) string {
	if cp == nil {
		return ""
	}
	b, err := json.Marshal(cp)
	if err != nil {
		return ""
	}
	return string(b)
}

// sshAlgorithmsJSON marshals an SSH endpoint's advertised host-key
// algorithms to a JSON array for storage, or "" when there are none (so
// nullString stores NULL rather than "[]").
func sshAlgorithmsJSON(algs []string) string {
	if len(algs) == 0 {
		return ""
	}
	b, err := json.Marshal(algs)
	if err != nil {
		return ""
	}
	return string(b)
}

// discoveryProtocolOrDefault normalizes the scanner's rich per-service
// protocol tags onto the endpoints.protocol column's CHECK vocabulary
// (000003). The scanner now classifies far more protocols than that column
// was created to hold; rather than a risky rebuild of a 17-column table
// with triggers and inbound FKs, the fine-grained service identity lives in
// server_tech/recommended_install_mode (which carry no CHECK), and this maps
// the coarse transport onto the allowed set. Anything unrecognized becomes
// 'other' — honest, not a silent CHECK violation that would fail the whole
// scan's persistence.
func discoveryProtocolOrDefault(protocol string) string {
	switch p := strings.TrimSpace(strings.ToLower(protocol)); p {
	case "":
		return "tls"
	case "tls", "ldaps", "imaps", "smtps", "pop3s", "ftps", "rdps", "kubernetes", "other",
		"mssql", "mysql", "oracle", "redis", "mongodb", "kafka": // widened by 000340
		return p // already in the allowed vocabulary
	case "k8s-tls-secret", "istio-mesh", "linkerd-mesh":
		// W19-22 (000058): these are the exact tags
		// internal/discovery/servicemesh.go's meshEndpoint() emits for its
		// port-0 (no network listener) K8s-secret sources -- recorded
		// honestly rather than collapsed into 'other' like every other
		// unrecognized tag below, so a caller of GET
		// /api/v1/discovery/endpoints can tell an Istio CA secret from a
		// Linkerd issuer from a bare TLS secret.
		return p
	case "https", "https-alt", "winrm-https", "etcd", "etcd-peer", "amqps", "mqtts":
		return "tls" // implicit-TLS transports the column groups under 'tls'
	case "kubernetes-api":
		return "kubernetes"
	case "ldaps-gc":
		return "ldaps"
	case "rdp":
		return "rdps"
	default:
		// ssh, starttls-*, postgres, and any future tag: recorded as 'other'
		// in the coarse column; server_tech carries the real identity.
		return "other"
	}
}

// endpointFingerprintCols are the endpoints.tech* column values for one scan
// result. Every field is NULL when the endpoint was never fingerprinted
// (agentless sources), so a rescan by a source that cannot fingerprint clears
// a stale value instead of keeping it.
type endpointFingerprintCols struct {
	tech, confidence, platform, tlsStack, evidence sql.NullString
}

func newEndpointFingerprintCols(ep scanner.DiscoveredEndpoint) endpointFingerprintCols {
	f := ep.Fingerprint
	if f == nil {
		return endpointFingerprintCols{}
	}
	return endpointFingerprintCols{
		tech: nullString(f.Tech), confidence: nullString(f.Confidence), platform: nullString(f.Platform),
		tlsStack: nullString(f.TLSStack), evidence: nullString(scanner.EvidenceJSON(f.Evidence)),
	}
}

func newDBDiscoveryProviderFromEnv() DiscoveryProvider {
	state := newDBProviderState[dbDiscoveryStore](
		"discovery",
		discoveryDBSQLiteDSNFromEnv,
		discoveryDBPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_DISCOVERY_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) dbDiscoveryStore { return &sqliteDiscoveryStore{db: db} },
		func(db *sql.DB) dbDiscoveryStore { return &postgresDiscoveryStore{db: db} },
	)
	if state.store != nil {
		if err := state.store.EnsureSchema(context.Background()); err != nil {
			logging.Warnf("discovery db mode: schema initialization failed: %v", err)
			return &dbDiscoveryProvider{openErr: err}
		}
	}
	// W2-11: constructed here rather than threaded through this
	// zero-argument constructor's signature — every existing caller
	// (cmd/kryptkeeper/main.go and ~20 test files) calls
	// NewDiscoveryProviderFromEnv() with no arguments and lives outside
	// this ticket's write_scope, so the store self-constructs from env
	// like every other *FromEnv store in this package. A nil store (env
	// misconfigured) degrades GetSummary's funnel to an empty active-
	// exception set rather than failing discovery entirely.
	findingExceptionStore, _ := newFindingExceptionStoreFromEnv()
	findingIdentityStore, _ := newFindingIdentityStoreFromEnv()
	return &dbDiscoveryProvider{store: state.store, openErr: state.openErr, findingExceptionStore: findingExceptionStore, findingIdentityStore: findingIdentityStore}
}

func discoveryDBSQLiteDSNFromEnv() (string, error) {
	return resolveSQLiteDSNFromEnv("APP_DISCOVERY_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
}

func discoveryDBPostgresDSNFromEnv() string {
	return resolvePostgresDSNFromEnv("APP_DISCOVERY_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
}

func (p *dbDiscoveryProvider) GetSummary(ctx context.Context) (DiscoverySummary, error) {
	if err := dbProviderUnavailable("discovery", p.openErr); err != nil {
		return DiscoverySummary{}, err
	}
	summary, err := p.store.GetSummary(ctx)
	if err != nil {
		return DiscoverySummary{}, err
	}
	findings, err := p.store.ListEndpointFindings(ctx)
	if err != nil {
		return DiscoverySummary{}, err
	}
	funnel := discoveryFindingFunnel(findings, activeFindingExceptions(ctx, p.findingExceptionStore))
	summary.Findings = funnel.Summary()
	observeFindingIdentities(ctx, p.findingIdentityStore, funnel.Identities())
	return summary, nil
}

// computeDiscoveryFindingFunnel is discovery's half of the finding funnel.
func computeDiscoveryFindingFunnel(findings []discoveryEndpointFindings, activeExceptions []FindingException) FindingFunnelSummary {
	return discoveryFindingFunnel(findings, activeExceptions).Summary()
}

// discoveryFindingFunnel: raw is every cipheraudit issue and certificate flag
// persisted across every endpoint. Endpoints can't be exception targets
// (target_type is fixed to certificate|ca), so an issue is attributed to the
// lexicographically smallest fingerprint the endpoint presents, which makes
// the same flaw on the same certificate one finding however many endpoints
// serve it. An endpoint presenting no certificate has nothing stable to
// attribute to: each of its issues is its own, unmerged finding. An issue is
// suppressed if ANY certificate its endpoint presents carries an active
// FindingException for that exact issue string.
func discoveryFindingFunnel(findings []discoveryEndpointFindings, activeExceptions []FindingException) *funnelBuilder {
	// Discovery endpoints are per-tenant rows, so an exception only counts
	// for endpoints of the tenant that created it.
	indexes := map[string]map[string]bool{}
	b := newFunnelBuilder()
	for _, ep := range findings {
		idx, ok := indexes[exceptionTenantKey(ep.Tenant)]
		if !ok {
			idx = findingExceptionIndexForTenant(activeExceptions, ep.Tenant)
			indexes[exceptionTenantKey(ep.Tenant)] = idx
		}
		primary := ""
		for _, fp := range ep.CertFingerprints {
			if primary == "" || fp < primary {
				primary = fp
			}
		}
		for _, issue := range ep.Issues {
			suppressed := false
			for _, fp := range ep.CertFingerprints {
				if idx[findingExceptionKey(FindingExceptionTargetCertificate, fp, issue)] {
					suppressed = true
					break
				}
			}
			if primary == "" {
				b.addUnmerged(suppressed)
				continue
			}
			b.Add(ep.Tenant, FindingExceptionTargetCertificate, primary, issue, suppressed)
		}
	}
	return b
}

func (p *dbDiscoveryProvider) ListEndpoints(ctx context.Context, q DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	if err := dbProviderUnavailable("discovery", p.openErr); err != nil {
		return DiscoveryEndpointResult{}, err
	}
	return p.store.ListEndpoints(ctx, q)
}

func (p *dbDiscoveryProvider) ListScanJobs(ctx context.Context, q DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	if err := dbProviderUnavailable("discovery", p.openErr); err != nil {
		return DiscoveryScanJobResult{}, err
	}
	return p.store.ListScanJobs(ctx, q)
}

func (p *dbDiscoveryProvider) CreateScan(ctx context.Context, scanType string, target string, extraPorts []int) (DiscoveryScanCreateResult, error) {
	if err := dbProviderUnavailable("discovery", p.openErr); err != nil {
		return DiscoveryScanCreateResult{}, err
	}
	return p.store.CreateScan(ctx, scanType, target, extraPorts)
}

func (p *dbDiscoveryProvider) CancelScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	if err := dbProviderUnavailable("discovery", p.openErr); err != nil {
		return DiscoveryScanJobActionResult{}, err
	}
	return p.store.CancelScanJob(ctx, scanJobID, reason)
}

func (p *dbDiscoveryProvider) RequeueScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	if err := dbProviderUnavailable("discovery", p.openErr); err != nil {
		return DiscoveryScanJobActionResult{}, err
	}
	return p.store.RequeueScanJob(ctx, scanJobID, reason)
}

// --- SQLite store ---

type sqliteDiscoveryStore struct {
	db        *sql.DB
	winrmScan winRMTargetScanner
	sshScan   sshTargetScanner
	trust     discoveryTrust
	diff      *scanDiffEngine // W24-06; nil = no scan diff
}

func (s *sqliteDiscoveryStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqliteDiscoverySchema)
	if err != nil {
		return err
	}
	// Best-effort: a deployment that ran this schema before W2-11 has an
	// endpoints table with no issues column; CREATE TABLE IF NOT EXISTS
	// above is a no-op against it. Error (already exists) is intentionally
	// discarded — matches agent_store_db.go/pending_action_store.go.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN issues TEXT NOT NULL DEFAULT '[]'") // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN server_tech TEXT")                  // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN recommended_install_mode TEXT")     // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN ssh_banner TEXT")                   // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN ssh_host_key_algorithms TEXT")      // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN crypto_posture TEXT")               // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tech TEXT")                         // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tech_confidence TEXT")              // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN platform TEXT")                     // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tls_stack TEXT")                    // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tech_evidence TEXT")                // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tenant TEXT NOT NULL DEFAULT ''")   // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE scan_jobs ADD COLUMN tenant TEXT NOT NULL DEFAULT ''")   // best-effort upgrade: duplicate-column error = already migrated
	if err := ensureDiscoveryTenantIndex(ctx, s.db); err != nil {
		return err
	}
	if err := ensureDiscoveredFilesSchema(ctx, s.db, false); err != nil {
		return err
	}
	s.trust.SetAuthorizedSource(dbAuthorizedSource(s.db, sqlitePlaceholder))
	// Same best-effort dance for a legacy discovery-only DB whose
	// certificates mirror predates the full-column upsert. Against the
	// migration-managed table every one of these is a duplicate-column
	// no-op.
	for _, stmt := range slices.Concat(discoveryCertMirrorUpgrades, discoveryTrustMirrorUpgradesSQLite, discoveryLinkUpgradesSQLite) {
		_, _ = s.db.ExecContext(ctx, stmt) // best-effort upgrade: duplicate-column error = already migrated
	}
	// Scan runners are in-process goroutines: any job still queued/running
	// at startup died with the previous process and would otherwise sit
	// "running" forever (and inflate Active Scans).
	if _, err := s.db.ExecContext(ctx,
		"UPDATE scan_jobs SET status = 'failed', error_message = 'interrupted by server restart' WHERE status IN ('queued', 'running')"); err != nil {
		return err
	}
	return nil
}

// discoveryCertMirrorUpgrades widens a pre-existing minimal certificates
// mirror to the columns the discovery upsert writes.
var discoveryCertMirrorUpgrades = []string{
	"ALTER TABLE certificates ADD COLUMN serial_number TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN subject_dn TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN common_name TEXT",
	"ALTER TABLE certificates ADD COLUMN subject_alt_names TEXT",
	"ALTER TABLE certificates ADD COLUMN issuer_dn TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN valid_from TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN valid_until TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN public_key_algorithm TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN signature_algorithm TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN risk_flags TEXT NOT NULL DEFAULT '[]'",
	"ALTER TABLE certificates ADD COLUMN raw_cert_b64 TEXT",
	"ALTER TABLE certificates ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN source TEXT NOT NULL DEFAULT 'discovery_network'",
	"ALTER TABLE certificates ADD COLUMN origin TEXT NOT NULL DEFAULT 'discovered'",
	"ALTER TABLE certificates ADD COLUMN management_state TEXT NOT NULL DEFAULT 'unmanaged'",
	"ALTER TABLE certificates ADD COLUMN issuer_cn TEXT",
	"ALTER TABLE certificates ADD COLUMN key_size_bits INTEGER",
	"ALTER TABLE certificates ADD COLUMN trust_class TEXT",
	"ALTER TABLE certificates ADD COLUMN issuer_class TEXT",
}

// Trust-verdict columns differ in type by dialect (sqlite has no BOOLEAN).
var (
	discoveryTrustMirrorUpgradesSQLite = []string{
		"ALTER TABLE certificates ADD COLUMN chain_complete INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE certificates ADD COLUMN chain_trusted INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE certificates ADD COLUMN is_ca INTEGER NOT NULL DEFAULT 0",
	}
	discoveryTrustMirrorUpgradesPostgres = []string{
		"ALTER TABLE certificates ADD COLUMN chain_complete BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificates ADD COLUMN chain_trusted BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificates ADD COLUMN is_ca BOOLEAN NOT NULL DEFAULT FALSE",
	}
)

// Endpoint-scoped columns on certificate_endpoints (migration 000079); a
// pre-existing link table gets them here, a migrated one already has them.
var (
	discoveryLinkUpgradesSQLite = []string{
		"ALTER TABLE certificate_endpoints ADD COLUMN endpoint_flags TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE certificate_endpoints ADD COLUMN endpoint_risk_score INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE certificate_endpoints ADD COLUMN chain_complete INTEGER",
		"ALTER TABLE certificate_endpoints ADD COLUMN chain_trusted INTEGER",
		"ALTER TABLE certificate_endpoints ADD COLUMN source_path TEXT", // 000145
	}
	discoveryLinkUpgradesPostgres = []string{
		"ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS endpoint_flags TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS endpoint_risk_score INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS chain_complete BOOLEAN",
		"ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS chain_trusted BOOLEAN",
		"ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS source_path TEXT", // 000145
	}
)

// upsertOutcome summarizes what upsertScanResults actually persisted.
// W19-22: a single row's failure (the port/protocol CHECK, or any future
// constraint this code doesn't know about) used to abort the WHOLE
// transaction via defer tx.Rollback(), discarding every other endpoint in
// the same sweep — the reason mesh discovery (port-0 Istio/Linkerd
// sources) never landed anything in inventory. Every row now persists
// inside its own SAVEPOINT (upsertOneEndpointWithSavepoint); a caller
// (mesh_discovery_wiring.go's tick, runAndPersistScan) surfaces this as
// "N persisted, M skipped: <first reason>" instead of losing the sweep.
type upsertOutcome struct {
	Persisted       int
	Skipped         int
	FirstSkipReason string
}

// upsertOneEndpointWithSavepoint runs fn (one endpoint's writes) inside a
// SAVEPOINT so its failure rolls back only that row. Required on Postgres,
// where any error inside a transaction poisons every later statement until
// a ROLLBACK (whole, or to a savepoint) — SQLite's own default
// CHECK-violation handling (ABORT: undoes just the failing statement, not
// the transaction) would tolerate skipping this, but the two dialects
// share this exact call site and a savepoint costs nothing extra here.
func upsertOneEndpointWithSavepoint(ctx context.Context, tx *sql.Tx, name string, fn func() error) error {
	if _, err := tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return fmt.Errorf("open savepoint: %w", err)
	}
	if err := fn(); err != nil {
		if _, rbErr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+name); rbErr != nil {
			return fmt.Errorf("%w (savepoint rollback also failed: %v)", err, rbErr)
		}
		_, _ = tx.ExecContext(ctx, "RELEASE SAVEPOINT "+name) // best-effort: the row's writes are already rolled back
		return err
	}
	if _, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+name); err != nil {
		return fmt.Errorf("release savepoint: %w", err)
	}
	return nil
}

// discoveryErrorIssuesJSON records a port-0 source's reachability/
// permission error (e.g. a K8s RBAC 403 reading a mesh secret) as a
// synthetic "issue" so it surfaces via GET /api/v1/discovery/endpoints and
// ListEndpointFindings rather than only a scheduler log line — W19-22's
// acceptance bar for a testable negative RBAC case.
func discoveryErrorIssuesJSON(errText string) string {
	b, err := json.Marshal([]string{"discovery-error: " + errText})
	if err != nil {
		return "[]"
	}
	return string(b)
}

// parseDiscoveryIssuesJSON is ListEndpoints' read-side counterpart to
// discoveryErrorIssuesJSON — best-effort like every other stored-JSON
// unmarshal in this file (sshAlgorithmsJSON/cryptoPostureJSON's readers):
// malformed or absent JSON yields no issues rather than an API error.
func parseDiscoveryIssuesJSON(raw string) []string {
	if raw == "" || raw == "[]" {
		return nil
	}
	var issues []string
	_ = json.Unmarshal([]byte(raw), &issues) // best-effort: malformed stored JSON leaves the slice empty
	return issues
}

// upsertScanResults persists a completed scan's endpoints/certs with dedup
// on (ip_address, port, sni_name) and staleness tracking on
// certificate_endpoints (W2-05/D-032/R-D2): a cert mapping observed in a
// prior scan of this same target but not re-observed now is marked
// currently_active=false ("gone"), scoped strictly to the endpoints this
// scan actually reached — endpoints/certs for OTHER targets are untouched,
// and a real network target this scan couldn't even connect to
// (ep.Error != "", ep.Port != 0) is left alone entirely rather than
// treated as evidence its cert is gone. A port-0 source's error (no prior
// network history to protect — see discoveryErrorIssuesJSON) is recorded
// instead of dropped. Each observed cert's risk_score (computed by the
// scanner) is upserted into the certificates mirror table so
// GetSummary/ListEndpoints' risk-score JOINs resolve against real data —
// see G-55 in DESIGN_REVIEW.md.
func (s *sqliteDiscoveryStore) upsertScanResults(ctx context.Context, results []scanner.DiscoveredEndpoint) (upsertOutcome, error) {
	s.trust.classify(ctx, results)
	issuesByEndpoint, err := auditEndpointTLSIssuesBatch(results)
	if err != nil {
		return upsertOutcome{}, err
	}

	// Before the tx, so the snapshot is what the previous scan left.
	var scanDiffPrior map[string]scanDiffLeaf
	if s.diff != nil {
		scanDiffPrior = s.loadScanDiffPrior(ctx, results)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return upsertOutcome{}, err
	}
	defer tx.Rollback()

	scanTenant := discoveryStampTenant(ctx)
	now := time.Now().UTC().Format(time.RFC3339)
	touchedPairs := make(map[[2]string]bool) // [endpointID, fingerprint]
	var out upsertOutcome

	for i, ep := range results {
		if endpointNeverReached(ep) {
			continue
		}
		issuesJSON := endpointIssuesJSON(ep, issuesByEndpoint[i])
		ep = carryListenerEvidence(ctx, tx, false, scanTenant, ep)
		fp := newEndpointFingerprintCols(ep)

		spErr := upsertOneEndpointWithSavepoint(ctx, tx, fmt.Sprintf("sp_ep_%d", i), func() error {
			var endpointID string
			if err := tx.QueryRowContext(ctx, `
INSERT INTO endpoints (id, ip_address, hostname, port, protocol, sni_name, issues, server_tech, recommended_install_mode, ssh_banner, ssh_host_key_algorithms, crypto_posture, last_scanned, updated_at, tenant, tech, tech_confidence, platform, tls_stack, tech_evidence)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (tenant, ip_address, port, sni_name) DO UPDATE SET
    issues = excluded.issues, protocol = excluded.protocol,
    server_tech = excluded.server_tech,
    recommended_install_mode = excluded.recommended_install_mode,
    ssh_banner = excluded.ssh_banner,
    ssh_host_key_algorithms = excluded.ssh_host_key_algorithms,
    crypto_posture = excluded.crypto_posture,
    tech = excluded.tech, tech_confidence = excluded.tech_confidence,
    platform = excluded.platform, tls_stack = excluded.tls_stack,
    tech_evidence = excluded.tech_evidence,
    last_scanned = excluded.last_scanned, updated_at = excluded.updated_at
RETURNING id
`, newDiscoveryEndpointID(), ep.Host, ep.Host, ep.Port, discoveryProtocolOrDefault(ep.Protocol), ep.Host, issuesJSON, nullString(ep.ServerTech), nullString(ep.RecommendedInstallMode), nullString(ep.Banner), nullString(sshAlgorithmsJSON(ep.HostKeyAlgorithms)), nullString(cryptoPostureJSON(ep.CryptoPosture)), now, now, scanTenant, fp.tech, fp.confidence, fp.platform, fp.tlsStack, fp.evidence).Scan(&endpointID); err != nil {
				return fmt.Errorf("upsert endpoint %s:%d: %w", ep.Host, ep.Port, err)
			}

			if !endpointCertsObserved(ep) {
				return nil // no certs, no staleness sweep: nothing was learned about them
			}

			for _, cert := range ep.Certs {
				if cert.Fingerprint == "" {
					continue
				}
				args, ok := discoveredCertRow(cert, now, false)
				if !ok {
					continue
				}
				if _, err := tx.ExecContext(ctx, `
INSERT INTO certificates `+discoveredCertUpsertColumns+`
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'discovery_network', 'discovered', 'unmanaged')
ON CONFLICT (fingerprint_sha256) DO UPDATE SET`+discoveredCertConflictUpdateSQLite, args...); err != nil {
					return fmt.Errorf("upsert certificates %s: %w", cert.Fingerprint, err)
				}
				if err := upsertCertificateLink(ctx, tx, false, cert, endpointID, now); err != nil {
					return err
				}
				touchedPairs[[2]string{endpointID, cert.Fingerprint}] = true
			}

			// Staleness sweep, scoped to this endpoint only: any mapping that
			// was active before this scan but wasn't just re-observed is gone.
			rows, err := tx.QueryContext(ctx, `
SELECT certificate_fingerprint FROM certificate_endpoints
WHERE endpoint_id = ? AND currently_active = 1
`, endpointID)
			if err != nil {
				return fmt.Errorf("staleness scan for endpoint %s: %w", endpointID, err)
			}
			var staleFingerprints []string
			for rows.Next() {
				var fp string
				if err := rows.Scan(&fp); err != nil {
					rows.Close()
					return err
				}
				if !touchedPairs[[2]string{endpointID, fp}] {
					staleFingerprints = append(staleFingerprints, fp)
				}
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return err
			}
			rows.Close()
			for _, fp := range staleFingerprints {
				if _, err := tx.ExecContext(ctx, `
UPDATE certificate_endpoints SET currently_active = 0 WHERE endpoint_id = ? AND certificate_fingerprint = ?
`, endpointID, fp); err != nil {
					return fmt.Errorf("mark stale %s/%s: %w", fp, endpointID, err)
				}
			}
			return nil
		})
		if spErr != nil {
			logging.Infof("discovery upsert: skipping endpoint %s:%d (%s): %v", ep.Host, ep.Port, ep.Protocol, spErr)
			out.Skipped++
			if out.FirstSkipReason == "" {
				out.FirstSkipReason = spErr.Error()
			}
			continue
		}
		out.Persisted++
	}

	if err := tx.Commit(); err != nil {
		return out, err
	}
	s.diff.afterCommit(ctx, scanDiffPrior, results)
	return out, nil
}

func (s *sqliteDiscoveryStore) GetSummary(ctx context.Context) (DiscoverySummary, error) {
	var summary DiscoverySummary
	sc := newDiscoverySummaryScope(ctx, "?1")
	err := s.db.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM endpoints e WHERE `+sc.endpoints+`) AS discovered_endpoints,
    (SELECT COUNT(DISTINCT ce.certificate_fingerprint) FROM certificate_endpoints ce
        LEFT JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
        WHERE ce.currently_active = 1 AND COALESCE(c.is_ca, 0) = 0 AND `+sc.links+`) AS mapped_certificates,
    (SELECT COUNT(*) FROM endpoints e WHERE `+sc.endpoints+` AND `+riskyEndpointSQL("1")+`) AS risky_endpoints,
    (SELECT COUNT(*) FROM scan_jobs WHERE status IN ('queued', 'running') AND `+sc.jobs+`) AS active_scan_jobs
`, sc.args...).Scan(&summary.DiscoveredEndpoints, &summary.MappedCertificates, &summary.RiskyEndpoints, &summary.ActiveScanJobs)
	if err != nil {
		return summary, err
	}
	summary.TrustClasses, err = loadTrustClassCounts(ctx, s.db, "ce.currently_active = 1 AND "+sc.links, "COALESCE(c.is_ca, 0) = 0", sc.args...)
	if err != nil {
		return summary, err
	}
	summary.InventoryClasses, err = loadInventoryClassCounts(ctx, s.db, "ce.currently_active = 1 AND "+sc.links, "COALESCE(c.is_ca, 0) = 0", sc.args...)
	return summary, err
}

// loadTrustClassCounts counts the distinct leaf certificates currently seen on
// the network per effective trust class, hub-issued ones included: a managed
// cert served on two endpoints is one managed certificate, and the classes
// always sum to the number of distinct certificates with an active endpoint
// mapping (the mapped_certificates figure). activeCond/notCA are the dialect's
// predicates over `ce` / `c`. Chain CAs are not leaf inventory; a certificate
// never classified, or carrying a value outside the vocabulary, counts as
// unknown. A managed row never carries a discovery verdict (discovery does not
// write managed rows), so management_state decides it.
func loadTrustClassCounts(ctx context.Context, db *sql.DB, activeCond, notCA string, args ...any) (TrustClassCounts, error) {
	rows, err := db.QueryContext(ctx, `
SELECT `+effectiveTrustClassSQL+` AS class, COUNT(DISTINCT ce.certificate_fingerprint)
FROM certificate_endpoints ce
LEFT JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
WHERE `+activeCond+` AND `+notCA+`
GROUP BY `+effectiveTrustClassSQL, args...)
	if err != nil {
		return TrustClassCounts{}, err
	}
	defer rows.Close()
	var out TrustClassCounts
	for rows.Next() {
		var class string
		var n int
		if err := rows.Scan(&class, &n); err != nil {
			return TrustClassCounts{}, err
		}
		out.add(class, n)
	}
	return out, rows.Err()
}

func (s *sqliteDiscoveryStore) ListEndpointFindings(ctx context.Context) ([]discoveryEndpointFindings, error) {
	sc := newDiscoverySummaryScope(ctx, "?1")
	return listDiscoveryEndpointFindings(ctx, s.db, "SELECT e.id, e.issues, e.tenant FROM endpoints e WHERE "+sc.endpoints,
		"SELECT ce.endpoint_id, ce.certificate_fingerprint, COALESCE(CAST(c.risk_flags AS TEXT), '[]'), COALESCE(ce.endpoint_flags, '[]') FROM certificate_endpoints ce LEFT JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256 WHERE ce.currently_active = 1 AND "+sc.links, sc.args...)
}

func (s *sqliteDiscoveryStore) ListEndpoints(ctx context.Context, q DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	cursor := q.Cursor
	if cursor < 0 {
		cursor = 0
	}

	where := make([]string, 0)
	args := make([]any, 0)
	if tenant, filter := discoveryFilterTenant(ctx); filter {
		where = append(where, "e.tenant = ?")
		args = append(args, tenant)
	}
	if q.Protocol != "" {
		where = append(where, "e.protocol = ?")
		args = append(args, q.Protocol)
	}
	if q.RiskyOnly {
		where = append(where, riskyEndpointSQL("1"))
	}
	if q.TrustClass != "" {
		where = append(where, `e.id IN (
			SELECT ce.endpoint_id FROM certificate_endpoints ce
			JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
			WHERE `+trustClassPredicate(q.TrustClass, "c", "ce.currently_active = 1", "c.is_ca = 0")+`
		)`)
	}
	if q.InventoryClass != "" {
		where = append(where, `e.id IN (
			SELECT ce.endpoint_id FROM certificate_endpoints ce
			JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
			WHERE `+inventoryClassPredicate(q.InventoryClass, "ce.currently_active = 1", "c.is_ca = 0")+`
		)`)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM endpoints e"+whereSQL, args...).Scan(&total); err != nil {
		return DiscoveryEndpointResult{}, err
	}

	if cursor > total {
		cursor = total
	}

	listArgs := append(append([]any{}, args...), limit, cursor)
	rows, err := s.db.QueryContext(ctx, `
SELECT e.id, COALESCE(e.hostname, e.ip_address), e.port, e.protocol,
       COALESCE((SELECT MAX(c.risk_score) FROM certificate_endpoints ce
                 JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
                 WHERE ce.endpoint_id = e.id AND ce.currently_active = 1), 0) AS risk_score,
       COALESCE(e.last_scanned, e.created_at) AS last_seen_at,
       COALESCE(e.server_tech, ''), COALESCE(e.recommended_install_mode, ''),
       COALESCE(e.tech, ''), COALESCE(e.tech_confidence, ''), COALESCE(e.platform, ''),
       COALESCE(e.tls_stack, ''), COALESCE(e.tech_evidence, ''),
       COALESCE(e.ssh_banner, ''), COALESCE(e.ssh_host_key_algorithms, ''),
       COALESCE(e.crypto_posture, ''), COALESCE(e.issues, '[]')
FROM endpoints e`+whereSQL+`
ORDER BY e.id ASC
LIMIT ? OFFSET ?
`, listArgs...)
	if err != nil {
		return DiscoveryEndpointResult{}, err
	}
	defer rows.Close()

	endpoints := make([]DiscoveryEndpoint, 0)
	for rows.Next() {
		var ep DiscoveryEndpoint
		var sshBanner, sshAlgs, postureJSON, issuesJSON, evidenceJSON string
		if err := rows.Scan(&ep.ID, &ep.Hostname, &ep.Port, &ep.Protocol, &ep.RiskScore, &ep.LastSeenAt, &ep.ServerTech, &ep.RecommendedInstallMode, &ep.Tech, &ep.TechConfidence, &ep.Platform, &ep.TLSStack, &evidenceJSON, &sshBanner, &sshAlgs, &postureJSON, &issuesJSON); err != nil {
			return DiscoveryEndpointResult{}, err
		}
		ep.TechEvidence = scanner.ParseEvidenceJSON(evidenceJSON)
		ep.SSHBanner = sshBanner
		if sshAlgs != "" && sshAlgs != "[]" {
			_ = json.Unmarshal([]byte(sshAlgs), &ep.SSHHostKeyAlgorithms) // best-effort: malformed stored JSON leaves the slice empty
		}
		if postureJSON != "" {
			var cp scanner.CryptoPosture
			if json.Unmarshal([]byte(postureJSON), &cp) == nil {
				ep.CryptoPosture = &cp
			}
		}
		ep.Issues = parseDiscoveryIssuesJSON(issuesJSON)
		endpoints = append(endpoints, ep)
	}
	if err := rows.Err(); err != nil {
		return DiscoveryEndpointResult{}, err
	}
	if err := attachMappedCerts(ctx, s.db, "?", endpoints); err != nil {
		return DiscoveryEndpointResult{}, err
	}
	attachInstallPosture(ctx, s.db, false, endpoints)
	setInventoryClasses(endpoints)
	markRiskyEndpoints(endpoints)

	end := cursor + limit
	if end > total {
		end = total
	}
	var nextCursor *int
	if end < total {
		n := end
		nextCursor = &n
	}
	var prevCursor *int
	if cursor > 0 {
		p := cursor - limit
		if p < 0 {
			p = 0
		}
		prevCursor = &p
	}

	return DiscoveryEndpointResult{
		Endpoints:  endpoints,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursor,
		PrevCursor: prevCursor,
	}, nil
}

// attachMappedCerts fills each endpoint's MappedCerts from the
// certificate_endpoints join. One query per page of endpoints (the page is
// ≤100 rows), placeholder style parameterized so both engines share it.
func attachMappedCerts(ctx context.Context, db *sql.DB, style string, endpoints []DiscoveryEndpoint) error {
	if len(endpoints) == 0 {
		return nil
	}
	byID := make(map[string]int, len(endpoints))
	placeholders := make([]string, 0, len(endpoints))
	args := make([]any, 0, len(endpoints))
	for i := range endpoints {
		byID[endpoints[i].ID] = i
		if style == "$" {
			placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
		} else {
			placeholders = append(placeholders, "?")
		}
		args = append(args, endpoints[i].ID)
	}
	active := "1"
	// risk_flags is JSON text on sqlite but TEXT[] on postgres, where a bare
	// '[]' literal is a malformed array and the array prints as {A,B}; emit
	// JSON there so both dialects unmarshal the same way.
	riskFlags := "COALESCE(c.risk_flags, '[]')"
	// is_ca is a native BOOLEAN on postgres, 0/1 on sqlite.
	chainBool := "COALESCE(c.is_ca, 0)"
	// chain_complete / chain_trusted are the LINK's: nullable, -1 = never judged
	// for this endpoint.
	chainComplete := "CASE WHEN ce.chain_complete IS NULL THEN -1 WHEN ce.chain_complete <> 0 THEN 1 ELSE 0 END"
	chainTrusted := "CASE WHEN ce.chain_trusted IS NULL THEN -1 WHEN ce.chain_trusted <> 0 THEN 1 ELSE 0 END"
	if style == "$" {
		active = "true"
		riskFlags = "COALESCE(array_to_json(c.risk_flags)::text, '[]')"
		chainBool = "CASE WHEN c.is_ca THEN 1 ELSE 0 END"
		chainComplete = "CASE WHEN ce.chain_complete IS NULL THEN -1 WHEN ce.chain_complete THEN 1 ELSE 0 END"
		chainTrusted = "CASE WHEN ce.chain_trusted IS NULL THEN -1 WHEN ce.chain_trusted THEN 1 ELSE 0 END"
	}
	rows, err := db.QueryContext(ctx, `
SELECT ce.endpoint_id, ce.certificate_fingerprint,
       COALESCE(c.common_name, ''), COALESCE(CAST(c.valid_until AS TEXT), ''), COALESCE(c.risk_score, 0),
       `+riskFlags+`, `+effectiveTrustClassSQL+`, `+effectiveIssuerClassSQL+`, `+inventoryClassSQL+`, COALESCE(c.issuer_dn, ''), `+chainBool+`, `+chainComplete+`, `+chainTrusted+`,
       COALESCE(ce.endpoint_flags, '[]'), COALESCE(ce.endpoint_risk_score, 0), COALESCE(ce.source_path, '')
FROM certificate_endpoints ce
LEFT JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
WHERE ce.currently_active = `+active+` AND ce.endpoint_id IN (`+strings.Join(placeholders, ", ")+`)
ORDER BY ce.certificate_fingerprint ASC
`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var endpointID, flagsJSON, linkFlagsJSON string
		var isCA, complete, trusted, linkScore int
		var mc DiscoveryMappedCert
		if err := rows.Scan(&endpointID, &mc.Fingerprint, &mc.CommonName, &mc.ValidUntil, &mc.RiskScore, &flagsJSON, &mc.TrustClass, &mc.IssuerClass, &mc.InventoryClass, &mc.IssuerDN, &isCA, &complete, &trusted, &linkFlagsJSON, &linkScore, &mc.SourcePath); err != nil {
			return err
		}
		mc.ChainCA, mc.ChainTrusted = isCA == 1, trusted == 1
		if complete >= 0 {
			known := complete == 1
			mc.ChainComplete = &known
		}
		// The certificate's own flags and score plus what this endpoint's
		// serving of it adds.
		mc.RiskFlags = mergeLinkFlags(parseRiskFlagsText(flagsJSON), parseRiskFlagsText(linkFlagsJSON))
		mc.RiskScore = min(mc.RiskScore+linkScore, 100)
		if i, ok := byID[endpointID]; ok {
			endpoints[i].MappedCerts = append(endpoints[i].MappedCerts, mc)
		}
	}
	return rows.Err()
}

func (s *sqliteDiscoveryStore) ListScanJobs(ctx context.Context, q DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	cursor := q.Cursor
	if cursor < 0 {
		cursor = 0
	}

	where := make([]string, 0)
	args := make([]any, 0)
	if tenant, filter := discoveryFilterTenant(ctx); filter {
		where = append(where, "tenant = ?")
		args = append(args, tenant)
	}
	if q.Status != "" {
		where = append(where, "status = ?")
		args = append(args, q.Status)
	}
	if q.Q != "" {
		where = append(where, `scope LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLIKE(q.Q)+"%")
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_jobs"+whereSQL, args...).Scan(&total); err != nil {
		return DiscoveryScanJobResult{}, err
	}

	if cursor > total {
		cursor = total
	}

	listArgs := append(append([]any{}, args...), limit, cursor)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, type, scope, status, created_at, COALESCE(error_message, '')
FROM scan_jobs`+whereSQL+`
ORDER BY created_at DESC
LIMIT ? OFFSET ?
`, listArgs...)
	if err != nil {
		return DiscoveryScanJobResult{}, err
	}
	defer rows.Close()

	jobs := make([]DiscoveryScanJob, 0)
	for rows.Next() {
		var j DiscoveryScanJob
		if err := rows.Scan(&j.ID, &j.ScanType, &j.Target, &j.Status, &j.QueuedAt, &j.Error); err != nil {
			return DiscoveryScanJobResult{}, err
		}
		j.Target = scanScopeTarget(j.Target)
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return DiscoveryScanJobResult{}, err
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	var nextCursor *int
	if end < total {
		n := end
		nextCursor = &n
	}
	var prevCursor *int
	if cursor > 0 {
		p := cursor - limit
		if p < 0 {
			p = 0
		}
		prevCursor = &p
	}

	return DiscoveryScanJobResult{
		ScanJobs:   jobs,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursor,
		PrevCursor: prevCursor,
	}, nil
}

func (s *sqliteDiscoveryStore) CreateScan(ctx context.Context, scanType string, target string, extraPorts []int) (DiscoveryScanCreateResult, error) {
	// W5-12: refuse BEFORE inserting — a running job nothing will ever
	// finish is worse than an error.
	if !isNetworkScanType(scanType) && !isCloudScanType(scanType) && scanType != scanTypeK8sCertManager && !(scanType == scanTypeWinRM && s.winrmScan != nil) && !(scanType == scanTypeSSH && s.sshScan != nil) {
		return DiscoveryScanCreateResult{}, fmt.Errorf("scan type %q has no runner (network types: full/targeted/fast/network; cloud types: cloud_acm/cloud_azure_kv/cloud_gcp_cm; k8s-certmanager: cert-manager connector; winrm and ssh need a managed target)", scanType)
	}
	now := time.Now().UTC()
	id := fmt.Sprintf("scan-%d", now.UnixNano())
	scanTenant := discoveryStampTenant(ctx)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO scan_jobs (id, type, connector, scope, status, tenant)
VALUES (?, ?, 'api', ?, 'running', ?)
`, id, scanType, scanScopeJSON(target, extraPorts), scanTenant)
	if err != nil {
		return DiscoveryScanCreateResult{}, err
	}
	// Runs in the background past this request's lifetime — matches
	// scannerDiscoveryProvider's own runNetworkScan pattern — so it must use
	// its own context, not the (about-to-be-canceled) request context.
	if isCloudScanType(scanType) {
		go runCloudScanAndFinalize(context.Background(), s.db, false, id, scanType)
		return DiscoveryScanCreateResult{
			ID:       id,
			Status:   "running",
			ScanType: scanType,
			Target:   target,
			QueuedAt: now.Format(time.RFC3339),
		}, nil
	}
	if scanType == scanTypeK8sCertManager {
		go runK8sCertManagerScanAndFinalize(context.Background(), s.db, false, id)
		return DiscoveryScanCreateResult{
			ID:       id,
			Status:   "running",
			ScanType: scanType,
			Target:   target,
			QueuedAt: now.Format(time.RFC3339),
		}, nil
	}
	go s.runAndPersistScan(carryJITSudo(ctx, withDiscoveryTenant(context.Background(), scanTenant)), id, target, scanType, extraPorts)
	return DiscoveryScanCreateResult{
		ID:       id,
		Status:   "running",
		ScanType: scanType,
		Target:   target,
		QueuedAt: now.Format(time.RFC3339),
	}, nil
}

// runAndPersistScan runs a real network scan against target (network scan
// types only — k8s-certmanager and other connector scans have no DB-mode
// path today, matching what "db" mode supported before this ticket: none)
// and persists the results via upsertScanResults, then finalizes the
// scan_jobs row's status. "completed" (not "complete") matches the canonical
// DiscoveryScanJob.Status spelling scannerDiscoveryProvider/discovery_file_provider.go
// already used (G-87/S-23 — this was the one real inconsistency).
func (s *sqliteDiscoveryStore) runAndPersistScan(ctx context.Context, jobID, target, scanType string, extraPorts []int) {
	defer afterDiscoveryScanPersist(jobID)
	result := runTargetOrNetworkScan(ctx, s.winrmScan, s.sshScan, jobID, target, scanType, extraPorts)

	out, err := s.upsertScanResults(ctx, result.Endpoints)
	if err == nil {
		applyHostObservations(ctx, s.db, false, result.Endpoints)
	}
	if err != nil {
		logging.Warnf("discovery scan %s: persist results failed: %v", jobID, err)
	} else if skipMsg := summarizeUpsertSkips(out); skipMsg != "" {
		// W19-22: a per-row skip (isolated by upsertOneEndpointWithSavepoint)
		// no longer aborts the whole scan, but it must not go unreported.
		logging.Infof("discovery scan %s: %s", jobID, skipMsg)
	}
	status, errMsg := scanJobOutcome(result, out, err)
	if _, err := s.db.ExecContext(ctx, "UPDATE scan_jobs SET status = ?, error_message = ? WHERE id = ?", status, errMsg, jobID); err != nil {
		logging.Warnf("discovery scan %s: finalize status failed: %v", jobID, err)
	}
}

// summarizeUpsertSkips renders upsertScanResults' outcome as an operator-
// visible line when at least one endpoint was skipped — "N persisted, M
// skipped: <first reason>" (W19-22 acceptance: a skipped row must be
// visible, not just silently absent from the endpoint count). Empty when
// nothing was skipped.
func summarizeUpsertSkips(out upsertOutcome) string {
	if out.Skipped == 0 {
		return ""
	}
	return fmt.Sprintf("%d endpoint(s) persisted, %d skipped: %s", out.Persisted, out.Skipped, out.FirstSkipReason)
}

// truncateScanError bounds what lands in scan_jobs.error_message — the
// column exists to explain a failure, not to archive a driver stack.
func truncateScanError(err error) string {
	msg := err.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

func (s *sqliteDiscoveryStore) CancelScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	if err := requireDiscoveryJobVisible(ctx, s.db, scanJobID, "?", "?"); err != nil {
		return DiscoveryScanJobActionResult{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.ExecContext(ctx, `
UPDATE scan_jobs SET status = 'cancelled', error_message = ? WHERE id = ? AND status IN ('queued', 'running')
`, reason, scanJobID)
	if err != nil {
		return DiscoveryScanJobActionResult{}, err
	}
	affected, _ := result.RowsAffected()
	status := "canceled"
	if affected == 0 {
		status = "not_found_or_already_terminal"
	}
	return DiscoveryScanJobActionResult{
		ScanJobID: scanJobID,
		Status:    status,
		Reason:    reason,
		UpdatedAt: now,
	}, nil
}

func (s *sqliteDiscoveryStore) RequeueScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	now := time.Now().UTC()
	newID := fmt.Sprintf("scan-%d", now.UnixNano())

	if err := requireDiscoveryJobVisible(ctx, s.db, scanJobID, "?", "?"); err != nil {
		return DiscoveryScanJobActionResult{}, err
	}
	var scanType, scope, jobTenant string
	err := s.db.QueryRowContext(ctx, "SELECT type, scope, tenant FROM scan_jobs WHERE id = ?", scanJobID).Scan(&scanType, &scope, &jobTenant)
	if err != nil {
		return DiscoveryScanJobActionResult{}, fmt.Errorf("original scan job not found: %w", err)
	}

	// The copy stays in the original job's tenant even when a super-admin
	// requeues it: whose scan this is doesn't change with who pressed retry.
	_, err = s.db.ExecContext(ctx, `
INSERT INTO scan_jobs (id, type, connector, scope, status, error_message, tenant)
VALUES (?, ?, 'api', ?, 'queued', ?, ?)
`, newID, scanType, scope, fmt.Sprintf("requeue of %s: %s", scanJobID, reason), jobTenant)
	if err != nil {
		return DiscoveryScanJobActionResult{}, err
	}

	return DiscoveryScanJobActionResult{
		PreviousID: scanJobID,
		ScanJobID:  newID,
		Status:     "queued",
		Reason:     reason,
		QueuedAt:   now.Format(time.RFC3339),
	}, nil
}

// --- Postgres store ---

type postgresDiscoveryStore struct {
	db        *sql.DB
	winrmScan winRMTargetScanner
	sshScan   sshTargetScanner
	trust     discoveryTrust
	diff      *scanDiffEngine // W24-06; nil = no scan diff
}

func (s *postgresDiscoveryStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, postgresDiscoverySchema)
	if err != nil {
		return err
	}
	// Best-effort: a deployment that ran this schema before W2-11 has an
	// endpoints table with no issues column; CREATE TABLE IF NOT EXISTS
	// above is a no-op against it. Error (already exists) is intentionally
	// discarded — matches agent_store_db.go/pending_action_store.go.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN issues TEXT NOT NULL DEFAULT '[]'") // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN server_tech TEXT")                  // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN recommended_install_mode TEXT")     // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN ssh_banner TEXT")                   // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN ssh_host_key_algorithms TEXT")      // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN crypto_posture TEXT")               // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tech TEXT")                         // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tech_confidence TEXT")              // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN platform TEXT")                     // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tls_stack TEXT")                    // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tech_evidence TEXT")                // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE endpoints ADD COLUMN tenant TEXT NOT NULL DEFAULT ''")   // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE scan_jobs ADD COLUMN tenant TEXT NOT NULL DEFAULT ''")   // best-effort upgrade: duplicate-column error = already migrated
	if err := ensureDiscoveryTenantIndex(ctx, s.db); err != nil {
		return err
	}
	if err := ensureDiscoveredFilesSchema(ctx, s.db, true); err != nil {
		return err
	}
	s.trust.SetAuthorizedSource(dbAuthorizedSource(s.db, postgresPlaceholder))
	for _, stmt := range slices.Concat(discoveryCertMirrorUpgrades, discoveryTrustMirrorUpgradesPostgres, discoveryLinkUpgradesPostgres) {
		_, _ = s.db.ExecContext(ctx, stmt) // best-effort upgrade: duplicate-column error = already migrated
	}
	if _, err := s.db.ExecContext(ctx,
		"UPDATE scan_jobs SET status = 'failed', error_message = 'interrupted by server restart' WHERE status IN ('queued', 'running')"); err != nil {
		return err
	}
	return nil
}

// upsertScanResults is the postgres counterpart to
// sqliteDiscoveryStore.upsertScanResults — see that method's doc comment for
// the dedup/staleness/error-handling semantics, identical here modulo
// placeholder syntax. The per-row SAVEPOINT isolation (upsertOutcome,
// upsertOneEndpointWithSavepoint) matters MORE here than on SQLite:
// Postgres poisons the whole transaction on any error until a ROLLBACK
// (whole, or to a savepoint), so without it the second endpoint's INSERT
// after a first-endpoint failure would itself fail with "current
// transaction is aborted."
func (s *postgresDiscoveryStore) upsertScanResults(ctx context.Context, results []scanner.DiscoveredEndpoint) (upsertOutcome, error) {
	s.trust.classify(ctx, results)
	issuesByEndpoint, err := auditEndpointTLSIssuesBatch(results)
	if err != nil {
		return upsertOutcome{}, err
	}

	// Before the tx, so the snapshot is what the previous scan left.
	var scanDiffPrior map[string]scanDiffLeaf
	if s.diff != nil {
		scanDiffPrior = s.loadScanDiffPrior(ctx, results)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return upsertOutcome{}, err
	}
	defer tx.Rollback()

	scanTenant := discoveryStampTenant(ctx)
	now := time.Now().UTC()
	touchedPairs := make(map[[2]string]bool)
	var out upsertOutcome

	for i, ep := range results {
		if endpointNeverReached(ep) {
			continue
		}
		issuesJSON := endpointIssuesJSON(ep, issuesByEndpoint[i])
		ep = carryListenerEvidence(ctx, tx, true, scanTenant, ep)
		fp := newEndpointFingerprintCols(ep)

		spErr := upsertOneEndpointWithSavepoint(ctx, tx, fmt.Sprintf("sp_ep_%d", i), func() error {
			var endpointID string
			if err := tx.QueryRowContext(ctx, `
INSERT INTO endpoints (id, ip_address, hostname, port, protocol, sni_name, issues, server_tech, recommended_install_mode, ssh_banner, ssh_host_key_algorithms, crypto_posture, last_scanned, updated_at, tenant, tech, tech_confidence, platform, tls_stack, tech_evidence)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
ON CONFLICT (tenant, ip_address, port, sni_name) DO UPDATE SET
    issues = excluded.issues, protocol = excluded.protocol,
    server_tech = excluded.server_tech,
    recommended_install_mode = excluded.recommended_install_mode,
    ssh_banner = excluded.ssh_banner,
    ssh_host_key_algorithms = excluded.ssh_host_key_algorithms,
    crypto_posture = excluded.crypto_posture,
    tech = excluded.tech, tech_confidence = excluded.tech_confidence,
    platform = excluded.platform, tls_stack = excluded.tls_stack,
    tech_evidence = excluded.tech_evidence,
    last_scanned = excluded.last_scanned, updated_at = excluded.updated_at
RETURNING id
`, newDiscoveryEndpointID(), ep.Host, ep.Host, ep.Port, discoveryProtocolOrDefault(ep.Protocol), ep.Host, issuesJSON, nullString(ep.ServerTech), nullString(ep.RecommendedInstallMode), nullString(ep.Banner), nullString(sshAlgorithmsJSON(ep.HostKeyAlgorithms)), nullString(cryptoPostureJSON(ep.CryptoPosture)), now, now, scanTenant, fp.tech, fp.confidence, fp.platform, fp.tlsStack, fp.evidence).Scan(&endpointID); err != nil {
				return fmt.Errorf("upsert endpoint %s:%d: %w", ep.Host, ep.Port, err)
			}

			if !endpointCertsObserved(ep) {
				return nil // no certs, no staleness sweep: nothing was learned about them
			}

			for _, cert := range ep.Certs {
				if cert.Fingerprint == "" {
					continue
				}
				args, ok := discoveredCertRow(cert, now.Format(time.RFC3339), true)
				if !ok {
					continue
				}
				if _, err := tx.ExecContext(ctx, `
INSERT INTO certificates `+discoveredCertUpsertColumns+`
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, 'discovery_network', 'discovered', 'unmanaged')
ON CONFLICT (fingerprint_sha256) DO UPDATE SET`+discoveredCertConflictUpdatePostgres, args...); err != nil {
					return fmt.Errorf("upsert certificates %s: %w", cert.Fingerprint, err)
				}
				if err := upsertCertificateLink(ctx, tx, true, cert, endpointID, now); err != nil {
					return err
				}
				touchedPairs[[2]string{endpointID, cert.Fingerprint}] = true
			}

			rows, err := tx.QueryContext(ctx, `
SELECT certificate_fingerprint FROM certificate_endpoints
WHERE endpoint_id = $1 AND currently_active = true
`, endpointID)
			if err != nil {
				return fmt.Errorf("staleness scan for endpoint %s: %w", endpointID, err)
			}
			var staleFingerprints []string
			for rows.Next() {
				var fp string
				if err := rows.Scan(&fp); err != nil {
					rows.Close()
					return err
				}
				if !touchedPairs[[2]string{endpointID, fp}] {
					staleFingerprints = append(staleFingerprints, fp)
				}
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return err
			}
			rows.Close()
			for _, fp := range staleFingerprints {
				if _, err := tx.ExecContext(ctx, `
UPDATE certificate_endpoints SET currently_active = false WHERE endpoint_id = $1 AND certificate_fingerprint = $2
`, endpointID, fp); err != nil {
					return fmt.Errorf("mark stale %s/%s: %w", fp, endpointID, err)
				}
			}
			return nil
		})
		if spErr != nil {
			logging.Infof("discovery upsert: skipping endpoint %s:%d (%s): %v", ep.Host, ep.Port, ep.Protocol, spErr)
			out.Skipped++
			if out.FirstSkipReason == "" {
				out.FirstSkipReason = spErr.Error()
			}
			continue
		}
		out.Persisted++
	}

	if err := tx.Commit(); err != nil {
		return out, err
	}
	s.diff.afterCommit(ctx, scanDiffPrior, results)
	return out, nil
}

func (s *postgresDiscoveryStore) GetSummary(ctx context.Context) (DiscoverySummary, error) {
	var summary DiscoverySummary
	sc := newDiscoverySummaryScope(ctx, "$1")
	err := s.db.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM endpoints e WHERE `+sc.endpoints+`) AS discovered_endpoints,
    (SELECT COUNT(DISTINCT ce.certificate_fingerprint) FROM certificate_endpoints ce
        LEFT JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
        WHERE ce.currently_active = true AND NOT COALESCE(c.is_ca, FALSE) AND `+sc.links+`) AS mapped_certificates,
    (SELECT COUNT(*) FROM endpoints e WHERE `+sc.endpoints+` AND `+riskyEndpointSQL("true")+`) AS risky_endpoints,
    (SELECT COUNT(*) FROM scan_jobs WHERE status IN ('queued', 'running') AND `+sc.jobs+`) AS active_scan_jobs
`, sc.args...).Scan(&summary.DiscoveredEndpoints, &summary.MappedCertificates, &summary.RiskyEndpoints, &summary.ActiveScanJobs)
	if err != nil {
		return summary, err
	}
	summary.TrustClasses, err = loadTrustClassCounts(ctx, s.db, "ce.currently_active = true AND "+sc.links, "NOT COALESCE(c.is_ca, FALSE)", sc.args...)
	if err != nil {
		return summary, err
	}
	summary.InventoryClasses, err = loadInventoryClassCounts(ctx, s.db, "ce.currently_active = true AND "+sc.links, "NOT COALESCE(c.is_ca, FALSE)", sc.args...)
	return summary, err
}

func (s *postgresDiscoveryStore) ListEndpointFindings(ctx context.Context) ([]discoveryEndpointFindings, error) {
	sc := newDiscoverySummaryScope(ctx, "$1")
	return listDiscoveryEndpointFindings(ctx, s.db, "SELECT e.id, e.issues, e.tenant FROM endpoints e WHERE "+sc.endpoints,
		"SELECT ce.endpoint_id, ce.certificate_fingerprint, COALESCE(CAST(c.risk_flags AS TEXT), '[]'), COALESCE(ce.endpoint_flags, '[]') FROM certificate_endpoints ce LEFT JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256 WHERE ce.currently_active = true AND "+sc.links, sc.args...)
}

func (s *postgresDiscoveryStore) ListEndpoints(ctx context.Context, q DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	cursor := q.Cursor
	if cursor < 0 {
		cursor = 0
	}

	where := make([]string, 0)
	args := make([]any, 0)
	nextArg := 1
	if tenant, filter := discoveryFilterTenant(ctx); filter {
		where = append(where, fmt.Sprintf("e.tenant = $%d", nextArg))
		args = append(args, tenant)
		nextArg++
	}
	if q.Protocol != "" {
		where = append(where, fmt.Sprintf("e.protocol = $%d", nextArg))
		args = append(args, q.Protocol)
		nextArg++
	}
	if q.RiskyOnly {
		where = append(where, riskyEndpointSQL("true"))
	}
	if q.TrustClass != "" {
		where = append(where, `e.id IN (
			SELECT ce.endpoint_id FROM certificate_endpoints ce
			JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
			WHERE `+trustClassPredicate(q.TrustClass, "c", "ce.currently_active = true", "NOT c.is_ca")+`
		)`)
	}
	if q.InventoryClass != "" {
		where = append(where, `e.id IN (
			SELECT ce.endpoint_id FROM certificate_endpoints ce
			JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
			WHERE `+inventoryClassPredicate(q.InventoryClass, "ce.currently_active = true", "NOT c.is_ca")+`
		)`)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM endpoints e"+whereSQL, args...).Scan(&total); err != nil {
		return DiscoveryEndpointResult{}, err
	}

	if cursor > total {
		cursor = total
	}

	limitPlaceholder := fmt.Sprintf("$%d", nextArg)
	args = append(args, limit)
	nextArg++
	offsetPlaceholder := fmt.Sprintf("$%d", nextArg)
	args = append(args, cursor)

	rows, err := s.db.QueryContext(ctx, `
SELECT e.id, COALESCE(e.hostname, e.ip_address), e.port, e.protocol,
       COALESCE((SELECT MAX(c.risk_score) FROM certificate_endpoints ce
                 JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
                 WHERE ce.endpoint_id = e.id AND ce.currently_active = true), 0) AS risk_score,
       COALESCE(e.last_scanned, e.created_at) AS last_seen_at,
       COALESCE(e.server_tech, ''), COALESCE(e.recommended_install_mode, ''),
       COALESCE(e.tech, ''), COALESCE(e.tech_confidence, ''), COALESCE(e.platform, ''),
       COALESCE(e.tls_stack, ''), COALESCE(e.tech_evidence, ''),
       COALESCE(e.ssh_banner, ''), COALESCE(e.ssh_host_key_algorithms, ''),
       COALESCE(e.crypto_posture, ''), COALESCE(e.issues, '[]')
FROM endpoints e`+whereSQL+`
ORDER BY e.id ASC
LIMIT `+limitPlaceholder+` OFFSET `+offsetPlaceholder+`
`, args...)
	if err != nil {
		return DiscoveryEndpointResult{}, err
	}
	defer rows.Close()

	endpoints := make([]DiscoveryEndpoint, 0)
	for rows.Next() {
		var ep DiscoveryEndpoint
		var sshBanner, sshAlgs, postureJSON, issuesJSON, evidenceJSON string
		if err := rows.Scan(&ep.ID, &ep.Hostname, &ep.Port, &ep.Protocol, &ep.RiskScore, &ep.LastSeenAt, &ep.ServerTech, &ep.RecommendedInstallMode, &ep.Tech, &ep.TechConfidence, &ep.Platform, &ep.TLSStack, &evidenceJSON, &sshBanner, &sshAlgs, &postureJSON, &issuesJSON); err != nil {
			return DiscoveryEndpointResult{}, err
		}
		ep.TechEvidence = scanner.ParseEvidenceJSON(evidenceJSON)
		ep.SSHBanner = sshBanner
		if sshAlgs != "" && sshAlgs != "[]" {
			_ = json.Unmarshal([]byte(sshAlgs), &ep.SSHHostKeyAlgorithms) // best-effort: malformed stored JSON leaves the slice empty
		}
		if postureJSON != "" {
			var cp scanner.CryptoPosture
			if json.Unmarshal([]byte(postureJSON), &cp) == nil {
				ep.CryptoPosture = &cp
			}
		}
		ep.Issues = parseDiscoveryIssuesJSON(issuesJSON)
		endpoints = append(endpoints, ep)
	}
	if err := rows.Err(); err != nil {
		return DiscoveryEndpointResult{}, err
	}
	if err := attachMappedCerts(ctx, s.db, "$", endpoints); err != nil {
		return DiscoveryEndpointResult{}, err
	}
	attachInstallPosture(ctx, s.db, true, endpoints)
	setInventoryClasses(endpoints)
	markRiskyEndpoints(endpoints)

	end := cursor + limit
	if end > total {
		end = total
	}
	var nextCursorP *int
	if end < total {
		n := end
		nextCursorP = &n
	}
	var prevCursorP *int
	if cursor > 0 {
		p := cursor - limit
		if p < 0 {
			p = 0
		}
		prevCursorP = &p
	}

	return DiscoveryEndpointResult{
		Endpoints:  endpoints,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursorP,
		PrevCursor: prevCursorP,
	}, nil
}

func (s *postgresDiscoveryStore) ListScanJobs(ctx context.Context, q DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	cursor := q.Cursor
	if cursor < 0 {
		cursor = 0
	}

	where := make([]string, 0)
	args := make([]any, 0)
	nextArg := 1
	if tenant, filter := discoveryFilterTenant(ctx); filter {
		where = append(where, fmt.Sprintf("tenant = $%d", nextArg))
		args = append(args, tenant)
		nextArg++
	}
	if q.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", nextArg))
		args = append(args, q.Status)
		nextArg++
	}
	if q.Q != "" {
		where = append(where, fmt.Sprintf(`scope ILIKE $%d ESCAPE '\'`, nextArg))
		args = append(args, "%"+escapeLIKE(q.Q)+"%")
		nextArg++
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_jobs"+whereSQL, args...).Scan(&total); err != nil {
		return DiscoveryScanJobResult{}, err
	}

	if cursor > total {
		cursor = total
	}

	limitPlaceholder := fmt.Sprintf("$%d", nextArg)
	args = append(args, limit)
	nextArg++
	offsetPlaceholder := fmt.Sprintf("$%d", nextArg)
	args = append(args, cursor)

	rows, err := s.db.QueryContext(ctx, `
SELECT id, type, scope, status, created_at, COALESCE(error_message, '')
FROM scan_jobs`+whereSQL+`
ORDER BY created_at DESC
LIMIT `+limitPlaceholder+` OFFSET `+offsetPlaceholder+`
`, args...)
	if err != nil {
		return DiscoveryScanJobResult{}, err
	}
	defer rows.Close()

	jobs := make([]DiscoveryScanJob, 0)
	for rows.Next() {
		var j DiscoveryScanJob
		var createdAt time.Time
		if err := rows.Scan(&j.ID, &j.ScanType, &j.Target, &j.Status, &createdAt, &j.Error); err != nil {
			return DiscoveryScanJobResult{}, err
		}
		j.Target = scanScopeTarget(j.Target)
		j.QueuedAt = createdAt.UTC().Format(time.RFC3339)
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return DiscoveryScanJobResult{}, err
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	var nextCursorP *int
	if end < total {
		n := end
		nextCursorP = &n
	}
	var prevCursorP *int
	if cursor > 0 {
		p := cursor - limit
		if p < 0 {
			p = 0
		}
		prevCursorP = &p
	}

	return DiscoveryScanJobResult{
		ScanJobs:   jobs,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursorP,
		PrevCursor: prevCursorP,
	}, nil
}

func (s *postgresDiscoveryStore) CreateScan(ctx context.Context, scanType string, target string, extraPorts []int) (DiscoveryScanCreateResult, error) {
	// W5-12: refuse BEFORE inserting — a running job nothing will ever
	// finish is worse than an error.
	if !isNetworkScanType(scanType) && !isCloudScanType(scanType) && scanType != scanTypeK8sCertManager && !(scanType == scanTypeWinRM && s.winrmScan != nil) && !(scanType == scanTypeSSH && s.sshScan != nil) {
		return DiscoveryScanCreateResult{}, fmt.Errorf("scan type %q has no runner (network types: full/targeted/fast/network; cloud types: cloud_acm/cloud_azure_kv/cloud_gcp_cm; k8s-certmanager: cert-manager connector; winrm and ssh need a managed target)", scanType)
	}
	now := time.Now().UTC()
	id := fmt.Sprintf("scan-%d", now.UnixNano())
	scanTenant := discoveryStampTenant(ctx)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO scan_jobs (id, type, connector, scope, status, tenant)
VALUES ($1, $2, 'api', $3, 'running', $4)
`, id, scanType, scanScopeJSON(target, extraPorts), scanTenant)
	if err != nil {
		return DiscoveryScanCreateResult{}, err
	}
	if isCloudScanType(scanType) {
		go runCloudScanAndFinalize(context.Background(), s.db, true, id, scanType)
		return DiscoveryScanCreateResult{
			ID:       id,
			Status:   "running",
			ScanType: scanType,
			Target:   target,
			QueuedAt: now.Format(time.RFC3339),
		}, nil
	}
	if scanType == scanTypeK8sCertManager {
		go runK8sCertManagerScanAndFinalize(context.Background(), s.db, true, id)
		return DiscoveryScanCreateResult{
			ID:       id,
			Status:   "running",
			ScanType: scanType,
			Target:   target,
			QueuedAt: now.Format(time.RFC3339),
		}, nil
	}
	go s.runAndPersistScan(carryJITSudo(ctx, withDiscoveryTenant(context.Background(), scanTenant)), id, target, scanType, extraPorts)
	return DiscoveryScanCreateResult{
		ID:       id,
		Status:   "running",
		ScanType: scanType,
		Target:   target,
		QueuedAt: now.Format(time.RFC3339),
	}, nil
}

// "completed" matches the canonical DiscoveryScanJob.Status spelling — see
// sqliteDiscoveryStore.runAndPersistScan's comment above (G-87/S-23).
func (s *postgresDiscoveryStore) runAndPersistScan(ctx context.Context, jobID, target, scanType string, extraPorts []int) {
	defer afterDiscoveryScanPersist(jobID)
	result := runTargetOrNetworkScan(ctx, s.winrmScan, s.sshScan, jobID, target, scanType, extraPorts)

	out, err := s.upsertScanResults(ctx, result.Endpoints)
	if err == nil {
		applyHostObservations(ctx, s.db, true, result.Endpoints)
	}
	if err != nil {
		logging.Warnf("discovery scan %s: persist results failed: %v", jobID, err)
	} else if skipMsg := summarizeUpsertSkips(out); skipMsg != "" {
		// W19-22: a per-row skip (isolated by upsertOneEndpointWithSavepoint)
		// no longer aborts the whole scan, but it must not go unreported.
		logging.Infof("discovery scan %s: %s", jobID, skipMsg)
	}
	status, errMsg := scanJobOutcome(result, out, err)
	if _, err := s.db.ExecContext(ctx, "UPDATE scan_jobs SET status = $1, error_message = $2 WHERE id = $3", status, errMsg, jobID); err != nil {
		logging.Warnf("discovery scan %s: finalize status failed: %v", jobID, err)
	}
}

func (s *postgresDiscoveryStore) CancelScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	if err := requireDiscoveryJobVisible(ctx, s.db, scanJobID, "$1", "$2"); err != nil {
		return DiscoveryScanJobActionResult{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.ExecContext(ctx, `
UPDATE scan_jobs SET status = 'cancelled', error_message = $1 WHERE id = $2 AND status IN ('queued', 'running')
`, reason, scanJobID)
	if err != nil {
		return DiscoveryScanJobActionResult{}, err
	}
	affected, _ := result.RowsAffected()
	status := "canceled"
	if affected == 0 {
		status = "not_found_or_already_terminal"
	}
	return DiscoveryScanJobActionResult{
		ScanJobID: scanJobID,
		Status:    status,
		Reason:    reason,
		UpdatedAt: now,
	}, nil
}

func (s *postgresDiscoveryStore) RequeueScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	now := time.Now().UTC()
	newID := fmt.Sprintf("scan-%d", now.UnixNano())

	if err := requireDiscoveryJobVisible(ctx, s.db, scanJobID, "$1", "$2"); err != nil {
		return DiscoveryScanJobActionResult{}, err
	}
	var scanType, scope, jobTenant string
	err := s.db.QueryRowContext(ctx, "SELECT type, scope, tenant FROM scan_jobs WHERE id = $1", scanJobID).Scan(&scanType, &scope, &jobTenant)
	if err != nil {
		return DiscoveryScanJobActionResult{}, fmt.Errorf("original scan job not found: %w", err)
	}

	// The copy stays in the original job's tenant even when a super-admin
	// requeues it: whose scan this is doesn't change with who pressed retry.
	_, err = s.db.ExecContext(ctx, `
INSERT INTO scan_jobs (id, type, connector, scope, status, error_message, tenant)
VALUES ($1, $2, 'api', $3, 'queued', $4, $5)
`, newID, scanType, scope, fmt.Sprintf("requeue of %s: %s", scanJobID, reason), jobTenant)
	if err != nil {
		return DiscoveryScanJobActionResult{}, err
	}

	return DiscoveryScanJobActionResult{
		PreviousID: scanJobID,
		ScanJobID:  newID,
		Status:     "queued",
		Reason:     reason,
		QueuedAt:   now.Format(time.RFC3339),
	}, nil
}

// The same tables the migration creates, for a discovery-only data directory
// whose EnsureSchema runs without the numbered migrations.
const (
	discoveredFilesDDLSQLite = `
CREATE TABLE IF NOT EXISTS discovered_files (
    id TEXT PRIMARY KEY, tenant TEXT NOT NULL DEFAULT '', target_id TEXT, agent_id TEXT,
    host TEXT NOT NULL, path TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('pem', 'jks', 'p12', 'key', 'config', 'cng_key')),
    owner_uid INTEGER, owner_gid INTEGER, owner_name TEXT, group_name TEXT, mode TEXT,
    service_tech TEXT, service_uid INTEGER, service_name TEXT,
    posture TEXT NOT NULL CHECK (posture IN ('standard', 'privileged', 'root_service', 'unknown')),
    findings TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (tenant, host, path)
);
CREATE INDEX IF NOT EXISTS idx_discovered_files_host ON discovered_files(tenant, host);
CREATE TABLE IF NOT EXISTS certificate_files (
    certificate_fingerprint TEXT NOT NULL,
    file_id TEXT NOT NULL REFERENCES discovered_files(id) ON DELETE CASCADE,
    PRIMARY KEY (certificate_fingerprint, file_id)
);
CREATE INDEX IF NOT EXISTS idx_certificate_files_file ON certificate_files(file_id);`

	discoveredFilesDDLPostgres = `
CREATE TABLE IF NOT EXISTS discovered_files (
    id TEXT PRIMARY KEY, tenant TEXT NOT NULL DEFAULT '', target_id TEXT, agent_id TEXT,
    host TEXT NOT NULL, path TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('pem', 'jks', 'p12', 'key', 'config', 'cng_key')),
    owner_uid INTEGER, owner_gid INTEGER, owner_name TEXT, group_name TEXT, mode TEXT,
    service_tech TEXT, service_uid INTEGER, service_name TEXT,
    posture TEXT NOT NULL CHECK (posture IN ('standard', 'privileged', 'root_service', 'unknown')),
    findings TEXT NOT NULL DEFAULT '[]',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, host, path)
);
CREATE INDEX IF NOT EXISTS idx_discovered_files_host ON discovered_files(tenant, host);
CREATE TABLE IF NOT EXISTS certificate_files (
    certificate_fingerprint TEXT NOT NULL,
    file_id TEXT NOT NULL REFERENCES discovered_files(id) ON DELETE CASCADE,
    PRIMARY KEY (certificate_fingerprint, file_id)
);
CREATE INDEX IF NOT EXISTS idx_certificate_files_file ON certificate_files(file_id);`
)

func ensureDiscoveredFilesSchema(ctx context.Context, db *sql.DB, postgres bool) error {
	ddl := discoveredFilesDDLSQLite
	if postgres {
		ddl = discoveredFilesDDLPostgres
	}
	_, err := db.ExecContext(ctx, ddl)
	return err
}
