// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/acme"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/cmp"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/est"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/scep"
)

// W22-06: route-matrix audit coverage over docs/openapi.yaml.
//
// Every mutating operation in the spec is driven through the real mux
// (built the way server.go builds it) behind withWriteAuthorization, twice:
//
//  1. DENIAL probe: a viewer principal. The route must refuse (401/403) and
//     leave at least one audit row with outcome "denied".
//  2. SUCCESS probe: a pki-admin principal with an empty (or fixture) body.
//     The route must leave at least one audit row of ANY outcome. This is
//     deliberately an "any-outcome" probe: building a valid success fixture
//     for ~200 routes is not feasible, so a handler that audits its
//     validation failure passes and a handler that emits nothing fails.
//     TestAuditRouteMatrixGenuineSuccess adds the stricter outcome=success
//     assertion for the US-035 write set (CA create, certificate issue and
//     revoke, template update), where a fixture is cheap.
//
// A route that legitimately writes no audit row goes in
// auditMatrixExceptions with a written reason.

type auditMatrixException struct {
	Method, Path string // OpenAPI path template, e.g. "POST /roles/{name}"
	Skip         string // "success" | "denial" | "both"
	Reason       string // REQUIRED
}

var auditMatrixExceptions = []auditMatrixException{
	// SCIM is mounted at the server root with its own bearer, outside the
	// /api/v1 write gate this test drives.
	{"POST", "/scim/v2/Users", "both", "root-mounted outside /api/v1 with its own SCIM bearer, so the write gate this test drives never sees it"},
	{"PATCH", "/scim/v2/Users/{id}", "both", "root-mounted outside /api/v1 with its own SCIM bearer, so the write gate this test drives never sees it"},
	{"DELETE", "/scim/v2/Users/{id}", "both", "root-mounted outside /api/v1 with its own SCIM bearer, so the write gate this test drives never sees it"},
	{"POST", "/scim/v2/Groups", "both", "root-mounted outside /api/v1 with its own SCIM bearer, so the write gate this test drives never sees it"},
	{"PATCH", "/scim/v2/Groups/{id}", "both", "root-mounted outside /api/v1 with its own SCIM bearer, so the write gate this test drives never sees it"},
	{"DELETE", "/scim/v2/Groups/{id}", "both", "root-mounted outside /api/v1 with its own SCIM bearer, so the write gate this test drives never sees it"},

	// Pre-authentication routes: a viewer is not refused because nobody is
	// expected to hold a role yet. Their failures are audited by the handlers.
	{"POST", "/auth/login", "denial", "pre-authentication route; the write gate passes it through by design"},
	{"POST", "/auth/logout", "denial", "pre-authentication route; the write gate passes it through by design"},
	{"POST", "/auth/saml/acs", "denial", "pre-authentication route (SAML assertion consumer); not RBAC-gated"},
	{"POST", "/auth/breakglass/login", "both", "pre-authentication; answers 503 before any attempt unless break-glass is configured (audited when configured, see breakglass tests)"},

	// Agent-token routes authenticate with X-Agent-ID/X-Agent-Token, not an
	// RBAC principal, so a viewer bearer is answered 400 (no agent identity);
	// the refusal itself is audited as denied.
	{"POST", "/agent/heartbeat", "denial", "agent-token auth, outside RBAC; missing credentials answer 400 and are audited as denied"},
	{"POST", "/agent/inventory", "denial", "agent-token auth, outside RBAC; missing credentials answer 400 and are audited as denied"},
	{"POST", "/agent/renewal-result", "denial", "agent-token auth, outside RBAC; missing credentials answer 400 and are audited as denied"},

	// The CI OIDC token is the credential: nobody holds a hub role, so a viewer
	// is not refused by the gate. Refusals are audited by the handler as
	// codesign.issue (denied, with issuer and reason); the success probe still
	// requires an audit row (the 503/400 paths are audited too).
	{"POST", "/codesign/issue", "denial", "unauthenticated by design (the OIDC token authenticates); token refusals are audited as denied by the handler"},
	{"POST", "/tsa", "denial", "permSelf: any authenticated principal (a viewer included) may obtain a timestamp by design, and anonymous access is an operator opt-in; refusals (401, 415, 405) are audited by the handler"},

	// POSTs that compute and persist nothing (the write gate's permQuery).
	{"POST", "/crypto-agility/roadmap", "both", "read-shaped POST (permQuery): computes a roadmap, mutates nothing"},
	{"PUT", "/users/me/prefs", "denial", "self-service (permQuery): any signed-in principal writes only its own prefs row; every outcome is audited by the handler"},
	{"POST", "/inventory/code-signing/policy-check", "denial", "read-shaped POST (permQuery): any signed-in principal may evaluate; mutates nothing"},
	{"POST", "/policies/dry-run", "success", "evaluates a CSR against the policy and persists nothing"},

	// Handlers outside handlers_*.go that the ticket's write scope excludes.
	{"POST", "/nhi/identities", "success", "needs emit in nhi_identity.go, outside W22-06 scope"},
	{"POST", "/nhi/identities/{id}/{verb}", "success", "needs emit in nhi_identity.go, outside W22-06 scope"},
	{"POST", "/spiffe/svid", "success", "needs emit in spiffe_workload*.go, outside W22-06 scope"},
	{"POST", "/spiffe/workload-entries", "success", "needs emit in spiffe_workload*.go, outside W22-06 scope"},
	{"POST", "/spiffe/workload-svid", "success", "needs emit in spiffe_workload*.go, outside W22-06 scope"},
}

// auditMatrixPaths substitutes a concrete path where "matrix-x" would 404
// before the handler authorizes anything (an unknown config key).
var auditMatrixPaths = map[string]string{
	"PUT /config/{key}":    "/api/v1/config/notifications.smtp_host",
	"DELETE /config/{key}": "/api/v1/config/notifications.smtp_host",
}

// matrixCeremonyEngine refuses everything: the matrix only needs the
// ceremony routes mounted, not a CA behind them.
type matrixCeremonyEngine struct{}

func (matrixCeremonyEngine) CreateRootCA(string, pkix.Name, keystore.Algorithm, time.Duration) (*ca.CA, error) {
	return nil, fmt.Errorf("matrix: no CA engine")
}
func (matrixCeremonyEngine) UpdateCAStatus(string, string) error {
	return fmt.Errorf("matrix: no CA engine")
}

type matrixAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (m *matrixAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (m *matrixAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}
func (m *matrixAudit) since(n int) []AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]AuditEntry(nil), m.entries[n:]...)
}
func (m *matrixAudit) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

type matrixOp struct{ method, tmpl string }

func (o matrixOp) key() string { return o.method + " " + o.tmpl }

func matrixSpecOps(t *testing.T) []matrixOp {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pathLine := regexp.MustCompile(`^  (/[^ ]+):\s*$`)
	writeOp := regexp.MustCompile(`^    (post|put|patch|delete):`)
	var ops []matrixOp
	current := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if m := pathLine.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if m := writeOp.FindStringSubmatch(line); m != nil && current != "" {
			ops = append(ops, matrixOp{strings.ToUpper(m[1]), current})
		}
	}
	return ops
}

func matrixException(op matrixOp) (auditMatrixException, bool) {
	for _, e := range auditMatrixExceptions {
		if e.Method+" "+e.Path == op.key() {
			return e, true
		}
	}
	return auditMatrixException{}, false
}

func TestAuditRouteMatrix(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "off")
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "matrix-credential-passphrase-32ch!")
	dataDir := t.TempDir()
	t.Setenv("KRYPTKEEPER_DATA_DIR", dataDir)

	audit := &matrixAudit{}
	auth := NewAuthenticatorFromEnv()
	_, adminTok, err := auth.CreateAPIKey("matrix-admin", "matrix-admin", "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, viewerTok, err := auth.CreateAPIKey("matrix-viewer", "matrix-viewer", "viewer", []string{}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("matrix-test-passphrase-32chars!!"))
	if err != nil {
		t.Fatal(err)
	}

	// Mirrors RunWithProtocols (server.go) minus the protocol mux and the
	// server-level middleware that is not under test.
	// The core DB cmd/kryptkeeper opens; the DB-backed groups below are the
	// ones main wires through ServerOptions.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "matrix.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	actions := &dbPendingActionStore{db: db, ph: sqlitePlaceholder}
	if err := actions.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	pe, err := ca.NewPolicyEngine(db, false)
	if err != nil {
		t.Fatal(err)
	}
	archive := NewAuditArchiveManager(db, false, actions, audit)
	if err := archive.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	ceremonies, err := ca.NewCeremonyManager(db, false, matrixCeremonyEngine{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { activeTeamEnforcer = nil }) // W33-21: WithTeamPolicyAdmin installs the global enforcer
	mux := http.NewServeMux()
	cfg := applyServerOptions(mux, []ServerOption{
		WithDeliveryPlugins(NewDeliveryPluginManager(db, false, actions, nil)),
		WithPolicyAdmin(auth, pe, audit),
		WithTeamPolicyAdmin(auth, db, false, audit),
		WithCodesignOIDC(nil, nil, &dbCodesignTrustStore{db: db, ph: sqlitePlaceholder}, actions, auth, audit),
		WithTSA(nil, auth, audit, false),
		WithExtraHandlers(func(m *http.ServeMux) {
			RegisterSCEPChallengeHandlers(m, auth, scep.NewDBChallengeStore(db, false), "matrix-ca", audit)
			RegisterACMEEABHandlers(m, auth, acme.NewMemEABAdmin(), ACMEEABOptions{Passphrase: []byte("matrix-passphrase")}, audit)
			RegisterACMEProvisionerHandlers(m, auth, acme.NewMemProvisionerStore(), func(string) bool { return true }, nil, "https://hub.example", audit)
			RegisterESTUserHandlers(m, auth, est.NewDBUserStore(db, false), nil, audit)
			RegisterESTLabelHandlers(m, auth, est.NewMemLabelStore(), NewFileTemplateProviderFromEnv(), audit)
			RegisterCMPCredentialHandlers(m, auth, cmp.NewDBCredentialStore(db, false, nil), func() []byte { return []byte("matrix-passphrase") }, audit)
			RegisterAuditArchiveHandlers(m, auth, archive, audit)
			RegisterCeremonyHandlers(m, auth, ceremonies, audit)
			registerAnomalyRemediationHandlers(m, auth, nil, NewFileCertificateProviderFromEnv(), NewFileCAProviderFromEnv(), NewFileTemplateProviderFromEnv(), actions, audit)
			registerPolicyDraftHandlers(m, auth, pe, NewFileCAProviderFromEnv(), actions, audit)
		}),
	})
	certs := NewFileCertificateProviderFromEnv()
	cas := NewFileCAProviderFromEnv()
	tpls := NewFileTemplateProviderFromEnv()
	installExceptions(cfg, auth, certs, cas, audit)
	registerHandlers(cfg, auth, stubCertSummaryForCA{}, audit, cas, tpls, certs, NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), keys)
	RegisterKeyHandlers(mux, auth, keys, audit, "software")
	RegisterBackupHandlers(mux, auth, keys, audit)
	RegisterSSHCertHandlers(mux, auth, keys, tpls, audit)
	RegisterOwnershipCMDBHandlers(mux, auth, certs, audit)
	RegisterOwnershipOrphanHandlers(mux, auth, certs, auth.userProvider, audit)
	registerGovernanceHandlers(mux, auth, audit)
	RegisterAuditExportHandlers(mux, auth, NewCustomRoleStoreFromEnv(), audit)
	RegisterApprovalInbox(mux, auth, audit, nil)
	chatopsIDs := chatopsSQLStore(db, sqlitePlaceholder)
	RegisterChatopsHandlers(mux, auth, chatopsIDs, audit)
	RegisterChatopsTeamsHandlers(mux, chatopsUserProvider(auth), audit, chatopsIDs, nil, nil)
	gate := withWriteAuthorization(mux, auth, NewCustomRoleStoreFromEnv(), audit)

	param := regexp.MustCompile(`\{[^}]+\}`)
	probe := func(op matrixOp, tok, body string) (code int, rows []AuditEntry, panicked any) {
		path := "/api/v1" + param.ReplaceAllString(op.tmpl, "matrix-x")
		if p, ok := auditMatrixPaths[op.key()]; ok {
			path = p
		}
		before := audit.count()
		func() {
			defer func() { panicked = recover() }()
			req := httptest.NewRequest(op.method, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, req)
			code = rec.Code
		}()
		return code, audit.since(before), panicked
	}

	var offenders []string
	total, excepted := 0, 0
	for _, op := range matrixSpecOps(t) {
		total++
		ex, isEx := matrixException(op)
		if isEx && ex.Skip == "both" {
			excepted++
			continue
		}
		if !isEx || ex.Skip != "denial" {
			code, rows, pv := probe(op, viewerTok, "{}")
			denied := false
			for _, r := range rows {
				if r.Outcome == AuditOutcomeDenied {
					denied = true
				}
			}
			switch {
			case pv != nil:
				offenders = append(offenders, fmt.Sprintf("%s: panic on denial probe: %v", op.key(), pv))
			case code != http.StatusUnauthorized && code != http.StatusForbidden:
				offenders = append(offenders, fmt.Sprintf("%s: viewer was not refused (status %d)", op.key(), code))
			case !denied:
				offenders = append(offenders, fmt.Sprintf("%s: no audit row on denial probe", op.key()))
			}
		}
		if !isEx || ex.Skip != "success" {
			code, rows, pv := probe(op, adminTok, "{}")
			switch {
			case pv != nil:
				offenders = append(offenders, fmt.Sprintf("%s: panic on success probe: %v", op.key(), pv))
			case code == http.StatusNotFound && len(rows) == 0 && !strings.Contains(op.tmpl, "{"):
				offenders = append(offenders, fmt.Sprintf("%s: unrouted in the test mux (404)", op.key()))
			case code == http.StatusMethodNotAllowed:
				offenders = append(offenders, fmt.Sprintf("%s: unrouted in the test mux (405)", op.key()))
			case len(rows) == 0:
				offenders = append(offenders, fmt.Sprintf("%s: no audit row on success probe (status %d)", op.key(), code))
			}
		}
		if isEx {
			excepted++
		}
	}
	sort.Strings(offenders)
	t.Logf("audit matrix: %d routes, %d excepted, %d offenders", total, excepted, len(offenders))
	for _, o := range offenders {
		t.Error(o)
	}
	if total < 120 {
		t.Errorf("only %d spec operations found; the collector is broken", total)
	}
}

// Acceptance 2: an allowlist entry needs a written reason and must name a
// route that still exists, so it cannot rot into a blanket bypass.
func TestAuditRouteMatrixExceptionsAreCurrent(t *testing.T) {
	live := map[string]bool{}
	for _, op := range matrixSpecOps(t) {
		live[op.key()] = true
	}
	for _, e := range auditMatrixExceptions {
		key := e.Method + " " + e.Path
		if strings.TrimSpace(e.Reason) == "" {
			t.Errorf("%s: exception has no reason", key)
		}
		switch e.Skip {
		case "success", "denial", "both":
		default:
			t.Errorf("%s: Skip must be success|denial|both, got %q", key, e.Skip)
		}
		if !live[key] {
			t.Errorf("%s: exception names a route that is not in docs/openapi.yaml", key)
		}
	}
}

// TestAuditRouteMatrixGenuineSuccess is the stricter half of the matrix for
// the US-035 write set: CA create, certificate issue, certificate revoke and
// template update must leave an outcome=success row with the expected action,
// not merely any row. Each runs against a fresh, seeded instance so the
// sweep above cannot have consumed its fixtures.
func TestAuditRouteMatrixGenuineSuccess(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "off")
	dataDir := t.TempDir()
	t.Setenv("KRYPTKEEPER_DATA_DIR", dataDir)

	const fp = "fp-matrix-cert"
	certBody := `[{"fingerprint_sha256":"` + fp + `","serial_number":"01","common_name":"svc.example.com","subject_dn":"CN=svc.example.com","subject_alt_names":[],"issuer_cn":"Root","issuer_dn":"CN=Root","ca_id":"ca-matrix","template_id":"tpl-matrix","team_id":"svc","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"manual","renewal_status":"active","source":"api","etag":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}]`
	tplBody := `[{"id":"tpl-matrix","name":"tpl-matrix","display_name":"Matrix","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D","auto_enroll":false,"active":true,"revision":1,"schema_version":1,"issued_count":0,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}]`
	for env, body := range map[string]string{"APP_CERTIFICATE_FILE": certBody, "APP_TEMPLATE_FILE": tplBody} {
		p := filepath.Join(dataDir, strings.ToLower(env)+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(env, p)
	}

	audit := &matrixAudit{}
	auth := NewAuthenticatorFromEnv()
	_, tok, err := auth.CreateAPIKey("matrix-admin", "matrix-admin", "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, stubCreatableCAProvider{}, nil, audit)
	registerTemplateHandlers(mux, auth, NewFileTemplateProviderFromEnv(), audit, nil)
	registerCertificateHandlers(mux, auth, NewFileCertificateProviderFromEnv(), audit, nil)
	gate := withWriteAuthorization(mux, auth, NewCustomRoleStoreFromEnv(), audit)

	for _, c := range []struct{ method, path, body, action string }{
		{http.MethodPost, "/api/v1/cas", `{"name":"matrix-root","type":"root","algorithm":"ecdsaP256","validity":"10y","subject_cn":"Matrix Root"}`, "ca.create"},
		{http.MethodPatch, "/api/v1/templates/tpl-matrix", `{"display_name":"Matrix 2"}`, "template.update"},
		{http.MethodPost, "/api/v1/certificates", `{"ca_id":"ca-matrix","template_id":"tpl-matrix","csr_pem":"matrix-csr","team_id":"svc"}`, "certificate.issue"},
		{http.MethodPost, "/api/v1/certificates/" + fp + "/revoke", `{"reason_code":1}`, "certificate.revoke"},
	} {
		before := audit.count()
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		found := false
		for _, e := range audit.since(before) {
			if e.Action == c.action && e.Outcome == AuditOutcomeSuccess {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %s: no %s/success audit row (status %d: %s)", c.method, c.path, c.action, rec.Code, rec.Body.String())
		}
	}
}
