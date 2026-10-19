// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/keystore"
)

type writeGateHarness struct {
	auth    *Authenticator
	roles   *CustomRoleStore
	audit   *scepRecordingAudit
	reached int
	gate    http.Handler
}

func newWriteGateHarness(t *testing.T, next http.Handler) *writeGateHarness {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	h := &writeGateHarness{auth: NewAuthenticatorFromEnv(), audit: &scepRecordingAudit{}}
	h.roles, _ = newCustomRoleStore(t)
	if next == nil {
		next = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			h.reached++
			w.WriteHeader(http.StatusOK)
		})
	}
	h.gate = withWriteAuthorization(next, h.auth, h.roles, h.audit)
	return h
}

func (h *writeGateHarness) key(t *testing.T, role string, scopes ...string) string {
	t.Helper()
	_, tok, err := h.auth.CreateAPIKey("k-"+role, "p-"+role, role, scopes, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (h *writeGateHarness) do(token, method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.gate.ServeHTTP(rec, req)
	return rec
}

// The matrix: each role against writes it must and must not reach. The
// first rows are the holes probes found on a real hub (W20-26, W20-27).
func TestWriteGateMatrix(t *testing.T) {
	h := newWriteGateHarness(t, nil)
	for _, r := range []CustomRole{
		{Name: "cert-reader", Permissions: []string{"certificate.read", "report.read"}},
		{Name: "cert-issuer", Permissions: []string{"certificate.read", "certificate.issue"}},
		{Name: "ca-admin", Permissions: []string{"ca.manage"}},
	} {
		if _, err := h.roles.CreateRole(r); err != nil {
			t.Fatal(err)
		}
	}
	tok := map[string]string{"bootstrap": "test-token"}
	for _, role := range []string{"pki-admin", "pki-operator", "service-account", "approver", "viewer", "pki-viewer",
		"auditor", "pki-auditor", "made-up-role", RoleMCPAgent, "discovery-operator", "notification-operator",
		"protocol-operator", "cert-reader", "cert-issuer", "ca-admin"} {
		tok[role] = h.key(t, role)
	}
	tok["mcp-agent+*"] = h.key(t, RoleMCPAgent, "*")
	tok["bot+ops:write"] = h.key(t, "ops-bot", "ops:write")
	tok["bot+*"] = h.key(t, "star-bot", "*")

	cases := []struct {
		method, path string
		allow        []string
		deny         []string
	}{
		// W20-27: a pki-operator invited a pki-admin user and created tenants.
		{"POST", "/api/v1/users/invite", []string{"pki-admin", "bootstrap"}, []string{"pki-operator", "service-account", "approver", "cert-issuer", "bot+ops:write", "bot+*"}},
		{"POST", "/api/v1/tenants", []string{"pki-admin"}, []string{"pki-operator", "service-account"}},
		// W20-26/27: CAs and templates by anyone who could write at all.
		{"POST", "/api/v1/cas", []string{"pki-admin", "ca-admin"}, []string{"bot+*", "pki-operator", "service-account", "approver", "viewer", RoleMCPAgent, "mcp-agent+*", "cert-issuer"}},
		{"PUT", "/api/v1/templates/tpl-1", []string{"pki-admin", "ca-admin"}, []string{"pki-operator", "viewer"}},
		{"POST", "/api/v1/connectors", []string{"pki-admin", "discovery-operator", "bot+ops:write", "bot+*"}, []string{"pki-operator", "service-account", "approver"}},
		{"PATCH", "/api/v1/targets/t-1", []string{"pki-admin", "discovery-operator"}, []string{"pki-operator", "viewer", RoleMCPAgent}},
		{"POST", "/api/v1/ssh/certificates", []string{"pki-admin", "pki-operator", "service-account", "cert-issuer"}, []string{"viewer", "approver", RoleMCPAgent, "cert-reader", "made-up-role"}},
		// What each role is for keeps working.
		{"POST", "/api/v1/certificates", []string{"pki-operator", "service-account", "cert-issuer"}, []string{"approver", "viewer", "auditor"}},
		{"POST", "/api/v1/certificates/abc/renew", []string{"pki-operator", "service-account"}, []string{"approver", "cert-issuer"}},
		{"POST", "/api/v1/certificates/abc/revoke", []string{"pki-operator"}, []string{"service-account", "approver"}},
		{"POST", "/api/v1/pending-actions/act-1/approve", []string{"pki-operator", "approver"}, []string{"service-account", RoleMCPAgent, "viewer"}},
		{"POST", "/api/v1/pending-actions", []string{RoleMCPAgent, "mcp-agent+*", "pki-operator", "service-account"}, []string{"viewer", "cert-reader", "made-up-role"}},
		{"POST", "/api/v1/notifications/rules", []string{"pki-operator", "notification-operator", "bot+ops:write"}, []string{"service-account", "discovery-operator"}},
		{"POST", "/api/v1/discovery/scans", []string{"discovery-operator", "bot+ops:write"}, []string{"pki-operator", "notification-operator"}},
		{"POST", "/api/v1/protocols/conformance/recheck", []string{"pki-operator", "protocol-operator"}, []string{"service-account"}},
		{"DELETE", "/api/v1/keys/k-1", []string{"pki-admin"}, []string{"pki-operator", "service-account"}},
		{"PUT", "/api/v1/config/x", []string{"pki-admin", "bootstrap"}, []string{"pki-operator", "bot+*"}},
		{"POST", "/api/v1/something-new", []string{"pki-admin"}, []string{"pki-operator", "bot+*"}},
		// Queries sent as POST stay open to readers.
		{"POST", "/api/v1/crypto-agility/roadmap", []string{"viewer", "auditor", "pki-operator"}, nil},
		// Self-authenticating routes are left to their handlers.
		{"POST", "/api/v1/auth/logout", []string{"viewer", RoleMCPAgent}, nil},
		{"POST", "/api/v1/agent/heartbeat", []string{"viewer"}, nil},
	}
	for _, c := range cases {
		for _, list := range []struct {
			roles []string
			want  bool
		}{{c.allow, true}, {c.deny, false}} {
			for _, role := range list.roles {
				before := h.reached
				rec := h.do(tok[role], c.method, c.path, nil)
				if got := h.reached > before; got != list.want {
					t.Errorf("%s %s by %s: reached=%v (code %d), want %v", c.method, c.path, role, got, rec.Code, list.want)
				}
				if !list.want && rec.Code != http.StatusForbidden {
					t.Errorf("%s %s by %s: code %d, want 403", c.method, c.path, role, rec.Code)
				}
			}
		}
	}
	for _, e := range h.audit.entries {
		if e.Action != "api.write" || e.Outcome != "denied" || !strings.Contains(e.ChangeSummary, "needs=") {
			t.Errorf("denial audit row: %+v", e)
		}
	}
	if len(h.audit.entries) == 0 {
		t.Error("no denial was audited")
	}
}

func TestWriteGatePassThrough(t *testing.T) {
	h := newWriteGateHarness(t, nil)
	viewer := h.key(t, "viewer")
	for _, c := range []struct{ name, token, method, path string }{
		{"reads", viewer, http.MethodGet, "/api/v1/cas"},
		{"SCIM (root-mounted, own bearer)", viewer, http.MethodPost, "/scim/v2/Users"},
		{"unauthenticated (handler answers 401)", "", http.MethodPost, "/api/v1/cas"},
		{"bad token (handler answers 401)", "nope", http.MethodPost, "/api/v1/cas"},
		{"protocol endpoints", viewer, http.MethodPost, "/acme/new-order"},
	} {
		before := h.reached
		h.do(c.token, c.method, c.path, nil)
		if h.reached == before {
			t.Errorf("%s: %s %s did not reach the handler", c.name, c.method, c.path)
		}
	}
}

// The finding that motivated the gate, through the real SSH CA handler.
func TestWriteGateStopsViewerSSHCertificate(t *testing.T) {
	mux := http.NewServeMux()
	h := newWriteGateHarness(t, mux)
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("ssh-ca-test-passphrase-32chars!!"))
	if err != nil {
		t.Fatal(err)
	}
	tpls := newSSHTestTemplates(t)
	RegisterSSHCertHandlers(mux, h.auth, keys, tpls, h.audit)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	body, _ := json.Marshal(map[string]any{
		"public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		"cert_type":  "user", "key_id": "probe", "principals": []string{"deploy"}, "ttl_hours": 1,
		"template_id": tpls.ids["ssh-user"],
	})
	for _, c := range []struct {
		role string
		want int
	}{{"viewer", http.StatusForbidden}, {RoleMCPAgent, http.StatusForbidden}, {"approver", http.StatusForbidden}, {"pki-operator", http.StatusCreated}} {
		if rec := h.do(h.key(t, c.role), http.MethodPost, "/api/v1/ssh/certificates", body); rec.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.role, rec.Code, rec.Body.String(), c.want)
		}
	}
	// The A01S-4 finding itself: a pki-operator asking for root is refused by the template policy.
	rootBody, _ := json.Marshal(map[string]any{
		"public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		"cert_type":  "user", "key_id": "probe", "principals": []string{"root", "admin"}, "ttl_hours": 1,
		"template_id": tpls.ids["ssh-user"],
	})
	if rec := h.do(h.key(t, "pki-operator"), http.MethodPost, "/api/v1/ssh/certificates", rootBody); rec.Code != http.StatusBadRequest {
		t.Errorf("pki-operator root cert: %d %s, want 400", rec.Code, rec.Body.String())
	}
}

// Every rule names a real permission, and no write needs only a .read one.
func TestWriteRoutesUseTheVocabulary(t *testing.T) {
	for _, rt := range writeRoutes {
		switch rt.perm {
		case permSelf, permQuery, permAdmin, permPropose:
			continue
		}
		if !permissionVocabulary[rt.perm] {
			t.Errorf("%s: %q is not in the permission vocabulary", rt.pattern, rt.perm)
		}
		if strings.HasSuffix(rt.perm, ".read") {
			t.Errorf("%s: a write mapped to read permission %q", rt.pattern, rt.perm)
		}
	}
}

// readOnlyAPIRoutes accept no writes (checked when this list was made, in
// each handler), so they need no rule. A route on neither list fails the
// coverage test below: decide it, then put it on one.
var readOnlyAPIRoutes = map[string]bool{
	"/api/v1/agents": true, "/api/v1/audit": true,
	"/api/v1/audit/export":                  true,
	"/api/v1/audit/transparency/checkpoint": true, "/api/v1/audit/transparency/consistency": true,
	"/api/v1/audit/transparency/inclusion": true, "/api/v1/authz-check": true, "/api/v1/blast-radius": true,
	"/api/v1/cbom": true, "/api/v1/certificates/x": true, "/api/v1/certificates/quota": true, "/api/v1/certificates/x/download": true, "/api/v1/ct/findings": true, "/api/v1/events": true, "/api/v1/meta": true, "/api/v1/openapi.yaml": true,
	"/api/v1/pending-actions/x": true, "/api/v1/protected/certs/summary": true, "/api/v1/protected/config": true,
	"/api/v1/protected/ping": true, "/api/v1/protected/whoami": true, "/api/v1/reports/algorithm-sunset": true,
	"/api/v1/reports/anomalies": true, "/api/v1/reports/ca-health": true, "/api/v1/reports/change-audit": true,
	"/api/v1/reports/compliance-evidence": true, "/api/v1/reports/crypto-posture": true,
	"/api/v1/reports/crypto-posture/trend": true, "/api/v1/reports/estate": true, "/api/v1/reports/executive-summary": true,
	"/api/v1/reports/expiry-timeline": true, "/api/v1/reports/export/findings": true,
	"/api/v1/reports/export/inventory": true, "/api/v1/reports/issuance-velocity": true,
	"/api/v1/reports/key-custody": true, "/api/v1/reports/pqc-countdown": true, "/api/v1/reports/pqc-migration": true,
	"/api/v1/reports/renewal-slo": true, "/api/v1/reports/revocation-activity": true,
	"/api/v1/scheduler/renewal/status": true, "/api/v1/target-policy": true, "/api/v1/search": true, "/api/v1/ssh/ca": true,
}

// Every route the server registers, the UI calls or the spec lists as a
// write is either classified by writeRoutes or known read-only. Without
// this, a new handler would silently fall to admin-only (safe, but a
// surprise) or, worse, be mapped by nobody's decision.
func TestWriteRoutesCoverEveryRoute(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	paths := map[string]string{}

	handle := regexp.MustCompile(`HandleFunc\("(?:[A-Z]+ )?(/api/v1/[^"]*)"`)
	goFiles, _ := filepath.Glob(filepath.Join(root, "internal", "bootstrap", "*.go"))
	cmdFiles, _ := filepath.Glob(filepath.Join(root, "cmd", "kryptkeeper", "*.go"))
	for _, f := range append(goFiles, cmdFiles...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, _ := os.ReadFile(f)
		for _, m := range handle.FindAllStringSubmatch(string(raw), -1) {
			p := m[1]
			if strings.HasSuffix(p, "/") {
				p += "x"
			}
			paths[p] = "mux " + filepath.Base(f)
		}
	}

	ui, err := os.ReadFile(filepath.Join(root, "ui", "src", "lib", "api.ts"))
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile("(?:fetchJSON|fetch)[^(]*\\(\\s*[`\"](/[a-z][^`\"?$]*(?:\\$\\{[^}]*\\}[^`\"?$]*)*)")
	for _, m := range call.FindAllStringSubmatch(string(ui), -1) {
		// A ${...} that is a whole segment is a path parameter; anything
		// else (a query-string helper) ends the path.
		p := regexp.MustCompile(`/\$\{[^}]*\}`).ReplaceAllString(m[1], "/x")
		p = regexp.MustCompile(`^[a-z0-9/_.-]+`).FindString(p)
		paths["/api/v1"+strings.TrimSuffix(p, "/")] = "ui/src/lib/api.ts"
	}

	spec, err := os.Open(filepath.Join(root, "docs", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Close()
	pathLine := regexp.MustCompile(`^  (/[^ ]+):\s*$`)
	writeOp := regexp.MustCompile(`^    (post|put|patch|delete):`)
	current := ""
	sc := bufio.NewScanner(spec)
	for sc.Scan() {
		if m := pathLine.FindStringSubmatch(sc.Text()); m != nil {
			current = regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(m[1], "x")
			continue
		}
		// SCIM's paths carry a root server override (/scim/v2), outside
		// /api/v1 and the gate.
		if current != "" && !strings.HasPrefix(current, "/scim/") && writeOp.MatchString(sc.Text()) {
			p := "/api/v1" + current
			if readOnlyAPIRoutes[p] {
				t.Errorf("%s is on the read-only list but the spec gives it a write operation", p)
			}
			paths[p] = "openapi"
		}
	}

	var missing []string
	for p, src := range paths {
		if _, ok := matchWriteRoute(p); !ok && !readOnlyAPIRoutes[p] {
			missing = append(missing, p+" ("+src+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("routes with no write rule and not known read-only:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(paths) < 150 {
		t.Errorf("only %d routes collected; the collectors are broken", len(paths))
	}
}
