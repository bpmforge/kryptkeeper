package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	"kryptkeeper/internal/keystore"
)

// NFR-013 / D-122: no API response carries private key bytes except the six
// dual-control routes below. The contract is enforced three ways: the
// openapi/mux route list is enumerated, every route is exercised against a
// seeded full mux and its response inspected, and a static scan fails when a
// new source file starts emitting key encodings without being classified.

// Whitelist keys use the openapi spelling (no /api/v1 prefix, {param} kept).
var nfr013Whitelist = map[string]bool{
	"/keys/{id}/export":    true,
	"/keys/escrow":         true,
	"/keys/escrow/recover": true,
	"/keys/byok/export":    true,
	"/admin/backup":        true,
	"/keys/leaf-escrow":    true,
}

// Debt that is explicit rather than silent. Each entry must still emit key
// bytes (otherwise the test fails and demands removal), and the map may not
// grow without this test being edited.
var nfr013KnownViolations = map[string]string{
	"/spiffe/svid": "returns key_pem; D-122 one-time delivery owned by B11",
}

var nfr013KeyBytes = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

var nfr013KeyFields = map[string]bool{
	"private_key": true, "privatekey": true, "key_pem": true,
	"pkcs8": true, "pkcs12": true, "p12": true, "pfx": true,
}

// File -> why it may mention a private-key encoding. Exact grep result today.
var nfr013KeyEmitterFiles = map[string]string{
	"internal/bootstrap/renewal_executor.go":            "generates, installs and zeroizes; never in a response",
	"internal/bootstrap/inventory_source_ejbca.go":      "resolves the mTLS client key from the credential store for the TLS handshake only (D-307); never in a response",
	"internal/bootstrap/inventory_source_entrust.go":    "resolves the mTLS client key from the credential store for the TLS handshake only (D-307); never in a response",
	"internal/bootstrap/connector_upstream.go":          "resolves vendor mTLS client keys and service-account keys per call for the outbound client only, zeroized after use (D-307); never in a response",
	"internal/bootstrap/connector_acme_revoke.go":       "loads the stored ACME account key to sign revokeCert (RFC 8555 §7.6); never in a response",
	"internal/bootstrap/inventory_source_globalsign.go": "resolves the mTLS client key from the credential store for the TLS handshake only (D-307); never in a response",
	"internal/bootstrap/pqc_wave_deliver.go":            "exports a PQC successor key for ssh install and zeroizes it; no route, never in a response",
	"internal/bootstrap/spiffe_workload.go":             "gRPC workload API, not HTTP",
	"internal/bootstrap/handlers_spiffe.go":             "known violation: /spiffe/svid key_pem (nfr013KnownViolations)",
	"internal/bootstrap/connector_acme.go":              "ACME account key is an input",
	"internal/bootstrap/handlers_tsa.go":                "reads the operator-provisioned TSA signing key from a file; never in a response",
	"internal/bootstrap/handlers_bulk_import.go":        "rejects private keys",
	"internal/bootstrap/handlers_scep_labels.go":        "only mentions private_key_pem in a message: a label names the Entra app credential by reference, and the handler never resolves, stores or returns it (the key is parsed in internal/intune to sign a token request, D-327)",
	"internal/bootstrap/connector_acme_dns01.go":        "names private_key only to reject it in config_json",
	"internal/bootstrap/connector_acme_dns01_gcp.go":    "reads a service-account key as a credential input; never emitted",
	"internal/bootstrap/credential_external.go":         "fetches an external credential's secret from the source per use for the caller only, zeroized by the caller; the audit row and error text never carry it (D-324); never in a response",
	"internal/bootstrap/credential_external_payload.go": "assembles an ssh_key payload from fields the secret manager returned and validates it; never in a response (D-324)",
	"cmd/kryptkeeper/tls.go":                            "listener certificate loading",
}

type nfr013Route struct{ method, path string } // path: openapi template, no /api/v1 prefix

func nfr013Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func nfr013OpenAPIRoutes(t *testing.T) []nfr013Route {
	t.Helper()
	spec, err := os.Open(filepath.Join(nfr013Root(), "docs", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Close()
	pathLine := regexp.MustCompile(`^  (/[^ ]+):\s*$`)
	methodLine := regexp.MustCompile(`^    (get|post|put|patch|delete):`)
	var routes []nfr013Route
	current := ""
	sc := bufio.NewScanner(spec)
	for sc.Scan() {
		if m := pathLine.FindStringSubmatch(sc.Text()); m != nil {
			current = m[1]
			continue
		}
		if m := methodLine.FindStringSubmatch(sc.Text()); m != nil && current != "" {
			routes = append(routes, nfr013Route{strings.ToUpper(m[1]), current})
		}
	}
	return routes
}

func nfr013Normalize(p string) string {
	return regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(p, "x")
}

// nfr013MuxOnlyPaths returns HandleFunc paths the spec does not list
// (e.g. /spiffe/svid), prefix-stripped.
func nfr013MuxOnlyPaths(openapi []nfr013Route) []string {
	known := map[string]bool{}
	for _, r := range openapi {
		known[nfr013Normalize(r.path)] = true
	}
	handle := regexp.MustCompile(`HandleFunc\("(?:[A-Z]+ )?/api/v1(/[^"]*)"`)
	root := nfr013Root()
	goFiles, _ := filepath.Glob(filepath.Join(root, "internal", "bootstrap", "*.go"))
	cmdFiles, _ := filepath.Glob(filepath.Join(root, "cmd", "kryptkeeper", "*.go"))
	seen := map[string]bool{}
	var out []string
	for _, f := range append(goFiles, cmdFiles...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, _ := os.ReadFile(f)
		for _, m := range handle.FindAllStringSubmatch(string(raw), -1) {
			p := m[1]
			norm := p
			if strings.HasSuffix(norm, "/") {
				norm += "x"
			}
			if known[norm] || known[strings.TrimSuffix(norm, "/x")] || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func TestNFR013OpenAPIRoutesAreEnumerated(t *testing.T) {
	routes := nfr013OpenAPIRoutes(t)
	if len(routes) < 150 {
		t.Fatalf("only %d openapi operations enumerated; the scanner is broken", len(routes))
	}
	have := map[string]bool{}
	for _, r := range routes {
		have[r.path] = true
	}
	for p := range nfr013Whitelist {
		if !have[p] {
			t.Errorf("whitelist entry %s is not in docs/openapi.yaml (renamed or removed route?)", p)
		}
	}
	mux := nfr013MuxOnlyPaths(routes)
	for p := range nfr013KnownViolations {
		if !have[p] {
			found := false
			for _, m := range mux {
				if m == p {
					found = true
				}
			}
			if !found {
				t.Errorf("known violation %s is neither in openapi nor a registered route", p)
			}
		}
	}
	if len(nfr013KnownViolations) != 1 {
		t.Errorf("nfr013KnownViolations has %d entries; it may not grow silently", len(nfr013KnownViolations))
	}
}

type nfr013Harness struct {
	mux     *http.ServeMux
	keyID   string
	fp      string
	caID    string
	svidURI string
}

func newNFR013Harness(t *testing.T) *nfr013Harness {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("SPIFFE_TRUST_DOMAIN", "nfr013.test")

	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	caID := getFirstCAID(t, engine)
	t.Setenv("SPIFFE_SIGNING_CA_ID", caID)
	SetSPIFFEEngine(engine)
	t.Cleanup(func() { SetSPIFFEEngine(nil) })

	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "nfr013.example.com", "nfr013.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-nfr013",
	})
	if err != nil {
		t.Fatalf("seed leaf: %v", err)
	}

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("nfr013-passphrase-32-bytes-long!"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.GenerateKey("nfr013-key", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), stubTemplateProviderForCA{}, provider, NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), keys)
	// The same fan-out RunWithProtocols performs after registerHandlers.
	RegisterKeyHandlers(mux, auth, keys, stubAuditProviderForCA{}, "software")
	RegisterBackupHandlers(mux, auth, keys, stubAuditProviderForCA{})
	RegisterSSHCertHandlers(mux, auth, keys, stubTemplateProviderForCA{}, stubAuditProviderForCA{})
	return &nfr013Harness{mux: mux, keyID: "nfr013-key", fp: issued.FingerprintSHA256, caID: caID, svidURI: "spiffe://nfr013.test/ns/default/sa/probe"}
}

func (h *nfr013Harness) do(method, target, body string) (int, string, string) {
	var rd *bytes.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	} else {
		rd = bytes.NewReader(nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req := httptest.NewRequest(method, target, rd).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer test-token")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header().Get("Content-Type")
}

func (h *nfr013Harness) substitute(path string) string {
	return regexp.MustCompile(`\{([^}]+)\}`).ReplaceAllStringFunc(path, func(m string) string {
		switch strings.Trim(m, "{}") {
		case "id":
			return h.keyID
		case "fingerprint":
			return h.fp
		}
		return "x"
	})
}

// nfr013Leaks returns a description of key material in a response (never the
// material itself), or "".
func nfr013Leaks(body, contentType string) string {
	if nfr013KeyBytes.MatchString(body) {
		return "PEM private key block"
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "application/x-pkcs12") || strings.Contains(ct, "application/pkcs8") {
		return "key container content-type " + ct
	}
	var v any
	if json.Unmarshal([]byte(body), &v) == nil {
		if f := nfr013KeyField(v); f != "" {
			return "JSON field " + f
		}
	}
	return ""
}

func nfr013KeyField(v any) string {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && s != "" && nfr013KeyFields[strings.ToLower(k)] {
				return k
			}
			if f := nfr013KeyField(val); f != "" {
				return f
			}
		}
	case []any:
		for _, e := range x {
			if f := nfr013KeyField(e); f != "" {
				return f
			}
		}
	}
	return ""
}

func TestNFR013NoRouteReturnsPrivateKeyBytes(t *testing.T) {
	h := newNFR013Harness(t)
	openapi := nfr013OpenAPIRoutes(t)

	type call struct {
		method, template, target, body string
	}
	var calls []call
	prefix := func(p string) string {
		if strings.HasPrefix(p, "/scim/") {
			return p
		}
		return "/api/v1" + p
	}
	for _, r := range openapi {
		body := ""
		if r.method == "POST" || r.method == "PUT" || r.method == "PATCH" {
			body = "{}"
		}
		if r.path == "/spiffe/svid" {
			body = fmt.Sprintf(`{"spiffe_id":%q}`, h.svidURI)
		}
		calls = append(calls, call{r.method, r.path, prefix(h.substitute(r.path)), body})
	}
	for _, p := range nfr013MuxOnlyPaths(openapi) {
		tp := strings.TrimSuffix(p, "/")
		if strings.HasSuffix(p, "/") {
			tp += "/x"
		}
		for _, m := range []string{"GET", "POST", "DELETE"} {
			body := ""
			if m == "POST" {
				body = "{}"
				if p == "/spiffe/svid" {
					body = fmt.Sprintf(`{"spiffe_id":%q}`, h.svidURI)
				}
			}
			calls = append(calls, call{m, p, "/api/v1" + tp, body})
		}
	}
	// Seeded success calls, so the walk is not only error pages.
	keyGen := fmt.Sprintf(`{"id":"nfr013-gen","algorithm":%q}`, string(keystore.ECDSAP256))
	csr := generateTestCSRPEM(t, "seeded.example.com", "seeded.example.com")
	issueBody, _ := json.Marshal(map[string]any{"ca_id": h.caID, "csr_pem": csr, "template_id": "file-backed-default", "team_id": "team-nfr013"})
	seeded := []call{
		{"POST", "/keys", "/api/v1/keys", keyGen},
		{"GET", "/keys/{id}", "/api/v1/keys/" + h.keyID, ""},
		{"GET", "/cas", "/api/v1/cas", ""},
		{"GET", "/cas/{id}/chain", "/api/v1/cas/" + h.caID + "/chain", ""},
		{"POST", "/certificates", "/api/v1/certificates", string(issueBody)},
		{"GET", "/certificates/{fingerprint}/download", "/api/v1/certificates/" + h.fp + "/download?format=pem&include_chain=true", ""},
		{"GET", "/certificates/{fingerprint}/download", "/api/v1/certificates/" + h.fp + "/download?format=p12", ""},
	}
	calls = append(calls, seeded...)

	leaked := map[string]string{}
	for _, c := range calls {
		code, body, ct := h.do(c.method, c.target, c.body)
		if nfr013Whitelist[c.template] {
			if code >= 500 && code != http.StatusServiceUnavailable {
				t.Errorf("%s %s (whitelisted) returned %d", c.method, c.template, code)
			}
			continue
		}
		if code >= 200 && code < 300 && (strings.Contains(c.target, "format=p12") || strings.Contains(c.target, "format=pfx")) {
			t.Errorf("%s %s: a 2xx PKCS#12 response is a key container and cannot be inspected", c.method, c.template)
		}
		if what := nfr013Leaks(body, ct); what != "" {
			if _, known := nfr013KnownViolations[c.template]; known {
				leaked[c.template] = what
				continue
			}
			t.Errorf("%s %s (%d) returned private key material (%s); classify it in the D-122 whitelist or fix the handler", c.method, c.template, code, what)
		}
	}
	for p, why := range nfr013KnownViolations {
		if leaked[p] == "" {
			t.Errorf("%s is listed in nfr013KnownViolations (%s) but returned no key bytes: remove it from nfr013KnownViolations", p, why)
		}
	}
	if len(calls) < 150 {
		t.Errorf("only %d calls issued; the route walk is broken", len(calls))
	}
}

func TestNFR013NewKeyEmittingSourceFileFailsUntilClassified(t *testing.T) {
	root := nfr013Root()
	re := regexp.MustCompile(`MarshalPKCS8PrivateKey|MarshalECPrivateKey|MarshalPKCS1PrivateKey|pkcs12\.(Modern|Legacy|Encode)|"PRIVATE KEY"|key_pem|private_key`)
	goFiles, _ := filepath.Glob(filepath.Join(root, "internal", "bootstrap", "*.go"))
	cmdFiles, _ := filepath.Glob(filepath.Join(root, "cmd", "kryptkeeper", "*.go"))
	matched := map[string]bool{}
	for _, f := range append(goFiles, cmdFiles...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if re.Match(raw) {
			rel, _ := filepath.Rel(root, f)
			matched[filepath.ToSlash(rel)] = true
		}
	}
	for f := range matched {
		if _, ok := nfr013KeyEmitterFiles[f]; !ok {
			t.Errorf("classify %s in nfr013KeyEmitterFiles or add its route to the D-122 whitelist", f)
		}
	}
	for f := range nfr013KeyEmitterFiles {
		if !matched[f] {
			t.Errorf("classify %s: pinned in nfr013KeyEmitterFiles but no longer matches; remove the stale entry", f)
		}
	}
}
