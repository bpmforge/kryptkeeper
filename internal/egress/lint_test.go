// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// rawHTTPAllowlist names every file under internal/ and cmd/ that builds a raw
// net/http client or transport instead of egress.NewClient, with the reason it
// is not a user-supplied URL call. Granularity is per file so line drift never
// breaks the test. The list should only shrink: a stale entry fails
// TestAllowlistEntriesAreReviewed. New code must use egress.NewClient.
//
// Rows marked "FOLLOW-UP" take operator-typed URLs and should move onto
// egress.NewClient; they are allowlisted here because W22-40 scopes the guard,
// not the migration.
var rawHTTPAllowlist = map[string]string{
	// Discovery scanners / inventory: intentionally internal.
	"internal/discovery/servicemesh.go":          "discovery scanner: dials in-cluster mesh control planes by design, not a user-supplied URL",
	"internal/agentdiscovery/agentless_winrm.go": "discovery scanner: dials operator-registered Windows hosts by design, not a user-supplied URL",
	"internal/ctmonitor/monitor.go":              "discovery scanner: polls Certificate Transparency logs from a fixed operator list, not a user-supplied URL",
	"internal/ctmonitor/source_certspotter.go":   "discovery scanner: Cert Spotter is a fixed vendor API base (api.certspotter.com), not a user-supplied URL; same posture as the crt.sh source",

	// Fixed vendor/cloud API hosts.
	"internal/cloudinventory/azure_keyvault.go":  "fixed Azure Key Vault API host derived from the cloud SDK, not a user-supplied URL",
	"internal/cloudinventory/gcp_certmanager.go": "fixed GCP Certificate Manager API host, not a user-supplied URL",
	"internal/keyinventory/azure.go":             "fixed Azure API host, not a user-supplied URL",
	"internal/keyinventory/gcp.go":               "fixed GCP API host, not a user-supplied URL",
	"internal/keystore/cloudkms_azure.go":        "fixed Azure Key Vault API host, not a user-supplied URL",
	"internal/keystore/cloudkms_gcp.go":          "fixed GCP Cloud KMS API host, not a user-supplied URL",
	"internal/keystore/destroy_cloud.go":         "fixed cloud KMS API hosts used for key destruction, not a user-supplied URL",

	// Operator-configured infrastructure endpoints (deploy-time config, not end-user input).
	"internal/keystore/vault.go":               "operator-configured Vault address set at deploy time, not end-user input",
	"internal/certmanager/connector.go":        "operator-configured cert-manager endpoint, not end-user input",
	"internal/certmanagerissuer/controller.go": "in-cluster cert-manager issuer controller talking to the hub it is configured with, not end-user input",
	"internal/certmanagerissuer/k8sclient.go":  "in-cluster Kubernetes API client, not end-user input",
	"internal/mcpserver/hubclient.go":          "MCP server to hub client using the operator-configured hub URL, not end-user input",
	"internal/agentclient/client.go":           "agent to hub client using the operator-configured hub URL, not end-user input",
	"internal/agentclient/acme_renewer.go":     "agent ACME renewer using operator-configured directory URLs, not end-user input",

	// Issuer connectors dialling an operator-registered CA (nil-client default only).
	"internal/connectors/est_client.go":   "default only; the hub always injects egress.NewClient (W27-35)",
	"internal/connectors/scep_client.go":  "default only; the hub always injects egress.NewClient (W27-35)",
	"internal/connectors/wstep_client.go": "default only; the hub always injects egress.NewClient (W27-35)",
	"internal/connectors/digicert.go":     "default only; the hub always injects egress.NewClient (W27-35)",

	// Plugin host and delivery.
	"internal/plugins/delivery/host.go": "sandboxed plugin host client; allowlisted hosts are enforced by the plugin capability model",

	// ACME.
	"internal/acme/http01.go":                    "ACME HTTP-01 validation uses its own guarded dialer (http01DialControl)",
	"internal/bootstrap/connector_acme_dns01.go": "ACME DNS-provider API client with operator-configured provider endpoints. FOLLOW-UP: migrate to egress.NewClient",

	// Container health probe.
	"cmd/healthcheck/main.go": "container health probe against localhost, not a user-supplied URL",
}

// rawUse is one raw net/http client construct found by the scanner.
type rawUse struct {
	File      string // slash-separated, relative to repo root
	Line      int
	Construct string
}

var rawSelectors = map[string]bool{
	"Get": true, "Post": true, "PostForm": true, "Head": true,
	"DefaultClient": true, "DefaultTransport": true,
}

func scanSource(filename string, src []byte) ([]rawUse, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}
	local := ""
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != "net/http" {
			continue
		}
		local = "http"
		if imp.Name != nil {
			local = imp.Name.Name
		}
	}
	if local == "" || local == "_" || local == "." {
		return nil, nil
	}
	isLocal := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == local
	}
	var out []rawUse
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CompositeLit:
			if sel, ok := v.Type.(*ast.SelectorExpr); ok && isLocal(sel.X) && (sel.Sel.Name == "Client" || sel.Sel.Name == "Transport") {
				out = append(out, rawUse{filename, fset.Position(v.Pos()).Line, local + "." + sel.Sel.Name + "{}"})
			}
		case *ast.SelectorExpr:
			if isLocal(v.X) && rawSelectors[v.Sel.Name] {
				out = append(out, rawUse{filename, fset.Position(v.Pos()).Line, local + "." + v.Sel.Name})
			}
		}
		return true
	})
	return out, nil
}

func scanRepo(root string) (map[string][]rawUse, error) {
	found := map[string][]rawUse{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || rel == "internal/egress/egress.go" {
				return nil
			}
			src, err := readFile(path)
			if err != nil {
				return err
			}
			uses, err := scanSource(rel, src)
			if err != nil {
				return err
			}
			if len(uses) > 0 {
				found[rel] = uses
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return found, nil
}

func TestLintScannerFlagsRawUsage(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"http.Get", `package p; import "net/http"; func f(u string) { http.Get(u) }`, 1},
		{"http.Client literal", `package p; import "net/http"; var c = &http.Client{}`, 1},
		{"DefaultClient", `package p; import "net/http"; func f(r *http.Request) { http.DefaultClient.Do(r) }`, 1},
		{"Transport literal", `package p; import "net/http"; var t = &http.Transport{}`, 1},
		{"aliased import", `package p; import h "net/http"; func f(u string) { h.Get(u) }`, 1},
		{"egress.NewClient", `package p; import ("net/http"; "kryptkeeper/internal/egress"); var c *http.Client = egress.NewClient(egress.Policy{})`, 0},
		{"NewRequest", `package p; import "net/http"; func f() { http.NewRequest("GET", "x", nil) }`, 0},
		{"status constant", `package p; import "net/http"; var s = http.StatusOK`, 0},
		{"Server literal", `package p; import "net/http"; var s = &http.Server{}`, 0},
		{"no net/http import", `package p; type http struct{}; func (http) Get() {}; func f() { var h http; h.Get() }`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanSource("x.go", []byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d findings %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

func TestNoRawHTTPOutsideAllowlist(t *testing.T) {
	found, err := scanRepo(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for file, uses := range found {
		if _, ok := rawHTTPAllowlist[file]; ok {
			continue
		}
		for _, u := range uses {
			t.Errorf("%s:%d raw %s: use egress.NewClient or add an allowlist entry with a reason", file, u.Line, u.Construct)
		}
	}
}

func TestAllowlistEntriesAreReviewed(t *testing.T) {
	found, err := scanRepo(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, 0, len(rawHTTPAllowlist))
	for f := range rawHTTPAllowlist {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		reason := rawHTTPAllowlist[f]
		if len(strings.TrimSpace(reason)) < 20 {
			t.Errorf("%s: allowlist reason too short", f)
		}
		if _, ok := found[f]; !ok {
			t.Errorf("%s: stale allowlist entry (file missing or no longer uses raw http); remove it", f)
		}
		t.Logf("allowlisted raw http: %s -- %s", f, reason)
	}
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }
