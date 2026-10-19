package provider

// Acceptance tests: the real provider binary driven by tofu/terraform
// (apply, plan, destroy) against a live hub. Gated by TF_ACC=1; they need
// KK_ACC_HUB_URL, KK_ACC_TOKEN (pki-admin) and KK_ACC_APPROVER_TOKEN (a
// second pki-admin, for the CA revoke dual control). tests/live/terraform/run.sh
// starts a hub and sets all of that. KK_ACC_TF_BIN overrides the CLI lookup.
// No Go dependency beyond the provider framework is used: the CLI is shelled
// out to with a dev_overrides config.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type accEnv struct {
	hubURL, token, approver, tfBin, providerDir string
}

func accSetup(t *testing.T) accEnv {
	t.Helper()
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("acceptance test: set TF_ACC=1 (see tests/live/terraform/run.sh)")
	}
	e := accEnv{
		hubURL:   strings.TrimRight(os.Getenv("KK_ACC_HUB_URL"), "/"),
		token:    os.Getenv("KK_ACC_TOKEN"),
		approver: os.Getenv("KK_ACC_APPROVER_TOKEN"),
		tfBin:    os.Getenv("KK_ACC_TF_BIN"),
	}
	if e.hubURL == "" || e.token == "" || e.approver == "" {
		t.Skip("acceptance test: KK_ACC_HUB_URL, KK_ACC_TOKEN and KK_ACC_APPROVER_TOKEN must be set")
	}
	if e.tfBin == "" {
		for _, n := range []string{"tofu", "terraform"} {
			if p, err := exec.LookPath(n); err == nil {
				e.tfBin = p
				break
			}
		}
	}
	if e.tfBin == "" {
		t.Fatal("TF_ACC=1 but neither tofu nor terraform is on PATH (set KK_ACC_TF_BIN)")
	}
	e.providerDir = t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(e.providerDir, "terraform-provider-kryptkeeper"), "../..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build provider: %v\n%s", err, out)
	}
	return e
}

func randHex(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// api calls the hub; the token is never logged.
func (e accEnv) api(t *testing.T, token, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.hubURL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// tf runs the CLI in dir and returns combined output and the exit code.
func (e accEnv) tf(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	cfg := filepath.Join(dir, "tf.rc")
	rc := fmt.Sprintf("provider_installation {\n  dev_overrides {\n    \"registry.terraform.io/kryptkeeper/kryptkeeper\" = %q\n  }\n  direct {}\n}\n", e.providerDir)
	if err := os.WriteFile(cfg, []byte(rc), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(e.tfBin, append(args, "-no-color")...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"TF_CLI_CONFIG_FILE="+cfg, "TF_IN_AUTOMATION=1", "TF_INPUT=0",
		"TF_DATA_DIR="+filepath.Join(dir, ".tfdata"),
		"TF_VAR_kk_hub_url="+e.hubURL, "TF_VAR_kk_token="+e.token)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %s: %v", e.tfBin, err)
		}
	}
	return string(out), code
}

func writeCSR(t *testing.T, dir, cn string, key any) {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "csr.pem"), p, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, dir, suffix, algs string, minKey int) {
	t.Helper()
	cfg := fmt.Sprintf(`terraform {
  required_providers {
    kryptkeeper = { source = "registry.terraform.io/kryptkeeper/kryptkeeper" }
  }
}
variable "kk_hub_url" { type = string }
variable "kk_token" {
  type      = string
  sensitive = true
}
provider "kryptkeeper" {
  hub_url = var.kk_hub_url
  token   = var.kk_token
}
resource "kryptkeeper_ca" "root" {
  name        = "tfacc-ca-%[1]s"
  common_name = "tfacc-root-%[1]s"
  algorithm   = "RSA-2048"
}
resource "kryptkeeper_template" "leaf" {
  name               = "tfacc-tpl-%[1]s"
  display_name       = "tfacc leaf %[1]s"
  validity_period    = "P30D"
  key_usage          = ["digitalSignature"]
  extended_key_usage = ["serverAuth"]
  allowed_algorithms = %[2]s
  min_key_size       = %[3]d
}
resource "kryptkeeper_certificate" "leaf" {
  ca_id       = kryptkeeper_ca.root.id
  template_id = kryptkeeper_template.leaf.id
  csr_pem     = file("${path.module}/csr.pem")
}
output "ca_id" { value = kryptkeeper_ca.root.id }
output "template_id" { value = kryptkeeper_template.leaf.id }
output "cert_fp" { value = kryptkeeper_certificate.leaf.fingerprint }
output "cert_pem" { value = kryptkeeper_certificate.leaf.certificate_pem }
output "chain_pem" { value = kryptkeeper_certificate.leaf.chain_pem }
`, suffix, algs, minKey)
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// caID returns the kryptkeeper_ca id from the state, or "" when none exists
// (for example after a failed apply that never reached the CA).
func (e accEnv) caID(t *testing.T, dir string) string {
	out, code := e.tf(t, dir, "state", "pull")
	if code != 0 {
		return ""
	}
	var s struct {
		Resources []struct {
			Type      string `json:"type"`
			Instances []struct {
				Attributes struct {
					ID string `json:"id"`
				} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}
	// state pull prints only the JSON state, but tf appends "-no-color" output safely.
	if json.Unmarshal([]byte(out), &s) != nil {
		return ""
	}
	for _, r := range s.Resources {
		if r.Type == "kryptkeeper_ca" && len(r.Instances) > 0 {
			return r.Instances[0].Attributes.ID
		}
	}
	return ""
}

// preDestroy revokes the CA out of band: the hub requires a second admin to
// approve (dual control), which the provider cannot do for itself.
func (e accEnv) preDestroy(t *testing.T, caID string) {
	t.Helper()
	code, body := e.api(t, e.token, http.MethodPost, "/api/v1/cas/"+caID+"/revoke", map[string]string{})
	if code != http.StatusAccepted {
		t.Fatalf("propose CA revoke: %d %s", code, body)
	}
	var r struct {
		Data struct {
			ActionID string `json:"action_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Data.ActionID == "" {
		t.Fatalf("no action_id in revoke proposal: %s", body)
	}
	if code, body = e.api(t, e.approver, http.MethodPost, "/api/v1/pending-actions/"+r.Data.ActionID+"/approve", nil); code != http.StatusOK {
		t.Fatalf("approve CA revoke: %d %s", code, body)
	}
	t.Logf("approve response: %s", body)
	if _, b := e.api(t, e.token, http.MethodGet, "/api/v1/cas/"+caID, nil); !strings.Contains(string(b), `"status":"revoked"`) {
		t.Fatalf("CA %s not revoked after approval: %.300s", caID, b)
	}
}

func (e accEnv) destroyAll(t *testing.T, dir string) {
	t.Helper()
	if caID := e.caID(t, dir); caID != "" {
		e.preDestroy(t, caID)
	}
	if out, code := e.tf(t, dir, "destroy", "-auto-approve"); code != 0 {
		t.Fatalf("destroy failed (exit %d):\n%s", code, out)
	}
}

// activeCertsFor counts non-revoked certificates with this common name.
func (e accEnv) activeCertsFor(t *testing.T, cn string) int {
	t.Helper()
	code, body := e.api(t, e.token, http.MethodGet, "/api/v1/certificates?limit=500", nil)
	if code != http.StatusOK {
		t.Fatalf("list certificates: %d %s", code, body)
	}
	var r struct {
		Data []struct {
			CommonName    string `json:"common_name"`
			RenewalStatus string `json:"renewal_status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("parse certificate list: %v", err)
	}
	n := 0
	for _, c := range r.Data {
		if c.CommonName == cn && c.RenewalStatus != "revoked" {
			n++
		}
	}
	return n
}

var boxChars = regexp.MustCompile(`[│╷╵]`)

// flatten undoes the CLI's diagnostic word-wrapping and box drawing.
func flatten(s string) string {
	return strings.Join(strings.Fields(boxChars.ReplaceAllString(s, " ")), " ")
}

func TestAcc_CA_Template_Certificate_RoundTrip(t *testing.T) {
	e := accSetup(t)
	dir := t.TempDir()
	sfx := randHex(t, 4)
	cn := "tfacc-" + sfx + ".example.test"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeCSR(t, dir, cn, key)
	writeConfig(t, dir, sfx, `["ECDSA-P256"]`, 0)

	if out, code := e.tf(t, dir, "apply", "-auto-approve"); code != 0 {
		t.Fatalf("apply failed (exit %d):\n%s", code, out)
	}

	out, code := e.tf(t, dir, "output", "-json")
	if code != 0 {
		t.Fatalf("output: %s", out)
	}
	var outs map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(out), &outs); err != nil {
		t.Fatalf("parse outputs: %v", err)
	}
	leafBlock, _ := pem.Decode([]byte(outs["cert_pem"].Value))
	if leafBlock == nil {
		t.Fatal("certificate_pem is not PEM")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("leaf does not parse: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(outs["chain_pem"].Value)) {
		t.Fatal("chain_pem holds no certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("leaf does not chain to the CA: %v", err)
	}
	if leaf.Subject.CommonName != cn {
		t.Errorf("leaf CN = %q, want %q", leaf.Subject.CommonName, cn)
	}

	if out, code := e.tf(t, dir, "plan", "-detailed-exitcode"); code != 0 {
		t.Errorf("second plan shows a diff or failed (exit %d):\n%s", code, out)
	}

	caID, tplID, fp := outs["ca_id"].Value, outs["template_id"].Value, outs["cert_fp"].Value
	e.destroyAll(t, dir)

	// Residuals: the CA is gone or (the hub keeps revoked CA records) revoked, the template is gone or (when the hub keeps it
	// because it issued a certificate) deactivated, the certificate is revoked.
	residual := 0
	if code, body := e.api(t, e.token, http.MethodGet, "/api/v1/cas/"+caID, nil); code != http.StatusNotFound &&
		!(code == http.StatusOK && strings.Contains(string(body), `"status":"revoked"`)) {
		residual++
		t.Errorf("CA neither gone nor revoked after destroy (GET -> %d)", code)
	}
	code, body := e.api(t, e.token, http.MethodGet, "/api/v1/templates/"+tplID, nil)
	if code != http.StatusNotFound {
		var tpl struct {
			Data struct {
				Active bool `json:"active"`
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &tpl) != nil || tpl.Data.Active {
			residual++
			t.Errorf("template still active after destroy (GET -> %d)", code)
		}
	}
	if n := e.activeCertsFor(t, cn); n != 0 {
		residual++
		t.Errorf("%d non-revoked certificate(s) for %s after destroy", n, cn)
	}
	if code, body := e.api(t, e.token, http.MethodGet, "/api/v1/certificates/"+fp, nil); code == http.StatusOK && !strings.Contains(string(body), `"renewal_status":"revoked"`) {
		residual++
		t.Errorf("certificate %s not revoked after destroy", fp)
	}
	t.Logf("residual=%d", residual)
}

func TestAcc_PolicyViolationSurfacesRule(t *testing.T) {
	e := accSetup(t)
	dir := t.TempDir()
	sfx := randHex(t, 4)
	cn := "tfacc-weak-" + sfx + ".example.test"
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	writeCSR(t, dir, cn, key)
	writeConfig(t, dir, sfx, `["RSA"]`, 2048)
	t.Cleanup(func() { e.destroyAll(t, dir) })

	out, code := e.tf(t, dir, "apply", "-auto-approve")
	if code == 0 {
		t.Fatalf("apply succeeded for a 1024-bit CSR against min_key_size 2048:\n%s", out)
	}
	flat := flatten(out)
	for _, want := range []string{"policy_violation", "key_size", "below template minimum 2048"} {
		if !strings.Contains(flat, want) {
			t.Errorf("diagnostics missing %q:\n%s", want, out)
		}
	}
	if n := e.activeCertsFor(t, cn); n != 0 {
		t.Errorf("%d certificate(s) issued despite the policy violation", n)
	}
}

// TestAcc_StateHasNoPrivateKey: the provider never generates keys, so neither
// the state file nor `state pull` may hold private-key bytes (the PEM header
// is "PRIVATE KEY" for PKCS#8/PKCS#1/EC alike).
func TestAcc_StateHasNoPrivateKey(t *testing.T) {
	e := accSetup(t)
	dir := t.TempDir()
	sfx := randHex(t, 4)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeCSR(t, dir, "tfacc-nokey-"+sfx+".example.test", key)
	writeConfig(t, dir, sfx, `["ECDSA-P256"]`, 0)
	t.Cleanup(func() { e.destroyAll(t, dir) })

	if out, code := e.tf(t, dir, "apply", "-auto-approve"); code != 0 {
		t.Fatalf("apply failed (exit %d):\n%s", code, out)
	}
	file, err := os.ReadFile(filepath.Join(dir, "terraform.tfstate"))
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	pulled, code := e.tf(t, dir, "state", "pull")
	if code != 0 {
		t.Fatalf("state pull failed (exit %d)", code)
	}
	for name, s := range map[string]string{"terraform.tfstate": string(file), "state pull": pulled} {
		// Guard against grepping an empty or wrong file: a real state holds the issued certificate.
		if !strings.Contains(s, "BEGIN CERTIFICATE") {
			t.Errorf("%s holds no certificate PEM; the check below would prove nothing", name)
		}
		if strings.Contains(s, "PRIVATE KEY") {
			t.Errorf("%s contains private-key bytes", name)
		}
	}
}

// TestAcc_DestroyPendingApprovalFails: destroying a CA needs a dual-control
// revoke. With no out-of-band revoke, destroy must fail and name the pending
// action id; once a second admin approves it, the same destroy completes.
func TestAcc_DestroyPendingApprovalFails(t *testing.T) {
	e := accSetup(t)
	dir := t.TempDir()
	sfx := randHex(t, 4)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeCSR(t, dir, "tfacc-pend-"+sfx+".example.test", key)
	writeConfig(t, dir, sfx, `["ECDSA-P256"]`, 0)
	t.Cleanup(func() { e.destroyAll(t, dir) })

	if out, code := e.tf(t, dir, "apply", "-auto-approve"); code != 0 {
		t.Fatalf("apply failed (exit %d):\n%s", code, out)
	}
	out, code := e.tf(t, dir, "destroy", "-auto-approve")
	if code == 0 {
		t.Fatalf("destroy succeeded although the CA revoke needs a second admin:\n%s", out)
	}
	m := regexp.MustCompile(`pending approval, action id ([A-Za-z0-9_-]+)`).FindStringSubmatch(flatten(out))
	if m == nil {
		t.Fatalf("destroy error does not carry the pending action id:\n%s", out)
	}
	if e.caID(t, dir) == "" {
		t.Error("CA left Terraform state although its revoke is still pending")
	}
	if code, body := e.api(t, e.approver, http.MethodPost, "/api/v1/pending-actions/"+m[1]+"/approve", nil); code != http.StatusOK {
		t.Fatalf("approve pending action %s: %d %s", m[1], code, body)
	}
	if out, code := e.tf(t, dir, "destroy", "-auto-approve"); code != 0 {
		t.Fatalf("destroy after approval failed (exit %d):\n%s", code, out)
	}
}

// TestAcc_ImportThenPlan: drop all three resources from state, terraform import
// them back by id, and plan. CA and template come back with no diff; the
// certificate's only diff is csr_pem null -> config (the hub never returns the
// CSR), an in-place no-op that must not be a replacement. Also reads the CA and
// template through the data sources.
func TestAcc_ImportThenPlan(t *testing.T) {
	e := accSetup(t)
	dir := t.TempDir()
	sfx := randHex(t, 4)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeCSR(t, dir, "tfacc-imp-"+sfx+".example.test", key)
	writeConfig(t, dir, sfx, `["ECDSA-P256"]`, 0)
	t.Cleanup(func() { e.destroyAll(t, dir) })

	if out, code := e.tf(t, dir, "apply", "-auto-approve"); code != 0 {
		t.Fatalf("apply failed (exit %d):\n%s", code, out)
	}
	out, _ := e.tf(t, dir, "output", "-json")
	var outs map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(out), &outs); err != nil {
		t.Fatalf("parse outputs: %v", err)
	}
	ids := map[string]string{"kryptkeeper_ca.root": outs["ca_id"].Value, "kryptkeeper_template.leaf": outs["template_id"].Value, "kryptkeeper_certificate.leaf": outs["cert_fp"].Value}
	for addr := range ids {
		if out, code := e.tf(t, dir, "state", "rm", addr); code != 0 {
			t.Fatalf("state rm %s: %s", addr, out)
		}
	}
	for addr, id := range ids {
		if out, code := e.tf(t, dir, "import", addr, id); code != 0 {
			t.Fatalf("import %s %s (exit %d):\n%s", addr, id, code, out)
		}
	}
	out, code := e.tf(t, dir, "plan")
	if code != 0 {
		t.Fatalf("plan after import failed:\n%s", out)
	}
	flat := flatten(out)
	if strings.Contains(flat, "must be replaced") || strings.Contains(flat, "will be destroyed") {
		t.Errorf("plan after import replaces something:\n%s", out)
	}
	if strings.Contains(flat, "kryptkeeper_ca.root will be updated") || strings.Contains(flat, "kryptkeeper_template.leaf will be updated") {
		t.Errorf("CA or template shows a diff after import:\n%s", out)
	}
	if out, code := e.tf(t, dir, "apply", "-auto-approve"); code != 0 {
		t.Fatalf("apply after import failed (exit %d):\n%s", code, out)
	}
	if out, code := e.tf(t, dir, "plan", "-detailed-exitcode"); code != 0 {
		t.Errorf("plan after the adopting apply is not empty (exit %d):\n%s", code, out)
	}

	// Data sources resolve the same objects by name.
	cfg, _ := os.ReadFile(filepath.Join(dir, "main.tf"))
	ds := fmt.Sprintf(`
data "kryptkeeper_ca" "by_name" {
  name       = "tfacc-ca-%[1]s"
  depends_on = [kryptkeeper_ca.root]
}
data "kryptkeeper_template" "by_name" {
  name       = "tfacc-tpl-%[1]s"
  depends_on = [kryptkeeper_template.leaf]
}
output "ds_ca_id" { value = data.kryptkeeper_ca.by_name.id }
output "ds_ca_cn" { value = data.kryptkeeper_ca.by_name.common_name }
output "ds_tpl_id" { value = data.kryptkeeper_template.by_name.id }
`, sfx)
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), append(cfg, ds...), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := e.tf(t, dir, "apply", "-auto-approve"); code != 0 {
		t.Fatalf("apply with data sources failed (exit %d):\n%s", code, out)
	}
	out, _ = e.tf(t, dir, "output", "-json")
	if err := json.Unmarshal([]byte(out), &outs); err != nil {
		t.Fatalf("parse outputs: %v", err)
	}
	if outs["ds_ca_id"].Value != ids["kryptkeeper_ca.root"] || outs["ds_tpl_id"].Value != ids["kryptkeeper_template.leaf"] {
		t.Errorf("data sources returned ca %q / template %q, want %q / %q", outs["ds_ca_id"].Value, outs["ds_tpl_id"].Value, ids["kryptkeeper_ca.root"], ids["kryptkeeper_template.leaf"])
	}
	if outs["ds_ca_cn"].Value != "tfacc-root-"+sfx {
		t.Errorf("data source common_name = %q", outs["ds_ca_cn"].Value)
	}
}
