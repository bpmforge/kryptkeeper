// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/privexec"
)

func newBundleFixture(t *testing.T) (mux *http.ServeMux, adminTok, auditorTok, otherTenantTok, targetID string, audit *sshRecordingAudit) {
	t.Helper()
	m, auth, store, tenants, _ := newTargetsTestMux(t)
	t.Setenv("MULTI_TENANCY", "on")
	audit = &sshRecordingAudit{}
	mux = http.NewServeMux()
	registerTargetHandlers(mux, auth, store, tenants, audit, targetEgressDeps{})
	_ = m
	ctx := t.Context()
	for _, tn := range []string{"tenant-a", "tenant-b"} {
		if _, err := tenants.CreateTenant(ctx, tn, tn); err != nil {
			t.Fatal(err)
		}
	}
	key := func(id, role, tenant string) string {
		scopes := []string{"*"}
		if role == "viewer" {
			scopes = nil // "*" would grant every permission
		}
		_, tok, err := auth.CreateAPIKey(id, id, role, scopes, "", tenant, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	adminTok = key("adm", "pki-admin", "tenant-a")
	auditorTok = key("aud", "viewer", "tenant-a")
	otherTenantTok = key("adm-b", "pki-admin", "tenant-b")
	tgt, err := store.Create(ctx, ManagedTarget{ID: "target-bundle", Name: "web", Host: "web.example.com", DiscoveryMode: "network",
		InstallMode: "ssh", RenewalMethod: "manual", InstallServerType: "nginx",
		InstallCertPath: "/etc/nginx/tls/site.crt", InstallKeyPath: "/etc/nginx/tls/site.key", Tenant: "tenant-a"})
	if err != nil {
		t.Fatal(err)
	}
	return mux, adminTok, auditorTok, otherTenantTok, tgt.ID, audit
}

type bundleResp struct {
	Data privilegeBundle `json:"data"`
}

func TestPrivilegeBundleHelper(t *testing.T) {
	mux, admin, _, _, id, audit := newBundleFixture(t)
	rec := doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+id+"/privilege-bundle?mode=helper", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp bundleResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	b := resp.Data
	sum := sha256.Sum256([]byte(b.Helper))
	if b.Helper != privexec.HelperScript || hex.EncodeToString(sum[:]) != b.HelperSHA256 || b.HelperSHA256 != privexec.HelperSHA256() {
		t.Fatal("served helper must be byte-identical to the embedded one and match its sha256")
	}
	if !strings.Contains(b.Sudoers, "Defaults:kkscan !requiretty") || strings.Count(b.Sudoers, "NOPASSWD:") != 1 {
		t.Fatalf("sudoers: %s", b.Sudoers)
	}
	joined := strings.Join(b.Checklist, "\n")
	for _, want := range []string{"useradd -m kkscan", b.HelperSHA256, "visudo -cf", "Test credential"} {
		if !strings.Contains(joined, want) {
			t.Errorf("checklist lacks %q:\n%s", want, joined)
		}
	}
	if b.HelperPath != privexec.DefaultHelperPath {
		t.Errorf("helper path %q", b.HelperPath)
	}
	assertAudit(t, audit, "target.privilege_bundle.read", AuditOutcomeSuccess)
}

func TestPrivilegeBundleRawAndPassword(t *testing.T) {
	mux, admin, _, _, id, _ := newBundleFixture(t)
	get := func(q string) (privilegeBundle, int) {
		rec := doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+id+"/privilege-bundle?"+q, admin, "")
		var r bundleResp
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return r.Data, rec.Code
	}
	raw, code := get("mode=nopasswd&user=svc-scan")
	if code != http.StatusOK || raw.Helper != "" || raw.HelperSHA256 != "" {
		t.Fatalf("nopasswd: %d %+v", code, raw)
	}
	if !strings.Contains(raw.Sudoers, "/usr/bin/install -m * /etc/nginx/tls/*") || !strings.Contains(raw.Sudoers, "svc-scan ALL=(root)") || !strings.Contains(raw.Sudoers, "nginx -t") {
		t.Fatalf("raw sudoers should cover the target's cert dir and server type:\n%s", raw.Sudoers)
	}
	if len(raw.Warnings) == 0 || !strings.Contains(raw.Warnings[0], "root read/write") {
		t.Fatalf("raw warnings: %v", raw.Warnings)
	}
	pw, code := get("mode=password")
	if code != http.StatusOK || strings.Contains(pw.Sudoers, "NOPASSWD") || len(pw.Warnings) == 0 || !strings.Contains(pw.Warnings[0], "Rotating") {
		t.Fatalf("password: %d %+v", code, pw)
	}
	if def, code := get(""); code != http.StatusOK || def.Mode != "helper" {
		t.Fatalf("default mode: %d %+v", code, def)
	}
	for _, q := range []string{"mode=none", "mode=root", "user=Bad%20User", "mode=nopasswd&user=a%0Ab"} {
		if _, code := get(q); code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", q, code)
		}
	}
}

func TestPrivilegeBundleGates(t *testing.T) {
	mux, admin, auditor, otherTenant, id, audit := newBundleFixture(t)
	path := "/api/v1/targets/" + id + "/privilege-bundle"
	if rec := doTargetsRequest(mux, http.MethodGet, path, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	if rec := doTargetsRequest(mux, http.MethodGet, path, auditor, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("auditor must lack the permission: %d", rec.Code)
	}
	if rec := doTargetsRequest(mux, http.MethodGet, path, otherTenant, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("other tenant: %d", rec.Code)
	}
	if rec := doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/nope/privilege-bundle", admin, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing target: %d", rec.Code)
	}
	if rec := doTargetsRequest(mux, http.MethodPost, path, admin, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
	assertAudit(t, audit, "target.privilege_bundle.read", AuditOutcomeDenied)
}

func assertAudit(t *testing.T, a *sshRecordingAudit, action string, outcome AuditOutcome) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			return
		}
	}
	t.Fatalf("no audit row %s/%s in %+v", action, outcome, a.entries)
}

func TestPrivilegeBundleWithoutStoredTarget(t *testing.T) {
	mux, admin, auditor, _, _, audit := newBundleFixture(t)
	path := "/api/v1/targets/privilege-bundle?mode=nopasswd&server_type=haproxy&cert_path=/etc/haproxy/certs/a.pem"
	rec := doTargetsRequest(mux, http.MethodGet, path, admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var r bundleResp
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if !strings.Contains(r.Data.Sudoers, "/etc/haproxy/certs/*") || !strings.Contains(r.Data.Sudoers, "haproxy -c") {
		t.Fatalf("install profile ignored:\n%s", r.Data.Sudoers)
	}
	if rec := doTargetsRequest(mux, http.MethodGet, path, auditor, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("auditor: %d", rec.Code)
	}
	assertAudit(t, audit, "target.privilege_bundle.read", AuditOutcomeSuccess)
}

// W34-20: scan_paths widens the raw allowlist to the keystore directories a scan
// reads, which are not the install directory.
func TestPrivilegeBundleScanPaths(t *testing.T) {
	mux, admin, _, _, id, _ := newBundleFixture(t)
	get := func(q string) (privilegeBundle, int) {
		rec := doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+id+"/privilege-bundle?"+q, admin, "")
		var r bundleResp
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return r.Data, rec.Code
	}
	b, code := get("mode=nopasswd&scan_paths=/opt/ssl,/etc/pki/java")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{"/usr/bin/cat /opt/ssl/*", "/usr/bin/find /opt/ssl *", "/usr/bin/cat /etc/pki/java/*", "/usr/bin/cat /etc/nginx/tls/*"} {
		if !strings.Contains(b.Sudoers, want) {
			t.Errorf("sudoers lacks %q:\n%s", want, b.Sudoers)
		}
	}
	if without, _ := get("mode=nopasswd"); strings.Contains(without.Sudoers, "/opt/ssl") {
		t.Error("without scan_paths the drop-in must keep to the install directory")
	}
	for _, q := range []string{"mode=nopasswd&scan_paths=/opt/ssl%3Bid", "mode=nopasswd&scan_paths=relative/dir", "mode=nopasswd&scan_paths=/", "mode=nopasswd&scan_paths=" + strings.Repeat("/a,", 17)} {
		if _, code := get(q); code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", q, code)
		}
	}
}
