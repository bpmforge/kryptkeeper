// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package adldap_test

// Live AD/LDAP acceptance for W19-06: proves the hub's "adcs_live"
// InventorySource (internal/bootstrap/inventory_source_adcs_live.go, W13-04)
// against a REAL Samba AD domain controller, following the
// KK_LIVE_WINRM=1 pattern (internal/agentdiscovery/live_winrm_test.go).
// Skipped unless KK_LIVE_ADLDAP=1. Bring the DC and hub up first with
// tests/live/ad-ldap/run.sh (or by hand per its steps), then set:
//
//	KK_ADLDAP_HUB_BASE    e.g. http://127.0.0.1:8095
//	KK_ADLDAP_TOKEN       the hub's bootstrap token
//	KK_ADLDAP_SOURCE_ID   an existing adcs_live inventory-sources id
//	KK_ADLDAP_DC_CTR      the Samba container name (default kk-uat-samba)
//	KK_ADLDAP_BASE_DN     e.g. CN=Users,DC=kkuat,DC=local
//	KK_ADLDAP_ADMIN_BIND  DOMAIN\Administrator
//	KK_ADLDAP_ADMIN_PASS
//
// This test does not stand up the DC/hub itself (run.sh owns that
// lifecycle) -- it proves the acceptance criterion run.sh cannot cover in
// a single pass: a directory-side change (a NEW certificate attached to an
// object that had none) is picked up on the very next sync, without
// restarting the hub or re-registering the source.

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func skipUnlessLive(t *testing.T) map[string]string {
	t.Helper()
	if os.Getenv("KK_LIVE_ADLDAP") != "1" {
		t.Skip("set KK_LIVE_ADLDAP=1 (and the KK_ADLDAP_* vars) to run against a real Samba AD DC; see tests/live/ad-ldap/run.sh")
	}
	env := map[string]string{
		"hub":       os.Getenv("KK_ADLDAP_HUB_BASE"),
		"token":     os.Getenv("KK_ADLDAP_TOKEN"),
		"sourceID":  os.Getenv("KK_ADLDAP_SOURCE_ID"),
		"dcCtr":     os.Getenv("KK_ADLDAP_DC_CTR"),
		"baseDN":    os.Getenv("KK_ADLDAP_BASE_DN"),
		"adminBind": os.Getenv("KK_ADLDAP_ADMIN_BIND"),
		"adminPass": os.Getenv("KK_ADLDAP_ADMIN_PASS"),
	}
	if env["dcCtr"] == "" {
		env["dcCtr"] = "kk-uat-samba"
	}
	for _, k := range []string{"hub", "token", "sourceID", "baseDN", "adminBind", "adminPass"} {
		if env[k] == "" {
			t.Fatalf("KK_LIVE_ADLDAP=1 but KK_ADLDAP_%s is unset", strings.ToUpper(k))
		}
	}
	return env
}

func syncAndCount(t *testing.T, env map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env["hub"]+"/api/v1/inventory-sources/"+env["sourceID"]+"/sync", nil)
	if err != nil {
		t.Fatalf("build sync request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env["token"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sync request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sync returned %d, want 200", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Synced int `json:"synced"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode sync response: %v", err)
	}
	return body.Data.Synced
}

// TestLive_NewCertificateReflectedOnNextSync attaches a fresh userCertificate
// to a new AD object via samba-tool/ldapmodify inside the DC container --
// standing in for "a directory-side change is reflected on the next sync"
// -- and asserts the very next sync run picks it up without any hub restart
// or re-registration of the inventory source.
func TestLive_NewCertificateReflectedOnNextSync(t *testing.T) {
	env := skipUnlessLive(t)

	before := syncAndCount(t, env)

	cn := "kkldaplivetest"
	if out, err := exec.Command(containerEngine(), "exec", env["dcCtr"], "samba-tool", "user", "create", cn, "Xy9!LiveTestPass1").CombinedOutput(); err != nil {
		// Idempotent re-run: the object may already exist from a prior pass.
		if !strings.Contains(string(out), "already exists") {
			t.Fatalf("samba-tool user create: %v: %s", err, out)
		}
	}
	genCert := exec.Command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-days", "30", "-nodes", "-subj", "/CN="+cn, "-keyout", "/tmp/"+cn+".key", "-out", "/tmp/"+cn+".pem")
	if out, err := genCert.CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v: %s", err, out)
	}
	if out, err := exec.Command("openssl", "x509", "-in", "/tmp/"+cn+".pem", "-outform", "der", "-out", "/tmp/"+cn+".der").CombinedOutput(); err != nil {
		t.Fatalf("openssl x509 to der: %v: %s", err, out)
	}
	if out, err := exec.Command(containerEngine(), "cp", "/tmp/"+cn+".der", env["dcCtr"]+":/tmp/"+cn+".der").CombinedOutput(); err != nil {
		t.Fatalf("podman cp: %v: %s", err, out)
	}
	// ldapmodify's -f file is generated inside the container so the
	// base64 DER never round-trips through this test's own stdout/logs.
	genLdif := "python3 -c \"import base64; d=open('/tmp/" + cn + ".der','rb').read(); print('dn: CN=" + cn + "," + env["baseDN"] + "\\nchangetype: modify\\nadd: userCertificate\\nuserCertificate:: '+base64.b64encode(d).decode())\" > /tmp/" + cn + ".ldif"
	if out, err := exec.Command(containerEngine(), "exec", env["dcCtr"], "sh", "-c", genLdif).CombinedOutput(); err != nil {
		t.Fatalf("build ldif: %v: %s", err, out)
	}
	// Samba refuses simple binds over plain ldap:// ("Transport encryption
	// required"); bind over LDAPS like run.sh does. REQCERT=never is the
	// DC's own loopback; the hub's trust of the DC CA is asserted elsewhere.
	if out, err := exec.Command(containerEngine(), "exec", "-e", "LDAPTLS_REQCERT=never", env["dcCtr"], "ldapmodify", "-x", "-H", "ldaps://127.0.0.1",
		"-D", env["adminBind"], "-w", env["adminPass"], "-f", "/tmp/"+cn+".ldif").CombinedOutput(); err != nil {
		t.Fatalf("ldapmodify: %v: %s", err, out)
	}

	after := syncAndCount(t, env)
	if after <= before {
		t.Fatalf("expected the next sync to report more synced certs after attaching one to a new AD object: before=%d after=%d", before, after)
	}
}

// containerEngine mirrors run.sh's CONTAINER_ENGINE: Samba AD provisioning
// needs security.* xattrs, which rootless podman refuses even under
// --privileged, so the fixture is run with a rootful engine wrapper.
func containerEngine() string {
	if ce := os.Getenv("CONTAINER_ENGINE"); ce != "" {
		return ce
	}
	return "podman"
}
