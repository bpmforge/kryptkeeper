// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// RC1-A-03: POST /renewal/execute used to take the install profile (cert and
// key paths, server_type used as a unit name, verify_host_port) from the body,
// so any certificate.renew principal could write PEM to arbitrary paths and
// reload arbitrary units over SSH.
func TestRenewalExecuteInstallOverrideNeedsAdmin(t *testing.T) {
	mux, auth, provider, targetStore, credStore, caID := newRenewalExecuteTestMuxAuth(t)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "prof.example.com", "prof.example.com"),
		TemplateID: "file-backed-default", TeamID: "svc-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credStore.Create(ctx, "cred-p1", "p", CredentialTypeSSHKey, "", testSSHCredentialJSON(t)); err != nil {
		t.Fatal(err)
	}
	target, err := targetStore.Create(ctx, ManagedTarget{
		ID: "tgt-p1", Name: "p", Host: "10.255.255.1", DiscoveryMode: "none", InstallMode: "ssh",
		RenewalMethod: "manual", CredentialRef: "cred-p1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, svcToken, err := auth.CreateAPIKey("svc-1", "svc-1", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp := issued.CertificateItem.FingerprintSHA256

	// A service-account may not choose where the key lands.
	rec := postRenewalExecute(t, mux, svcToken, map[string]any{
		"fingerprint": fp, "target_id": target.ID,
		"install": map[string]string{"server_type": "sshd", "cert_path": "/root/.ssh/authorized_keys", "key_path": "/etc/cron.d/x", "verify_host_port": "10.0.0.9:443"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("override by service-account: got %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if got, _, _ := provider.GetCertificate(ctx, fp); got.SuccessorFP != nil {
		t.Fatal("a refused override still renewed the certificate")
	}

	// Without an override the stored profile is used; this target has none, so
	// the engine refuses for want of a profile instead of obeying the caller.
	rec = postRenewalExecute(t, mux, svcToken, map[string]any{"fingerprint": fp, "target_id": target.ID})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "install profile") {
		t.Fatalf("stored-profile path: got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestInstallProfileForCaller(t *testing.T) {
	target := ManagedTarget{InstallServerType: "nginx", InstallCertPath: "/a.crt", InstallKeyPath: "/a.key", VerifyHostPort: "h:443"}
	over := RenewalInstallProfile{ServerType: "x", CertPath: "/x", KeyPath: "/y"}

	if p, ok := installProfileForCaller(AuthPrincipal{Role: "service-account"}, target, RenewalInstallProfile{}); !ok || p.CertPath != "/a.crt" || p.VerifyHostPort != "h:443" {
		t.Fatalf("stored profile not used: %+v ok=%v", p, ok)
	}
	if _, ok := installProfileForCaller(AuthPrincipal{Role: "pki-operator"}, target, over); ok {
		t.Fatal("pki-operator override accepted")
	}
	if p, ok := installProfileForCaller(AuthPrincipal{Role: "pki-admin"}, target, over); !ok || p != over {
		t.Fatalf("admin override refused: %+v ok=%v", p, ok)
	}
}
