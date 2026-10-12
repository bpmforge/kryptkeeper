// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/pem"
	"testing"

	"kryptkeeper/internal/agentinstall"
)

// RC1-A-04: a hub-side executor must verify through the egress-guarded dial.
func TestNewRenewalExecutorVerifiesThroughEgressPolicy(t *testing.T) {
	exec := NewRenewalExecutor(nil, nil)
	if exec.verifier == nil {
		t.Fatal("hub executor has no egress-guarded verifier")
	}
	for _, hp := range []string{"169.254.169.254:80", "127.0.0.1:443"} {
		if _, err := exec.verifier(context.Background(), hp); err == nil {
			t.Fatalf("hub verify dialled %s", hp)
		}
	}
}

func TestValidateVerifyHostPort(t *testing.T) {
	for _, ok := range []string{"", "web.example.com:8443", "10.0.0.5:443", "[fd00::5]:8443"} {
		if err := validateVerifyHostPort(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"web.example.com", ":443", "web:0", "web:70000", "web:https",
		// RC1-A-04: loopback and link-local (metadata) are never verify targets.
		"169.254.169.254:80", "169.254.1.1:443", "127.0.0.1:443", "127.1.2.3:8443", "[::1]:8443",
		"localhost:443", "LOCALHOST:443", "app.localhost:443", "0.0.0.0:443", "[fe80::1]:443"} {
		if err := validateVerifyHostPort(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestManagedTargetStoreRoundTripsVerifyHostPort(t *testing.T) {
	store := newSweepTestTargetStore(t)
	ctx := context.Background()
	tg := sweepTarget(true)
	tg.VerifyHostPort = "sweep.example.com:8443"
	if _, err := store.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, tg.ID)
	if err != nil || got.VerifyHostPort != "sweep.example.com:8443" {
		t.Fatalf("round-trip: %+v %v", got, err)
	}
	bad := "nope"
	if _, err := store.Update(ctx, tg.ID, ManagedTargetUpdate{VerifyHostPort: &bad}); err == nil {
		t.Fatal("PATCH accepted a verify_host_port without a port")
	}
	cleared := ""
	if u, err := store.Update(ctx, tg.ID, ManagedTargetUpdate{VerifyHostPort: &cleared}); err != nil || u.VerifyHostPort != "" {
		t.Fatalf("clear: %+v %v", u, err)
	}
}

// Scheduled verification dials the target's verify_host_port when set, and
// <host>:443 otherwise.
func TestRenewalSweepVerifiesAtTargetVerifyHostPort(t *testing.T) {
	for _, tc := range []struct{ name, set, want string }{
		{"default", "", "sweep.example.com:443"},
		{"override", "sweep.example.com:8443", "sweep.example.com:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupIntegrationDB(t)
			provider, engine := newIntegrationCAProvider(t, db)
			ctx := context.Background()
			if _, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
				CAID:       getFirstCAID(t, engine),
				CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
				TemplateID: "file-backed-default",
				TeamID:     "team-vhp-" + tc.name,
			}); err != nil {
				t.Fatal(err)
			}
			targets := newSweepTestTargetStore(t)
			tg := sweepTarget(true)
			tg.VerifyHostPort = tc.set
			if _, err := targets.Create(ctx, tg); err != nil {
				t.Fatal(err)
			}
			fake := &renewalFakeExecutor{files: map[string][]byte{}}
			exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
			var dialed string
			exec.verifier = func(_ context.Context, addr string) (string, error) {
				dialed = addr
				block, _ := pem.Decode(fake.files["/etc/nginx/tls/sweep.crt"])
				return agentinstall.FingerprintSHA256(block.Bytes), nil
			}
			sched := newSweepScheduler(t, provider, targets, exec)
			sched.runScan()
			if dialed != tc.want {
				t.Fatalf("verified at %q, want %q", dialed, tc.want)
			}
		})
	}
}
