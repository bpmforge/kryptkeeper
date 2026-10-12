// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// RC1-A-01: the sweep re-checks the principal that armed a target.
func TestVerifyEgressStamp(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	users := &fileUserProvider{users: []UserRecord{
		{ID: "u-op", Email: "op@example.test", Role: "pki-operator", Status: "active"},
		{ID: "u-view", Email: "v@example.test", Role: "viewer", Status: "active"},
	}}
	auth.userProvider = users
	ctx := context.Background()
	now := time.Now()

	opKey, _, err := auth.CreateAPIKey("k-op", "svc-op", "pki-operator", nil, "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	viewKey, _, err := auth.CreateAPIKey("k-view", "svc-view", "viewer", nil, "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	expiredKey, _, err := auth.CreateAPIKey("k-exp", "svc-exp", "pki-operator", nil, now.Add(time.Hour).UTC().Format(time.RFC3339), "", now)
	if err != nil {
		t.Fatal(err)
	}

	check := func(stamp string, want error) {
		t.Helper()
		if got := auth.verifyEgressStamp(ctx, stamp, now); !errors.Is(got, want) {
			t.Fatalf("verify(%q) = %v, want %v", stamp, got, want)
		}
	}

	// Still valid.
	check(stampBootstrap, nil)
	check(stampKey+opKey.Kid, nil)
	check(stampUser+"u-op", nil)
	check(stampToken+"external-sub", nil)

	// Lost certificate.renew.
	check(stampKey+viewKey.Kid, errStampLostAuth)
	check(stampUser+"u-view", errStampLostAuth)
	if _, err := users.UpdateUser(ctx, "u-op", "viewer", "active"); err != nil {
		t.Fatal(err)
	}
	check(stampUser+"u-op", errStampLostAuth)

	// The principal is gone: deleted key, deactivated or unknown user, expired key.
	if found, _ := auth.RevokeAPIKey(opKey.Kid); !found {
		t.Fatal("delete key")
	}
	check(stampKey+opKey.Kid, errStampUnresolvable)
	if err := users.DeactivateUser(ctx, "u-view"); err != nil {
		t.Fatal(err)
	}
	check(stampUser+"u-view", errStampUnresolvable)
	check(stampUser+"never-existed", errStampUnresolvable)
	if got := auth.verifyEgressStamp(ctx, stampKey+expiredKey.Kid, now.Add(2*time.Hour)); !errors.Is(got, errStampUnresolvable) {
		t.Fatalf("expired key: %v", got)
	}

	// A stamp in a form nobody can verify (a pre-prefix value) is not trusted.
	check("admin-1", errStampUnrecognized)
}

func TestEgressStampKinds(t *testing.T) {
	for _, c := range []struct {
		pd   AuthPrincipal
		want string
	}{
		{AuthPrincipal{AuthType: "bootstrap", ID: "bootstrap"}, "bootstrap"},
		{AuthPrincipal{AuthType: "api-key", ID: "free-text", Kid: "kid1"}, "key:kid1"},
		{AuthPrincipal{AuthType: "local", ID: "u1"}, "user:u1"},
		{AuthPrincipal{AuthType: "oidc", ID: "sub1"}, "token:sub1"},
	} {
		if got, ok := egressStamp(c.pd); !ok || got != c.want {
			t.Errorf("egressStamp(%+v) = %q, %v, want %q", c.pd, got, ok, c.want)
		}
	}
}

// An auth kind the stamp switch does not know (a new login path, a typo, the
// empty zero value) must not arm a target with an unverifiable stamp.
func TestEgressStampRefusesUnknownAuthType(t *testing.T) {
	for _, at := range []AuthType{"", "saml", "scim", "agent", "mcp", "API-KEY", "peercred"} {
		pd := AuthPrincipal{AuthType: at, ID: "x", Kid: "k"}
		if got, ok := egressStamp(pd); ok || got != "" {
			t.Errorf("AuthType %q armed with stamp %q", at, got)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/targets", nil)
		if _, ok := armStamp(rec, req, nil, pd, "target.create", "targets"); ok || rec.Code != http.StatusForbidden {
			t.Errorf("AuthType %q: armStamp ok=%v code=%d, want refusal 403", at, ok, rec.Code)
		}
	}
}

// A stamped principal who is gone or demoted stops the push, loudly: the
// certificate is not renewed and a denied row names the target and principal.
func TestRenewalSweepSkipsWhenStampedPrincipalLostAuthority(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"demoted", errStampLostAuth},
		{"deleted", errStampUnresolvable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupIntegrationDB(t)
			provider, engine := newIntegrationCAProvider(t, db)
			ctx := context.Background()
			issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
				CAID:       getFirstCAID(t, engine),
				CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
				TemplateID: "file-backed-default",
				TeamID:     "team-stale-" + tc.name,
			})
			if err != nil {
				t.Fatal(err)
			}
			targets := newSweepTestTargetStore(t)
			if _, err := targets.Create(ctx, sweepTarget(true)); err != nil {
				t.Fatal(err)
			}
			fake := &renewalFakeExecutor{files: map[string][]byte{}}
			sched := newSweepScheduler(t, provider, targets, newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t)))
			rec := &recordingAuditProvider{}
			sched.auditProvider = rec
			var seen string
			sched.WithStampVerifier(func(_ context.Context, stamp string) error { seen = stamp; return tc.err })
			sched.runScan()

			if seen != "sweep-test-admin" {
				t.Fatalf("verifier saw stamp %q", seen)
			}
			if st := sched.Status(); st.LastAutoRenewTriggers != 0 {
				t.Fatalf("pushed despite a stale stamp: %+v", st)
			}
			after, _, _ := provider.GetCertificate(ctx, issued.CertificateItem.FingerprintSHA256)
			if after.SuccessorFP != nil || len(fake.files) != 0 {
				t.Fatal("a certificate was renewed or written for a target armed by a principal without authority")
			}
			denied := false
			for _, e := range rec.entries {
				if e.Action == "certificate.renew_execute_denied" && e.Outcome == "denied" {
					denied = true
				}
			}
			if !denied {
				t.Fatalf("no denied audit row: %+v", rec.entries)
			}
		})
	}
}

// With the stamped principal still authorized, the same sweep renews.
func TestRenewalSweepProceedsWhenStampStillValid(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-stamp-ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	targets := newSweepTestTargetStore(t)
	if _, err := targets.Create(ctx, sweepTarget(true)); err != nil {
		t.Fatal(err)
	}
	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	exec.verifier = func(context.Context, string) (string, error) { return "", errors.New("unused") }
	sched := newSweepScheduler(t, provider, targets, exec)
	sched.WithStampVerifier(func(context.Context, string) error { return nil })
	sched.runScan()
	after, _, _ := provider.GetCertificate(ctx, issued.CertificateItem.FingerprintSHA256)
	if after.SuccessorFP == nil {
		t.Fatal("a valid stamp did not reach the renewal engine")
	}
}
