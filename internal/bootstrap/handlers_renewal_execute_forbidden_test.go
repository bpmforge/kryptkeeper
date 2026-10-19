// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"kryptkeeper/internal/connectors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type renewExecAuditRecorder struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (p *renewExecAuditRecorder) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (p *renewExecAuditRecorder) AppendEntry(_ context.Context, e AuditEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, e)
	return nil
}

// A team-scope refusal from authorizeCertificateResourceAccess
// (errCertificateTeamScopeForbidden / errCertificateTenantForbidden) used to
// fall into the default branch and answer 503 "certificate unavailable",
// which hides a permission problem as an outage. It must be 403 with a denied
// audit row, as the retry handler does.
func TestRenewalExecuteTeamScopeForbiddenIs403Denied(t *testing.T) {
	_, auth, provider, targetStore, credStore, caID := newRenewalExecuteTestMuxAuth(t)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "scope.example.com", "scope.example.com"),
		TemplateID: "file-backed-default", TeamID: "svc-owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, otherToken, err := auth.CreateAPIKey("svc-other", "svc-other", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	audit := &renewExecAuditRecorder{}
	mux := http.NewServeMux()
	RegisterRenewalExecuteHandler(mux, auth, provider, targetStore, credStore, audit)

	rec := postRenewalExecute(t, mux, otherToken, map[string]string{
		"fingerprint": issued.CertificateItem.FingerprintSHA256, "target_id": "tgt-any",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-team execute: got %d, want 403: %s", rec.Code, rec.Body.String())
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	var denied bool
	for _, e := range audit.entries {
		if e.Action == "certificate.renew_execute" && e.Outcome == AuditOutcomeDenied {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("no denied certificate.renew_execute audit row: %+v", audit.entries)
	}
}

type rateLimitedRunner struct{ err error }

func (r rateLimitedRunner) ExecuteRenewal(context.Context, string, ManagedTarget, RenewalInstallProfile) (RenewalExecuteResult, error) {
	return RenewalExecuteResult{}, r.err
}

// A throttle or upstream rate limit is the caller's cue to wait, not an outage:
// 429 with Retry-After, and an audit row.
func TestRenewalExecuteRateLimitedIs429WithRetryAfter(t *testing.T) {
	_, auth, provider, targetStore, credStore, caID := newRenewalExecuteTestMuxAuth(t)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "rl.example.com", "rl.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-rl",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := targetStore.Create(ctx, ManagedTarget{
		ID: "tgt-rl", Name: "rl", Host: "10.255.255.1", DiscoveryMode: "none", InstallMode: "ssh",
		RenewalMethod: "manual", CredentialRef: "cred-rl",
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, wait := range map[string]time.Duration{"backoff": 90500 * time.Millisecond, "zero": 0} {
		t.Run(name, func(t *testing.T) {
			audit := &renewExecAuditRecorder{}
			mux := http.NewServeMux()
			runner := rateLimitedRunner{err: fmt.Errorf("upstream renewal: %w", &connectors.RateLimitError{ConnectorID: "c1", Reason: "backoff", RetryAfter: wait})}
			registerRenewalExecuteHandlerWithRunner(mux, auth, provider, targetStore, credStore, audit, runner, time.Minute)
			rec := postRenewalExecute(t, mux, "test-token", map[string]string{
				"fingerprint": issued.CertificateItem.FingerprintSHA256, "target_id": target.ID,
			})
			want := "91"
			if wait == 0 {
				want = "1"
			}
			if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != want {
				t.Fatalf("got %d Retry-After=%q, want 429 and %q: %s", rec.Code, rec.Header().Get("Retry-After"), want, rec.Body.String())
			}
			audit.mu.Lock()
			defer audit.mu.Unlock()
			var rows int
			for _, e := range audit.entries {
				if e.Action == "certificate.renew_execute" && e.Outcome == AuditOutcomeFailure && strings.Contains(e.ChangeSummary, "rate_limited") {
					rows++
				}
			}
			if rows != 1 {
				t.Fatalf("want one rate_limited audit row, got %+v", audit.entries)
			}
		})
	}
}

// ctxRunner records the context the executor received and what the JIT secret
// held at that moment.
type ctxRunner struct {
	seen     string
	hadValue bool
}

func (c *ctxRunner) ExecuteRenewal(ctx context.Context, _ string, _ ManagedTarget, _ RenewalInstallProfile) (RenewalExecuteResult, error) {
	if j := jitSudoFrom(ctx); j != nil {
		c.hadValue, c.seen = true, j.text()
	}
	return RenewalExecuteResult{Renewed: true, InstallOutcome: "installed_verified", Verified: true}, nil
}

// W34-17: the manual renew route carries a sudo password to the executor for
// that call only, records privilege_source=jit, and never echoes it.
func TestRenewalExecuteJITSudoPasswordIsMemoryOnly(t *testing.T) {
	const pw = "Renew-Jit-Pw-6613"
	logs := captureLogs(t, slog.LevelDebug)
	_, auth, provider, targetStore, credStore, caID := newRenewalExecuteTestMuxAuth(t)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "jit.example.com", "jit.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-jit",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := targetStore.Create(ctx, ManagedTarget{
		ID: "tgt-jit", Name: "jit", Host: "10.255.255.1", DiscoveryMode: "none", InstallMode: "ssh",
		RenewalMethod: "manual", CredentialRef: "cred-jit",
	})
	if err != nil {
		t.Fatal(err)
	}
	audit := &renewExecAuditRecorder{}
	mux := http.NewServeMux()
	runner := &ctxRunner{}
	registerRenewalExecuteHandlerWithRunner(mux, auth, provider, targetStore, credStore, audit, runner, time.Minute)
	rec := postRenewalExecute(t, mux, "test-token", map[string]string{
		"fingerprint": issued.CertificateItem.FingerprintSHA256, "target_id": target.ID, "jit_sudo_password": pw,
	})
	if rec.Code != http.StatusOK || !runner.hadValue || runner.seen != pw {
		t.Fatalf("%d %s hadValue=%v", rec.Code, rec.Body.String(), runner.hadValue)
	}
	if strings.Contains(rec.Body.String(), pw) || strings.Contains(logs.String(), pw) {
		t.Fatal("password echoed or logged")
	}
	audit.mu.Lock()
	var jit bool
	for _, e := range audit.entries {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), pw) {
			t.Fatalf("password in audit: %s", b)
		}
		if e.Action == "certificate.renew_execute" && strings.Contains(e.ChangeSummary, "privilege_source=jit") {
			jit = true
		}
	}
	audit.mu.Unlock()
	if !jit {
		t.Fatalf("audit lacks privilege_source=jit: %+v", audit.entries)
	}
	// Without the field nothing is carried.
	runner.hadValue = false
	postRenewalExecute(t, mux, "test-token", map[string]string{"fingerprint": issued.CertificateItem.FingerprintSHA256, "target_id": target.ID})
	if runner.hadValue {
		t.Fatal("no password sent, none may be in the context")
	}
}
