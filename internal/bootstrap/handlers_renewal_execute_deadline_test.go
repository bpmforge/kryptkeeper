// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// slowRenewer stands in for an ACME dns-01 renewal that waits on TXT
// propagation.
type slowRenewer struct {
	delay  time.Duration
	result RenewalExecuteResult
	err    error
	// gotDeadline is the executor context's deadline, for the budget check.
	gotDeadline time.Time
}

func (s *slowRenewer) ExecuteRenewal(ctx context.Context, _ string, _ ManagedTarget, _ RenewalInstallProfile) (RenewalExecuteResult, error) {
	s.gotDeadline, _ = ctx.Deadline()
	time.Sleep(s.delay) // deliberately ignores ctx: a worst-case executor
	return s.result, s.err
}

// The write deadline must outlast the longest dns-01 wait the connector
// allows plus ACME order and install-verify time. Before the fix it was a
// fixed 180s, equal to the default propagation wait and below the maximum.
func TestRenewalExecuteBudgetCoversDNS01(t *testing.T) {
	const orderAndInstall = 4 * time.Minute // CA order + 135s verify-retry window, rounded up
	if renewalExecuteBudget < maxDNSPropagationTimeout+orderAndInstall {
		t.Fatalf("budget %s does not cover the %s dns-01 wait plus order/install time", renewalExecuteBudget, maxDNSPropagationTimeout)
	}
	if renewalExecuteBudget+renewalResponseWindow <= 180*time.Second+maxDNSPropagationTimeout {
		t.Fatalf("write window %s is not past the old 180s deadline plus the dns-01 maximum", renewalExecuteBudget+renewalResponseWindow)
	}
}

// startRenewalServer serves the handler with a global WriteTimeout shorter
// than the renewer's runtime, like server.go's 15s against a minutes-long
// order. It returns the server and an issued certificate fingerprint and
// target id the handler will accept.
func startRenewalServer(t *testing.T, runner renewalRunner, budget time.Duration, writeTimeout time.Duration) (srv *httptest.Server, fingerprint, targetID string) {
	t.Helper()
	_, auth, provider, targetStore, credStore, caID := newRenewalExecuteTestMuxAuth(t)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "slow.example.com", "slow.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-slow",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	target, err := targetStore.Create(ctx, ManagedTarget{
		ID: "tgt-slow", Name: "slow-target", Host: "127.0.0.1",
		DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-slow",
	})
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	mux := http.NewServeMux()
	registerRenewalExecuteHandlerWithRunner(mux, auth, provider, targetStore, credStore, stubAuditProvider{}, runner, budget)
	srv = httptest.NewUnstartedServer(mux)
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, issued.CertificateItem.FingerprintSHA256, target.ID
}

func postSlow(t *testing.T, srv *httptest.Server, fp, target string) (int, []byte, error) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"fingerprint": fp, "target_id": target, "install": map[string]string{"server_type": "nginx", "cert_path": "/a", "key_path": "/b"}})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/renewal/execute", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, err
}

// A renewal that fails after the server's own WriteTimeout must still
// deliver the error as JSON, and one that succeeds slowly must still deliver
// its result.
func TestRenewalExecuteSlowRenewalStillAnswersInJSON(t *testing.T) {
	const writeTimeout = 150 * time.Millisecond
	const slow = 500 * time.Millisecond

	t.Run("control: without the override the connection is cut", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(slow)
			writeServiceUnavailable(w, "renewal execution failed")
		}))
		srv.Config.WriteTimeout = writeTimeout
		srv.Start()
		defer srv.Close()
		resp, err := http.Get(srv.URL)
		if err == nil {
			defer resp.Body.Close()
			_, err = io.ReadAll(resp.Body)
		}
		if err == nil {
			t.Fatal("harness does not reproduce the empty reply; the tests below prove nothing")
		}
	})

	t.Run("slow failure", func(t *testing.T) {
		runner := &slowRenewer{delay: slow, err: errors.New("dns-01: _acme-challenge.slow.example.com not visible at ns1.example.test before the deadline")}
		srv, fp, tgt := startRenewalServer(t, runner, time.Minute, writeTimeout)
		code, raw, err := postSlow(t, srv, fp, tgt)
		if err != nil {
			t.Fatalf("empty reply instead of the error JSON: %v", err)
		}
		var env struct {
			Error string `json:"error"`
		}
		if code != http.StatusServiceUnavailable || json.Unmarshal(raw, &env) != nil || env.Error != "service_unavailable" || !strings.Contains(string(raw), "renewal execution failed") {
			t.Fatalf("status %d body %s", code, raw)
		}
		if d := time.Until(runner.gotDeadline); d <= 0 || d > time.Minute {
			t.Errorf("executor context deadline %v is not the budget", d)
		}
	})

	t.Run("slow success", func(t *testing.T) {
		runner := &slowRenewer{delay: slow, result: RenewalExecuteResult{Renewed: true, NewFingerprint: "abc", InstallOutcome: "installed_verified"}}
		srv, fp, tgt := startRenewalServer(t, runner, time.Minute, writeTimeout)
		code, raw, err := postSlow(t, srv, fp, tgt)
		if err != nil || code != http.StatusOK {
			t.Fatalf("status %d err %v body %s", code, err, raw)
		}
		var resp struct {
			Data RenewalExecuteResult `json:"data"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil || !resp.Data.Renewed || resp.Data.NewFingerprint != "abc" {
			t.Fatalf("body %s (%v)", raw, err)
		}
	})

	// An executor that runs past the budget (here ignoring its context) must
	// not lose the response: the write window is re-armed after it returns.
	t.Run("over budget still answers", func(t *testing.T) {
		runner := &slowRenewer{delay: 2 * slow, err: context.DeadlineExceeded}
		srv, fp, tgt := startRenewalServer(t, runner, 100*time.Millisecond, writeTimeout)
		code, raw, err := postSlow(t, srv, fp, tgt)
		if err != nil || code != http.StatusServiceUnavailable || !strings.Contains(string(raw), "renewal execution failed") {
			t.Fatalf("status %d err %v body %s", code, err, raw)
		}
	})
}
