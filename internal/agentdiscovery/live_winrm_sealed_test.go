// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery_test

// Live check for W18-09: WinRM over plain http://host:5985 with NTLM message
// sealing, against a real Windows listener left on its defaults
// (AllowUnencrypted=false). Skipped unless KK_LIVE_WINRM_HTTP=1:
//
//	KK_WINRM_HTTP_URL  http://<host>:5985/wsman
//	KK_WINRM_USER      DOMAIN\user or a bare local user
//	KK_WINRM_PASS
//
// The server refuses every unencrypted body, so a command that runs at all
// proves the body was sealed; the test also reads the listener's own
// AllowUnencrypted setting so a host misconfigured to accept plaintext
// cannot produce a false green.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentdiscovery"
)

func TestLiveWinRMSealedHTTP(t *testing.T) {
	if os.Getenv("KK_LIVE_WINRM_HTTP") != "1" {
		t.Skip("set KK_LIVE_WINRM_HTTP=1 with a Windows host's http://host:5985/wsman to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg := agentdiscovery.WinRMConfig{
		EndpointURL: os.Getenv("KK_WINRM_HTTP_URL"),
		Username:    os.Getenv("KK_WINRM_USER"),
		Password:    os.Getenv("KK_WINRM_PASS"),
	}
	if !strings.HasPrefix(cfg.EndpointURL, "http://") {
		t.Fatalf("KK_WINRM_HTTP_URL must be a plain http:// endpoint, got %q", cfg.EndpointURL)
	}
	host := strings.TrimPrefix(cfg.EndpointURL, "http://")
	host = strings.SplitN(strings.SplitN(host, "/", 2)[0], ":", 2)[0]

	t.Run("listener_refuses_plaintext_and_sealed_command_runs", func(t *testing.T) {
		out, stderr, code, err := agentdiscovery.NewWSManShell(cfg, nil).RunExit(ctx, "winrm", "get", "winrm/config/service")
		if err != nil {
			t.Fatalf("sealed command failed: %v (stderr=%q)", err, stderr)
		}
		if code != 0 {
			t.Fatalf("winrm get exited %d: %s", code, stderr)
		}
		if !strings.Contains(out, "AllowUnencrypted = false") {
			t.Fatalf("listener does not report AllowUnencrypted = false, so this run proves nothing about sealing:\n%s", out)
		}
	})

	t.Run("discovery_over_sealed_http", func(t *testing.T) {
		res := agentdiscovery.NewAgentlessWinRMScanner(agentdiscovery.NewWSManShell(cfg, nil), host).Scan(ctx)
		t.Logf("certs=%d errors=%v", len(res.Certs), res.Errors)
		for _, e := range res.Errors {
			if !strings.Contains(e, "unparseable cert") {
				t.Fatalf("discovery error: %s", e)
			}
		}
		if len(res.Certs) == 0 {
			t.Fatal("discovery returned no certificates")
		}
	})

	t.Run("wrong_password_is_401", func(t *testing.T) {
		c := cfg
		c.Password = "definitely-wrong"
		res := agentdiscovery.NewAgentlessWinRMScanner(agentdiscovery.NewWSManShell(c, nil), host).Scan(ctx)
		if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "401") {
			t.Fatalf("expected a 401: %v", res.Errors)
		}
	})
}
