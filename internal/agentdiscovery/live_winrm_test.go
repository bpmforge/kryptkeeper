// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery_test

// Live WinRM acceptance for W18-06 (listener trust) and the W18-10/W18-11
// privilege captures. Skipped unless KK_LIVE_WINRM=1; needs a Windows host
// prepared per docs/ops/WINRM_ENABLEMENT.md and these variables:
//
//	KK_WINRM_URL   https://host:5986/wsman
//	KK_WINRM_USER  a LOCAL account, no domain prefix
//	KK_WINRM_PASS
//	KRYPTKEEPER_WINRM_CA_CERT_FILE  the exported listener certificate
//
// Two modes, selected by the account's real privilege:
//
//	default              a STANDARD user in Remote Management Users: discovery
//	                     succeeds, preflight says discover-only, and an IIS
//	                     install fails as a privilege error -- never as a false
//	                     success.
//	KK_LIVE_WINRM_ADMIN=1  a local Administrator: preflight says install, and a
//	                     real IIS install on KK_LIVE_IIS_IPPORT (default
//	                     0.0.0.0:443) imports, rebinds, reloads and is VERIFIED
//	                     by an independent TLS dial; the prior binding and the
//	                     test certificate are restored afterwards, so the host
//	                     is left as found. Set KK_LIVE_IIS_PRIOR_HASH /
//	                     KK_LIVE_IIS_APPID to what `netsh http show sslcert`
//	                     reports beforehand.
//
// First green runs 2026-09-10 against a Windows 11 22621 host, which is also
// where every defect this file guards against was captured (missing
// MessageID, unrouted shell calls, parse-time %ERRORLEVEL%, double-encoded
// scripts past the command-line limit, a .NET Core API in a script run by
// Windows PowerShell 5.1).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // Windows store thumbprint is a lookup key, not a signature
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/agentinstall"
)

func liveSelfSigned(t *testing.T, cn string, ips ...string) (certPEM, keyPEM, der []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, ip := range ips {
		tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(ip))
	}
	der, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), der
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestLiveWinRM(t *testing.T) {
	if os.Getenv("KK_LIVE_WINRM") != "1" {
		t.Skip("set KK_LIVE_WINRM=1 with a prepared Windows host to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	roots, err := agentdiscovery.WinRMRootCAsFromEnv()
	if err != nil || roots == nil {
		t.Fatalf("KRYPTKEEPER_WINRM_CA_CERT_FILE must name the listener certificate: %v", err)
	}
	cfg := agentdiscovery.WinRMConfig{
		EndpointURL: os.Getenv("KK_WINRM_URL"), Username: os.Getenv("KK_WINRM_USER"),
		Password: os.Getenv("KK_WINRM_PASS"), RootCAs: roots,
	}
	host := strings.TrimPrefix(strings.TrimPrefix(cfg.EndpointURL, "https://"), "http://")
	if h, _, err := net.SplitHostPort(strings.SplitN(host, "/", 2)[0]); err == nil {
		host = h
	}

	t.Run("discovery_as_standard_user", func(t *testing.T) {
		res := agentdiscovery.NewAgentlessWinRMScanner(agentdiscovery.NewWSManShell(cfg, nil), host).Scan(ctx)
		t.Logf("certs=%d errors=%v iis_service=%q", len(res.Certs), res.Errors, res.IISService)
		for _, e := range res.Errors {
			// One legacy Windows root is rejected by crypto/x509; that is a
			// per-cert warning, not a discovery failure.
			if !strings.Contains(e, "unparseable cert") {
				t.Fatalf("discovery error: %s", e)
			}
		}
		if len(res.Certs) == 0 {
			t.Fatal("discovery returned no certificates")
		}
	})

	t.Run("red_check_unrelated_bundle_is_rejected", func(t *testing.T) {
		wrongPEM, _, _ := liveSelfSigned(t, "unrelated")
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(wrongPEM)
		c := cfg
		c.RootCAs = pool
		res := agentdiscovery.NewAgentlessWinRMScanner(agentdiscovery.NewWSManShell(c, nil), host).Scan(ctx)
		if len(res.Certs) != 0 || !strings.Contains(strings.Join(res.Errors, " "), "x509") {
			t.Fatalf("an unrelated bundle was NOT rejected — verification is not happening: %v", res.Errors)
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

	t.Run("exit_status_propagates", func(t *testing.T) {
		ex := agentinstall.NewWinRMExecutor(agentdiscovery.NewWSManShell(cfg, nil))
		if _, err := ex.Run(ctx, "cmd", "/c", "exit", "7"); err == nil || !strings.Contains(err.Error(), "exit status 7") {
			t.Fatalf("remote exit 7 must be an error naming the status, got: %v", err)
		}
	})

	admin := os.Getenv("KK_LIVE_WINRM_ADMIN") == "1"

	t.Run("preflight_matches_privilege", func(t *testing.T) {
		got := agentdiscovery.PreflightWinRM(ctx, cfg, nil)
		t.Logf("%+v", got)
		if admin && (got.Level != agentdiscovery.PreflightInstall || !got.CanInstall) {
			t.Fatalf("an Administrator must preflight as install-capable: %+v", got)
		}
		if !admin && (got.Level != agentdiscovery.PreflightDiscover || !got.CanDiscover || got.CanInstall) {
			t.Fatalf("a standard Remote Management User must preflight as discover-only: %+v", got)
		}
		c := cfg
		c.Password = "definitely-wrong"
		if got := agentdiscovery.PreflightWinRM(ctx, c, nil); got.Level != agentdiscovery.PreflightUnauthenticated {
			t.Fatalf("wrong password must preflight as unauthenticated: %+v", got)
		}
	})

	t.Run("install_matches_privilege", func(t *testing.T) {
		ex := agentinstall.NewWinRMExecutor(agentdiscovery.NewWSManShell(cfg, nil))
		certPEM, keyPEM, der := liveSelfSigned(t, "kk-live-winrm", host)
		req := agentinstall.IISInstallRequest{IPPort: envOr("KK_LIVE_IIS_IPPORT", "0.0.0.0:443"), StoreName: "My", CertPEM: certPEM, KeyPEM: keyPEM}
		if !admin {
			res, err := agentinstall.NewIISInstaller(ex).Install(ctx, req)
			t.Logf("result=%+v err=%v", res, err)
			if res.Installed || err == nil {
				t.Fatalf("a standard user must never be reported as having installed: %+v", res)
			}
			if !strings.Contains(err.Error(), "not a local Administrator") {
				t.Fatalf("expected the privilege hint, got: %v", err)
			}
			return
		}

		// Administrator: a real install, verified, then the host restored.
		priorHash, priorAppID := os.Getenv("KK_LIVE_IIS_PRIOR_HASH"), os.Getenv("KK_LIVE_IIS_APPID")
		if priorHash == "" || priorAppID == "" {
			t.Skip("admin mode needs KK_LIVE_IIS_PRIOR_HASH and KK_LIVE_IIS_APPID to restore the binding afterwards")
		}
		sha1sum := sha1.Sum(der) //nolint:gosec // store lookup key
		testThumb := hex.EncodeToString(sha1sum[:])
		t.Cleanup(func() {
			rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer rcancel()
			_, _ = ex.Run(rctx, "netsh", "http", "delete", "sslcert", "ipport="+req.IPPort)
			if _, err := ex.Run(rctx, "netsh", "http", "add", "sslcert", "ipport="+req.IPPort, "certhash="+priorHash, "appid="+priorAppID, "certstorename=My"); err != nil {
				t.Errorf("RESTORE FAILED, host left with the test binding: %v", err)
			}
			_, _ = ex.Run(rctx, "certutil", "-delstore", "My", testThumb)
		})
		sum := sha256.Sum256(der)
		fp := hex.EncodeToString(sum[:])
		req.VerifyHostPort = net.JoinHostPort(host, strings.TrimPrefix(req.IPPort, "0.0.0.0:"))
		req.ExpectedFingerprint = fp
		res, err := agentinstall.NewIISInstaller(ex).Install(ctx, req)
		t.Logf("result=%+v err=%v", res, err)
		if err != nil || !res.Verified || res.Outcome != agentinstall.OutcomeInstalledVerified {
			t.Fatalf("an Administrator's install must complete and verify: %+v %v", res, err)
		}
		// Independent proof: what the host serves, read by a plain TLS dial.
		conn, derr := tls.Dial("tcp", req.VerifyHostPort, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // probe only
		if derr != nil {
			t.Fatalf("dial %s: %v", req.VerifyHostPort, derr)
		}
		defer conn.Close()
		leaf := conn.ConnectionState().PeerCertificates[0]
		lsum := sha256.Sum256(leaf.Raw)
		if hex.EncodeToString(lsum[:]) != fp {
			t.Fatalf("IIS serves CN=%s, not the installed certificate", leaf.Subject.CommonName)
		}
	})
}
