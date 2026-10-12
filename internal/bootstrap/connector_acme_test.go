// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kkacme "kryptkeeper/internal/acme"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/keystore"
)

// W11-04: the ACME connector against the IN-REPO ACME server, in-process —
// order, http-01 solve, finalize, download, inventory landing. Zero live
// network (playbook rule): the server validates http-01 by GETting
// http://<identifier>/..., and identifiers must be DNS names on port 80, so
// the server's http-01 dial seam routes the test name to the connector's
// 127.0.0.1:<solver-port> listener. The seam replaces only the dial; the
// fetch, KeyAuthorization comparison and order state machine are real.

const acmeTestHost = "solver.example.test"

// newTestUpstreamACME starts an in-repo ACME server whose http-01 validation
// resolves acmeTestHost to solverAddr.
func newTestUpstreamACME(t *testing.T, solverAddr string) (baseURL string) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("Upstream ACME Root", pkix.Name{CommonName: "Upstream ACME Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root CA: %v", err)
	}
	ts := httptest.NewServer(nil)
	srv := kkacme.NewServerWithStore(ts.URL, engine, rootCA.ID, kkacme.NewMemStore(), ca.NewMemRevocationStore())
	srv.SetHTTP01DialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || host != acmeTestHost {
			return nil, fmt.Errorf("test dial seam: %q is not routed", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, solverAddr)
	})
	ts.Config.Handler = srv.Handler()
	t.Cleanup(ts.Close)
	return ts.URL
}

// freeLocalPort reserves then releases a port — the standard test trick; the
// tiny race is acceptable in-process.
func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func newACMETestConnector(t *testing.T, directoryURL string, solverPort int, inventory CertificateProvider) connectors.IssuerConnector {
	t.Helper()
	cfg, _ := json.Marshal(acmeConnectorConfig{
		DirectoryURL: directoryURL + "/acme/directory",
		Email:        "ops@example.com",
		HTTP01Listen: fmt.Sprintf("127.0.0.1:%d", solverPort),
	})
	conn := NewACMEIssuerConnector(ConnectorRecord{
		ID: "conn-acme-test", Name: "Upstream Test CA", Type: "acme",
		ConfigJSON: string(cfg),
	}, inventory, nil)
	conn.(*acmeIssuerConnector).allowLoopbackForTest = true // upstream is http on loopback
	return conn
}

func TestACMEConnectorIssuesEndToEnd(t *testing.T) {
	solverPort := freeLocalPort(t)
	upstream := newTestUpstreamACME(t, fmt.Sprintf("127.0.0.1:%d", solverPort))
	db := setupIntegrationDB(t)
	inventory, _ := newIntegrationCAProvider(t, db)
	identifier := acmeTestHost

	conn := newACMETestConnector(t, upstream, solverPort, inventory)
	if h := conn.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("upstream directory should probe healthy: %+v", h)
	}

	res, err := conn.Issue(context.Background(), connectors.IssueRequest{
		CSRPEM: generateTestCSRPEM(t, identifier),
		TeamID: "team-acme",
	})
	if err != nil {
		t.Fatalf("acme issue: %v", err)
	}
	if !strings.Contains(res.CertificatePEM, "BEGIN CERTIFICATE") || res.FingerprintSHA256 == "" {
		t.Fatalf("incomplete issue result: fp=%q pemlen=%d", res.FingerprintSHA256, len(res.CertificatePEM))
	}

	// The upstream-issued leaf is OUR inventory now: synced, managed, and
	// wired to renew through this connector.
	item, ok, err := inventory.GetCertificate(context.Background(), res.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("upstream cert not in inventory: ok=%v err=%v", ok, err)
	}
	if item.Origin != "synced" || item.ManagementState != "managed" ||
		item.RenewalMethod != "acme" || item.RenewalConnectorID != "conn-acme-test" {
		t.Fatalf("estate stamp wrong: origin=%q state=%q method=%q conn=%q",
			item.Origin, item.ManagementState, item.RenewalMethod, item.RenewalConnectorID)
	}
	if item.IssuerCN != "Upstream ACME Root CA" {
		t.Fatalf("leaf not issued by the upstream CA: issuer=%q", item.IssuerCN)
	}
}

// A failed challenge surfaces the CA's problem, never a silent zero result:
// the identifier points at a port nobody serves.
func TestACMEConnectorSurfacesChallengeFailure(t *testing.T) {
	solverPort := freeLocalPort(t)
	deadPort := freeLocalPort(t) // nothing listens here
	// The identifier routes to the dead port, not the connector's solver.
	upstream := newTestUpstreamACME(t, fmt.Sprintf("127.0.0.1:%d", deadPort))

	conn := newACMETestConnector(t, upstream, solverPort, nil)
	_, err := conn.Issue(context.Background(), connectors.IssueRequest{
		CSRPEM: generateTestCSRPEM(t, acmeTestHost),
	})
	if err == nil {
		t.Fatal("expected challenge validation to fail for an unreachable identifier")
	}
	if !strings.Contains(err.Error(), "challenge validation") {
		t.Fatalf("failure should name the phase, got: %v", err)
	}
}

// The renewal executor routes certificates carrying a renewal_connector_id
// THROUGH the registry — the upstream half of acceptance #2. A fake
// connector keeps this test fast; the real ACME path is covered above.
func TestRenewalExecutorRoutesUpstreamConnector(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-upstream",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256
	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{
		ManagementState: "managed", RenewalMethod: "acme", RenewalConnectorID: "conn-fake-up",
	}); err != nil {
		t.Fatalf("estate update: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	upstreamPEM := estateTestCertPEM(t)
	registry := connectors.NewRegistry()
	registry.Register(recordingConnector{id: "conn-fake-up", pem: upstreamPEM})
	exec.WithConnectorRegistry(registry)
	// The fake upstream chain differs from the internal CA's; verify against
	// what the installer wrote (same closure shape as the engine tests).
	exec.verifier = func(_ context.Context, _ string) (string, error) {
		return leafFingerprint(fake.files["/etc/nginx/tls/renewed.crt"])
	}

	result, err := exec.ExecuteRenewal(ctx, fp, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !result.Renewed || result.NewFingerprint != "fp-upstream" {
		t.Fatalf("upstream path not taken: %+v", result)
	}
	// The installed bytes are the CONNECTOR's chain, not an internal
	// re-issue — the routing proof.
	installedFP, err := leafFingerprint(fake.files["/etc/nginx/tls/renewed.crt"])
	if err != nil {
		t.Fatalf("installed leaf: %v", err)
	}
	wantFP, err := leafFingerprint([]byte(upstreamPEM))
	if err != nil {
		t.Fatalf("want leaf: %v", err)
	}
	if installedFP != wantFP {
		t.Fatalf("installed %s, want the upstream connector's %s", installedFP, wantFP)
	}
}

type recordingConnector struct {
	id  string
	pem string
}

func (r recordingConnector) ID() string     { return r.id }
func (r recordingConnector) Type() string   { return "acme" }
func (r recordingConnector) Origin() string { return "synced" }
func (r recordingConnector) Health(context.Context) connectors.Health {
	return connectors.Health{Status: "healthy"}
}
func (r recordingConnector) Issue(context.Context, connectors.IssueRequest) (connectors.IssueResult, error) {
	return connectors.IssueResult{FingerprintSHA256: "fp-upstream", CertificatePEM: r.pem}, nil
}
