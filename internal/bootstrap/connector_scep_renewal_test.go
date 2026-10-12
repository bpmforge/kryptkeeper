// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"crypto/rsa"
	"testing"

	"kryptkeeper/internal/connectors"
)

// recordingSCEPConnector captures the IssueRequest it receives so the test
// can inspect what the renewal executor actually wired onto it, instead of
// speaking real SCEP wire format (internal/connectors/scep_client_test.go
// already proves that against internal/scep.Server).
type recordingSCEPConnector struct {
	id       string
	pem      string
	lastReq  connectors.IssueRequest
	received bool
}

func (r *recordingSCEPConnector) ID() string     { return r.id }
func (r *recordingSCEPConnector) Type() string   { return "scep" }
func (r *recordingSCEPConnector) Origin() string { return "synced" }
func (r *recordingSCEPConnector) Health(context.Context) connectors.Health {
	return connectors.Health{Status: "healthy"}
}
func (r *recordingSCEPConnector) Issue(_ context.Context, req connectors.IssueRequest) (connectors.IssueResult, error) {
	r.lastReq = req
	r.received = true
	return connectors.IssueResult{FingerprintSHA256: "fp-scep-upstream", CertificatePEM: r.pem}, nil
}

// TestRenewalExecutorPassesSignerToSCEPConnector proves the W19-28 wiring:
// a certificate whose renewal_connector_id resolves to a "scep"-typed
// connector gets an RSA key (classic SCEP's PKCS#7 key-transport has no EC
// analogue) with that SAME key object handed through as
// IssueRequest.Signer/Decrypter -- never re-derived, never serialized
// anywhere but keyPEM.
func TestRenewalExecutorPassesSignerToSCEPConnector(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "scep-renew.example.com", "scep-renew.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-scep",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256
	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{
		ManagementState: "managed", RenewalMethod: "scep", RenewalConnectorID: "conn-fake-scep",
	}); err != nil {
		t.Fatalf("estate update: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	upstreamPEM := estateTestCertPEM(t)
	conn := &recordingSCEPConnector{id: "conn-fake-scep", pem: upstreamPEM}
	registry := connectors.NewRegistry()
	registry.Register(conn)
	exec.WithConnectorRegistry(registry)
	exec.verifier = func(_ context.Context, _ string) (string, error) {
		return leafFingerprint(fake.files["/etc/nginx/tls/renewed.crt"])
	}

	result, err := exec.ExecuteRenewal(ctx, fp, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !result.Renewed || result.NewFingerprint != "fp-scep-upstream" {
		t.Fatalf("scep upstream path not taken: %+v", result)
	}
	if !conn.received {
		t.Fatal("scep connector never received an IssueRequest")
	}
	if conn.lastReq.Signer == nil {
		t.Fatal("IssueRequest.Signer not set for a scep-typed connector")
	}
	if conn.lastReq.Decrypter == nil {
		t.Fatal("IssueRequest.Decrypter not set for a scep-typed connector")
	}
	if conn.lastReq.Signer != crypto.Signer(conn.lastReq.Decrypter.(crypto.Signer)) {
		t.Fatal("Signer and Decrypter must be the SAME key object, not independently derived ones")
	}
	if _, ok := conn.lastReq.Signer.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected an RSA key for a scep-typed connector, got %T", conn.lastReq.Signer)
	}
}
