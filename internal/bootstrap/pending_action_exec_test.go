// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

// W5-06: issue/renew/rotate execute ONLY as approved pending actions,
// and rotate's contract — a NEW key — is enforced.

type execFakeCertProvider struct {
	CertificateProvider
	issued      []CertificateIssueRequest
	renewed     []string
	downloadPEM []byte
}

func (f *execFakeCertProvider) IssueCertificate(_ context.Context, req CertificateIssueRequest) (CertificateIssueResult, error) {
	f.issued = append(f.issued, req)
	return CertificateIssueResult{CertificateItem: CertificateItem{FingerprintSHA256: "fp-new"}}, nil
}

func (f *execFakeCertProvider) RenewCertificate(_ context.Context, fp string, _ CertificateRenewRequest) (CertificateIssueResult, error) {
	f.renewed = append(f.renewed, fp)
	return CertificateIssueResult{CertificateItem: CertificateItem{FingerprintSHA256: "fp-successor"}}, nil
}

func (f *execFakeCertProvider) DownloadCertificate(_ context.Context, _ string, _ string, _ bool) (CertificateDownloadResult, error) {
	return CertificateDownloadResult{Body: f.downloadPEM}, nil
}

// selfSignedPair returns a cert PEM and a CSR PEM sharing (or not) a key.
func selfSignedPair(t *testing.T, reuseKey bool) (certPEM, csrPEM string) {
	t.Helper()
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rotate.example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	csrKey := certKey
	if !reuseKey {
		csrKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("csr key: %v", err)
		}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rotate.example.com"},
	}, csrKey)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return certPEM, csrPEM
}

func TestExecIssueRenewRotateThroughApprovalOnly(t *testing.T) {
	f := &execFakeCertProvider{}
	ctx := context.Background()

	// issue
	res, err := executePendingAction(ctx, f, PendingAction{
		ActionType: "issue",
		Params:     json.RawMessage(`{"ca_id":"ca-1","template_id":"tpl-1","csr_pem":"PEM","team_id":"team-a"}`),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(f.issued) != 1 || f.issued[0].CAID != "ca-1" || f.issued[0].TeamID != "team-a" {
		t.Fatalf("issue params not threaded: %+v", f.issued)
	}
	if !strings.Contains(string(res), "fp-new") {
		t.Fatalf("issue result must carry the fingerprint: %s", res)
	}

	// renew (key reuse permitted — no predecessor check)
	if _, err := executePendingAction(ctx, f, PendingAction{
		ActionType: "renew",
		Params:     json.RawMessage(`{"fingerprint":"fp-old","csr_pem":"PEM"}`),
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if len(f.renewed) != 1 || f.renewed[0] != "fp-old" {
		t.Fatalf("renew not executed: %v", f.renewed)
	}

	// All four mutation types are valid, proposable action types.
	for _, at := range []string{"issue", "renew", "revoke", "rotate", "bulk_revoke"} {
		if !validActionType(at) {
			t.Errorf("%s must be a valid action type", at)
		}
	}
	if validActionType("nuke") {
		t.Error("unknown types must stay invalid")
	}
}

func TestExecRotateRequiresNewKey(t *testing.T) {
	ctx := context.Background()

	// Same key: refused, nothing renewed.
	certPEM, sameKeyCSR := selfSignedPair(t, true)
	f := &execFakeCertProvider{downloadPEM: []byte(certPEM)}
	params, _ := json.Marshal(map[string]string{"fingerprint": "fp-1", "csr_pem": sameKeyCSR})
	_, err := executePendingAction(ctx, f, PendingAction{ActionType: "rotate", Params: params})
	if err == nil || !strings.Contains(err.Error(), "NEW key") {
		t.Fatalf("same-key rotation must be refused with the reason, got %v", err)
	}
	if len(f.renewed) != 0 {
		t.Fatal("a refused rotation must renew nothing")
	}

	// New key: proceeds through the renewal path.
	certPEM2, newKeyCSR := selfSignedPair(t, false)
	f2 := &execFakeCertProvider{downloadPEM: []byte(certPEM2)}
	params2, _ := json.Marshal(map[string]string{"fingerprint": "fp-2", "csr_pem": newKeyCSR})
	res, err := executePendingAction(ctx, f2, PendingAction{ActionType: "rotate", Params: params2})
	if err != nil {
		t.Fatalf("new-key rotation: %v", err)
	}
	if len(f2.renewed) != 1 || !strings.Contains(string(res), "rotated") {
		t.Fatalf("rotation must execute the renewal: %v %s", f2.renewed, res)
	}
}
