// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
)

// stubUpstream signs whatever CSR it receives with an intermediate under a
// root the operator trusts, and sends leaf + intermediate.
type stubUpstream struct {
	root, inter *x509.Certificate
	interKey    *ecdsa.PrivateKey
}

func newStubUpstream(t *testing.T) *stubUpstream {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Stub Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * 365 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rd, _ := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	root, _ := x509.ParseCertificate(rd)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Stub Issuing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * 365 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	id, _ := x509.CreateCertificate(rand.Reader, it, root, &ik.PublicKey, rk)
	inter, _ := x509.ParseCertificate(id)
	return &stubUpstream{root: root, inter: inter, interKey: ik}
}

func (u *stubUpstream) IssueExternal(_ context.Context, _, _, csrPEM, _ string) (string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		DNSNames: csr.DNSNames, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, u.inter, csr.PublicKey, u.interKey)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: u.inter.Raw})
	return out.String(), nil
}

func TestCAProviderRecordsExternalIssuanceAsSyncedWithConnector(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	up := newStubUpstream(t)
	engine.SetExternalIssuer(up)
	ext, err := engine.CreateExternalCA("Customer CA", "conn-vault", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.root.Raw}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: ext.ID, CSRPEM: generateTestCSRPEM(t, "svc.example.com", "svc.example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Origin != "synced" || res.RenewalConnectorID != "conn-vault" || res.CAID != ext.ID {
		t.Fatalf("external issuance recorded as origin=%q connector=%q ca=%q", res.Origin, res.RenewalConnectorID, res.CAID)
	}
	if res.IssuerCN != "Stub Issuing" {
		t.Fatalf("issuer %q", res.IssuerCN)
	}
	p := provider.(*caCertificateProvider)
	p.mu.Lock()
	stored := p.certs[res.FingerprintSHA256]
	p.mu.Unlock()
	if stored == nil || !bytes.Contains(stored.certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.inter.Raw})) {
		t.Fatal("stored PEM must carry the verified intermediate, not just the leaf")
	}
}

func TestCAProviderLeavesHubIssuanceInternal(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	cas, _ := engine.ListCAs()
	res, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: cas[0].ID, CSRPEM: generateTestCSRPEM(t, "a.example.com", "a.example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Origin != "internal" || res.RenewalConnectorID != "" {
		t.Fatalf("hub issuance must stay internal: %q %q", res.Origin, res.RenewalConnectorID)
	}
	_ = ca.CATypeExternal
}

type fakeRevoker struct {
	supports bool
	err      error
	calls    []connectors.RevokeRequest
}

func (f *fakeRevoker) SupportsRevoke(context.Context, string) bool { return f.supports }
func (f *fakeRevoker) RevokeUpstream(_ context.Context, _ string, req connectors.RevokeRequest) error {
	f.calls = append(f.calls, req)
	return f.err
}

func issueExternal(t *testing.T) (*caCertificateProvider, *ca.Engine, CertificateIssueResult) {
	t.Helper()
	provider, engine := newTestCAProvider(t)
	up := newStubUpstream(t)
	engine.SetExternalIssuer(up)
	ext, err := engine.CreateExternalCA("Customer CA", "conn-vault", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.root.Raw}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: ext.ID, CSRPEM: generateTestCSRPEM(t, "svc.example.com", "svc.example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider.(*caCertificateProvider), engine, res
}

func TestRevokeExternalCertificateGoesUpstreamFirst(t *testing.T) {
	p, _, res := issueExternal(t)
	rv := &fakeRevoker{supports: true}
	p.SetUpstreamRevoker(rv)
	out, err := p.RevokeCertificate(context.Background(), res.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 1})
	if err != nil {
		t.Fatal(err)
	}
	if out.RevocationScope != RevocationScopeUpstream || len(rv.calls) != 1 {
		t.Fatalf("scope=%s calls=%d", out.RevocationScope, len(rv.calls))
	}
	if rv.calls[0].Reason != 1 || rv.calls[0].SerialHex == "" || rv.calls[0].CertificatePEM == "" {
		t.Fatalf("upstream request incomplete: %+v", rv.calls[0])
	}
}

func TestRevokeExternalCertificateFailsLoudWhenUpstreamRefuses(t *testing.T) {
	p, _, res := issueExternal(t)
	p.SetUpstreamRevoker(&fakeRevoker{supports: true, err: errors.New("CA unreachable")})
	_, err := p.RevokeCertificate(context.Background(), res.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 1})
	var upErr *UpstreamRevokeError
	if !errors.As(err, &upErr) || upErr.ConnectorID != "conn-vault" {
		t.Fatalf("want UpstreamRevokeError, got %v", err)
	}
	d, _, _ := p.GetCertificate(context.Background(), res.FingerprintSHA256)
	if d.RevokedAt != nil {
		t.Fatal("a refused upstream revocation must leave the certificate unrevoked")
	}
}

func TestRevokeExternalCertificateWithoutRevokeSupport(t *testing.T) {
	p, _, res := issueExternal(t)
	p.SetUpstreamRevoker(&fakeRevoker{supports: false})
	if _, err := p.RevokeCertificate(context.Background(), res.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 4}); !errors.Is(err, ErrUpstreamRevokeUnsupported) {
		t.Fatalf("want ErrUpstreamRevokeUnsupported, got %v", err)
	}
	out, err := p.RevokeCertificate(context.Background(), res.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 4, Scope: RevocationScopeInventoryOnly})
	if err != nil || out.RevocationScope != RevocationScopeInventoryOnly {
		t.Fatalf("explicit inventory_only: %v %+v", err, out)
	}
}

func TestRevokeHubCertificateRefusesInventoryOnlyAndNeverCallsUpstream(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	p := provider.(*caCertificateProvider)
	rv := &fakeRevoker{supports: true}
	p.SetUpstreamRevoker(rv)
	cas, _ := engine.ListCAs()
	res, err := p.IssueCertificate(context.Background(), CertificateIssueRequest{CAID: cas[0].ID, CSRPEM: generateTestCSRPEM(t, "a.example.com", "a.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.RevokeCertificate(context.Background(), res.FingerprintSHA256, CertificateRevokeRequest{Scope: RevocationScopeInventoryOnly}); !errors.Is(err, errCertificateInvalid) {
		t.Fatalf("hub cert inventory_only must be refused: %v", err)
	}
	if _, err := p.RevokeCertificate(context.Background(), res.FingerprintSHA256, CertificateRevokeRequest{Scope: "bogus"}); !errors.Is(err, errCertificateInvalid) {
		t.Fatalf("unknown scope must be refused: %v", err)
	}
	out, err := p.RevokeCertificate(context.Background(), res.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 1})
	if err != nil || out.RevocationScope != RevocationScopeCA || len(rv.calls) != 0 {
		t.Fatalf("hub cert: scope=%s err=%v upstream calls=%d", out.RevocationScope, err, len(rv.calls))
	}
}

func TestScrubUpstreamErrorMasksCredentials(t *testing.T) {
	got := scrubUpstreamError(`401: {"error":"bad token","api_key":"sk-live-123"} Authorization: Bearer eyJabc`)
	if strings.Contains(got, "sk-live-123") || strings.Contains(got, "eyJabc") {
		t.Fatalf("secret leaked: %s", got)
	}
}

func TestWriteExternalCAIssueErrorStatuses(t *testing.T) {
	cases := []struct {
		err  error
		code int
		want string
	}{
		{&ca.ExternalRejection{Reason: "extra SAN"}, 502, "upstream_response_rejected"},
		{fmt.Errorf("%w: %w", ca.ErrExternalCAUpstream, errors.New(`401 {"api_key":"sk-1"}`)), 502, "upstream_issue_failed"},
		{fmt.Errorf("%w: %w", ca.ErrExternalCAUpstream, &connectors.RateLimitError{Reason: "upstream_429", RetryAfter: 30 * time.Second}), 429, "upstream_rate_limited"},
		{ca.ErrExternalCAUnsupportedKey, 400, "bad_request"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		if !writeExternalCAIssueError(rec, tc.err) {
			t.Fatalf("%v not handled", tc.err)
		}
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.want) || strings.Contains(rec.Body.String(), "sk-1") {
			t.Fatalf("%v: %d %s", tc.err, rec.Code, rec.Body.String())
		}
	}
	if writeExternalCAIssueError(httptest.NewRecorder(), errors.New("other")) {
		t.Fatal("unrelated errors must fall through")
	}
}
