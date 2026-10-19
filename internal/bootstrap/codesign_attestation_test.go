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
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kryptkeeper/internal/attestation"
	"kryptkeeper/internal/ca"
)

// attFixture is an in-test attestation chain (root -> f9 -> leaf over the
// device key). No real keys, no files.
type attFixture struct {
	verifier *attestation.Verifier
	leafPEM  string
	interPEM string
	dev      *ecdsa.PrivateKey
}

func attPEM(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func attOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func attKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attOK(t, err)
	return k
}

func attCert(t *testing.T, tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	attOK(t, err)
	c, err := x509.ParseCertificate(der)
	attOK(t, err)
	return c, der
}

func newAttFixture(t *testing.T) *attFixture {
	t.Helper()
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	rk := attKey(t)
	rtpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, _ := attCert(t, rtpl, rtpl, &rk.PublicKey, rk)
	ik := attKey(t)
	inter, iDER := attCert(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test F9"}, NotBefore: nb, NotAfter: na},
		root, &ik.PublicKey, rk)
	dev := attKey(t)
	serial, err := asn1.Marshal(big.NewInt(4242))
	attOK(t, err)
	ltpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Test Attest"}, NotBefore: nb, NotAfter: na,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}, Value: []byte{5, 4, 3}},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}, Value: serial},
		}}
	_, lDER := attCert(t, ltpl, inter, &dev.PublicKey, ik)
	return &attFixture{verifier: &attestation.Verifier{Roots: []*x509.Certificate{root}},
		leafPEM: attPEM("CERTIFICATE", lDER), interPEM: attPEM("CERTIFICATE", iDER), dev: dev}
}

func attCSR(t *testing.T, k *ecdsa.PrivateKey) string {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "signer.example.com"}}, k)
	attOK(t, err)
	return attPEM("CERTIFICATE REQUEST", der)
}

func (f *attFixture) metadata() map[string]interface{} {
	return map[string]interface{}{"attestation": map[string]interface{}{
		"format": "yubikey-piv", "certificate_pem": f.leafPEM, "intermediates_pem": []interface{}{f.interPEM}}}
}

var attCSTemplate = TemplateItem{ID: "tpl-cs", Active: true, ExtendedKeyUsage: []string{"codeSigning"}}

// setupAttestation wires the singleton against a sqlite approval store and
// the fixture verifier; protected toggles KRYPTKEEPER_CODESIGN_PROTECTED.
func setupAttestation(t *testing.T, protected bool, f *attFixture) *scepRecordingAudit {
	t.Helper()
	if protected {
		t.Setenv(codesignProtectedEnv, "true")
	} else {
		t.Setenv(codesignProtectedEnv, "")
	}
	audit := &scepRecordingAudit{}
	initCodesignAttestation(newTestApprovalStore(t), audit)
	codesignVerifier = f.verifier
	t.Cleanup(func() {
		codesignAttestStorePtr.Store(nil)
		codesignAuditPtr.Store(nil)
		codesignVerifier = nil
	})
	return audit
}

func attRowCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := codesignAttestStorePtr.Load().db.QueryRow(`SELECT COUNT(*) FROM codesign_attestations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func auditHas(a *scepRecordingAudit, action string, outcome AuditOutcome) bool {
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			return true
		}
	}
	return false
}

func TestPreIssueCheckNoopOutsideProtectedMode(t *testing.T) {
	f := newAttFixture(t)
	setupAttestation(t, false, f)
	req := CertificateIssueRequest{CSRPEM: attCSR(t, attKey(t))}
	if err := codesignPreIssueCheck(context.Background(), attCSTemplate, req); err != nil {
		t.Fatalf("unprotected mode must not check: %v", err)
	}
}

func TestPreIssueCheckNoopForNonCodeSigningTemplate(t *testing.T) {
	f := newAttFixture(t)
	setupAttestation(t, true, f)
	web := TemplateItem{ID: "tpl-web", Active: true, ExtendedKeyUsage: []string{"serverAuth"}}
	if err := codesignPreIssueCheck(context.Background(), web, CertificateIssueRequest{CSRPEM: attCSR(t, attKey(t))}); err != nil {
		t.Fatalf("non code-signing template must not check: %v", err)
	}
}

func TestPreIssueCheckNoopForHubHeldKey(t *testing.T) {
	f := newAttFixture(t)
	setupAttestation(t, true, f)
	ctx := context.WithValue(context.Background(), codesignHubKeyKey{}, true)
	if err := codesignPreIssueCheck(ctx, attCSTemplate, CertificateIssueRequest{CSRPEM: attCSR(t, attKey(t))}); err != nil {
		t.Fatalf("hub-held key must not need attestation: %v", err)
	}
}

func TestProtectedModeRefusesMissingAttestation(t *testing.T) {
	f := newAttFixture(t)
	audit := setupAttestation(t, true, f)
	err := codesignPreIssueCheck(context.Background(), attCSTemplate, CertificateIssueRequest{CSRPEM: attCSR(t, f.dev)})
	if !errors.Is(err, ca.ErrPolicyViolation) {
		t.Fatalf("want ErrPolicyViolation, got %v", err)
	}
	if !auditHas(audit, auditCodesignDeny, AuditOutcomeDenied) {
		t.Fatalf("missing deny audit: %+v", audit.entries)
	}
	if n := attRowCount(t); n != 0 {
		t.Fatalf("rows = %d, want 0", n)
	}
}

func TestProtectedModeRefusesMalformedMetadata(t *testing.T) {
	f := newAttFixture(t)
	setupAttestation(t, true, f)
	csr := attCSR(t, f.dev)
	for name, md := range map[string]map[string]interface{}{
		"not a map":      {"attestation": "yes"},
		"bad format":     {"attestation": map[string]interface{}{"format": "tpm2", "certificate_pem": "x"}},
		"cert not str":   {"attestation": map[string]interface{}{"format": "yubikey-piv", "certificate_pem": 7}},
		"inter not list": {"attestation": map[string]interface{}{"format": "yubikey-piv", "certificate_pem": f.leafPEM, "intermediates_pem": "x"}},
		"inter elem":     {"attestation": map[string]interface{}{"format": "yubikey-piv", "certificate_pem": f.leafPEM, "intermediates_pem": []interface{}{3}}},
	} {
		err := codesignPreIssueCheck(context.Background(), attCSTemplate, CertificateIssueRequest{CSRPEM: csr, Metadata: md})
		if !errors.Is(err, ca.ErrPolicyViolation) {
			t.Errorf("%s: want ErrPolicyViolation, got %v", name, err)
		}
	}
	if n := attRowCount(t); n != 0 {
		t.Fatalf("rows = %d, want 0", n)
	}
}

func TestProtectedModeStoresValidAttestation(t *testing.T) {
	f := newAttFixture(t)
	audit := setupAttestation(t, true, f)
	csr := attCSR(t, f.dev)
	if err := codesignPreIssueCheck(context.Background(), attCSTemplate, CertificateIssueRequest{CSRPEM: csr, Metadata: f.metadata()}); err != nil {
		t.Fatalf("valid attestation refused: %v", err)
	}
	if n := attRowCount(t); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	got, ok, err := LookupCodesignAttestation(context.Background(), csr)
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	if got.Serial != "4242" || got.Firmware != "5.4.3" || got.Format != "yubikey-piv" || got.TemplateID != "tpl-cs" ||
		len(got.IntermediatesPEM) != 1 || got.KeySPKISHA256 == "" || got.VendorRootSHA256 == "" {
		t.Fatalf("stored = %+v", got)
	}
	if !auditHas(audit, auditCodesignAttestVerify, AuditOutcomeSuccess) {
		t.Fatalf("missing verify audit: %+v", audit.entries)
	}
	// Idempotent re-submission upserts.
	if err := codesignPreIssueCheck(context.Background(), attCSTemplate, CertificateIssueRequest{CSRPEM: csr, Metadata: f.metadata()}); err != nil {
		t.Fatal(err)
	}
	if n := attRowCount(t); n != 1 {
		t.Fatalf("rows after re-submit = %d, want 1", n)
	}
}

func TestProtectedModeRefusesMismatchedKey(t *testing.T) {
	f := newAttFixture(t)
	audit := setupAttestation(t, true, f)
	err := codesignPreIssueCheck(context.Background(), attCSTemplate,
		CertificateIssueRequest{CSRPEM: attCSR(t, attKey(t)), Metadata: f.metadata()})
	if !errors.Is(err, ca.ErrPolicyViolation) {
		t.Fatalf("want ErrPolicyViolation, got %v", err)
	}
	found := false
	for _, e := range audit.entries {
		if e.Action == auditCodesignDeny && bytes.Contains([]byte(e.ChangeSummary), []byte("key_mismatch")) {
			found = true
		}
	}
	if !found || attRowCount(t) != 0 {
		t.Fatalf("want key_mismatch deny audit and 0 rows; entries=%+v", audit.entries)
	}
}

func TestProtectedModeRefusesForgedRoot(t *testing.T) {
	f := newAttFixture(t)
	setupAttestation(t, true, f)
	codesignVerifier = newAttFixture(t).verifier // different trust anchor
	err := codesignPreIssueCheck(context.Background(), attCSTemplate, CertificateIssueRequest{CSRPEM: attCSR(t, f.dev), Metadata: f.metadata()})
	if !errors.Is(err, ca.ErrPolicyViolation) {
		t.Fatalf("want ErrPolicyViolation, got %v", err)
	}
}

func TestProtectedModeFailsClosedWithoutStore(t *testing.T) {
	f := newAttFixture(t)
	setupAttestation(t, true, f)
	codesignAttestStorePtr.Store(nil)
	err := codesignPreIssueCheck(context.Background(), attCSTemplate, CertificateIssueRequest{CSRPEM: attCSR(t, f.dev), Metadata: f.metadata()})
	if !errors.Is(err, ca.ErrPolicyViolation) {
		t.Fatalf("want ErrPolicyViolation, got %v", err)
	}
}

// attGateProvider runs the real pre-issue check ahead of the approval gate,
// as certificate_ca_provider.go does.
type attGateProvider struct {
	CertificateProvider
	tpl TemplateItem
}

func (p attGateProvider) IssueCertificate(ctx context.Context, req CertificateIssueRequest) (CertificateIssueResult, error) {
	if ctx.Value(approvalBypassKey{}) == nil {
		if err := codesignPreIssueCheck(ctx, p.tpl, req); err != nil {
			return CertificateIssueResult{}, err
		}
	}
	return CertificateIssueResult{}, errApprovalRequired
}

func TestPostCertificatesRefusesBadAttestationWith422(t *testing.T) {
	f := newAttFixture(t)
	h := newWriteGateHarness(t, nil)
	setupAttestation(t, true, f)
	approvals := newTestApprovalStore(t)
	mux := http.NewServeMux()
	registerCertificateHandlers(mux, h.auth, attGateProvider{tpl: attCSTemplate}, h.audit, approvals)
	_, tok, err := h.auth.CreateAPIKey("k-att", "p-att", "pki-admin", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	post := func(md map[string]interface{}, csr string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]interface{}{"ca_id": "ca-1", "template_id": "tpl-cs", "csr_pem": csr, "metadata": md})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	rec := post(nil, attCSR(t, f.dev))
	if rec.Code != http.StatusUnprocessableEntity || !bytes.Contains(rec.Body.Bytes(), []byte("policy_violation")) {
		t.Fatalf("missing attestation: %d %s", rec.Code, rec.Body.String())
	}
	rec = post(f.metadata(), attCSR(t, attKey(t)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched key: %d %s", rec.Code, rec.Body.String())
	}
	if _, total, _ := approvals.List(context.Background(), "", 10, 0); total != 0 {
		t.Fatalf("refused request was queued: %d", total)
	}
	rec = post(f.metadata(), attCSR(t, f.dev))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("valid attestation: %d %s", rec.Code, rec.Body.String())
	}
}
