// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"kryptkeeper/internal/keystore"
)

// recordingRenewProvider captures each renewal CSR and can fail chosen members
// without touching the real CA, so the old certificate is provably untouched.
type recordingRenewProvider struct {
	CertificateProvider
	mu     sync.Mutex
	failFP string
	csrs   []string
}

func (p *recordingRenewProvider) RenewCertificate(ctx context.Context, fp string, req CertificateRenewRequest) (CertificateIssueResult, error) {
	p.mu.Lock()
	p.csrs = append(p.csrs, req.CSRPEM)
	p.mu.Unlock()
	if fp == p.failFP {
		return CertificateIssueResult{}, errors.New("simulated CA outage")
	}
	return p.CertificateProvider.RenewCertificate(ctx, fp, req)
}

func rsaCSRPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// runP384Wave issues three RSA-2048 members, proposes and approves a P-384
// wave, and returns the decoded result plus the wrapper and member fingerprints.
func runP384Wave(t *testing.T, failIdx int) (*waveExecuteTestFixture, *recordingRenewProvider, []string, migrateWaveExecutionResult, *captureAudit) {
	t.Helper()
	fx := newWaveExecuteTestFixture(t)
	ctx := context.Background()
	fx.templates.templates["tpl-p384"] = TemplateItem{ID: "tpl-p384", Active: true, ValidityPeriod: "8760h", AllowedAlgorithms: []string{"ECDSA-P384"}}

	fx.templates.templates["tpl-rsa"] = TemplateItem{ID: "tpl-rsa", Active: true, ValidityPeriod: "8760h", AllowedAlgorithms: []string{"RSA-2048"}}

	caID := getFirstCAID(t, fx.engine)
	wave, err := fx.waveStore.CreateWave(ctx, MigrationWave{Name: "p384-wave"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	var fps []string
	for _, cn := range []string{"p384-a.example.com", "p384-b.example.com", "p384-c.example.com"} {
		issued, err := fx.certs.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-rsa", CSRPEM: rsaCSRPEM(t, cn), TeamID: "team-1"})
		if err != nil {
			t.Fatalf("issue %s: %v", cn, err)
		}
		if err := fx.waveStore.AddMember(ctx, wave.ID, MigrationWaveMember{Fingerprint: issued.FingerprintSHA256}); err != nil {
			t.Fatalf("add member: %v", err)
		}
		fps = append(fps, issued.FingerprintSHA256)
	}

	rec := &recordingRenewProvider{CertificateProvider: fx.certs}
	if failIdx >= 0 {
		rec.failFP = fps[failIdx]
	}
	audit := &captureAudit{}
	mux := http.NewServeMux()
	registerPQCWaveHandlers(mux, fx.auth, rec, fx.templates, fx.waveStore, fx.keys, audit)
	fx.mux = mux

	proposer := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	pr := httptest.NewRecorder()
	mux.ServeHTTP(pr, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute", proposer,
		migrateWaveExecutionParams{TemplateID: "tpl-p384", TargetAlgorithm: "ECDSA-P384"}))
	if pr.Code != http.StatusCreated {
		t.Fatalf("propose: %d %s", pr.Code, pr.Body.String())
	}
	var pa struct {
		Data PendingAction `json:"data"`
	}
	if err := json.Unmarshal(pr.Body.Bytes(), &pa); err != nil {
		t.Fatalf("decode: %v", err)
	}

	approver := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	ar := httptest.NewRecorder()
	mux.ServeHTTP(ar, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute/"+pa.Data.ID+"/approve", approver, nil))
	if ar.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", ar.Code, ar.Body.String())
	}
	var resp struct {
		Data migrateWaveExecutionResult `json:"data"`
	}
	if err := json.Unmarshal(ar.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return fx, rec, fps, resp.Data, audit
}

func TestWaveExecuteReissuesAsP384(t *testing.T) {
	fx, rec, fps, res, audit := runP384Wave(t, -1)
	if res.Migrated != 3 || res.Failed != 0 {
		t.Fatalf("migrated=%d failed=%d, want 3/0", res.Migrated, res.Failed)
	}
	if len(rec.csrs) != 3 {
		t.Fatalf("captured %d CSRs, want 3", len(rec.csrs))
	}
	for _, p := range rec.csrs {
		block, _ := pem.Decode([]byte(p))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse CSR: %v", err)
		}
		if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P384() {
			t.Fatalf("CSR key = %T, want P-384", csr.PublicKey)
		}
	}
	for _, fp := range fps {
		d, _, _ := fx.certs.GetCertificate(context.Background(), fp)
		if d.SuccessorFP == nil {
			t.Errorf("member %s has no successor", fp)
		}
	}
	seen := map[string]bool{}
	for _, e := range audit.entries {
		if e.Outcome == AuditOutcomeSuccess {
			seen[e.Action] = true
		}
	}
	if !seen["pqc.wave_execute_propose"] || !seen["pqc.wave_execute_approve"] {
		t.Errorf("PQC wave audit actions not reused: %v", seen)
	}
}

func TestWaveExecuteFailedMemberKeepsOldSerial(t *testing.T) {
	fx, _, fps, res, _ := runP384Wave(t, 1)
	if res.Migrated != 2 || res.Failed != 1 {
		t.Fatalf("migrated=%d failed=%d, want 2/1", res.Migrated, res.Failed)
	}
	var failed *migrateWaveMemberResult
	for i := range res.Results {
		if res.Results[i].Fingerprint == fps[1] {
			failed = &res.Results[i]
		}
	}
	if failed == nil || failed.Status != "failed" || failed.Error == "" {
		t.Fatalf("failed member result = %+v", failed)
	}
	d, ok, err := fx.certs.GetCertificate(context.Background(), fps[1])
	if err != nil || !ok {
		t.Fatalf("get failed member: ok=%v err=%v", ok, err)
	}
	if d.SuccessorFP != nil {
		t.Errorf("failed member gained successor %s", *d.SuccessorFP)
	}
	if d.PQCReadiness != "vulnerable" {
		t.Errorf("failed member readiness = %q, want vulnerable", d.PQCReadiness)
	}
	tok := waveExecuteToken(t, fx.auth, "reader", "pki-admin")
	for _, w := range listWavesForTest(t, fx.mux, tok) {
		if w.Status == "done" {
			t.Errorf("wave with a failed member must not be done: %+v", w)
		}
	}
}

func TestResolveWaveTargetAlgorithm(t *testing.T) {
	pqcTpl := TemplateItem{AllowedAlgorithms: []string{"ECDSA", "ML-DSA-65"}}
	if a, ok := resolveWaveTargetAlgorithm(pqcTpl, ""); !ok || a != keystore.MLDSA65 {
		t.Errorf("empty request = %v,%v, want ML-DSA-65", a, ok)
	}
	if _, ok := resolveWaveTargetAlgorithm(pqcTpl, "ECDSA-P384"); ok {
		t.Error("P-384 absent from template must not resolve")
	}
	if _, ok := resolveWaveTargetAlgorithm(TemplateItem{AllowedAlgorithms: []string{"ECDSA"}}, "ECDSA"); ok {
		t.Error("loose ECDSA must not satisfy a target")
	}
	if _, ok := resolveWaveTargetAlgorithm(TemplateItem{AllowedAlgorithms: []string{"RSA-2048"}}, "RSA-2048"); ok {
		t.Error("RSA-2048 is not a transition target")
	}
	if _, ok := resolveWaveTargetAlgorithm(TemplateItem{AllowedAlgorithms: []string{"ECDSA-P384"}}, "ECDSA-P384"); !ok {
		t.Error("allowed P-384 must resolve")
	}
	if _, ok := resolveWaveTargetAlgorithm(TemplateItem{AllowedAlgorithms: []string{"ECDSA"}}, ""); ok {
		t.Error("classical template without request stays refused")
	}
}

func TestProposeInvalidTargetAlgorithmAudited(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	wave, _ := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "w"})
	audit := &captureAudit{}
	mux := http.NewServeMux()
	registerPQCWaveHandlers(mux, fx.auth, fx.certs, fx.templates, fx.waveStore, fx.keys, audit)
	tok := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute", tok,
		migrateWaveExecutionParams{TemplateID: "tpl-pqc", TargetAlgorithm: "DES-3"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	found := false
	for _, e := range audit.entries {
		if e.Action == "pqc.wave_execute_propose" && e.Outcome == AuditOutcomeFailure {
			found = true
		}
	}
	if !found {
		t.Error("invalid target_algorithm not audited as failure")
	}
}
