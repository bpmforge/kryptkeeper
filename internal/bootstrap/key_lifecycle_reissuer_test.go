// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W23-39: production CertReissuer and the compromise report buckets.

// reissueProvider serves certificate details, a listing, revocation and the
// estate flag the compromise flow needs.
type reissueProvider struct {
	CertificateProvider
	mu       sync.Mutex
	details  map[string]CertificateDetail
	order    []string
	revoked  map[string]bool
	statuses map[string]string
}

func newReissueProvider(details ...CertificateDetail) *reissueProvider {
	p := &reissueProvider{details: map[string]CertificateDetail{}, revoked: map[string]bool{}, statuses: map[string]string{}}
	for _, d := range details {
		p.details[d.FingerprintSHA256] = d
		p.order = append(p.order, d.FingerprintSHA256)
	}
	return p
}

func (p *reissueProvider) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	d, ok := p.details[fp]
	return d, ok, nil
}

func (p *reissueProvider) ListCertificates(_ context.Context, q CertificateListQuery) (CertificateListResult, error) {
	var out []CertificateItem
	for _, fp := range p.order {
		if d := p.details[fp]; q.CAID == "" || d.CAID == q.CAID {
			out = append(out, d.CertificateItem)
		}
	}
	return CertificateListResult{Items: out, Total: len(out)}, nil
}

func (p *reissueProvider) RevokeCertificate(_ context.Context, fp string, _ CertificateRevokeRequest) (CertificateRevokeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked[fp] = true
	return CertificateRevokeResult{FingerprintSHA256: fp}, nil
}

func (p *reissueProvider) UpdateEstate(_ context.Context, fp string, u EstateUpdate) (CertificateItem, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statuses[fp] = u.RenewalStatus
	return CertificateItem{FingerprintSHA256: fp}, nil
}

type reissueTargets struct {
	ManagedTargetStore
	list []ManagedTarget
}

func (s reissueTargets) List(context.Context) ([]ManagedTarget, error) { return s.list, nil }

// stubRenewer is the renewalRunner seam: per-fingerprint canned outcomes.
type stubRenewer struct {
	results map[string]RenewalExecuteResult
	errs    map[string]error
	calls   []stubRenewCall
}

type stubRenewCall struct {
	fp      string
	target  ManagedTarget
	profile RenewalInstallProfile
}

func (r *stubRenewer) ExecuteRenewal(_ context.Context, fp string, target ManagedTarget, profile RenewalInstallProfile) (RenewalExecuteResult, error) {
	r.calls = append(r.calls, stubRenewCall{fp, target, profile})
	if err := r.errs[fp]; err != nil {
		return RenewalExecuteResult{PredecessorFingerprint: fp}, err
	}
	if res, ok := r.results[fp]; ok {
		return res, nil
	}
	return RenewalExecuteResult{PredecessorFingerprint: fp, Renewed: true, NewFingerprint: fp + "-new", InstallOutcome: "installed_verified", Verified: true}, nil
}

func certOn(fp, caID, host string) CertificateDetail {
	return CertificateDetail{
		CertificateItem: CertificateItem{FingerprintSHA256: fp, CAID: caID, CommonName: "cn-" + fp + ".invalid"},
		Endpoints:       []CertificateEndpoint{{Hostname: host}},
	}
}

func sshTarget(host string) ManagedTarget {
	return ManagedTarget{
		ID: "t-" + host, Name: host, Host: host, InstallMode: "ssh", CredentialRef: "cred-" + host,
		InstallServerType: "nginx", InstallCertPath: "/etc/ssl/c.pem", InstallKeyPath: "/etc/ssl/k.pem",
	}
}

func TestReissuerDefersWhenNoManagedTarget(t *testing.T) {
	certs := newReissueProvider(certOn("aaa", "ca-1", "orphan.example.com"))
	exec := &stubRenewer{}
	r := NewRenewalCertReissuer(certs, reissueTargets{list: []ManagedTarget{sshTarget("other.example.com")}}, exec)
	err := r.ReissueCertificate(context.Background(), "aaa")
	if !errors.Is(err, ErrReissueDeferred) {
		t.Fatalf("want ErrReissueDeferred, got %v", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("executor must not run without a target: %+v", exec.calls)
	}
}

func TestReissuerIgnoresTargetWithoutCredential(t *testing.T) {
	certs := newReissueProvider(certOn("aaa", "ca-1", "web.example.com"))
	tgt := sshTarget("web.example.com")
	tgt.CredentialRef = ""
	r := NewRenewalCertReissuer(certs, reissueTargets{list: []ManagedTarget{tgt}}, &stubRenewer{})
	if err := r.ReissueCertificate(context.Background(), "aaa"); !errors.Is(err, ErrReissueDeferred) {
		t.Fatalf("a target the hub cannot reach must defer, got %v", err)
	}
}

func TestReissuerUnknownCertificate(t *testing.T) {
	r := NewRenewalCertReissuer(newReissueProvider(), reissueTargets{}, &stubRenewer{})
	if err := r.ReissueCertificate(context.Background(), "nope"); !errors.Is(err, errCertificateNotFound) {
		t.Fatalf("want errCertificateNotFound, got %v", err)
	}
}

func TestReissuerCallsExecutorForMatchingTarget(t *testing.T) {
	certs := newReissueProvider(certOn("aaa", "ca-1", "web.example.com"))
	want := sshTarget("web.example.com")
	exec := &stubRenewer{}
	r := NewRenewalCertReissuer(certs, reissueTargets{list: []ManagedTarget{sshTarget("other.example.com"), want}}, exec)
	if err := r.ReissueCertificate(context.Background(), "aaa"); err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if len(exec.calls) != 1 || exec.calls[0].fp != "aaa" || exec.calls[0].target.ID != want.ID {
		t.Fatalf("executor called wrong: %+v", exec.calls)
	}
	if exec.calls[0].profile != profileFromTarget(want) {
		t.Fatalf("install profile must come from the target: %+v", exec.calls[0].profile)
	}
}

func TestReissuerReportsInstallFailure(t *testing.T) {
	certs := newReissueProvider(certOn("aaa", "ca-1", "web.example.com"))
	exec := &stubRenewer{results: map[string]RenewalExecuteResult{
		"aaa": {PredecessorFingerprint: "aaa", Renewed: true, NewFingerprint: "aaa-new", InstallOutcome: "reload_failed", InstallDetail: "nginx -t failed"},
	}}
	r := NewRenewalCertReissuer(certs, reissueTargets{list: []ManagedTarget{sshTarget("web.example.com")}}, exec)
	err := r.ReissueCertificate(context.Background(), "aaa")
	if err == nil || errors.Is(err, ErrReissueDeferred) {
		t.Fatalf("install failure must fail, not defer: %v", err)
	}
	for _, want := range []string{"renewed but install failed", "aaa-new", "reload_failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must mention %q (the successor exists)", err, want)
		}
	}
}

func TestReissuerAgentTargetDefers(t *testing.T) {
	certs := newReissueProvider(certOn("aaa", "ca-1", "web.example.com"))
	exec := &stubRenewer{errs: map[string]error{"aaa": errRenewalTargetNotSSH}}
	r := NewRenewalCertReissuer(certs, reissueTargets{list: []ManagedTarget{sshTarget("web.example.com")}}, exec)
	if err := r.ReissueCertificate(context.Background(), "aaa"); !errors.Is(err, ErrReissueDeferred) {
		t.Fatalf("an agent-mode target renews via the agent queue: want deferred, got %v", err)
	}
}

type alertRecord struct{ kind, keyID string }

// compromiseWithReissuer runs the flow over three certs under the burned CA:
// "ok" renews, "orphan" has no managed target, "boom" fails in the executor.
func compromiseWithReissuer(t *testing.T) (CompromiseReport, *reissueProvider, *[]alertRecord) {
	t.Helper()
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("burned", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: "issuing-1", KeyID: "burned", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	certs := newReissueProvider(
		certOn("ok", "issuing-1", "ok.example.com"),
		certOn("orphan", "issuing-1", "orphan.example.com"),
		certOn("boom", "issuing-1", "boom.example.com"),
		certOn("elsewhere", "other-ca", "ok.example.com"),
	)
	exec := &stubRenewer{errs: map[string]error{"boom": errors.New("ssh: connection refused")}}
	reissuer := NewRenewalCertReissuer(certs, reissueTargets{list: []ManagedTarget{sshTarget("ok.example.com"), sshTarget("boom.example.com")}}, exec)
	var alerts []alertRecord
	m, err := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(&recordingRotator{}, caStore),
		WithLifecycleReissue(certs, reissuer),
		WithLifecycleRevoker(certs),
		WithLifecycleAlerts(func(_ context.Context, kind, keyID string, _ map[string]any) {
			alerts = append(alerts, alertRecord{kind, keyID})
		}))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetPolicy("burned", "alice", nil, 0); err != nil {
		t.Fatal(err)
	}
	report, err := m.MarkCompromised(context.Background(), "burned")
	if err != nil {
		t.Fatal(err)
	}
	return report, certs, &alerts
}

func TestCompromiseReportBuckets(t *testing.T) {
	report, _, _ := compromiseWithReissuer(t)
	if len(report.Reissued) != 1 || report.Reissued[0] != "ok" {
		t.Errorf("Reissued = %v, want [ok]", report.Reissued)
	}
	if len(report.Deferred) != 1 || report.Deferred[0] != "orphan" {
		t.Errorf("Deferred = %v, want [orphan]", report.Deferred)
	}
	if len(report.Failed) != 1 || report.Failed["boom"] == "" {
		t.Errorf("Failed = %v, want boom", report.Failed)
	}
	if len(report.Errors) != 0 {
		t.Errorf("reissue outcomes must not leak into Errors: %v", report.Errors)
	}
}

func TestCompromiseRevokesAllOldKeyCerts(t *testing.T) {
	report, certs, _ := compromiseWithReissuer(t)
	if len(report.Affected) != 3 || len(report.Revoked) != len(report.Affected) {
		t.Fatalf("every affected cert must be revoked: affected=%v revoked=%v", report.Affected, report.Revoked)
	}
	for _, fp := range report.Affected {
		if !certs.revoked[fp] {
			t.Errorf("%s not revoked", fp)
		}
	}
	// A failed or deferred re-issue never un-revokes.
	if !certs.revoked["boom"] || !certs.revoked["orphan"] {
		t.Error("failed/deferred certs must stay revoked")
	}
	if certs.revoked["elsewhere"] {
		t.Error("a cert under another CA must not be revoked")
	}
}

func TestCompromiseAlertsEmitted(t *testing.T) {
	_, _, alerts := compromiseWithReissuer(t)
	got := map[string]int{}
	for _, a := range *alerts {
		if a.keyID != "burned" {
			t.Errorf("alert for wrong key: %+v", a)
		}
		got[a.kind]++
	}
	for _, kind := range []string{"key.compromised", "key.reissue_deferred", "key.reissue_failed"} {
		if got[kind] != 1 {
			t.Errorf("alert %s emitted %d times, want 1 (all: %v)", kind, got[kind], got)
		}
	}
}

func TestCompromiseOnlyCompromisedAlertWhenAllReissue(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("burned", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	caStore := ca.NewMemStore()
	_ = caStore.Save(&ca.CA{ID: "issuing-1", KeyID: "burned", Status: "active"})
	certs := newReissueProvider(certOn("ok", "issuing-1", "ok.example.com"))
	reissuer := NewRenewalCertReissuer(certs, reissueTargets{list: []ManagedTarget{sshTarget("ok.example.com")}}, &stubRenewer{})
	var kinds []string
	m, _ := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(&recordingRotator{}, caStore),
		WithLifecycleReissue(certs, reissuer), WithLifecycleRevoker(certs),
		WithLifecycleAlerts(func(_ context.Context, kind, _ string, _ map[string]any) { kinds = append(kinds, kind) }))
	_ = m.SetPolicy("burned", "alice", nil, 0)
	if _, err := m.MarkCompromised(context.Background(), "burned"); err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 1 || kinds[0] != "key.compromised" {
		t.Fatalf("alerts = %v, want only key.compromised", kinds)
	}
}
