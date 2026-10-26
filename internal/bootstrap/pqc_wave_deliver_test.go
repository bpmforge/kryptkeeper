// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/pqc"
)

type fakeKeyExporter struct {
	der []byte
	err error
}

func (f fakeKeyExporter) ExportPrivateKeyPKCS8(string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte(nil), f.der...), nil
}

// fakeMaterialInstaller records what the deliverer handed to the install path.
type fakeMaterialInstaller struct {
	calls  int
	pushed int    // calls routed to PushMaterial (k8s)
	keyPEM []byte // copy taken during the call, before the deliverer zeroizes
	res    RenewalExecuteResult
	err    error
}

func (f *fakeMaterialInstaller) PushMaterial(_ context.Context, _ ManagedTarget, _ RenewalInstallProfile, _, keyPEM []byte) (RenewalExecuteResult, error) {
	f.calls++
	f.pushed++
	f.keyPEM = append([]byte(nil), keyPEM...)
	return f.res, f.err
}

func (f *fakeMaterialInstaller) InstallMaterial(_ context.Context, _ ManagedTarget, _ RenewalInstallProfile, _, keyPEM []byte, _ string) (RenewalExecuteResult, error) {
	f.calls++
	f.keyPEM = append([]byte(nil), keyPEM...)
	return f.res, f.err
}

// waveCertStub serves a fixed PEM from DownloadCertificate.
type waveCertStub struct {
	CertificateProvider
	body []byte
}

func (s waveCertStub) DownloadCertificate(context.Context, string, string, bool) (CertificateDownloadResult, error) {
	return CertificateDownloadResult{Body: s.body}, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}

func TestWaveDeliverer_SupportsOnlyHubPushableSSHTargets(t *testing.T) {
	d := &keystoreWaveDeliverer{}
	ok := ManagedTarget{InstallMode: "ssh", CredentialRef: "c", InstallServerType: "nginx", InstallCertPath: "/c", InstallKeyPath: "/k"}
	if sup, why := d.Supports(ok); !sup {
		t.Fatalf("complete ssh target unsupported: %s", why)
	}
	for name, mutate := range map[string]func(*ManagedTarget){
		"agent mode":            func(t *ManagedTarget) { t.InstallMode = "agent" },
		"f5 push":               func(t *ManagedTarget) { t.InstallMode = "f5" },
		"client csr":            func(t *ManagedTarget) { t.KeyHandlingMode = KeyModeClientCSR },
		"no credential":         func(t *ManagedTarget) { t.CredentialRef = "" },
		"no key path":           func(t *ManagedTarget) { t.InstallKeyPath = "" },
		"tomcat":                func(t *ManagedTarget) { t.InstallServerType = "tomcat" },
		"iis":                   func(t *ManagedTarget) { t.InstallMode = "iis" },
		"sqlserver":             func(t *ManagedTarget) { t.InstallMode = "sqlserver" },
		"rdp":                   func(t *ManagedTarget) { t.InstallMode = "rdp" },
		"exchange":              func(t *ManagedTarget) { t.InstallMode = "exchange" },
		"citrix":                func(t *ManagedTarget) { t.InstallMode = "citrix" },
		"plugin":                func(t *ManagedTarget) { t.InstallMode = "plugin" },
		"haproxy binary reload": func(t *ManagedTarget) { t.InstallServerType = "haproxy"; t.InstallReloadMethod = "binary" },
		"haproxy no path":       func(t *ManagedTarget) { t.InstallServerType = "haproxy"; t.InstallCertPath = "" },
		"k8s no credential":     func(t *ManagedTarget) { t.InstallMode = "k8s"; t.CredentialRef = "" },
	} {
		tgt := ok
		mutate(&tgt)
		if sup, why := d.Supports(tgt); sup || why == "" {
			t.Errorf("%s: supports=%v reason=%q, want unsupported with a reason", name, sup, why)
		}
	}
}

func TestWaveDeliverer_ExportsAuditsAndZeroizes(t *testing.T) {
	der := []byte("fake-pkcs8-der-bytes-0123456789")
	inst := &fakeMaterialInstaller{res: RenewalExecuteResult{InstallOutcome: agentinstall.OutcomeInstalledVerified, Verified: true}}
	audit := &memAuditProvider{}
	var spyDER, spyPEM []byte
	d := &keystoreWaveDeliverer{
		exporter: fakeKeyExporter{der: der}, certs: waveCertStub{body: []byte("CHAIN")}, installer: inst, audit: audit,
		wipeSpy: func(d, p []byte) { spyDER, spyPEM = d, p },
	}

	got, err := d.Deliver(context.Background(), ManagedTarget{ID: "t1"}, "oldfp", "newfp", "key-1")
	if err != nil || got.Outcome != waveDeliveryOK || !got.Verified {
		t.Fatalf("Deliver = %+v, %v; want ok+verified", got, err)
	}
	blk, _ := pem.Decode(inst.keyPEM)
	if blk == nil || blk.Type != "PRIVATE KEY" || !bytes.Equal(blk.Bytes, der) {
		t.Fatalf("installer received %q, want a PRIVATE KEY PEM of the exported DER", inst.keyPEM)
	}
	if !allZero(spyDER) || !allZero(spyPEM) {
		t.Fatalf("key buffers not zeroized: der=%v pem-zero=%v", allZero(spyDER), allZero(spyPEM))
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(audit.entries))
	}
	e := audit.entries[0]
	if e.Action != "key.export_for_delivery" || e.Outcome != AuditOutcomeSuccess || e.ResourceID != "newfp" {
		t.Fatalf("audit row = %+v", e)
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	if strings.Contains(e.ChangeSummary, b64) || strings.Contains(e.ChangeSummary, string(der)) {
		t.Fatalf("audit row leaks key material: %q", e.ChangeSummary)
	}
}

func TestWaveDeliverer_NonExportableKeyIsUnsupportedNotInstalled(t *testing.T) {
	inst := &fakeMaterialInstaller{}
	audit := &memAuditProvider{}
	d := &keystoreWaveDeliverer{
		exporter: fakeKeyExporter{err: fmt.Errorf("%w: hsm", keystore.ErrPrivateKeyNotExportable)},
		certs:    waveCertStub{body: []byte("CHAIN")}, installer: inst, audit: audit,
	}
	_, err := d.Deliver(context.Background(), ManagedTarget{ID: "t1"}, "o", "n", "k")
	if !errors.Is(err, errWaveDeliveryUnsupported) || inst.calls != 0 {
		t.Fatalf("err=%v installs=%d, want unsupported and no install", err, inst.calls)
	}
	if len(audit.entries) != 1 || audit.entries[0].Outcome != AuditOutcomeFailure {
		t.Fatalf("audit = %+v, want one failure row", audit.entries)
	}
}

func TestWaveDeliverer_OutcomeMapping(t *testing.T) {
	for _, tc := range []struct {
		outcome string
		want    string
		wantErr bool
	}{
		{agentinstall.OutcomeVerifyFailed, waveDeliveryRolledBack, false},
		{agentinstall.OutcomeConfigTestFailed, waveDeliveryRolledBack, false},
		{agentinstall.OutcomeRollbackFailed, waveDeliveryFailed, false},
		{agentinstall.OutcomeInstalled, waveDeliveryFailed, false}, // unverified is never ok
		{"connect_failed", "", true},
	} {
		inst := &fakeMaterialInstaller{res: RenewalExecuteResult{InstallOutcome: tc.outcome, InstallDetail: "x"}}
		d := &keystoreWaveDeliverer{exporter: fakeKeyExporter{der: []byte("k")}, certs: waveCertStub{body: []byte("C")}, installer: inst}
		got, err := d.Deliver(context.Background(), ManagedTarget{ID: "t"}, "o", "n", "k")
		if (err != nil) != tc.wantErr || got.Outcome != tc.want || got.Verified {
			t.Errorf("%s: got %+v err=%v, want outcome %q err=%v", tc.outcome, got, err, tc.want, tc.wantErr)
		}
	}
}

// waveE2E runs a real ML-DSA-65 wave member through the real RenewalExecutor
// install path against an in-memory host, with the served fingerprint chosen by
// serve (nil = whatever the host's cert file holds, like a reloaded nginx).
func waveE2E(t *testing.T, serve func() string) (fx *waveExecuteTestFixture, res migrateWaveExecutionResult, host *renewalFakeExecutor, oldFP string, audit *memAuditProvider, wave MigrationWave) {
	t.Helper()
	fx = newWaveExecuteTestFixture(t)
	oldFP, wave = waveTestMember(t, fx, "e2e.example.com")
	host = &renewalFakeExecutor{files: map[string][]byte{
		"/etc/nginx/tls/renewed.crt": []byte("OLD-CERT"), "/etc/nginx/tls/renewed.key": []byte("OLD-KEY"),
	}}
	exec := newRenewalTestEngine(t, fx.certs, host, testSSHCredentialJSON(t))
	if serve != nil {
		exec.verifier = func(context.Context, string) (string, error) { return serve(), nil }
	}
	audit = &memAuditProvider{}
	exp, ok := fx.keys.(keystore.PrivateKeyPKCS8Exporter)
	if !ok {
		t.Fatal("software keystore must export PKCS#8")
	}
	tgt := ManagedTarget{ID: "t1", Name: "web", Host: "e2e.example.com", InstallMode: "ssh", CredentialRef: "cred-1",
		InstallServerType: "nginx", InstallCertPath: "/etc/nginx/tls/renewed.crt", InstallKeyPath: "/etc/nginx/tls/renewed.key", InstallReloadMethod: "binary"}
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{list: []ManagedTarget{tgt}}, waves: fx.waveStore,
		deliver: &keystoreWaveDeliverer{exporter: exp, certs: fx.certs, installer: exec, audit: audit}}
	res = runWaveMigration(context.Background(), d, wave, "ML-DSA-65", waveHooks{})
	return fx, res, host, oldFP, audit, wave
}

func TestWaveDeliverer_MLDSAMemberDeliveredAndVerified(t *testing.T) {
	_, res, host, _, audit, _ := waveE2E(t, nil)
	if res.Migrated != 1 || res.Regressed || res.Results[0].Delivery != "verified" {
		t.Fatalf("result = %+v, want migrated with verified delivery", res)
	}
	blk, _ := pem.Decode(host.files["/etc/nginx/tls/renewed.key"])
	if blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatalf("host key file is not a PRIVATE KEY PEM: %.40q", host.files["/etc/nginx/tls/renewed.key"])
	}
	signer, alg, err := keystore.ParseMLDSAPKCS8(blk.Bytes)
	if err != nil || alg != keystore.MLDSA65 || signer == nil {
		t.Fatalf("installed key does not parse as ML-DSA-65: %v %v", alg, err)
	}
	leaf, err := leafFingerprint(host.files["/etc/nginx/tls/renewed.crt"])
	if err != nil || leaf != res.Results[0].NewFingerprint {
		t.Fatalf("host serves leaf %s, want successor %s (%v)", leaf, res.Results[0].NewFingerprint, err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "key.export_for_delivery" || audit.entries[0].ResourceID != res.Results[0].NewFingerprint {
		t.Fatalf("audit = %+v, want one key.export_for_delivery row for the successor", audit.entries)
	}
}

func TestWaveDeliverer_VerifyFailureRestoresPreviousMaterial(t *testing.T) {
	fx, res, host, oldFP, _, wave := waveE2E(t, func() string { return strings.Repeat("ab", 32) })
	_ = oldFP
	r := res.Results[0]
	if r.Status != pqc.MemberFailed || r.Delivery != "failed" || r.OldSerialServed == nil || !*r.OldSerialServed || !res.Regressed {
		t.Fatalf("member = %+v regressed=%v, want failed/rolled back/regressed", r, res.Regressed)
	}
	if string(host.files["/etc/nginx/tls/renewed.crt"]) != "OLD-CERT" || string(host.files["/etc/nginx/tls/renewed.key"]) != "OLD-KEY" {
		t.Fatalf("previous material not restored: crt=%q key=%.20q", host.files["/etc/nginx/tls/renewed.crt"], host.files["/etc/nginx/tls/renewed.key"])
	}
	if got := waveStatusOf(t, fx, wave.ID); got != waveStatusRegressed {
		t.Fatalf("wave status = %q, want regressed", got)
	}
}

func TestWaveMigration_NonExportableKeyReportsDeliveryUnsupported(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	_, wave := waveTestMember(t, fx, "hsm.example.com")
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{list: []ManagedTarget{{ID: "t1", Host: "hsm.example.com", InstallMode: "ssh", CredentialRef: "c",
		InstallServerType: "nginx", InstallCertPath: "/c", InstallKeyPath: "/k"}}}, waves: fx.waveStore,
		deliver: &keystoreWaveDeliverer{exporter: fakeKeyExporter{err: keystore.ErrPrivateKeyNotExportable}, certs: fx.certs, installer: &fakeMaterialInstaller{}}}
	res := runWaveMigration(context.Background(), d, wave, "ML-DSA-65", waveHooks{})
	r := res.Results[0]
	if r.Status != pqc.MemberDeliveryUnsupported || res.Unsupported != 1 || res.Regressed || !strings.Contains(r.Reason, "cannot be exported") {
		t.Fatalf("result = %+v, want delivery_unsupported with reason, not regressed", res)
	}
}

func TestWaveDeliverer_SupportsHAProxyAndK8s(t *testing.T) {
	d := &keystoreWaveDeliverer{}
	for name, tgt := range map[string]ManagedTarget{
		"haproxy combined pem": {InstallMode: "ssh", CredentialRef: "c", InstallServerType: "haproxy", InstallCertPath: "/etc/haproxy/kk.pem"},
		"k8s tls secret":       {InstallMode: "k8s", CredentialRef: "c"},
	} {
		if sup, why := d.Supports(tgt); !sup {
			t.Errorf("%s unsupported: %s", name, why)
		}
	}
	// the Windows and tomcat reasons must say why, not just "no"
	for mode, want := range map[string]string{"iis": "PFX", "rdp": "Schannel"} {
		if _, why := d.Supports(ManagedTarget{InstallMode: mode}); !strings.Contains(why, want) {
			t.Errorf("%s reason %q lacks %q", mode, why, want)
		}
	}
	if _, why := d.Supports(ManagedTarget{InstallMode: "ssh", CredentialRef: "c", InstallServerType: "tomcat", InstallCertPath: "/k", InstallKeyPath: "/k"}); !strings.Contains(why, "PKCS#12") {
		t.Errorf("tomcat reason %q", why)
	}
}

func TestWaveDeliverer_K8sUsesPushPathAndZeroizes(t *testing.T) {
	inst := &fakeMaterialInstaller{res: RenewalExecuteResult{InstallOutcome: agentinstall.OutcomeInstalledVerified, Verified: true}}
	audit := &memAuditProvider{}
	var spyDER, spyPEM []byte
	d := &keystoreWaveDeliverer{exporter: fakeKeyExporter{der: []byte("fake-pkcs8-der-0123456789")}, certs: waveCertStub{body: []byte("CHAIN")}, installer: inst, audit: audit,
		wipeSpy: func(d, p []byte) { spyDER, spyPEM = d, p }}
	got, err := d.Deliver(context.Background(), ManagedTarget{ID: "k", InstallMode: "k8s"}, "o", "n", "key-1")
	if err != nil || got.Outcome != waveDeliveryOK || !got.Verified || inst.pushed != 1 {
		t.Fatalf("got %+v err=%v pushed=%d, want verified via PushMaterial", got, err, inst.pushed)
	}
	if !allZero(spyDER) || !allZero(spyPEM) || len(audit.entries) != 1 || audit.entries[0].Action != "key.export_for_delivery" {
		t.Fatalf("zeroize/audit wrong: der=%v pem=%v audit=%+v", allZero(spyDER), allZero(spyPEM), audit.entries)
	}
}

func TestWaveDeliverer_K8sVerifyFailureIsRolledBackAndRollbackFailureIsFailed(t *testing.T) {
	for outcome, want := range map[string]string{
		agentinstall.OutcomeVerifyFailed:   waveDeliveryRolledBack,
		agentinstall.OutcomeRollbackFailed: waveDeliveryFailed,
	} {
		inst := &fakeMaterialInstaller{res: RenewalExecuteResult{InstallOutcome: outcome}}
		d := &keystoreWaveDeliverer{exporter: fakeKeyExporter{der: []byte("k")}, certs: waveCertStub{body: []byte("C")}, installer: inst}
		got, err := d.Deliver(context.Background(), ManagedTarget{ID: "k", InstallMode: "k8s"}, "o", "n", "k")
		if err != nil || got.Outcome != want || got.Verified {
			t.Errorf("%s: got %+v err=%v, want %s", outcome, got, err, want)
		}
	}
}
