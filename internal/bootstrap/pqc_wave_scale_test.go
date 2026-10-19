// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// RSA-2048 keygen dominates runtime, and the engine does not enforce key
// uniqueness, so a small pool is generated once and cycled across certs.
const scaleKeyPoolSize = 25

var (
	scaleKeyPoolOnce sync.Once
	scaleKeyPool     []*rsa.PrivateKey
)

func scaleRSAKeys(t *testing.T) []*rsa.PrivateKey {
	t.Helper()
	scaleKeyPoolOnce.Do(func() {
		keys := make([]*rsa.PrivateKey, scaleKeyPoolSize)
		var wg sync.WaitGroup
		jobs := make(chan int)
		for w := 0; w < runtime.NumCPU(); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					k, err := rsa.GenerateKey(rand.Reader, 2048)
					if err != nil {
						continue
					}
					keys[i] = k
				}
			}()
		}
		for i := range keys {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		scaleKeyPool = keys
	})
	for _, k := range scaleKeyPool {
		if k == nil {
			t.Fatal("RSA key pool generation failed")
		}
	}
	return scaleKeyPool
}

func scaleRSACSR(t *testing.T, key *rsa.PrivateKey, host string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: host},
		DNSNames: []string{host},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// fixedTargets serves a fixed target list; the embedded nil interface is never
// otherwise called, which keeps the fake honest about what the executor uses.
type fixedTargets struct {
	ManagedTargetStore
	list []ManagedTarget
}

func (f fixedTargets) List(context.Context) ([]ManagedTarget, error) { return f.list, nil }

// scaleDeliverer models many SSH targets, each serving one fingerprint. A
// host in failVerify never presents the new cert, so the install is rolled
// back and the old fingerprint keeps being served.
type scaleDeliverer struct {
	mu         sync.Mutex
	served     map[string]string
	failVerify map[string]bool
}

func (d *scaleDeliverer) Supports(t ManagedTarget) (bool, string) {
	return t.InstallMode == "ssh", "unsupported install mode"
}

func (d *scaleDeliverer) Deliver(_ context.Context, t ManagedTarget, _, newFP string) (waveDelivery, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failVerify[t.Host] {
		return waveDelivery{Outcome: waveDeliveryRolledBack, Detail: "served fingerprint != new"}, nil
	}
	d.served[t.Host] = newFP
	return waveDelivery{Outcome: waveDeliveryOK, Detail: "served fingerprint matches", Verified: true}, nil
}

func (d *scaleDeliverer) servedFP(host string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.served[host]
}

// scaleFailingRenewProvider injects per-member issuance failures.
type scaleFailingRenewProvider struct {
	CertificateProvider
	fail map[string]bool
}

func (p scaleFailingRenewProvider) RenewCertificate(ctx context.Context, fp string, req CertificateRenewRequest) (CertificateIssueResult, error) {
	if p.fail[fp] {
		return CertificateIssueResult{}, errors.New("injected issuance failure")
	}
	return p.CertificateProvider.RenewCertificate(ctx, fp, req)
}

type scaleConfig struct {
	members, bound   int
	failVerifyPos    []int // positions in wave.Members (all < bound)
	failIssuePos     []int
	outageFrom, span int // CA suspended after outageFrom results for span results; 0 disables
}

type scaleRun struct {
	fx       *waveExecuteTestFixture
	wave     MigrationWave
	res      migrateWaveExecutionResult
	results  []migrateWaveMemberResult
	deliver  *scaleDeliverer
	hostOf   map[string]string // member fingerprint -> host
	duration time.Duration
}

func runScaleScenario(t *testing.T, cfg scaleConfig) *scaleRun {
	t.Helper()
	ctx := context.Background()
	fx := newWaveExecuteTestFixture(t)
	fx.templates.templates["tpl-rsa"] = TemplateItem{ID: "tpl-rsa", Active: true, ValidityPeriod: "8760h", AllowedAlgorithms: []string{"RSA", "ECDSA"}}
	keys := scaleRSAKeys(t)
	caID := getFirstCAID(t, fx.engine)

	wave, err := fx.waveStore.CreateWave(ctx, MigrationWave{Name: "scale"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	hostOf := make(map[string]string, cfg.members)
	for i := 0; i < cfg.members; i++ {
		host := fmt.Sprintf("host-%04d.scale.test", i)
		issued, err := fx.certs.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-rsa", CSRPEM: scaleRSACSR(t, keys[i%len(keys)], host), TeamID: "team-1"})
		if err != nil {
			t.Fatalf("issue %s: %v", host, err)
		}
		if err := fx.waveStore.AddMember(ctx, wave.ID, MigrationWaveMember{Fingerprint: issued.FingerprintSHA256}); err != nil {
			t.Fatalf("add member: %v", err)
		}
		hostOf[issued.FingerprintSHA256] = host
	}
	waves, err := fx.waveStore.ListWaves(ctx)
	if err != nil {
		t.Fatalf("list waves: %v", err)
	}
	for _, w := range waves {
		if w.ID == wave.ID {
			wave = w
		}
	}
	if len(wave.Members) != cfg.members {
		t.Fatalf("wave has %d members, want %d", len(wave.Members), cfg.members)
	}

	del := &scaleDeliverer{served: map[string]string{}, failVerify: map[string]bool{}}
	var targets []ManagedTarget
	for i := 0; i < cfg.bound; i++ {
		fp := wave.Members[i].Fingerprint
		host := hostOf[fp]
		targets = append(targets, ManagedTarget{
			ID: fmt.Sprintf("t-%04d", i), Name: host, Host: host, AutoRenew: true, AutoRenewSetBy: "scale-test",
			CredentialRef: "cred", InstallMode: "ssh", InstallServerType: "nginx",
			InstallCertPath: "/etc/tls/c.crt", InstallKeyPath: "/etc/tls/c.key",
		})
		del.served[host] = fp
	}
	for _, p := range cfg.failVerifyPos {
		del.failVerify[hostOf[wave.Members[p].Fingerprint]] = true
	}
	failIssue := map[string]bool{}
	for _, p := range cfg.failIssuePos {
		failIssue[wave.Members[p].Fingerprint] = true
	}

	var mu sync.Mutex
	var results []migrateWaveMemberResult
	hooks := waveHooks{MemberResult: func(_ string, r migrateWaveMemberResult) {
		mu.Lock()
		results = append(results, r)
		n := len(results)
		mu.Unlock()
		if cfg.outageFrom > 0 {
			switch n {
			case cfg.outageFrom:
				if err := fx.engine.UpdateCAStatus(caID, "suspended"); err != nil {
					t.Errorf("suspend CA: %v", err)
				}
			case cfg.outageFrom + cfg.span:
				if err := fx.engine.UpdateCAStatus(caID, "active"); err != nil {
					t.Errorf("restore CA: %v", err)
				}
			}
		}
	}}
	if cfg.outageFrom > 0 {
		t.Cleanup(func() { _ = fx.engine.UpdateCAStatus(caID, "active") })
	}

	d := waveDeps{certs: scaleFailingRenewProvider{CertificateProvider: fx.certs, fail: failIssue}, keys: fx.keys, targets: fixedTargets{list: targets}, deliver: del, waves: fx.waveStore}
	start := time.Now()
	res := runWaveMigration(ctx, d, wave, keystore.MLDSA65, hooks)
	elapsed := time.Since(start)
	t.Logf("migrated %d members in %s (migrated=%d failed=%d skipped=%d unsupported=%d regressed=%v)", cfg.members, elapsed, res.Migrated, res.Failed, res.Skipped, res.Unsupported, res.Regressed)
	return &scaleRun{fx: fx, wave: wave, res: res, results: results, deliver: del, hostOf: hostOf, duration: elapsed}
}

func assertNothingSilent(t *testing.T, run *scaleRun) {
	t.Helper()
	res, n := run.res, len(run.wave.Members)
	if got := res.Migrated + res.Failed + res.Skipped + res.Unsupported; got != n {
		t.Fatalf("migrated+failed+skipped+unsupported = %d, want %d members", got, n)
	}
	distinct := map[string]bool{}
	for _, r := range run.results {
		distinct[r.Fingerprint] = true
	}
	if len(distinct) != n || len(run.results) != n || len(res.Results) != n {
		t.Fatalf("distinct=%d hook results=%d result rows=%d, want %d each", len(distinct), len(run.results), len(res.Results), n)
	}
	for _, m := range run.wave.Members {
		if !distinct[m.Fingerprint] {
			t.Fatalf("member %s has no recorded result", m.Fingerprint)
		}
	}
	for _, r := range run.results {
		if r.Status != "migrated" && r.Reason == "" {
			t.Fatalf("non-migrated member %s (%s) has no reason", r.Fingerprint, r.Status)
		}
	}
}

// assertWaveProgressMatchesInventory checks the D-105 invariant on a clean
// run: the fixture CA is ECDSA, so every migrated member is leaf-only and the
// wave is never marked done.
func assertWaveProgressMatchesInventory(t *testing.T, run *scaleRun) {
	t.Helper()
	ctx := context.Background()
	all, err := listAllCertificates(ctx, run.fx.certs, CertificateListQuery{})
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	current := waveCurrentReadiness(all.Items)
	waves, err := run.fx.waveStore.ListWaves(ctx)
	if err != nil {
		t.Fatalf("list waves: %v", err)
	}
	progress := syncWaveStatuses(ctx, run.fx.waveStore, waves, current)
	var wp *WaveProgress
	for i := range progress {
		if progress[i].ID == run.wave.ID {
			wp = &progress[i]
		}
	}
	if wp == nil {
		t.Fatal("wave missing from progress")
	}
	countPQC := 0
	for _, m := range run.wave.Members {
		if l := current[m.Fingerprint]; l == "quantum_safe" || l == "quantum_safe_leaf_only" {
			countPQC++
		}
	}
	total := len(run.wave.Members)
	if wp.ProgressPercent != 100*countPQC/total {
		t.Fatalf("ProgressPercent = %d, want %d", wp.ProgressPercent, 100*countPQC/total)
	}
	if wp.LeafOnly != run.res.Migrated {
		t.Fatalf("LeafOnly = %d, want Migrated %d", wp.LeafOnly, run.res.Migrated)
	}
	if got := waveStatusOf(t, run.fx, run.wave.ID); got == waveStatusDone {
		t.Fatalf("stored wave status = %q; leaf-only members must never complete a wave (D-105)", got)
	}
}

func TestWaveScale_1000RSAToMLDSA(t *testing.T) {
	// ~80s without -race; PR CI runs internal/bootstrap under -race close to
	// its 30m budget, so the 1,000-cert run is nightly-only (W31-10).
	if testing.Short() || os.Getenv("KRYPTKEEPER_SCALE_TESTS") != "1" {
		t.Skip("1,000-cert scale test: set KRYPTKEEPER_SCALE_TESTS=1 (nightly)")
	}
	run := runScaleScenario(t, scaleConfig{members: 1000, bound: 40})
	if run.duration >= 60*time.Minute {
		t.Fatalf("wave took %s, want < 60m", run.duration)
	}
	// 99% on the clean pass; the injection scenario is judged by the
	// accounting identity instead of a percentage.
	if run.res.Migrated < 990 {
		t.Fatalf("migrated = %d, want >= 990 (99%% of 1000)", run.res.Migrated)
	}
	if len(run.results) != 1000 {
		t.Fatalf("hook results = %d, want 1000", len(run.results))
	}
	assertNothingSilent(t, run)

	all, err := listAllCertificates(context.Background(), run.fx.certs, CertificateListQuery{})
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	byFP := make(map[string]CertificateItem, len(all.Items))
	for _, c := range all.Items {
		byFP[c.FingerprintSHA256] = c
	}
	for _, r := range run.results {
		if r.Status != "migrated" {
			continue
		}
		c, ok := byFP[r.NewFingerprint]
		if !ok || c.PublicKeyAlgorithm != "ML-DSA" {
			t.Fatalf("migrated member %s new cert %s: found=%v algorithm=%q, want ML-DSA", r.Fingerprint, r.NewFingerprint, ok, c.PublicKeyAlgorithm)
		}
	}
	assertWaveProgressMatchesInventory(t, run)
}

func TestWaveScale_FailureInjection_OldCertKeepsServing(t *testing.T) {
	run := runScaleScenario(t, scaleConfig{
		members: 200, bound: 20,
		failVerifyPos: []int{2, 5, 9, 14},
		failIssuePos:  []int{30, 50, 70, 150, 170, 190},
		outageFrom:    100, span: 30,
	})
	ctx := context.Background()
	assertNothingSilent(t, run)

	// 4 verify failures + 6 issuance failures + 30 members issued during the outage.
	if run.res.Failed != 40 || run.res.Migrated != 160 {
		t.Fatalf("failed=%d migrated=%d, want 40/160", run.res.Failed, run.res.Migrated)
	}
	outageReasons := 0
	for _, r := range run.results {
		if r.Status != "failed" {
			continue
		}
		if r.Reason == "" {
			t.Fatalf("failed member %s has no reason", r.Fingerprint)
		}
		if strings.Contains(r.Reason, "not active") {
			outageReasons++
		}
		if r.NewFingerprint == "" {
			// Issuance never happened: the old cert must still be current.
			d, ok, err := run.fx.certs.GetCertificate(ctx, r.Fingerprint)
			if err != nil || !ok {
				t.Fatalf("get %s: ok=%v err=%v", r.Fingerprint, ok, err)
			}
			if d.SuccessorFP != nil {
				t.Fatalf("failed-issuance member %s was superseded by %s", r.Fingerprint, *d.SuccessorFP)
			}
			continue
		}
		// Delivery failed after issuance: the target must still serve the old serial.
		host := run.hostOf[r.Fingerprint]
		if got := run.deliver.servedFP(host); got != r.Fingerprint {
			t.Fatalf("host %s serves %q, want old fingerprint %q", host, got, r.Fingerprint)
		}
		if r.OldSerialServed == nil || !*r.OldSerialServed {
			t.Fatalf("member %s OldSerialServed = %v, want true", r.Fingerprint, r.OldSerialServed)
		}
	}
	if outageReasons != 30 {
		t.Fatalf("members failed with a CA-not-active reason = %d, want 30", outageReasons)
	}
	if !run.res.Regressed || run.res.WaveStatus != waveStatusRegressed {
		t.Fatalf("result regressed=%v status=%q, want regressed", run.res.Regressed, run.res.WaveStatus)
	}
	if got := waveStatusOf(t, run.fx, run.wave.ID); got != waveStatusRegressed {
		t.Fatalf("stored wave status = %q, want regressed", got)
	}
	assertNothingSilent(t, run)
	for _, pct := range []int{0, 80, 100} {
		if got := advanceWaveStatus(waveStatusRegressed, pct, 200); got == waveStatusDone {
			t.Fatalf("advanceWaveStatus(regressed, %d) = done", pct)
		}
	}
}

func TestWaveScale_NothingSilent(t *testing.T) {
	if testing.Short() || os.Getenv("KRYPTKEEPER_SCALE_TESTS") != "1" {
		t.Skip("200-member scale scenario: set KRYPTKEEPER_SCALE_TESTS=1 (nightly)")
	}
	run := runScaleScenario(t, scaleConfig{
		members: 200, bound: 20,
		failVerifyPos: []int{1, 7}, failIssuePos: []int{40, 120}, outageFrom: 160, span: 10,
	})
	assertNothingSilent(t, run)
	if run.res.Failed == 0 {
		t.Fatal("expected injected failures to be recorded")
	}
}

func TestWaveScale_ProgressMatchesPQCCurrentCerts(t *testing.T) {
	if testing.Short() || os.Getenv("KRYPTKEEPER_SCALE_TESTS") != "1" {
		t.Skip("200-member scale scenario: set KRYPTKEEPER_SCALE_TESTS=1 (nightly)")
	}
	run := runScaleScenario(t, scaleConfig{members: 200, bound: 20})
	if run.res.Migrated != 200 {
		t.Fatalf("migrated = %d, want 200", run.res.Migrated)
	}
	assertWaveProgressMatchesInventory(t, run)
}
