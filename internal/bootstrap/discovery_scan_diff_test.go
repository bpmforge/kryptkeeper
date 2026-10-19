// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

var (
	diffRSAOnce sync.Once
	diffRSA     = map[int]*rsa.PrivateKey{}
)

func diffRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	diffRSAOnce.Do(func() {
		for _, b := range []int{2048, 3072} {
			k, err := rsa.GenerateKey(rand.Reader, b)
			if err != nil {
				panic(err)
			}
			diffRSA[b] = k
		}
	})
	return diffRSA[bits]
}

func diffCert(t *testing.T, key crypto.Signer, cn string) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func diffECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func answeringEP(c *x509.Certificate) scanner.DiscoveredEndpoint {
	return scanner.DiscoveredEndpoint{Host: "app.example.com", Port: 443, Protocol: "tls", Reachable: true,
		Certs: []scanner.DiscoveredCert{scanner.CertToDiscovered(c, "app.example.com", true)}}
}

func silentEP() scanner.DiscoveredEndpoint {
	return scanner.DiscoveredEndpoint{Host: "app.example.com", Port: 443, Protocol: "tls", Error: "connection refused"}
}

const diffKey = "app.example.com:443"

func kinds(evs []ScanDiffEvent) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func TestScanDiff_CertificateReplaced(t *testing.T) {
	a, b := diffCert(t, diffECKey(t), "a"), diffCert(t, diffECKey(t), "b")
	fpA := scanner.CertToDiscovered(a, "h", true).Fingerprint
	e := newScanDiffEngine(2)
	got := e.diff(map[string]scanDiffLeaf{diffKey: {Fingerprint: fpA, Algorithm: "ECDSA", Bits: 256}}, []scanner.DiscoveredEndpoint{answeringEP(b)}, time.Now())
	if len(got) != 1 || got[0].Kind != ScanDiffCertificateReplaced || got[0].OldFingerprint != fpA ||
		got[0].NewFingerprint == fpA || !strings.HasPrefix(got[0].Detail, "leaf "+fpA[:12]+" -> ") {
		t.Fatalf("events: %+v", got)
	}
}

func TestScanDiff_CertificateDisappearedAfterNMisses(t *testing.T) {
	c := diffCert(t, diffECKey(t), "c")
	fp := scanner.CertToDiscovered(c, "h", true).Fingerprint
	prior := map[string]scanDiffLeaf{diffKey: {Fingerprint: fp, Algorithm: "ECDSA", Bits: 256}}
	e := newScanDiffEngine(2)
	now := time.Now()
	step := func(ep scanner.DiscoveredEndpoint) []ScanDiffEvent {
		return e.diff(prior, []scanner.DiscoveredEndpoint{ep}, now)
	}

	if got := step(silentEP()); len(got) != 0 {
		t.Fatalf("miss 1 must not emit: %+v", got)
	}
	if got := step(silentEP()); len(got) != 1 || got[0].Kind != ScanDiffCertificateDisappeared || got[0].OldFingerprint != fp {
		t.Fatalf("miss 2 must emit once: %+v", got)
	}
	if got := step(silentEP()); len(got) != 0 {
		t.Fatalf("miss 3 must not re-emit: %+v", got)
	}
	// An answering scan (even a handshake failure on an open port) resets.
	if got := step(answeringEP(c)); len(got) != 0 {
		t.Fatalf("answering unchanged scan: %+v", got)
	}
	open := silentEP()
	open.Reachable = true // open port, failed handshake: answering, not a miss
	step(open)
	step(silentEP())
	if got := step(silentEP()); len(got) != 1 || got[0].Kind != ScanDiffCertificateDisappeared {
		t.Fatalf("after a reset the count restarts and re-announces: %+v", got)
	}
}

func TestScanDiff_KeyDowngrade(t *testing.T) {
	rsa2048, rsa3072 := diffCert(t, diffRSAKey(t, 2048), "r2"), diffCert(t, diffRSAKey(t, 3072), "r3")
	ec256 := diffCert(t, diffECKey(t), "e")
	cases := []struct {
		name  string
		prior scanDiffLeaf
		cur   *x509.Certificate
		want  bool
	}{
		{"RSA 4096 to 2048", scanDiffLeaf{"old", "RSA", 4096}, rsa2048, true},
		{"ECDSA 384 to 256", scanDiffLeaf{"old", "ECDSA", 384}, ec256, true},
		{"ECDSA to RSA 2048", scanDiffLeaf{"old", "ECDSA", 256}, rsa2048, true},
		{"RSA 2048 to 3072", scanDiffLeaf{"old", "RSA", 2048}, rsa3072, false},
		{"ECDSA to RSA 3072", scanDiffLeaf{"old", "ECDSA", 256}, rsa3072, false},
		{"unknown prior size", scanDiffLeaf{"old", "RSA", 0}, rsa2048, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs := newScanDiffEngine(2).diff(map[string]scanDiffLeaf{diffKey: tc.prior}, []scanner.DiscoveredEndpoint{answeringEP(tc.cur)}, time.Now())
			has := false
			for _, ev := range evs {
				if ev.Kind == ScanDiffKeyDowngrade {
					has = true
				}
			}
			if has != tc.want {
				t.Fatalf("downgrade = %v, want %v (events %v)", has, tc.want, kinds(evs))
			}
			if tc.want && len(evs) != 2 {
				t.Fatalf("a replace plus weaker key yields BOTH events, got %v", kinds(evs))
			}
		})
	}
}

func TestScanDiff_UnchangedRescanEmitsNothing(t *testing.T) {
	c := diffCert(t, diffECKey(t), "c")
	fp := scanner.CertToDiscovered(c, "h", true).Fingerprint
	got := newScanDiffEngine(2).diff(map[string]scanDiffLeaf{diffKey: {fp, "ECDSA", 256}}, []scanner.DiscoveredEndpoint{answeringEP(c)}, time.Now())
	if len(got) != 0 {
		t.Fatalf("unchanged re-scan emitted %+v", got)
	}
}

func TestScanDiff_FirstScanEmitsNothing(t *testing.T) {
	c := diffCert(t, diffECKey(t), "c")
	if got := newScanDiffEngine(2).diff(nil, []scanner.DiscoveredEndpoint{answeringEP(c)}, time.Now()); len(got) != 0 {
		t.Fatalf("first scan emitted %+v", got)
	}
}

func TestScanDiff_NeverReachedHostEmitsNothing(t *testing.T) {
	e := newScanDiffEngine(2)
	for i := 0; i < 5; i++ {
		if got := e.diff(nil, []scanner.DiscoveredEndpoint{silentEP()}, time.Now()); len(got) != 0 {
			t.Fatalf("scan %d: a host with no recorded leaf emitted %+v", i, got)
		}
	}
	// Port-0 sources (mesh, k8s) and ssh inventories are not diffed at all.
	c := diffCert(t, diffECKey(t), "c")
	mesh := answeringEP(c)
	mesh.Port = 0
	if got := e.diff(map[string]scanDiffLeaf{"app.example.com:0": {"x", "ECDSA", 256}}, []scanner.DiscoveredEndpoint{mesh}, time.Now()); len(got) != 0 {
		t.Fatalf("port-0 endpoint emitted %+v", got)
	}
}

type diffFakeNotifications struct {
	NotificationProvider
	rules     []NotificationRule
	delivered []string
}

func (f *diffFakeNotifications) ListRules(context.Context) ([]NotificationRule, error) {
	return f.rules, nil
}
func (f *diffFakeNotifications) TestDelivery(_ context.Context, ch, target, msg string) (NotificationTestDeliveryResult, error) {
	f.delivered = append(f.delivered, ch+"|"+target+"|"+msg)
	return NotificationTestDeliveryResult{}, nil
}
func (f *diffFakeNotifications) Delivers() bool { return true }
func (f *diffFakeNotifications) Name() string   { return "fake" }

func TestProviderScanDiffNotifier_FansOutToEnabledRules(t *testing.T) {
	np := &diffFakeNotifications{rules: []NotificationRule{
		{ID: "r1", Channel: "email", Target: "ops@example.com", Enabled: true},
		{ID: "r2", Channel: "slack", Target: "#sec", Enabled: false},
	}}
	ap := &recordingAuditProvider{}
	n := newProviderScanDiffNotifier(np, ap)
	if err := n.Notify(context.Background(), ScanDiffEvent{Kind: ScanDiffCertificateReplaced, Host: "app.example.com", Port: 443, Detail: "leaf aaa -> bbb"}); err != nil {
		t.Fatal(err)
	}
	if len(np.delivered) != 1 || !strings.HasPrefix(np.delivered[0], "email|ops@example.com|") || !strings.Contains(np.delivered[0], "CERTIFICATE_REPLACED") {
		t.Fatalf("deliveries: %v", np.delivered)
	}
	if len(ap.entries) != 1 || ap.entries[0].Action != "discovery.scan_diff.certificate_replaced" || ap.entries[0].ResourceID != "app.example.com:443" {
		t.Fatalf("audit: %+v", ap.entries)
	}
}

type recordingScanDiffNotifier struct {
	mu  sync.Mutex
	evs []ScanDiffEvent
}

func (r *recordingScanDiffNotifier) Notify(_ context.Context, ev ScanDiffEvent) error {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
	return nil
}

func TestSqliteUpsertScanResults_EmitsReplacedThroughStore(t *testing.T) {
	stubEndpointAudit(t)
	db := setupIntegrationDB(t)
	store := migratedDiscoveryStore(t, db)
	rec := &recordingScanDiffNotifier{}
	store.SetScanDiffNotifier(rec)
	upsert := func(eps ...scanner.DiscoveredEndpoint) {
		t.Helper()
		if _, err := store.upsertScanResults(context.Background(), eps); err != nil {
			t.Fatal(err)
		}
	}
	a, b := diffCert(t, diffECKey(t), "a"), diffCert(t, diffECKey(t), "b")

	upsert(answeringEP(a))
	if len(rec.evs) != 0 {
		t.Fatalf("first scan emitted %+v", rec.evs)
	}
	upsert(answeringEP(a))
	if len(rec.evs) != 0 {
		t.Fatalf("unchanged re-scan emitted %+v", rec.evs)
	}
	upsert(answeringEP(b))
	if len(rec.evs) != 1 || rec.evs[0].Kind != ScanDiffCertificateReplaced || rec.evs[0].Host != "app.example.com" || rec.evs[0].Port != 443 {
		t.Fatalf("want one REPLACED, got %+v", rec.evs)
	}
	// Silent scans leave the stored leaf alone, so the second one announces it.
	upsert(silentEP())
	upsert(silentEP())
	if len(rec.evs) != 2 || rec.evs[1].Kind != ScanDiffCertificateDisappeared || rec.evs[1].OldFingerprint != rec.evs[0].NewFingerprint {
		t.Fatalf("want REPLACED then DISAPPEARED, got %+v", rec.evs)
	}
}
