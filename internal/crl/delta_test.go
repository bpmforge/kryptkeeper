// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// deltaFixture is a generator over a mutable revoked list.
type deltaFixture struct {
	ca      *testCRLCA
	mu      sync.Mutex
	revoked []RevokedCert
	events  []Event
	gen     *Generator
	caErr   error
}

func newDeltaFixture(t *testing.T, validity, deltaValidity time.Duration) *deltaFixture {
	t.Helper()
	f := &deltaFixture{ca: newTestCRLCA(t)}
	f.gen = NewGenerator(
		func(string) ([]RevokedCert, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return append([]RevokedCert(nil), f.revoked...), nil
		},
		func(string) (*x509.Certificate, crypto.Signer, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.caErr != nil {
				return nil, nil, f.caErr
			}
			return f.ca.cert, f.ca.key, nil
		},
		validity,
	).WithEventSink(func(e Event) {
		f.mu.Lock()
		f.events = append(f.events, e)
		f.mu.Unlock()
	})
	if deltaValidity > 0 {
		f.gen.WithDelta(deltaValidity, "http://crl.example.test")
	}
	return f
}

func (f *deltaFixture) revoke(serial int64, at time.Time) {
	f.mu.Lock()
	f.revoked = append(f.revoked, RevokedCert{SerialNumber: big.NewInt(serial), RevokedAt: at, ReasonCode: 1})
	f.mu.Unlock()
}

func (f *deltaFixture) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var a []string
	for _, e := range f.events {
		a = append(a, e.Action)
	}
	return a
}

func TestDeltaCRLCarriesIndicatorAndVerifies(t *testing.T) {
	f := newDeltaFixture(t, time.Hour, 15*time.Minute)
	old := time.Now().Add(-time.Hour)
	f.revoke(1, old)
	f.revoke(2, old)
	base, err := f.gen.Generate("ca1")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []int64{10, 11, 12} {
		f.revoke(s, time.Now())
	}
	d, err := f.gen.GenerateDelta("ca1")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(d.DER)
	if err != nil {
		t.Fatalf("parse delta: %v", err)
	}
	if err := parsed.CheckSignatureFrom(f.ca.cert); err != nil {
		t.Fatalf("delta signature: %v", err)
	}
	if parsed.Number.Cmp(base.Number) <= 0 {
		t.Fatalf("delta number %s must exceed base %s", parsed.Number, base.Number)
	}
	var found bool
	for _, e := range parsed.Extensions {
		if e.Id.Equal(oidDeltaCRLIndicator) {
			found = true
			if !e.Critical {
				t.Fatal("Delta CRL Indicator must be critical")
			}
			var n *big.Int
			if _, err := asn1.Unmarshal(e.Value, &n); err != nil || n.Cmp(base.Number) != 0 {
				t.Fatalf("indicator = %v (%v), want base %s", n, err, base.Number)
			}
		}
	}
	if !found {
		t.Fatal("delta CRL has no Delta CRL Indicator")
	}
	got := map[string]bool{}
	for _, e := range parsed.RevokedCertificateEntries {
		got[e.SerialNumber.String()] = true
	}
	if len(got) != 3 || !got["10"] || !got["11"] || !got["12"] {
		t.Fatalf("delta entries = %v, want exactly 10,11,12", got)
	}
}

func TestDeltaCRLUnder100KBForBenchmarkVolume(t *testing.T) {
	f := newDeltaFixture(t, 24*time.Hour, 15*time.Minute)
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 100000; i++ {
		s, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		f.revoked = append(f.revoked, RevokedCert{SerialNumber: s, RevokedAt: old, ReasonCode: 1})
	}
	if _, err := f.gen.Generate("ca1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1500; i++ {
		s, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		f.revoked = append(f.revoked, RevokedCert{SerialNumber: s.Add(s, new(big.Int).Lsh(big.NewInt(1), 126)), RevokedAt: time.Now(), ReasonCode: 1})
	}
	d, err := f.gen.GenerateDelta("ca1")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("delta = %d bytes for 1500 entries (%d B/entry)", len(d.DER), len(d.DER)/1500)
	if len(d.DER) >= 100*1024 {
		t.Fatalf("delta is %d bytes, budget 102400", len(d.DER))
	}
	parsed, err := x509.ParseRevocationList(d.DER)
	if err != nil || len(parsed.RevokedCertificateEntries) != 1500 {
		t.Fatalf("parse: %v entries=%d", err, len(parsed.RevokedCertificateEntries))
	}
}

func TestDeltaCRLOpenSSLVerify(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	f := newDeltaFixture(t, time.Hour, 15*time.Minute)
	f.revoke(1, time.Now().Add(-time.Hour))
	base, err := f.gen.Generate("ca1")
	if err != nil {
		t.Fatal(err)
	}
	f.revoke(2, time.Now())
	d, err := f.gen.GenerateDelta("ca1")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.cert.Raw})
	for name, data := range map[string][]byte{"ca.pem": caPEM, "delta.der": d.DER, "base.der": base.DER} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) string {
		out, err := exec.Command(openssl, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	if out := run("crl", "-inform", "DER", "-in", filepath.Join(dir, "delta.der"), "-CAfile", filepath.Join(dir, "ca.pem"), "-noout", "-verify"); !strings.Contains(out, "verify OK") {
		t.Fatalf("delta verify: %s", out)
	}
	if out := run("crl", "-inform", "DER", "-in", filepath.Join(dir, "delta.der"), "-noout", "-text"); !strings.Contains(out, "Delta CRL Indicator") {
		t.Fatalf("delta -text lacks indicator:\n%s", out)
	}
	if out := run("crl", "-inform", "DER", "-in", filepath.Join(dir, "base.der"), "-noout", "-text"); !strings.Contains(out, "Freshest CRL") {
		t.Fatalf("base -text lacks Freshest CRL:\n%s", out)
	}
}

func TestBaseCRLAdvertisesFreshestCRLOnlyInDeltaMode(t *testing.T) {
	has := func(der []byte) (bool, string) {
		p, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Extensions {
			if e.Id.Equal(oidFreshestCRL) {
				return true, string(e.Value)
			}
		}
		return false, ""
	}
	on := newDeltaFixture(t, time.Hour, time.Minute)
	b, _ := on.gen.Generate("ca1")
	if ok, v := has(b.DER); !ok || !strings.Contains(v, "http://crl.example.test/crl/ca1/delta.crl") {
		t.Fatalf("delta mode base lacks Freshest CRL pointer (ok=%v)", ok)
	}
	off := newDeltaFixture(t, time.Hour, 0)
	b, _ = off.gen.Generate("ca1")
	if ok, _ := has(b.DER); ok {
		t.Fatal("delta off: base must not carry Freshest CRL")
	}
}

func TestDeltaModeInvalidateKeepsFullDropsDelta(t *testing.T) {
	f := newDeltaFixture(t, time.Hour, 15*time.Minute)
	if _, err := f.gen.GenerateDelta("ca1"); err != nil {
		t.Fatal(err)
	}
	f.revoke(77, time.Now())
	f.gen.InvalidateCache(big.NewInt(77))
	if f.gen.GetCRL("ca1") == nil {
		t.Fatal("delta mode must keep the full CRL")
	}
	if f.gen.GetDelta("ca1") != nil {
		t.Fatal("delta mode must drop the delta")
	}
}

func TestDeltaOffInvalidateUnchanged(t *testing.T) {
	f := newDeltaFixture(t, time.Hour, 0)
	if _, err := f.gen.Generate("ca1"); err != nil {
		t.Fatal(err)
	}
	f.revoke(77, time.Now())
	f.gen.InvalidateCache(big.NewInt(77))
	if f.gen.GetCRL("ca1") != nil {
		t.Fatal("delta off: full CRL must be dropped")
	}
}

func TestDeltaOffServes404(t *testing.T) {
	f := newDeltaFixture(t, time.Hour, 0)
	rec := httptest.NewRecorder()
	f.gen.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/crl/ca1/delta.crl", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}

func TestDeltaHandlerServesDelta(t *testing.T) {
	f := newDeltaFixture(t, time.Hour, 20*time.Minute)
	rec := httptest.NewRecorder()
	f.gen.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/crl/ca1/delta.crl", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/pkix-crl" ||
		rec.Header().Get("Cache-Control") != "max-age=600, public" {
		t.Fatalf("code=%d hdr=%v", rec.Code, rec.Header())
	}
}

func TestAuditEventsGenerateAndDeltaGenerate(t *testing.T) {
	f := newDeltaFixture(t, time.Hour, 15*time.Minute)
	if _, err := f.gen.Generate("ca1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.gen.GenerateDelta("ca1"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.actions(), ",")
	if got != "crl.generate,crl.delta_generate" {
		t.Fatalf("events = %s", got)
	}
	if d := f.events[1].Detail; !strings.Contains(d, "base=1") || !strings.Contains(d, "entries=0") {
		t.Fatalf("delta detail = %q", d)
	}
}

func TestCRLStaleAlertWhenNextUpdatePassed(t *testing.T) {
	f := newDeltaFixture(t, time.Millisecond, 0)
	h := f.gen.Handler()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/crl/ca1.crl", nil))
	time.Sleep(20 * time.Millisecond)
	f.mu.Lock()
	f.events = nil
	f.mu.Unlock()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/crl/ca1.crl", nil))
	if a := f.actions(); len(a) < 2 || a[0] != "crl.stale" || a[1] != "crl.generate" {
		t.Fatalf("events = %v, want stale then generate", a)
	}

	// Regeneration failing after expiry still raises the alert.
	time.Sleep(20 * time.Millisecond)
	f.mu.Lock()
	f.events = nil
	f.caErr = fmt.Errorf("ca unavailable")
	f.mu.Unlock()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/crl/ca1.crl", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expired CRL must not be served, code=%d", rec.Code)
	}
	if a := f.actions(); len(a) == 0 || a[0] != "crl.stale" {
		t.Fatalf("events = %v, want crl.stale first", a)
	}
}

func TestParseCRLPath(t *testing.T) {
	cases := []struct {
		in    string
		ca    string
		delta bool
		ok    bool
	}{
		{"/crl/abc.crl", "abc", false, true},
		{"/crl/abc/delta.crl", "abc", true, true},
		{"/crl/x/delta.crl", "x", true, true},
		{"/crl/.crl", "", false, false},
		{"/crl//delta.crl", "", false, false},
		{"/crl/../etc.crl", "", false, false},
		{"/crl/a/b.crl", "", false, false},
		{"/crl/abc", "", false, false},
		{"/other/abc.crl", "", false, false},
	}
	for _, c := range cases {
		ca, delta, ok := parseCRLPath(c.in)
		if ca != c.ca || delta != c.delta || ok != c.ok {
			t.Errorf("parseCRLPath(%q) = (%q,%v,%v), want (%q,%v,%v)", c.in, ca, delta, ok, c.ca, c.delta, c.ok)
		}
	}
}

func TestCRLNumbersMonotonicAcrossBaseAndDelta(t *testing.T) {
	f := newDeltaFixture(t, time.Hour, time.Minute)
	var last *big.Int
	for i := 0; i < 3; i++ {
		b, _ := f.gen.Generate("ca1")
		d, _ := f.gen.GenerateDelta("ca1")
		for _, n := range []*big.Int{b.Number, d.Number} {
			if last != nil && n.Cmp(last) <= 0 {
				t.Fatalf("number %s not above %s", n, last)
			}
			last = n
		}
	}
}
