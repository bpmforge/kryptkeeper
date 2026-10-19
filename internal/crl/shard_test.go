// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
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

const shardBase = "http://crl.example"

func randSerial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, shardSpace)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func revokedSet(t testing.TB, n int) []RevokedCert {
	out := make([]RevokedCert, n)
	now := time.Now().UTC().Add(-time.Hour)
	for i := range out {
		out[i] = RevokedCert{SerialNumber: randSerial(t), RevokedAt: now, ReasonCode: 1}
	}
	return out
}

type shardFixture struct {
	ca      *testCRLCA
	mu      sync.Mutex
	revoked []RevokedCert
	listed  int
	gen     *Generator
}

func newShardFixture(t testing.TB, n int, revoked []RevokedCert) *shardFixture {
	f := &shardFixture{revoked: revoked}
	switch tt := t.(type) {
	case *testing.T:
		f.ca = newTestCRLCA(tt)
	case *testing.B:
		f.ca = newBenchCRLCA(tt)
	}
	f.gen = NewGenerator(
		func(string) ([]RevokedCert, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.listed++
			return f.revoked, nil
		},
		func(string) (*x509.Certificate, crypto.Signer, error) { return f.ca.cert, f.ca.key, nil },
		time.Hour,
	).WithShards(n, shardBase)
	return f
}

func newBenchCRLCA(b *testing.B) *testCRLCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bench CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		b.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCRLCA{cert: cert, key: key, id: "bench-ca"}
}

func TestShardIndexRangeAndBalance(t *testing.T) {
	const n, total = 8, 100000
	counts := make([]int, n)
	for i := 0; i < total; i++ {
		counts[ShardIndex(randSerial(t), n)]++
	}
	mean := float64(total) / n
	for i, c := range counts {
		if float64(c) < mean*0.8 || float64(c) > mean*1.2 {
			t.Errorf("shard %d has %d entries, mean %.0f", i, c, mean)
		}
	}
	over := new(big.Int).Add(shardSpace, big.NewInt(5))
	maxSerial := new(big.Int).Sub(shardSpace, big.NewInt(1))
	for _, c := range []struct {
		serial  *big.Int
		n, want int
	}{
		{over, 8, 7}, {big.NewInt(0), 8, 0}, {maxSerial, 8, 7}, {randSerial(t), 1, 0},
		{big.NewInt(-3), 8, 0}, {nil, 8, 0}, {randSerial(t), 0, 0},
	} {
		if got := ShardIndex(c.serial, c.n); got != c.want {
			t.Errorf("ShardIndex(%v,%d) = %d, want %d", c.serial, c.n, got, c.want)
		}
	}
}

func idpOf(t *testing.T, rl *x509.RevocationList) (url string) {
	t.Helper()
	for _, e := range rl.Extensions {
		if !e.Id.Equal(oidIssuingDistributionPoint) {
			continue
		}
		if !e.Critical {
			t.Fatal("IDP must be critical")
		}
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(e.Value, &seq); err != nil {
			t.Fatal(err)
		}
		i := bytes.Index(e.Value, []byte("http://"))
		if i < 0 {
			t.Fatal("no URI in IDP")
		}
		return string(e.Value[i:])
	}
	t.Fatal("no IDP extension")
	return ""
}

func TestShardCRLsPartitionRevocationsWithIDP(t *testing.T) {
	const n = 4
	revoked := revokedSet(t, 5000)
	f := newShardFixture(t, n, revoked)
	set, err := f.gen.GenerateAllShards("ca-1")
	if err != nil || len(set) != n {
		t.Fatalf("GenerateAllShards: %v len=%d", err, len(set))
	}
	if f.listed != 1 {
		t.Fatalf("revoked list scanned %d times, want 1", f.listed)
	}
	seen := map[string]int{}
	for i, s := range set {
		rl, err := x509.ParseRevocationList(s.DER)
		if err != nil {
			t.Fatalf("shard %d parse: %v", i, err)
		}
		if err := rl.CheckSignatureFrom(f.ca.cert); err != nil {
			t.Fatalf("shard %d signature: %v", i, err)
		}
		if got, want := idpOf(t, rl), ShardURL(shardBase, "ca-1", i); got != want {
			t.Fatalf("shard %d IDP %q, want %q", i, got, want)
		}
		for _, e := range rl.RevokedCertificateEntries {
			if ShardIndex(e.SerialNumber, n) != i {
				t.Fatalf("serial in wrong shard %d", i)
			}
			seen[e.SerialNumber.String()]++
		}
	}
	if len(seen) != len(revoked) {
		t.Fatalf("union has %d serials, want %d", len(seen), len(revoked))
	}
	for s, c := range seen {
		if c != 1 {
			t.Fatalf("serial %s in %d shards", s, c)
		}
	}
}

func TestShardNumbersArePerShardAndMonotonic(t *testing.T) {
	f := newShardFixture(t, 3, revokedSet(t, 10))
	a, _ := f.gen.GenerateAllShards("ca-1")
	b, _ := f.gen.GenerateAllShards("ca-1")
	for i := range a {
		if b[i].Number.Cmp(a[i].Number) <= 0 || a[i].Number.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("shard %d numbers %s then %s", i, a[i].Number, b[i].Number)
		}
	}
}

func TestOpenSSLVerifiesRevokedAndGoodAgainstShard(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	const n = 4
	ca := newTestCRLCA(t)
	mkLeaf := func() (*x509.Certificate, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial := randSerial(t)
		tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "leaf"},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			CRLDistributionPoints: []string{ShardURL(shardBase, ca.id, ShardIndex(serial, n))}}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	good, goodPEM := mkLeaf()
	bad, badPEM := mkLeaf()
	gen := NewGenerator(
		func(string) ([]RevokedCert, error) {
			return []RevokedCert{{SerialNumber: bad.SerialNumber, RevokedAt: time.Now().Add(-time.Minute), ReasonCode: 1}}, nil
		},
		func(string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		time.Hour,
	).WithShards(n, shardBase)
	set, err := gen.GenerateAllShards(ca.id)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caPEM := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
	verify := func(leafPEM []byte, c *x509.Certificate) string {
		shard := set[ShardIndex(c.SerialNumber, n)]
		out, _ := exec.Command(openssl, "verify", "-crl_check", "-CAfile", caPEM,
			"-CRLfile", write("shard.pem", shard.PEM), write("leaf.pem", leafPEM)).CombinedOutput()
		return string(out)
	}
	if out := verify(goodPEM, good); !strings.Contains(out, ": OK") {
		t.Fatalf("good leaf: %s", out)
	}
	if out := verify(badPEM, bad); !strings.Contains(out, "certificate revoked") {
		t.Fatalf("revoked leaf: %s", out)
	}
}

func TestHandlerServesShardsAndKeepsLegacyFullCRL(t *testing.T) {
	const n = 3
	revoked := revokedSet(t, 60)
	f := newShardFixture(t, n, revoked)
	h := f.gen.Handler()
	get := func(p string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		return w
	}
	for i := 0; i < n; i++ {
		w := get("/crl/ca-1/s" + string(rune('0'+i)) + ".crl")
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/pkix-crl" {
			t.Fatalf("shard %d: %d %q", i, w.Code, w.Header().Get("Content-Type"))
		}
	}
	for _, p := range []string{"/crl/ca-1/s3.crl", "/crl/ca-1/s-1.crl", "/crl/ca-1/s01.crl", "/crl/ca-1/sx.crl"} {
		if w := get(p); w.Code != 404 {
			t.Errorf("%s = %d, want 404", p, w.Code)
		}
	}
	w := get("/crl/ca-1.crl")
	if w.Code != 200 {
		t.Fatalf("full CRL %d", w.Code)
	}
	rl, err := x509.ParseRevocationList(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(rl.RevokedCertificateEntries) != len(revoked) {
		t.Fatalf("full CRL has %d entries, want %d", len(rl.RevokedCertificateEntries), len(revoked))
	}
	for _, e := range rl.Extensions {
		if e.Id.Equal(oidIssuingDistributionPoint) {
			t.Fatal("legacy full CRL must carry no IDP")
		}
	}
	// Sharding off: shard paths 404.
	off := newShardFixture(t, 1, revoked)
	w = httptest.NewRecorder()
	off.gen.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/crl/ca-1/s0.crl", nil))
	if w.Code != 404 {
		t.Fatalf("sharding off: shard path = %d", w.Code)
	}
}

func TestShardCachesInvalidatedOnRevoke(t *testing.T) {
	f := newShardFixture(t, 2, revokedSet(t, 20))
	if _, err := f.gen.GenerateAllShards("ca-1"); err != nil {
		t.Fatal(err)
	}
	if f.gen.GetShard("ca-1", 0) == nil || f.gen.GetShard("ca-1", 1) == nil {
		t.Fatal("shards not cached")
	}
	f.gen.InvalidateCache(randSerial(t)) // not revoked: untouched
	if f.gen.GetShard("ca-1", 0) == nil {
		t.Fatal("unrelated serial dropped the cache")
	}
	f.gen.InvalidateCache(f.revoked[0].SerialNumber)
	if f.gen.GetShard("ca-1", 0) != nil || f.gen.GetShard("ca-1", 1) != nil {
		t.Fatal("shards survived a revoke of a listed serial")
	}
	if _, err := f.gen.GenerateAllShards("ca-1"); err != nil {
		t.Fatal(err)
	}
	f.gen.SyncVersion("a") // first call only records the stamp
	if !f.gen.SyncVersion("b") {
		t.Fatal("changed stamp not reported")
	}
	if f.gen.GetShard("ca-1", 0) != nil {
		t.Fatal("stamp change must drop shard caches")
	}
}

func TestShardCountFromEnv(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{{"", 1}, {"0", 1}, {"abc", 1}, {"-4", 1}, {"8", 8}, {"1000", 256}} {
		t.Setenv("KRYPTKEEPER_CRL_SHARDS", c.in)
		if got := ShardCountFromEnv(); got != c.want {
			t.Errorf("%q -> %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseCRLRequestTable(t *testing.T) {
	for _, c := range []struct {
		p    string
		want crlRequest
		ok   bool
	}{
		{"/crl/ca-1/s0.crl", crlRequest{"ca-1", 0, false}, true},
		{"/crl/ca-1/s12.crl", crlRequest{"ca-1", 12, false}, true},
		{"/crl/ca-1.crl", crlRequest{"ca-1", -1, false}, true},
		{"/crl/ca-1/delta.crl", crlRequest{"ca-1", -1, true}, true},
		{"/crl/ca-1/s.crl", crlRequest{}, false},
		{"/crl/../s0.crl", crlRequest{}, false},
		{"/crl//s0.crl", crlRequest{}, false},
		{"/other/ca-1/s0.crl", crlRequest{}, false},
		{"/crl/a/b/s0.crl", crlRequest{}, false},
	} {
		got, ok := parseCRLRequest(c.p)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s = %+v,%v want %+v,%v", c.p, got, ok, c.want, c.ok)
		}
	}
}

func TestShardedCRLGenerationUnder2sAt100kRevocations(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	f := newShardFixture(t, 8, revokedSet(t, 100000))
	start := time.Now()
	set, err := f.gen.GenerateAllShards("ca-1")
	if err != nil {
		t.Fatal(err)
	}
	full, err := f.gen.Generate("ca-1")
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	bytesTotal := len(full.DER)
	for _, s := range set {
		bytesTotal += len(s.DER)
	}
	t.Logf("100000 revocations: 8 shards + full CRL, %d bytes total, %s", bytesTotal, took)
	// The 2s budget is a production-build target; the race detector slows
	// generation 5-10x, so only the functional checks apply under -race.
	if !raceEnabled && took >= 2*time.Second {
		t.Fatalf("took %s, want < 2s", took)
	}
}

func BenchmarkGenerate100k(b *testing.B) {
	f := newShardFixture(b, 8, revokedSet(b, 100000))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.gen.GenerateAllShards("ca-1"); err != nil {
			b.Fatal(err)
		}
		if _, err := f.gen.Generate("ca-1"); err != nil {
			b.Fatal(err)
		}
	}
}
