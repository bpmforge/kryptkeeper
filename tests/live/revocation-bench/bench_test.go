// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package revocationbench_test measures CRL generation at scale, OCSP latency
// under open-loop load, and revoke-to-visible time on a second replica
// (W23-52). Every test skips unless KK_LIVE_REVBENCH=1; run.sh sets it. Only
// measured values are written to the result JSON: a leg that did not run is
// null, never a guess.
package revocationbench_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/crl"
	"kryptkeeper/internal/ocsp"
)

// Published targets (docs/release/REVOCATION_BENCH_v0.11.md).
const (
	targetCRL100kSeconds = 2.0
	targetOCSPP99Ms      = 50.0
	targetReplicaSeconds = 60.0
)

type crlResult struct {
	Revocations int     `json:"revocations"`
	DERBytes    int     `json:"der_bytes"`
	GenMsMedian float64 `json:"gen_ms_median"`
	HeapDeltaMB float64 `json:"heap_delta_mb"` // retained heap after generation (the cached CRL), not peak
	AllocMB     float64 `json:"alloc_mb"`      // bytes allocated during one generation
}

type ocspResult struct {
	RPS     int     `json:"rps"`
	Seconds float64 `json:"seconds"`
	N       int     `json:"n"`
	Errors  int     `json:"errors"`
	P50Ms   float64 `json:"p50_ms"`
	P95Ms   float64 `json:"p95_ms"`
	P99Ms   float64 `json:"p99_ms"`
	MaxMs   float64 `json:"max_ms"`
}

type replicaResult struct {
	Certs         int       `json:"certs"`
	CRLSeconds    []float64 `json:"crl_s"`
	OCSPSeconds   []float64 `json:"ocsp_s"`
	MaxSeconds    float64   `json:"max_s"`
	MedianSeconds float64   `json:"median_s"`
	HubCRLRegenMs []float64 `json:"hub_crl_regen_ms,omitempty"`
}

type results struct {
	Env          map[string]string      `json:"env"`
	CRL          []crlResult            `json:"crl"`
	OCSP         map[string]*ocspResult `json:"ocsp"`
	OCSPAttached *ocspResult            `json:"ocsp_attached"`
	Replica      *replicaResult         `json:"replica"`
	Targets      map[string]float64     `json:"targets"`
	Pass         map[string]*bool       `json:"pass"`
}

var (
	resMu sync.Mutex
	res   = results{OCSP: map[string]*ocspResult{}, Targets: map[string]float64{
		"crl_100k_s": targetCRL100kSeconds, "ocsp_p99_ms": targetOCSPP99Ms, "replica_visible_s": targetReplicaSeconds,
	}}
)

func TestMain(m *testing.M) {
	code := m.Run()
	if os.Getenv("KK_LIVE_REVBENCH") == "1" {
		if err := writeResults(); err != nil {
			fmt.Fprintln(os.Stderr, "write results:", err)
			code = 1
		}
	}
	os.Exit(code)
}

func boolp(b bool) *bool { return &b }

func writeResults() error {
	resMu.Lock()
	defer resMu.Unlock()
	res.Env = captureEnv()
	res.Pass = map[string]*bool{"crl_100k": nil, "ocsp_p99": nil, "replica": nil}
	for _, c := range res.CRL {
		if c.Revocations == 100000 {
			res.Pass["crl_100k"] = boolp(c.GenMsMedian/1000 < targetCRL100kSeconds)
		}
	}
	if cold := res.OCSP["cold"]; cold != nil {
		ok := cold.P99Ms < targetOCSPP99Ms && cold.Errors == 0
		if a := res.OCSPAttached; a != nil {
			ok = ok && a.P99Ms < targetOCSPP99Ms && a.Errors == 0
		}
		res.Pass["ocsp_p99"] = boolp(ok)
	}
	if r := res.Replica; r != nil {
		res.Pass["replica"] = boolp(r.MaxSeconds < targetReplicaSeconds)
	}
	out := os.Getenv("KK_BENCH_OUT")
	if out == "" {
		out = "results/last.json"
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(b, '\n'), 0o644)
}

func sh(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func captureEnv() map[string]string {
	env := map[string]string{
		"uname":     sh("uname", "-sm"),
		"cores":     strconv.Itoa(runtime.NumCPU()),
		"go":        runtime.Version(),
		"commit":    sh("git", "rev-parse", "--short", "HEAD"),
		"utc":       time.Now().UTC().Format(time.RFC3339),
		"db_engine": os.Getenv("KK_DB_ENGINE"),
	}
	if cpu := sh("sysctl", "-n", "machdep.cpu.brand_string"); cpu != "" {
		env["cpu"] = cpu
		if mem, err := strconv.ParseInt(sh("sysctl", "-n", "hw.memsize"), 10, 64); err == nil {
			env["ram_gb"] = strconv.FormatInt(mem>>30, 10)
		}
		env["os"] = sh("sw_vers", "-productVersion")
	} else if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "model name") {
				env["cpu"] = strings.TrimSpace(l[strings.Index(l, ":")+1:])
				break
			}
		}
		if m, err := os.ReadFile("/proc/meminfo"); err == nil {
			f := strings.Fields(string(m))
			if len(f) >= 2 {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					env["ram_gb"] = strconv.FormatInt(kb>>20, 10)
				}
			}
		}
	}
	// The machine is often shared; the 1/5/15 minute load goes next to the numbers.
	if l := sh("sysctl", "-n", "vm.loadavg"); l != "" {
		env["loadavg_at_end"] = strings.Trim(l, "{} ")
	} else if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		env["loadavg_at_end"] = strings.Join(strings.Fields(string(b))[:3], " ")
	}
	if v := os.Getenv("KK_BENCH_NOTE"); v != "" {
		env["note"] = v
	}
	return env
}

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("KK_LIVE_REVBENCH") != "1" {
		t.Skip("set KK_LIVE_REVBENCH=1 (see run.sh) to run the revocation benchmark")
	}
}

var ipCounter atomic.Uint64

// spoofClientIP gives each request its own client address through
// X-Forwarded-For when KK_BENCH_XFF=1. The hub rate-limits CRL (30/min) and
// OCSP (200/min) per client IP, so a single-source load generator would only
// measure the limiter. The hub must run with APP_TRUSTED_PROXY_CIDRS covering
// the generator's address for the header to be believed; the published
// numbers say when this was on.
func spoofClientIP(req *http.Request) {
	if os.Getenv("KK_BENCH_XFF") != "1" {
		return
	}
	n := ipCounter.Add(1)
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.%d.%d.%d", (n>>16)&255, (n>>8)&255, n&255))
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

type benchCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newBenchCA(t *testing.T) *benchCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Revocation Bench CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &benchCA{cert: cert, key: key}
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func TestCRLScale(t *testing.T) {
	requireLive(t)
	ca := newBenchCA(t)
	for _, field := range strings.Split(envStr("KK_BENCH_SIZES", "10000,100000,1000000"), ",") {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || n <= 0 {
			t.Fatalf("bad KK_BENCH_SIZES entry %q", field)
		}
		revoked := make([]crl.RevokedCert, n) // built outside the timer
		at := time.Now().UTC().Add(-time.Hour)
		for i := range revoked {
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			if err != nil {
				t.Fatal(err)
			}
			revoked[i] = crl.RevokedCert{SerialNumber: serial, RevokedAt: at, ReasonCode: 1}
		}
		gen := crl.NewGenerator(
			func(string) ([]crl.RevokedCert, error) { return revoked, nil },
			func(string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
			time.Hour,
		)
		runtime.GC()
		var before, mid, after runtime.MemStats
		runtime.ReadMemStats(&before)
		var ms []float64
		var last *crl.GeneratedCRL
		for i := 0; i < 3; i++ {
			if i == 2 {
				runtime.ReadMemStats(&mid)
			}
			start := time.Now()
			last, err = gen.Generate("bench-ca")
			if err != nil {
				t.Fatal(err)
			}
			ms = append(ms, float64(time.Since(start).Microseconds())/1000)
		}
		runtime.ReadMemStats(&after)
		runtime.GC()
		var settled runtime.MemStats
		runtime.ReadMemStats(&settled)
		r := crlResult{
			Revocations: n, DERBytes: len(last.DER), GenMsMedian: round(median(ms)),
			HeapDeltaMB: round(float64(int64(settled.HeapAlloc)-int64(before.HeapAlloc)) / (1 << 20)),
			AllocMB:     round(float64(after.TotalAlloc-mid.TotalAlloc) / (1 << 20)),
		}
		t.Logf("CRL %d revocations: %d bytes, median %.1f ms (runs %v)", n, r.DERBytes, r.GenMsMedian, ms)
		resMu.Lock()
		res.CRL = append(res.CRL, r)
		resMu.Unlock()
		revoked, last = nil, nil
		runtime.GC()
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func round(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// loadResult runs an open-loop load: request i is due at start+i/rps and is
// fired then regardless of earlier replies, and its latency is measured from
// the due time, so a stalled server shows as latency instead of being hidden
// by a slow client (coordinated omission).
func openLoop(t *testing.T, client *http.Client, url string, bodies [][]byte, rps, seconds int) *ocspResult {
	t.Helper()
	total := rps * seconds
	lat := make([]float64, total)
	var errs int
	var emu sync.Mutex
	var wg sync.WaitGroup
	interval := time.Second / time.Duration(rps)
	start := time.Now()
	for i := 0; i < total; i++ {
		due := start.Add(time.Duration(i) * interval)
		if d := time.Until(due); d > 0 {
			time.Sleep(d)
		}
		wg.Add(1)
		go func(i int, due time.Time) {
			defer wg.Done()
			ok := false
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(bodies[i%len(bodies)]))
			if err == nil {
				req.Header.Set("Content-Type", "application/ocsp-request")
				spoofClientIP(req)
				var resp *http.Response
				if resp, err = client.Do(req); err == nil {
					b, rerr := io.ReadAll(resp.Body)
					resp.Body.Close()
					// An OCSP error response is a 5-byte DER; a signed one is far larger.
					ok = rerr == nil && resp.StatusCode == http.StatusOK && len(b) > 64
				}
			}
			lat[i] = float64(time.Since(due).Microseconds()) / 1000
			if !ok {
				emu.Lock()
				errs++
				emu.Unlock()
			}
		}(i, due)
	}
	wg.Wait()
	s := append([]float64(nil), lat...)
	sort.Float64s(s)
	pct := func(p float64) float64 { return round(s[min(len(s)-1, int(float64(len(s))*p))]) }
	return &ocspResult{RPS: rps, Seconds: round(time.Since(start).Seconds()), N: total, Errors: errs,
		P50Ms: pct(0.50), P95Ms: pct(0.95), P99Ms: pct(0.99), MaxMs: round(s[len(s)-1])}
}

func loadClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns: 1024, MaxIdleConnsPerHost: 512, IdleConnTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

func TestOCSPLoad(t *testing.T) {
	requireLive(t)
	rps, seconds := envInt("KK_BENCH_OCSP_RPS", 500), envInt("KK_BENCH_OCSP_SECONDS", 30)
	total := rps * seconds
	ca := newBenchCA(t)

	// 10% of serials are revoked; the status lookup is an in-memory map, so
	// this leg isolates the responder (signing, cache, HTTP), not a database.
	revokedSet := map[string]bool{}
	bodies := make([][]byte, total)
	for i := range bodies {
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatal(err)
		}
		if i%10 == 0 {
			revokedSet[serial.String()] = true
		}
		b, err := goocsp.CreateRequest(&x509.Certificate{SerialNumber: serial}, ca.cert, nil)
		if err != nil {
			t.Fatal(err)
		}
		bodies[i] = b
	}
	responder := ocsp.NewResponder(
		func(serial *big.Int, _ *x509.Certificate) (bool, time.Time, int, error) {
			if revokedSet[serial.String()] {
				return true, time.Now().Add(-time.Hour).UTC(), 1, nil
			}
			return false, time.Time{}, 0, nil
		},
		func([]byte) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		24*time.Hour, 200000,
	)
	srv := httptest.NewServer(responder.Handler())
	defer srv.Close()
	client := loadClient()

	// Correctness spot check before timing: one revoked and one good response
	// must verify against the CA.
	for _, i := range []int{0, 1} {
		resp, err := client.Post(srv.URL, "application/ocsp-request", bytes.NewReader(bodies[i]))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		parsed, err := goocsp.ParseResponse(b, ca.cert)
		if err != nil {
			t.Fatalf("response %d does not verify: %v", i, err)
		}
		if want := map[int]int{0: goocsp.Revoked, 1: goocsp.Good}[i]; parsed.Status != want {
			t.Fatalf("response %d status %d, want %d", i, parsed.Status, want)
		}
	}
	// The spot check cached bodies 0 and 1; start cold from a fresh responder.
	responder.SyncVersion("reset-a")
	responder.SyncVersion("reset-b")

	for _, phase := range []string{"cold", "warm"} {
		r := openLoop(t, client, srv.URL, bodies, rps, seconds)
		t.Logf("OCSP %s: n=%d errors=%d p50=%.2fms p95=%.2fms p99=%.2fms max=%.2fms", phase, r.N, r.Errors, r.P50Ms, r.P95Ms, r.P99Ms, r.MaxMs)
		resMu.Lock()
		res.OCSP[phase] = r
		resMu.Unlock()
		if phase == "cold" && (r.Errors != 0 || r.P99Ms >= targetOCSPP99Ms) {
			t.Errorf("cold p99 %.2f ms / %d errors misses the %.0f ms target", r.P99Ms, r.Errors, targetOCSPP99Ms)
		}
	}
}

func mustPEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOCSPLoadAttached(t *testing.T) {
	requireLive(t)
	url, leafPath, issuerPath := os.Getenv("KK_BENCH_OCSP_URL"), os.Getenv("KK_BENCH_LEAF_PEM"), os.Getenv("KK_BENCH_ISSUER_PEM")
	if url == "" || leafPath == "" || issuerPath == "" {
		t.Skip("set KK_BENCH_OCSP_URL, KK_BENCH_LEAF_PEM, KK_BENCH_ISSUER_PEM to load a running hub")
	}
	body, err := goocsp.CreateRequest(mustPEM(t, leafPath), mustPEM(t, issuerPath), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := openLoop(t, loadClient(), url, [][]byte{body}, envInt("KK_BENCH_OCSP_RPS", 500), envInt("KK_BENCH_OCSP_SECONDS", 30))
	t.Logf("OCSP attached: n=%d errors=%d p50=%.2fms p99=%.2fms max=%.2fms", r.N, r.Errors, r.P50Ms, r.P99Ms, r.MaxMs)
	resMu.Lock()
	res.OCSPAttached = r
	resMu.Unlock()
	if r.Errors != 0 || r.P99Ms >= targetOCSPP99Ms {
		t.Errorf("attached p99 %.2f ms / %d errors misses the %.0f ms target", r.P99Ms, r.Errors, targetOCSPP99Ms)
	}
}

// hubAPI is a tiny client for the hub REST API. The token goes only in the
// Authorization header and is never logged.
type hubAPI struct {
	base, token string
	c           *http.Client
}

func newHubAPI(t *testing.T, base string) *hubAPI {
	t.Helper()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p := os.Getenv("KK_CACERT"); p != "" {
		pool := x509.NewCertPool()
		b, err := os.ReadFile(p)
		if err != nil || !pool.AppendCertsFromPEM(b) {
			t.Fatalf("KK_CACERT %s unusable", p)
		}
		cfg.RootCAs = pool
	}
	return &hubAPI{base: strings.TrimRight(base, "/"), token: os.Getenv("KK_TOKEN"),
		c: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}}
}

func (h *hubAPI) do(t *testing.T, method, path string, body any) []byte {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("%s %s: HTTP %d: %.200s", method, path, resp.StatusCode, b)
	}
	return b
}

func jsonField(t *testing.T, b []byte, path ...string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, p := range path {
		switch x := v.(type) {
		case map[string]any:
			v = x[p]
		case []any:
			i, _ := strconv.Atoi(p)
			if i >= len(x) {
				t.Fatalf("path %v: index %d out of range", path, i)
			}
			v = x[i]
		default:
			t.Fatalf("path %v: cannot descend into %T", path, v)
		}
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("path %v is not a string", path)
	}
	return s
}

func TestRevokeVisibleOnSecondReplica(t *testing.T) {
	requireLive(t)
	aURL, bURL, bRev := os.Getenv("KK_A_URL"), os.Getenv("KK_B_URL"), os.Getenv("KK_B_REVOCATION_URL")
	if aURL == "" || bURL == "" || bRev == "" || os.Getenv("KK_TOKEN") == "" {
		t.Skip("set KK_A_URL, KK_B_URL, KK_B_REVOCATION_URL and KK_TOKEN to measure revoke visibility across replicas")
	}
	certs := envInt("KK_BENCH_REPLICA_CERTS", 5)
	a := newHubAPI(t, aURL)
	aRev := envStr("KK_A_REVOCATION_URL", aURL)
	plain := &http.Client{Timeout: 30 * time.Second}

	caID := os.Getenv("KK_CA_ID")
	if caID == "" {
		caID = jsonField(t, a.do(t, http.MethodGet, "/api/v1/cas", nil), "data", "0", "id")
	}
	// The chain endpoint returns the CA certificate first.
	blk, _ := pem.Decode(a.do(t, http.MethodGet, "/api/v1/cas/"+caID+"/chain?format=pem", nil))
	if blk == nil {
		t.Fatal("CA certificate PEM missing from the chain endpoint")
	}
	issuer, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tpl := jsonField(t, a.do(t, http.MethodPost, "/api/v1/templates", map[string]any{
		"name": "revbench-" + strconv.FormatInt(time.Now().UnixNano(), 36), "display_name": "Revocation bench leaf",
		"validity_period": "P30D", "key_usage": []string{"digitalSignature"}, "extended_key_usage": []string{"clientAuth"},
		"allowed_algorithms": []string{"ECDSA"}, "active": true,
	}), "data", "id")

	fetchCRL := func(base string) (*x509.RevocationList, time.Duration) {
		start := time.Now()
		req, _ := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+"/crl/"+caID+".crl", nil)
		spoofClientIP(req)
		resp, err := plain.Do(req)
		if err != nil {
			t.Fatalf("CRL fetch: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		el := time.Since(start)
		rl, err := x509.ParseRevocationList(b)
		if err != nil {
			t.Fatalf("CRL parse (HTTP %d): %v", resp.StatusCode, err)
		}
		return rl, el
	}
	ocspRevoked := func(req []byte) bool {
		hr, _ := http.NewRequest(http.MethodPost, strings.TrimRight(bRev, "/")+"/ocsp", bytes.NewReader(req))
		hr.Header.Set("Content-Type", "application/ocsp-request")
		spoofClientIP(hr)
		resp, err := plain.Do(hr)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		parsed, err := goocsp.ParseResponse(b, issuer)
		return err == nil && parsed.Status == goocsp.Revoked
	}

	out := &replicaResult{Certs: certs}
	for i := 0; i < certs; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: fmt.Sprintf("revbench-%d", i)}}, key)
		if err != nil {
			t.Fatal(err)
		}
		issued := a.do(t, http.MethodPost, "/api/v1/certificates", map[string]any{
			"ca_id": caID, "template_id": tpl,
			"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		})
		fp := jsonField(t, issued, "data", "fingerprint_sha256")
		leafBlk, _ := pem.Decode(a.do(t, http.MethodGet, "/api/v1/certificates/"+fp+"/download?format=pem", nil))
		if leafBlk == nil {
			t.Fatal("leaf PEM missing")
		}
		leaf, err := x509.ParseCertificate(leafBlk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		ocspReq, err := goocsp.CreateRequest(leaf, issuer, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Warm B's caches so the measurement is a cache INVALIDATION, not a first fill.
		if ocspRevoked(ocspReq) {
			t.Fatal("leaf already revoked before the test revoked it")
		}
		fetchCRL(bRev)

		a.do(t, http.MethodPost, "/api/v1/certificates/"+fp+"/revoke", map[string]any{"reason_code": 1, "reason_text": "revocation bench"})
		revokedAt := time.Now()

		_, regen := fetchCRL(aRev)
		out.HubCRLRegenMs = append(out.HubCRLRegenMs, round(float64(regen.Microseconds())/1000))

		inCRL := func() bool {
			rl, _ := fetchCRL(bRev)
			for _, e := range rl.RevokedCertificateEntries {
				if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
					return true
				}
			}
			return false
		}
		var crlS, ocspS float64
		deadline := revokedAt.Add(time.Duration(targetReplicaSeconds*2) * time.Second)
		for crlS == 0 || ocspS == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("cert %d not visible on B within %.0f s (crl=%.2f ocsp=%.2f)", i, targetReplicaSeconds*2, crlS, ocspS)
			}
			if crlS == 0 && inCRL() {
				crlS = time.Since(revokedAt).Seconds()
			}
			if ocspS == 0 && ocspRevoked(ocspReq) {
				ocspS = time.Since(revokedAt).Seconds()
			}
			time.Sleep(100 * time.Millisecond)
		}
		out.CRLSeconds = append(out.CRLSeconds, round(crlS))
		out.OCSPSeconds = append(out.OCSPSeconds, round(ocspS))
		t.Logf("cert %d: visible on B via CRL after %.2f s, OCSP after %.2f s", i, crlS, ocspS)
	}
	all := append(append([]float64(nil), out.CRLSeconds...), out.OCSPSeconds...)
	sort.Float64s(all)
	out.MaxSeconds, out.MedianSeconds = all[len(all)-1], median(all)
	resMu.Lock()
	res.Replica = out
	resMu.Unlock()
	if out.MaxSeconds >= targetReplicaSeconds {
		t.Errorf("max visibility %.2f s misses the %.0f s target", out.MaxSeconds, targetReplicaSeconds)
	}
}
