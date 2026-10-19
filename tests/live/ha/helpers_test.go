// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package ha_test is the W23-28 chaos harness and the W23-29 soak for two hub
// replicas on one Postgres. run.sh brings the stack up and exports the KK_HA_*
// variables; without them (or without KK_LIVE_HA / KK_HA_SOAK) every test
// skips, so `go test ./...` never starts containers.
package ha_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	goocsp "golang.org/x/crypto/ocsp"
)

type haEnv struct {
	aURL, bURL, dsn, token, project string
	pollMinutes                     int
}

func (e haEnv) container(service string) string { return e.project + "_" + service + "_1" }

// loadEnv skips the test unless gate is "1" and the run.sh variables are set.
func loadEnv(t *testing.T, gate string) haEnv {
	t.Helper()
	if os.Getenv(gate) != "1" {
		t.Skipf("set %s=1 (see tests/live/ha/run.sh) to run the HA harness", gate)
	}
	e := haEnv{
		aURL: os.Getenv("KK_HA_A_URL"), bURL: os.Getenv("KK_HA_B_URL"), dsn: os.Getenv("KK_HA_DSN"),
		token: os.Getenv("KK_HA_TOKEN"), project: os.Getenv("KK_HA_PROJECT"), pollMinutes: 1,
	}
	if e.project == "" {
		e.project = "kkha"
	}
	if v := os.Getenv("KK_HA_POLL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			e.pollMinutes = n
		}
	}
	if e.aURL == "" || e.bURL == "" || e.dsn == "" || e.token == "" {
		t.Fatal("KK_HA_A_URL, KK_HA_B_URL, KK_HA_DSN and KK_HA_TOKEN must be set by run.sh")
	}
	return e
}

// waitFor polls fn every interval until it returns true, errors fatally, or ctx ends.
func waitFor(ctx context.Context, interval time.Duration, fn func() (bool, error)) error {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		ok, err := fn()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tk.C:
		}
	}
}

func podman(args ...string) (string, error) {
	out, err := exec.Command("podman", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ---- hub API client ------------------------------------------------------

type hub struct {
	name, base, token string
	hc                *http.Client
	rc                *http.Client // /readyz probes: short, separate from the request timeout
}

func newHub(name, base, token string, timeout time.Duration) *hub {
	return &hub{name: name, base: strings.TrimRight(base, "/"), token: token,
		hc: &http.Client{Timeout: timeout, Transport: &http.Transport{MaxIdleConnsPerHost: 16}},
		rc: &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 4}}}
}

var xffCounter atomic.Uint64

// spoofIP gives each CRL/OCSP request its own client address. The hub limits
// CRL fetches to 30/min and OCSP to 200/min per client IP; run.sh's compose
// file trusts the podman gateway so the header is believed.
func spoofIP(req *http.Request) {
	n := xffCounter.Add(1)
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.%d.%d.%d", (n>>16)&255, (n>>8)&255, n&255))
}

// do returns the status (0 on transport error), the body and the error.
func (h *hub) do(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func (h *hub) ready() bool {
	resp, err := h.rc.Get(h.base + "/readyz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func jsonPath(b []byte, path ...string) (string, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	for _, p := range path {
		switch x := v.(type) {
		case map[string]any:
			v = x[p]
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i >= len(x) {
				return "", fmt.Errorf("bad index %q", p)
			}
			v = x[i]
		default:
			return "", fmt.Errorf("cannot descend into %T at %q", v, p)
		}
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("path %v is not a string", path)
	}
	return s, nil
}

// ---- fixtures ------------------------------------------------------------

type fixture struct {
	caID, tplID string
	issuer      *x509.Certificate
}

// setupFixture finds the CA, creates one ECDSA leaf template through A (B sees
// it through the shared templates file, see docker-compose.ha.yml) and loads
// the issuer certificate.
func setupFixture(t testing.TB, a *hub, b *hub) fixture {
	t.Helper()
	var f fixture
	st, body, err := a.do(http.MethodGet, "/api/v1/cas", nil)
	if err != nil || st != 200 {
		t.Fatalf("GET /cas on A: %d %v %.200s", st, err, body)
	}
	if f.caID, err = jsonPath(body, "data", "0", "id"); err != nil {
		t.Fatal(err)
	}
	st, body, err = a.do(http.MethodPost, "/api/v1/templates", map[string]any{
		"name": "ha-" + strconv.FormatInt(time.Now().UnixNano(), 36), "display_name": "HA leaf",
		"validity_period": "P30D", "key_usage": []string{"digitalSignature"}, "extended_key_usage": []string{"clientAuth"},
		"allowed_algorithms": []string{"ECDSA"}, "active": true,
	})
	if err != nil || st/100 != 2 {
		t.Fatalf("create template on A: %d %v %.200s", st, err, body)
	}
	if f.tplID, err = jsonPath(body, "data", "id"); err != nil {
		t.Fatal(err)
	}
	// B must see the same template before any load starts.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitFor(ctx, time.Second, func() (bool, error) {
		st, body, err := b.do(http.MethodGet, "/api/v1/templates/"+f.tplID, nil)
		return err == nil && st == 200 && len(body) > 0, nil
	}); err != nil {
		t.Fatalf("template %s not visible on B: %v", f.tplID, err)
	}
	st, body, err = a.do(http.MethodGet, "/api/v1/cas/"+f.caID+"/chain?format=pem", nil)
	if err != nil || st != 200 {
		t.Fatalf("CA chain: %d %v", st, err)
	}
	blk, _ := pem.Decode(body)
	if blk == nil {
		t.Fatal("CA certificate PEM missing from the chain endpoint")
	}
	if f.issuer, err = x509.ParseCertificate(blk.Bytes); err != nil {
		t.Fatal(err)
	}
	return f
}

func newCSR(cn string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

type issued struct {
	fingerprint string
	serial      *big.Int
}

// issue posts one issuance; status 0 means a transport error.
func (f fixture) issue(h *hub, cn string) (issued, int, []byte, error) {
	csr, err := newCSR(cn)
	if err != nil {
		return issued{}, 0, nil, err
	}
	st, body, err := h.do(http.MethodPost, "/api/v1/certificates", map[string]any{
		"ca_id": f.caID, "template_id": f.tplID, "csr_pem": csr,
	})
	if err != nil || st != http.StatusCreated {
		return issued{}, st, body, err
	}
	fp, err1 := jsonPath(body, "data", "fingerprint_sha256")
	sn, err2 := jsonPath(body, "data", "serial_number")
	n, ok := new(big.Int).SetString(sn, 10)
	if err1 != nil || err2 != nil || !ok {
		return issued{}, st, body, fmt.Errorf("201 without a usable fingerprint/serial: %v %v", err1, err2)
	}
	return issued{fingerprint: fp, serial: n}, st, body, nil
}

// ocspRequest builds a request for a serial under the issuer. Only the serial
// number of the stand-in certificate is read by ocsp.CreateRequest.
func (f fixture) ocspRequest(serial *big.Int) ([]byte, error) {
	return goocsp.CreateRequest(&x509.Certificate{SerialNumber: serial}, f.issuer, nil)
}

// ocspStatus asks base for the status of serial. ok is true only for a
// response whose signature verifies against the issuer; status is then set.
func (f fixture) ocspStatus(hc *http.Client, base string, serial *big.Int) (status int, ok bool, err error) {
	reqDER, err := f.ocspRequest(serial)
	if err != nil {
		return 0, false, err
	}
	hr, _ := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+"/ocsp", bytes.NewReader(reqDER))
	hr.Header.Set("Content-Type", "application/ocsp-request")
	spoofIP(hr)
	resp, err := hc.Do(hr)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	parsed, err := goocsp.ParseResponse(b, f.issuer)
	if err != nil {
		return 0, false, err
	}
	return parsed.Status, true, nil
}

func (f fixture) crlFetch(hc *http.Client, base string) error {
	hr, _ := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+"/crl/"+f.caID+".crl", nil)
	spoofIP(hr)
	resp, err := hc.Do(hr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	rl, err := x509.ParseRevocationList(b)
	if err != nil {
		return err
	}
	return rl.CheckSignatureFrom(f.issuer)
}

// ---- database assertions -------------------------------------------------

func openDB(t testing.TB, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// retryQuery runs fn until it succeeds or 60 s pass: the soak's Postgres
// restart can still be settling when the first assertion runs.
func retryQuery(db *sql.DB, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var last error
	err := waitFor(ctx, time.Second, func() (bool, error) {
		last = fn()
		return last == nil, nil
	})
	if err != nil && last != nil {
		return last
	}
	return err
}

type dupRow struct {
	Key   string
	Count int
}

func queryDups(db *sql.DB, q string) ([]dupRow, error) {
	var out []dupRow
	err := retryQuery(db, func() error {
		out = nil
		rows, err := db.Query(q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d dupRow
			var a, b sql.NullString
			if err := rows.Scan(&a, &b, &d.Count); err != nil {
				// two-column queries
				return err
			}
			d.Key = a.String + "/" + b.String
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

func queryCount(db *sql.DB, q string, args ...any) (int, error) {
	var n int
	err := retryQuery(db, func() error { return db.QueryRow(q, args...).Scan(&n) })
	return n, err
}

const (
	qDupSerials = `SELECT ca_id, serial_number, COUNT(*) FROM certificates GROUP BY 1,2 HAVING COUNT(*) > 1`
	qDupRenewal = `SELECT predecessor_fingerprint, '' AS pad, COUNT(*) FROM certificates WHERE predecessor_fingerprint IS NOT NULL GROUP BY 1 HAVING COUNT(*) > 1`
	qDupAlerts  = `SELECT resource_id, '' AS pad, COUNT(*) FROM audit_log WHERE action='renewal_notification_sent' AND outcome='success' AND COALESCE(change_summary,'') NOT LIKE 'rule_id=%' GROUP BY 1 HAVING COUNT(*) > 1`
)

// assertNoDuplicateRenewalsOrAlerts runs the two W23-28 queries and returns
// how many rows they examined, so a vacuous pass is visible in the log.
func assertNoDuplicateRenewalsOrAlerts(t testing.TB, db *sql.DB) (renewalRows, alertRows int) {
	t.Helper()
	d, err := queryDups(db, qDupRenewal)
	if err != nil {
		t.Errorf("duplicate-renewal query: %v", err)
	} else if len(d) > 0 {
		t.Errorf("duplicate renewals (predecessor_fingerprint): %v", d)
	}
	d, err = queryDups(db, qDupAlerts)
	if err != nil {
		t.Errorf("duplicate-alert query: %v", err)
	} else if len(d) > 0 {
		t.Errorf("duplicate alert deliveries: %v", d)
	}
	renewalRows, _ = queryCount(db, `SELECT COUNT(*) FROM certificates WHERE predecessor_fingerprint IS NOT NULL`)
	alertRows, _ = queryCount(db, `SELECT COUNT(*) FROM audit_log WHERE action='renewal_notification_sent' AND outcome='success' AND COALESCE(change_summary,'') NOT LIKE 'rule_id=%'`)
	return renewalRows, alertRows
}

// ---- readiness-aware balancer (stands in for the Service / LB) ------------

type transition struct {
	At      time.Time `json:"at"`
	Replica string    `json:"replica"`
	Ready   bool      `json:"ready"`
}

type replica struct {
	*hub
	isReady atomic.Bool
}

type balancer struct {
	reps []*replica
	rr   atomic.Uint64
	mu   sync.Mutex
	log  []transition
}

func newBalancer(hubs ...*hub) *balancer {
	b := &balancer{}
	for _, h := range hubs {
		r := &replica{hub: h}
		r.isReady.Store(r.ready())
		b.reps = append(b.reps, r)
		b.log = append(b.log, transition{At: time.Now(), Replica: h.name, Ready: r.isReady.Load()})
	}
	return b
}

// run probes /readyz of every replica each second until ctx ends.
func (b *balancer) run(ctx context.Context) {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		var wg sync.WaitGroup
		for _, r := range b.reps {
			wg.Add(1)
			go func(r *replica) {
				defer wg.Done()
				now := r.ready()
				if was := r.isReady.Swap(now); was != now {
					b.mu.Lock()
					b.log = append(b.log, transition{At: time.Now(), Replica: r.name, Ready: now})
					b.mu.Unlock()
				}
			}(r)
		}
		wg.Wait()
	}
}

// pick returns the next ready replica round-robin, or nil when none is ready.
func (b *balancer) pick() *replica {
	n := uint64(len(b.reps))
	start := b.rr.Add(1)
	for i := uint64(0); i < n; i++ {
		r := b.reps[(start+i)%n]
		if r.isReady.Load() {
			return r
		}
	}
	return nil
}

func (b *balancer) transitions() []transition {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]transition(nil), b.log...)
}
