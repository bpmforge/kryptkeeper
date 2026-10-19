// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command fixture is the W27-34 storm test's world: a rate-limited stub ACME CA,
// a fake Kubernetes Secrets API with per-target TLS verify listeners
// (`fixture serve`), and the seeder that loads N due certificates into a hub
// through its public API (`fixture seed`). TEST-ONLY.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fixture serve|seed [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "seed":
		err = seed(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		log.Fatalf("fixture %s: %v", os.Args[1], err)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	out := fs.String("out", "/out", "directory that receives ca.pem (the stub root)")
	acmeAddr := fs.String("acme-addr", ":9443", "stub ACME CA listen address (HTTPS)")
	k8sAddr := fs.String("k8s-addr", ":9444", "fake Kubernetes API listen address (HTTPS)")
	token := fs.String("k8s-token", "storm", "bearer token the fake API requires")
	limit := fs.Int("limit", 100, "new orders per window")
	window := fs.Duration("window", 15*time.Second, "rate-limit window (real time)")
	service := fs.Duration("service", 50*time.Millisecond, "per-order issuance time (real time)")
	grace := fs.Duration("grace", time.Second, "requests within this long of a 429 count as concurrent, not late")
	verifyBase := fs.Int("verify-base", 21000, "first per-target verify port")
	verifyCount := fs.Int("verify-count", 0, "number of per-target verify listeners")
	names := fs.String("names", "fixture", "DNS name the HTTPS listeners present")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ca, err := newStubCA(stubConfig{Limit: *limit, Window: *window, Service: *service, Grace: *grace})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out+"/ca.pem", ca.RootPEM(), 0o644); err != nil {
		return err
	}
	crt, key, err := ca.signServerCert([]string{*names, "localhost"})
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}

	fake := newK8sFake(*token)
	if *verifyCount > 0 {
		if _, err := fake.serveVerifyListeners("", *verifyBase, *verifyCount); err != nil {
			return err
		}
		log.Printf("fixture: %d verify listeners on %d..%d", *verifyCount, *verifyBase, *verifyBase+*verifyCount-1)
	}
	errc := make(chan error, 2)
	go func() {
		errc <- (&http.Server{Addr: *acmeAddr, Handler: ca.Handler(), TLSConfig: tlsCfg.Clone(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServeTLS("", "")
	}()
	go func() {
		errc <- (&http.Server{Addr: *k8sAddr, Handler: fake.Handler(), TLSConfig: tlsCfg.Clone(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServeTLS("", "")
	}()
	log.Printf("fixture: stub CA %s (limit %d per %s, service %s), fake k8s %s", *acmeAddr, *limit, *window, *service, *k8sAddr)
	return <-errc
}

type seedResult struct {
	Count       int   `json:"count"`
	SetupS      int64 `json:"setup_s"`  // credentials and targets
	ImportS     int64 `json:"import_s"` // certificates and takeovers
	BindS       int64 `json:"bind_s"`   // bindings: the storm starts here
	ExpiryUnix  int64 `json:"expiry_unix"`
	T0Unix      int64 `json:"t0_unix"` // all bindings in place
	RemainingS  int64 `json:"remaining_s"`
	Backoffs429 int64 `json:"backoffs_429"`
}

// seed loads N due certificates in four phases so that the renewal storm starts
// at one instant and every certificate has the same, known time left:
//
//  1. credentials and targets (slow; no certificate exists yet)
//  2. certificates (all expire at one instant) and their takeovers
//  3. certificate-target bindings, the only thing that makes the scheduler
//     act on a certificate, so t0 is when the last one lands
func seed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	hub := fs.String("hub", "", "hub base URL")
	tokenFlag := fs.String("token", "", "bootstrap bearer token (or KK_TOKEN)")
	count := fs.Int("count", 2000, "certificates to seed")
	cnTmpl := fs.String("cn-template", "storm-%04d.storm.test", "CN printf template")
	expiry := fs.Duration("expiry", 7*time.Minute, "time left on every certificate once seeding is done")
	allowance := fs.Duration("import-allowance", 3*time.Minute, "estimated time to import and take over every certificate; added to -expiry")
	directory := fs.String("directory", "https://fixture:9443/directory", "ACME directory URL as the hub sees it")
	k8sURL := fs.String("k8s-url", "https://fixture:9444", "fake Kubernetes API URL as the hub sees it")
	caPEMPath := fs.String("ca-pem", "", "stub root PEM the hub's k8s pusher trusts")
	verifyHost := fs.String("verify-host", "fixture", "host of the per-target verify listeners")
	verifyBase := fs.Int("verify-base", 21000, "first per-target verify port")
	workers := fs.Int("workers", 32, "concurrent seeders")
	if err := fs.Parse(args); err != nil {
		return err
	}
	token := *tokenFlag
	if token == "" {
		token = os.Getenv("KK_TOKEN")
	}
	if *hub == "" || token == "" || *caPEMPath == "" {
		return errors.New("--hub, --token (or KK_TOKEN) and --ca-pem are required")
	}
	caPEM, err := os.ReadFile(*caPEMPath)
	if err != nil {
		return err
	}
	c := &hubClient{base: *hub, token: token, http: &http.Client{Timeout: 60 * time.Second}}

	var connID struct{ Data struct{ ID string } }
	cfg, _ := json.Marshal(map[string]string{"directory_url": *directory, "challenge": "http-01", "http01_listen": "127.0.0.1:0"})
	if err := c.post("/api/v1/connectors", map[string]any{"name": "storm-stub-ca", "type": "acme", "config_json": string(cfg)}, &connID); err != nil {
		return fmt.Errorf("create connector: %w", err)
	}
	if connID.Data.ID == "" {
		return errors.New("connector create returned no id")
	}

	n := *count
	targets := make([]string, n)
	fps := make([]string, n)

	t1 := time.Now()
	if err := parallel(n, *workers, func(i int) error {
		var cred struct{ Data struct{ ID string } }
		if err := c.post("/api/v1/credentials", map[string]any{
			"name": fmt.Sprintf("storm-k8s-%04d", i), "credential_type": "api_token",
			"payload": map[string]string{
				"base_url": *k8sURL, "bearer_token": "storm", "namespace": "storm",
				"secret_name": "s" + strconv.Itoa(i), "ca_cert": string(caPEM),
			},
		}, &cred); err != nil {
			return fmt.Errorf("credential: %w", err)
		}
		var tgt struct{ Data struct{ ID string } }
		if err := c.post("/api/v1/targets", map[string]any{
			"name": fmt.Sprintf("storm-%04d", i), "host": fmt.Sprintf(*cnTmpl, i), "discovery_mode": "none",
			"install_mode": "k8s", "renewal_method": "acme", "credential_ref": cred.Data.ID,
			"auto_renew": true, "verify_host_port": fmt.Sprintf("%s:%d", *verifyHost, *verifyBase+i),
		}, &tgt); err != nil {
			return fmt.Errorf("target: %w", err)
		}
		targets[i] = tgt.Data.ID
		return nil
	}); err != nil {
		return err
	}
	setup := time.Since(t1)

	notAfter := time.Now().Add(*allowance + *expiry)
	t2 := time.Now()
	if err := parallel(n, *workers, func(i int) error {
		fp, err := importOne(c, fmt.Sprintf(*cnTmpl, i), notAfter)
		if err != nil {
			return err
		}
		fps[i] = fp
		if err := c.post("/api/v1/estate/takeover", map[string]any{
			"fingerprint": fp, "owner_team": "storm",
			"renewal_path": map[string]string{"mode": "connector", "connector_id": connID.Data.ID},
		}, nil); err != nil {
			return fmt.Errorf("takeover: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	imp := time.Since(t2)

	t3 := time.Now()
	if err := parallel(n, *workers, func(i int) error {
		err := c.post("/api/v1/targets/"+targets[i]+"/bindings", map[string]string{"cert_fingerprint": fps[i]}, nil)
		var he *httpError
		if errors.As(err, &he) && he.status == http.StatusConflict {
			return nil // a retried bind that already landed
		}
		if err != nil {
			return fmt.Errorf("binding: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	t0 := time.Now()
	return json.NewEncoder(os.Stdout).Encode(seedResult{
		Count: n, SetupS: int64(setup.Seconds()), ImportS: int64(imp.Seconds()), BindS: int64(t0.Sub(t3).Seconds()),
		ExpiryUnix: notAfter.Unix(), T0Unix: t0.Unix(), RemainingS: int64(notAfter.Sub(t0).Seconds()),
		Backoffs429: c.backoffs.Load(),
	})
}

// parallel runs fn(0..n-1) on a bounded pool and reports the first failure.
func parallel(n, workers int, fn func(i int) error) error {
	idx := make(chan int)
	var wg sync.WaitGroup
	var failed atomic.Int64
	var firstErr atomic.Value
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				if err := fn(i); err != nil {
					failed.Add(1)
					firstErr.CompareAndSwap(nil, fmt.Errorf("index %d: %w", i, err))
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		idx <- i
	}
	close(idx)
	wg.Wait()
	if failed.Load() > 0 {
		return fmt.Errorf("%d of %d failed; first: %v", failed.Load(), n, firstErr.Load())
	}
	return nil
}

// importOne mints a self-signed certificate and imports it, returning its
// fingerprint. It is computed here, so a retried import that finds the first
// attempt already landed (409) is not an error.
func importOne(c *hubClient, cn string, notAfter time.Time) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	err = c.post("/api/v1/certificates/import", map[string]any{
		"certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}, nil)
	var he *httpError
	if err != nil && !(errors.As(err, &he) && he.status == http.StatusConflict) {
		return "", fmt.Errorf("import: %w", err)
	}
	return hex.EncodeToString(sum[:]), nil
}

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.body) }

type hubClient struct {
	base, token string
	http        *http.Client
	backoffs    atomic.Int64
}

// post sends JSON and decodes the reply, backing off on 429 and 5xx (the API
// rate limiter is expected to bite a 32-way seeder).
func (c *hubClient) post(path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < 8; attempt++ {
		req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			last = err
			log.Printf("seed: %s -> %v (attempt %d), backing off", path, err, attempt+1)
		} else {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			switch {
			case resp.StatusCode < 300:
				if out != nil {
					return json.Unmarshal(b, out)
				}
				return nil
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				c.backoffs.Add(1)
				last = &httpError{resp.StatusCode, string(bytes.TrimSpace(b))}
				log.Printf("seed: %s -> %v (attempt %d), backing off", path, last, attempt+1)
				if ra, _ := strconv.Atoi(resp.Header.Get("Retry-After")); ra > 0 {
					time.Sleep(time.Duration(ra) * time.Second)
					continue
				}
			default:
				return &httpError{resp.StatusCode, string(bytes.TrimSpace(b))}
			}
		}
		time.Sleep(time.Duration(1<<attempt) * 100 * time.Millisecond)
	}
	return last
}
