// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
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
	"flag"
	"fmt"
	"io"
	"io/fs"
	"kryptkeeper/internal/egress"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// `kryptkeeper demo seed|reset` (W37-07, D-310) fills an empty hub with clearly
// labelled sample data so a first visitor sees a populated dashboard. It is a
// client of the hub's public REST API only: no database access, no private
// routes. Every object it creates is labelled demo=true (certificates carry the
// label; CAs and templates carry the "Demo " / "demo-" name prefix because they
// have no label field), and reset finds certificates by that label alone.

const (
	demoLabel         = "demo=true"
	demoRootName      = "Demo Root CA"
	demoIssuingName   = "Demo Issuing CA"
	demoTLSTemplate   = "demo-tls-server"
	demoShortTemplate = "demo-tls-short-lived"
	demoMarkerKey     = "demo.seeded_at"
)

type demoOptions struct {
	hub     string
	token   string
	caFile  string
	targets []string
	wait    time.Duration
}

// runDemo is the CLI entry point; it returns the process exit code.
func runDemo(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "seed" && args[0] != "reset") {
		fmt.Fprintln(stderr, "usage: kryptkeeper demo seed|reset --hub URL --token TOKEN [--targets host:port,...]")
		return 2
	}
	action := args[0]
	flags := flag.NewFlagSet("demo "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var opts demoOptions
	var targets string
	flags.StringVar(&opts.hub, "hub", "", "hub base URL, e.g. http://localhost:8080")
	flags.StringVar(&opts.token, "token", os.Getenv("KRYPTKEEPER_DEMO_TOKEN"), "admin API token (default: $KRYPTKEEPER_DEMO_TOKEN)")
	flags.StringVar(&opts.caFile, "ca-file", "", "PEM CA bundle that signed the hub's TLS certificate")
	flags.StringVar(&targets, "targets", "", "comma-separated host:port demo TLS targets for one discovery scan (seed only)")
	flags.DurationVar(&opts.wait, "wait", 2*time.Minute, "how long to wait for the hub to become ready")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if opts.hub == "" || opts.token == "" {
		fmt.Fprintln(stderr, "demo: --hub and --token are required")
		return 2
	}
	for _, t := range strings.Split(targets, ",") {
		if t = strings.TrimSpace(t); t != "" {
			opts.targets = append(opts.targets, t)
		}
	}
	// In a compose stack the hub writes its CA bundle a moment after the
	// seeder starts, so a --ca-file that does not exist yet is retried.
	waitUntil := time.Now().Add(opts.wait)
	var c *demoClient
	var err error
	for {
		c, err = newDemoClient(opts)
		if err == nil || !errors.Is(err, fs.ErrNotExist) || time.Now().After(waitUntil) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		fmt.Fprintf(stderr, "demo: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := c.waitReady(ctx, opts.wait); err != nil {
		fmt.Fprintf(stderr, "demo: %v\n", err)
		return 1
	}
	d := &demoRunner{c: c, out: stdout, now: time.Now}
	if action == "seed" {
		err = d.seed(ctx, opts.targets)
	} else {
		err = d.reset(ctx)
	}
	if err != nil {
		fmt.Fprintf(stderr, "demo %s: %v\n", action, err)
		return 1
	}
	return 0
}

type demoClient struct {
	base  string
	token string
	http  *http.Client
}

func newDemoClient(opts demoOptions) (*demoClient, error) {
	u, err := url.Parse(strings.TrimRight(opts.hub, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("--hub must be an http(s) URL, got %q", opts.hub)
	}
	// The hub URL is typed by the operator and is usually loopback or a
	// container network, so private and loopback addresses are allowed; the
	// egress guard still refuses link-local and metadata addresses.
	policy := egress.Policy{AllowPrivate: true, AllowLoopback: true, Timeout: 60 * time.Second}
	if opts.caFile != "" {
		pemBytes, err := os.ReadFile(opts.caFile)
		if err != nil {
			return nil, fmt.Errorf("read --ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("--ca-file holds no PEM certificate")
		}
		policy.RootCAs = pool
	}
	return &demoClient{base: u.String(), token: opts.token, http: egress.NewClient(policy)}, nil
}

// do sends one request. A non-2xx status is returned as *demoHTTPError so a
// caller can branch on it; out may be nil.
func (c *demoClient) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &demoHTTPError{Method: method, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w", method, path, err)
		}
	}
	return nil
}

type demoHTTPError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *demoHTTPError) Error() string {
	b := e.Body
	if len(b) > 300 {
		b = b[:300]
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, b)
}

func isStatus(err error, status int) bool {
	var he *demoHTTPError
	return errors.As(err, &he) && he.Status == status
}

func (c *demoClient) waitReady(ctx context.Context, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		var meta struct{}
		err := c.do(ctx, http.MethodGet, "/api/v1/meta", nil, &meta)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("hub not ready after %s: %w", wait, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

type demoCert struct {
	Fingerprint string   `json:"fingerprint_sha256"`
	CommonName  string   `json:"common_name"`
	Labels      []string `json:"labels"`
	Origin      string   `json:"origin"`
	RevokedAt   *string  `json:"revoked_at"`
}

func (c demoCert) isDemo() bool {
	for _, l := range c.Labels {
		if l == demoLabel {
			return true
		}
	}
	return false
}

type demoCA struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type demoRunner struct {
	c   *demoClient
	out io.Writer
	now func() time.Time
}

func (d *demoRunner) say(format string, a ...any) { fmt.Fprintf(d.out, format+"\n", a...) }

func (d *demoRunner) listCerts(ctx context.Context) ([]demoCert, error) {
	var all []demoCert
	cursor := 0
	for {
		var page struct {
			Data []demoCert `json:"data"`
			Meta struct {
				NextCursor *int `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := d.c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/certificates?limit=100&cursor=%d", cursor), nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		if page.Meta.NextCursor == nil || len(page.Data) == 0 {
			return all, nil
		}
		cursor = *page.Meta.NextCursor
	}
}

func (d *demoRunner) listCAs(ctx context.Context) ([]demoCA, error) {
	var page struct {
		Data []demoCA `json:"data"`
	}
	if err := d.c.do(ctx, http.MethodGet, "/api/v1/cas?limit=100", nil, &page); err != nil {
		return nil, err
	}
	return page.Data, nil
}

// guard refuses a production hub, a hub that already holds demo data, and a
// hub that holds anything of the operator's own.
func (d *demoRunner) guard(ctx context.Context) ([]demoCA, error) {
	var meta struct {
		Environment string `json:"environment"`
	}
	if err := d.c.do(ctx, http.MethodGet, "/api/v1/meta", nil, &meta); err != nil {
		return nil, err
	}
	if strings.EqualFold(meta.Environment, "production") {
		return nil, errors.New("refusing: this hub reports KRYPTKEEPER_ENV=production")
	}
	var st struct {
		Data struct {
			Demo bool `json:"demo"`
		} `json:"data"`
	}
	if err := d.c.do(ctx, http.MethodGet, "/api/v1/demo/status", nil, &st); err != nil {
		return nil, err
	}
	if st.Data.Demo {
		return nil, errors.New("refusing: demo data is already seeded; run `kryptkeeper demo reset` first")
	}
	certs, err := d.listCerts(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if !c.isDemo() {
			return nil, errors.New("refusing: the hub already holds certificates that are not demo data")
		}
	}
	cas, err := d.listCAs(ctx)
	if err != nil {
		return nil, err
	}
	foreign := 0
	for _, ca := range cas {
		if !strings.HasPrefix(ca.Name, "Demo ") {
			foreign++
		}
	}
	// One non-demo CA is the bootstrap default (KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT).
	if foreign > 1 {
		return nil, errors.New("refusing: the hub already holds CAs other than the bootstrap default")
	}
	return cas, nil
}

func (d *demoRunner) seed(ctx context.Context, targets []string) error {
	cas, err := d.guard(ctx)
	if err != nil {
		return err
	}
	root, err := d.ensureCA(ctx, cas, demoCAReq{Name: demoRootName, Type: "root", Algorithm: "ECDSA-P384", SubjectCN: demoRootName, Validity: "3650d"})
	if err != nil {
		return err
	}
	issuing, err := d.ensureCA(ctx, cas, demoCAReq{Name: demoIssuingName, Type: "intermediate", Algorithm: "ECDSA-P256", SubjectCN: demoIssuingName, Validity: "1825d", ParentCAID: root})
	if err != nil {
		return err
	}
	d.say("CAs: %s, %s", demoRootName, demoIssuingName)
	standard, err := d.ensureTemplate(ctx, demoTLSTemplate, "Demo TLS server (90 days)", "P90D")
	if err != nil {
		return err
	}
	short, err := d.ensureTemplate(ctx, demoShortTemplate, "Demo TLS server (10 days)", "P10D")
	if err != nil {
		return err
	}

	issued := 0
	issue := func(tpl, cn string, rsaKey bool) (string, error) {
		fp, err := d.issue(ctx, issuing, tpl, cn, rsaKey)
		if err == nil {
			issued++
		}
		return fp, err
	}
	// 28 active, of which 6 use RSA-3072 (a classical key, so PQC-vulnerable).
	for i := 1; i <= 28; i++ {
		kind := []string{"web", "api", "db", "cache", "queue", "auth", "mail"}[i%7]
		if _, err := issue(standard, fmt.Sprintf("demo-%s-%02d.demo.example", kind, i), i%5 == 0); err != nil {
			return err
		}
	}
	// 6 short-lived certificates that expire within 14 days.
	for i := 1; i <= 6; i++ {
		if _, err := issue(short, fmt.Sprintf("demo-expiring-%02d.demo.example", i), false); err != nil {
			return err
		}
	}
	// 4 revoked.
	for i, reason := range []int{1, 4, 5, 4} {
		fp, err := issue(standard, fmt.Sprintf("demo-revoked-%02d.demo.example", i+1), false)
		if err != nil {
			return err
		}
		body := map[string]any{"reason_code": reason, "reason_text": "demo data"}
		if err := d.c.do(ctx, http.MethodPost, "/api/v1/certificates/"+fp+"/revoke", body, nil); err != nil {
			return err
		}
	}
	d.say("issued %d certificates from %s", issued, demoIssuingName)

	now := d.now()
	// 1 expired, brought in by import: the hub never issues an expired certificate.
	expired, err := demoSelfSigned("demo-expired.demo.example", 2048, now.AddDate(0, 0, -400), now.AddDate(0, 0, -35), false)
	if err != nil {
		return err
	}
	if err := d.importCert(ctx, expired); err != nil {
		return fmt.Errorf("import expired certificate: %w", err)
	}
	// 1 weak: RSA-1024, SHA-1 where this Go build still signs with it.
	weak, err := demoSelfSigned("demo-legacy-weak.demo.example", 1024, now.AddDate(0, -3, 0), now.AddDate(0, 9, 0), true)
	if err != nil {
		return err
	}
	if err := d.importCert(ctx, weak); err != nil {
		return fmt.Errorf("import weak certificate: %w", err)
	}
	d.say("imported 2 (one expired, one RSA-1024 weak)")

	if len(targets) > 0 {
		d.discover(ctx, targets)
	}
	if err := d.c.do(ctx, http.MethodPut, "/api/v1/config/"+demoMarkerKey, map[string]string{"value": now.UTC().Format(time.RFC3339)}, nil); err != nil {
		return fmt.Errorf("set demo marker: %w", err)
	}
	d.say("demo data seeded (%d certificates, label %s)", issued+2, demoLabel)
	return nil
}

type demoCAReq struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Algorithm  string `json:"algorithm"`
	SubjectCN  string `json:"subject_cn"`
	Validity   string `json:"validity"`
	ParentCAID string `json:"parent_ca_id,omitempty"`
}

func (d *demoRunner) ensureCA(ctx context.Context, existing []demoCA, req demoCAReq) (string, error) {
	for _, ca := range existing {
		if ca.Name == req.Name {
			return ca.ID, nil
		}
	}
	var resp struct {
		Data demoCA `json:"data"`
	}
	if err := d.c.do(ctx, http.MethodPost, "/api/v1/cas", req, &resp); err != nil {
		return "", fmt.Errorf("create CA %q: %w", req.Name, err)
	}
	return resp.Data.ID, nil
}

func (d *demoRunner) ensureTemplate(ctx context.Context, name, display, validity string) (string, error) {
	var list struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := d.c.do(ctx, http.MethodGet, "/api/v1/templates?limit=100", nil, &list); err != nil {
		return "", err
	}
	for _, t := range list.Data {
		if t.Name == name {
			return t.ID, nil
		}
	}
	body := map[string]any{
		"name": name, "display_name": display, "validity_period": validity,
		"key_usage": []string{"digitalSignature"}, "extended_key_usage": []string{"serverAuth"},
		"allowed_algorithms": []string{"ECDSA-P256", "RSA-3072"}, "min_key_size": 2048, "active": true,
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := d.c.do(ctx, http.MethodPost, "/api/v1/templates", body, &resp); err != nil {
		return "", fmt.Errorf("create template %q: %w", name, err)
	}
	return resp.Data.ID, nil
}

// issue requests a certificate for a throwaway key (never stored or logged: the
// demo certificates are display data) and labels it.
func (d *demoRunner) issue(ctx context.Context, caID, tplID, cn string, rsaKey bool) (string, error) {
	csr, err := demoCSR(cn, rsaKey)
	if err != nil {
		return "", err
	}
	var resp struct {
		Data demoCert `json:"data"`
	}
	body := map[string]any{"ca_id": caID, "template_id": tplID, "csr_pem": csr}
	if err := d.c.do(ctx, http.MethodPost, "/api/v1/certificates", body, &resp); err != nil {
		return "", fmt.Errorf("issue %s: %w", cn, err)
	}
	if resp.Data.Fingerprint == "" {
		return "", fmt.Errorf("issue %s: response carried no fingerprint", cn)
	}
	return resp.Data.Fingerprint, d.label(ctx, resp.Data.Fingerprint)
}

func (d *demoRunner) label(ctx context.Context, fp string) error {
	body := map[string]any{"labels": []string{demoLabel}, "service_name": "demo"}
	if err := d.c.do(ctx, http.MethodPatch, "/api/v1/certificates/"+fp+"/ownership", body, nil); err != nil {
		return fmt.Errorf("label %s: %w", fp, err)
	}
	return nil
}

func (d *demoRunner) importCert(ctx context.Context, certPEM string) error {
	var resp struct {
		Data demoCert `json:"data"`
	}
	if err := d.c.do(ctx, http.MethodPost, "/api/v1/certificates/import", map[string]string{"certificate_pem": certPEM}, &resp); err != nil {
		return err
	}
	return d.label(ctx, resp.Data.Fingerprint)
}

// discover starts one targeted scan per demo TLS target and labels what the
// scan finds. A scan that does not finish in time is not a seeding failure:
// the jobs keep running in the hub.
func (d *demoRunner) discover(ctx context.Context, targets []string) {
	started := 0
	for _, t := range targets {
		err := d.c.do(ctx, http.MethodPost, "/api/v1/discovery/scans", map[string]any{"scan_type": "targeted", "target": t}, nil)
		if err != nil {
			d.say("warning: discovery scan of %s not started: %v", t, err)
			continue
		}
		started++
	}
	if started == 0 {
		return
	}
	d.say("started %d discovery scan(s)", started)
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		var jobs struct {
			Data struct {
				ScanJobs []struct {
					Status string `json:"status"`
				} `json:"scan_jobs"`
			} `json:"data"`
		}
		if err := d.c.do(ctx, http.MethodGet, "/api/v1/discovery/scan-jobs?limit=100", nil, &jobs); err != nil {
			break
		}
		busy := false
		for _, j := range jobs.Data.ScanJobs {
			if j.Status == "queued" || j.Status == "running" {
				busy = true
			}
		}
		if !busy {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	certs, err := d.listCerts(ctx)
	if err != nil {
		return
	}
	n := 0
	for _, c := range certs {
		if c.Origin == "discovered" && !c.isDemo() && d.label(ctx, c.Fingerprint) == nil {
			n++
		}
	}
	d.say("labelled %d discovered certificate(s)", n)
}

// reset revokes the demo-labelled certificates and clears the marker. The demo
// CAs and templates stay: revoking a CA is always dual control (a second human
// must approve), which a one-token CLI must not and cannot bypass, and a
// re-seed reuses them.
func (d *demoRunner) reset(ctx context.Context) error {
	certs, err := d.listCerts(ctx)
	if err != nil {
		return err
	}
	revoked, kept := 0, 0
	for _, c := range certs {
		if !c.isDemo() {
			kept++
			continue
		}
		if c.RevokedAt != nil {
			continue
		}
		path := "/api/v1/certificates/" + c.Fingerprint + "/revoke"
		if c.Origin != "" && c.Origin != "internal" {
			path += "?scope=inventory_only"
		}
		body := map[string]any{"reason_code": 5, "reason_text": "demo reset"}
		if err := d.c.do(ctx, http.MethodPost, path, body, nil); err != nil {
			return fmt.Errorf("revoke %s: %w", c.CommonName, err)
		}
		revoked++
	}
	if err := d.c.do(ctx, http.MethodDelete, "/api/v1/config/"+demoMarkerKey, nil, nil); err != nil && !isStatus(err, http.StatusNotFound) {
		return fmt.Errorf("clear demo marker: %w", err)
	}
	d.say("demo reset: revoked %d demo certificate(s), left %d other certificate(s) untouched, marker cleared", revoked, kept)
	return nil
}

func demoCSR(cn string, rsaKey bool) (string, error) {
	var key any
	var err error
	if rsaKey {
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// demoSelfSigned makes a throwaway self-signed certificate for the import path.
// preferSHA1 asks for SHA-1 and falls back to SHA-256 if this build refuses.
func demoSelfSigned(cn string, bits int, notBefore, notAfter time.Time, preferSHA1 bool) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	var der []byte
	if preferSHA1 {
		tpl.SignatureAlgorithm = x509.SHA1WithRSA
		der, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	}
	if !preferSHA1 || err != nil {
		tpl.SignatureAlgorithm = x509.SHA256WithRSA
		der, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	}
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
