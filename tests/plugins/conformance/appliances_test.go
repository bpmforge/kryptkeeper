// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock F5 BIG-IP (iControl REST) and Citrix ADC (NITRO) management APIs for
// the first-party plugins (W20-22). They model only what the plugins call,
// with the request shapes the built-in pushers' tests pinned.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"kryptkeeper/internal/plugins/delivery"
)

// mockEnv reaches ts as https://example.com, verifying TLS for real.
func mockEnv(ts *httptest.Server, cred map[string]string, secrets []string, target map[string]string) delivery.Env {
	addr := ts.Listener.Addr().String()
	tr := ts.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	return delivery.Env{Credential: cred, Secrets: secrets, Target: target, HTTPClient: &http.Client{Transport: tr}}
}

// failSet is the "fail the next X" switch both mocks share.
type failSet map[string]bool

func (f failSet) take(step string) bool {
	if f[step] {
		delete(f, step)
		return true
	}
	return false
}

// --- F5 BIG-IP ---

type f5Device struct {
	ts      *httptest.Server
	mu      sync.Mutex
	uploads map[string]string
	certs   map[string]string // crypto cert object -> PEM
	keys    map[string]string
	profile string // cert object the client-ssl profile serves
	fail    failSet
	initial Cert
}

func newF5Device(t *testing.T) *f5Device {
	d := &f5Device{initial: NewCert(t, "f5-initial")}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	d.Reset()
	return d
}

func (d *f5Device) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.uploads, d.keys = map[string]string{}, map[string]string{}
	d.certs = map[string]string{"initial": string(d.initial.CertPEM)}
	d.profile, d.fail = "initial", failSet{}
}

func (d *f5Device) FailNext(step string) { d.mu.Lock(); d.fail[step] = true; d.mu.Unlock() }

func (d *f5Device) Served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Fingerprint(d.certs[d.profile])
}

func (d *f5Device) Env() delivery.Env {
	return mockEnv(d.ts, map[string]string{"base_url": "https://example.com", "username": "admin", "password": "f5-secret-pass-123"},
		[]string{"password"}, map[string]string{"client_ssl_profile": "clientssl-shop"})
}

func (d *f5Device) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "f5-secret-pass-123" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/"):
		if d.fail.take("upload") {
			http.Error(w, "disk full", http.StatusInternalServerError)
			return
		}
		raw, _ := io.ReadAll(r.Body) // a short read stores a truncated file, which the served-fingerprint checks catch
		d.uploads[strings.TrimPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/")] = string(raw)
	case r.URL.Path == "/mgmt/tm/sys/crypto/cert" || r.URL.Path == "/mgmt/tm/sys/crypto/key":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		file := strings.TrimPrefix(body["fromLocalFile"], "/var/config/rest/downloads/")
		if strings.HasSuffix(r.URL.Path, "/cert") {
			d.certs[body["name"]] = d.uploads[file]
		} else {
			d.keys[body["name"]] = d.uploads[file]
		}
	case r.URL.Path == "/mgmt/tm/ltm/profile/client-ssl/clientssl-shop":
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"cert": d.profile, "key": d.profile})
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		step := "rollback"
		if strings.HasPrefix(body["cert"], "kk-conformance") {
			step = "bind"
		}
		if d.fail.take(step) {
			http.Error(w, "profile locked", http.StatusConflict)
			return
		}
		if _, ok := d.certs[body["cert"]]; !ok {
			http.Error(w, "no such cert", http.StatusNotFound)
			return
		}
		d.profile = body["cert"]
	default:
		http.NotFound(w, r)
	}
}

// --- Citrix ADC ---

type citrixDevice struct {
	ts      *httptest.Server
	mu      sync.Mutex
	files   map[string]string
	pair    map[string]string // cert, key file paths of the cert-key pair
	fail    failSet
	initial Cert
}

func newCitrixDevice(t *testing.T) *citrixDevice {
	d := &citrixDevice{initial: NewCert(t, "adc-initial")}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	d.Reset()
	return d
}

func (d *citrixDevice) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.files = map[string]string{"/nsconfig/ssl/initial.crt": string(d.initial.CertPEM), "/nsconfig/ssl/initial.key": "k"}
	d.pair = map[string]string{"cert": "/nsconfig/ssl/initial.crt", "key": "/nsconfig/ssl/initial.key"}
	d.fail = failSet{}
}

func (d *citrixDevice) FailNext(step string) { d.mu.Lock(); d.fail[step] = true; d.mu.Unlock() }

func (d *citrixDevice) Served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Fingerprint(d.files[d.pair["cert"]])
}

func (d *citrixDevice) Env() delivery.Env {
	return mockEnv(d.ts, map[string]string{"base_url": "https://example.com", "username": "nsroot", "password": "adc-secret-pass-456"},
		[]string{"password"}, map[string]string{"certkey_name": "shop-certkey"})
}

func (d *citrixDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Header.Get("X-NITRO-USER") != "nsroot" || r.Header.Get("X-NITRO-PASS") != "adc-secret-pass-456" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/nitro/v1/config/systemfile":
		if d.fail.take("upload") {
			http.Error(w, "disk full", http.StatusInternalServerError)
			return
		}
		var body struct {
			SystemFile map[string]string `json:"systemfile"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, _ := base64.StdEncoding.DecodeString(body.SystemFile["filecontent"])
		d.files[body.SystemFile["filelocation"]+"/"+body.SystemFile["filename"]] = string(raw)
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet && r.URL.Path == "/nitro/v1/config/sslcertkey/shop-certkey":
		_ = json.NewEncoder(w).Encode(map[string]any{"sslcertkey": []map[string]string{{"certkey": "shop-certkey", "cert": d.pair["cert"], "key": d.pair["key"]}}})
	case r.Method == http.MethodPost && r.URL.Path == "/nitro/v1/config/sslcertkey":
		var body struct {
			SSLCertKey map[string]string `json:"sslcertkey"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		step := "rollback"
		if strings.Contains(body.SSLCertKey["cert"], "kk-conformance") {
			step = "bind"
		}
		if d.fail.take(step) {
			http.Error(w, "certkey in use", http.StatusConflict)
			return
		}
		if _, ok := d.files[body.SSLCertKey["cert"]]; !ok {
			http.Error(w, "no such file", http.StatusNotFound)
			return
		}
		d.pair = map[string]string{"cert": body.SSLCertKey["cert"], "key": body.SSLCertKey["key"]}
	default:
		http.NotFound(w, r)
	}
}

// The first-party plugins pass the same kit as any community plugin.
func TestF5PluginConforms(t *testing.T) {
	rt := newRuntime(t)
	Suite(t, Load(t, rt, repoPath(t, "plugins/f5")), newF5Device(t))
}

func TestCitrixPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	Suite(t, Load(t, rt, repoPath(t, "plugins/citrix")), newCitrixDevice(t))
}
