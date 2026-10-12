// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"kryptkeeper/internal/plugins/delivery"
)

const (
	exampleToken    = "device-api-token-0123456789"
	exampleListener = "vip-443"
)

// exampleDevice mocks the example plugin's HTTPS API. The plugin reaches it
// as https://example.com: httptest's certificate is valid for that name,
// and the client dials the test listener, so TLS is verified for real.
type exampleDevice struct {
	ts       *httptest.Server
	mu       sync.Mutex
	certs    map[string]string // name -> cert PEM
	keys     map[string]string // name -> key PEM as received
	binding  string
	failNext map[string]bool
	initial  Cert
}

func newExampleDevice(t *testing.T) *exampleDevice {
	d := &exampleDevice{initial: NewCert(t, "initial")}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	d.Reset()
	return d
}

func (d *exampleDevice) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.certs = map[string]string{"initial": string(d.initial.CertPEM)}
	d.keys = map[string]string{}
	d.binding = "initial"
	d.failNext = map[string]bool{}
}

func (d *exampleDevice) FailNext(step string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failNext[step] = true
}

func (d *exampleDevice) Served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Fingerprint(d.certs[d.binding])
}

func (d *exampleDevice) Env() delivery.Env {
	addr := d.ts.Listener.Addr().String()
	client := d.ts.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	return delivery.Env{
		Credential: map[string]string{"base_url": "https://example.com", "token": exampleToken},
		Secrets:    []string{"token"},
		Target:     map[string]string{"listener": exampleListener},
		HTTPClient: &http.Client{Transport: tr},
	}
}

func (d *exampleDevice) take(step string) bool {
	if d.failNext[step] {
		delete(d.failNext, step)
		return true
	}
	return false
}

func (d *exampleDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+exampleToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body map[string]string
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/status":
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && r.URL.Path == "/api/certs":
		if d.take("upload") {
			http.Error(w, "disk full", http.StatusInternalServerError)
			return
		}
		d.certs[body["name"]] = body["cert_pem"]
		d.keys[body["name"]] = body["key_pem"]
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet && r.URL.Path == "/api/binding":
		_ = json.NewEncoder(w).Encode(map[string]string{"cert": d.binding})
	case r.Method == http.MethodPut && r.URL.Path == "/api/binding":
		step := "bind"
		if body["cert"] != "" && body["cert"] != "kk-conformance" {
			step = "rollback"
		}
		if d.take(step) {
			http.Error(w, "profile locked", http.StatusConflict)
			return
		}
		if _, ok := d.certs[body["cert"]]; !ok {
			http.Error(w, "no such cert", http.StatusNotFound)
			return
		}
		d.binding = body["cert"]
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}
