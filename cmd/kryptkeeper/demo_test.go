// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDemoHub is an in-memory stand-in for the slice of the REST API the demo
// command uses. It records every request so tests can assert the CLI only ever
// touched public /api/v1 routes.
type fakeDemoHub struct {
	mu          sync.Mutex
	env         string
	token       string
	marker      string
	cas         []demoCA
	templates   map[string]string
	certs       []*fakeCert
	requests    []string
	scans       []string
	revokeScope map[string]string
}

type fakeCert struct {
	demoCert
	sigAlg string
}

func newFakeDemoHub(t *testing.T) (*fakeDemoHub, *httptest.Server) {
	t.Helper()
	h := &fakeDemoHub{token: "tok", templates: map[string]string{}, revokeScope: map[string]string{}}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, srv
}

func (h *fakeDemoHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = append(h.requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer "+h.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	path := r.URL.Path
	switch {
	case path == "/api/v1/meta":
		reply(200, map[string]string{"environment": h.env})
	case path == "/api/v1/demo/status":
		reply(200, map[string]any{"data": map[string]any{"demo": h.marker != ""}})
	case path == "/api/v1/config/demo.seeded_at" && r.Method == http.MethodPut:
		h.marker, _ = body["value"].(string)
		w.WriteHeader(204)
	case path == "/api/v1/config/demo.seeded_at" && r.Method == http.MethodDelete:
		if h.marker == "" {
			w.WriteHeader(404)
			return
		}
		h.marker = ""
		w.WriteHeader(204)
	case path == "/api/v1/cas" && r.Method == http.MethodGet:
		reply(200, map[string]any{"data": h.cas})
	case path == "/api/v1/cas" && r.Method == http.MethodPost:
		ca := demoCA{ID: fmt.Sprintf("ca-%d", len(h.cas)+1), Name: body["name"].(string)}
		h.cas = append(h.cas, ca)
		reply(201, map[string]any{"data": ca})
	case path == "/api/v1/templates" && r.Method == http.MethodGet:
		var items []map[string]string
		for n, id := range h.templates {
			items = append(items, map[string]string{"id": id, "name": n})
		}
		reply(200, map[string]any{"data": items})
	case path == "/api/v1/templates" && r.Method == http.MethodPost:
		name := body["name"].(string)
		h.templates[name] = "tpl-" + name
		reply(201, map[string]any{"data": map[string]string{"id": h.templates[name]}})
	case path == "/api/v1/certificates" && r.Method == http.MethodGet:
		out := make([]demoCert, 0, len(h.certs))
		for _, c := range h.certs {
			out = append(out, c.demoCert)
		}
		reply(200, map[string]any{"data": out, "meta": map[string]any{"next_cursor": nil}})
	case path == "/api/v1/certificates" && r.Method == http.MethodPost:
		block, _ := pem.Decode([]byte(body["csr_pem"].(string)))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			reply(400, map[string]string{"error": "bad csr"})
			return
		}
		c := h.add(csr.Subject.CommonName, "internal")
		reply(201, map[string]any{"data": c.demoCert})
	case path == "/api/v1/certificates/import":
		block, _ := pem.Decode([]byte(body["certificate_pem"].(string)))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			reply(400, map[string]string{"error": "bad cert"})
			return
		}
		c := h.add(cert.Subject.CommonName, "imported")
		c.sigAlg = cert.SignatureAlgorithm.String()
		reply(201, map[string]any{"data": c.demoCert})
	case strings.HasSuffix(path, "/ownership") && r.Method == http.MethodPatch:
		fp := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/certificates/"), "/ownership")
		for _, c := range h.certs {
			if c.Fingerprint == fp {
				for _, l := range body["labels"].([]any) {
					c.Labels = append(c.Labels, l.(string))
				}
			}
		}
		w.WriteHeader(200)
	case strings.HasSuffix(path, "/revoke") && r.Method == http.MethodPost:
		fp := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/certificates/"), "/revoke")
		for _, c := range h.certs {
			if c.Fingerprint == fp {
				now := "2026-10-25T00:00:00Z"
				c.RevokedAt = &now
				h.revokeScope[fp] = r.URL.Query().Get("scope")
			}
		}
		w.WriteHeader(200)
	case path == "/api/v1/discovery/scans" && r.Method == http.MethodPost:
		h.scans = append(h.scans, body["target"].(string))
		reply(201, map[string]any{})
	case path == "/api/v1/discovery/scan-jobs":
		reply(200, map[string]any{"data": map[string]any{"scan_jobs": []any{}}})
	default:
		http.NotFound(w, r)
	}
}

func (h *fakeDemoHub) add(cn, origin string) *fakeCert {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", cn, len(h.certs))))
	c := &fakeCert{demoCert: demoCert{Fingerprint: hex.EncodeToString(sum[:]), CommonName: cn, Origin: origin}}
	h.certs = append(h.certs, c)
	return c
}

func runDemoCmd(t *testing.T, srv *httptest.Server, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	full := append(args, "--hub", srv.URL, "--token", "tok", "--wait", "5s")
	code := runDemo(full, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestDemoSeedBuildsLabelledMixedEstate(t *testing.T) {
	h, srv := newFakeDemoHub(t)
	code, out, errOut := runDemoCmd(t, srv, "seed", "--targets", "demo-web1:8443, demo-web2:8443")
	if code != 0 {
		t.Fatalf("seed exit %d: %s%s", code, out, errOut)
	}
	if len(h.certs) != 40 {
		t.Fatalf("seeded %d certificates, want 40", len(h.certs))
	}
	var revoked, weak, imported int
	for _, c := range h.certs {
		if !c.isDemo() {
			t.Fatalf("%s is not labelled demo=true", c.CommonName)
		}
		if c.RevokedAt != nil {
			revoked++
		}
		if c.Origin == "imported" {
			imported++
		}
		if strings.Contains(c.sigAlg, "SHA1") {
			weak++
		}
	}
	if revoked != 4 || imported != 2 {
		t.Fatalf("revoked=%d imported=%d, want 4 and 2", revoked, imported)
	}
	if weak > 1 {
		t.Fatalf("more than one SHA-1 certificate: %d", weak)
	}
	if len(h.cas) != 2 || h.cas[0].Name != demoRootName || h.cas[1].Name != demoIssuingName {
		t.Fatalf("CAs = %+v", h.cas)
	}
	if len(h.templates) != 2 || h.marker == "" {
		t.Fatalf("templates=%v marker=%q", h.templates, h.marker)
	}
	if strings.Join(h.scans, ",") != "demo-web1:8443,demo-web2:8443" {
		t.Fatalf("scans = %v", h.scans)
	}
	for _, r := range h.requests {
		if !strings.Contains(r, " /api/v1/") {
			t.Fatalf("request outside the public API: %s", r)
		}
	}
}

func TestDemoSeedRefusals(t *testing.T) {
	t.Run("production", func(t *testing.T) {
		h, srv := newFakeDemoHub(t)
		h.env = "Production"
		code, _, errOut := runDemoCmd(t, srv, "seed")
		if code == 0 || !strings.Contains(errOut, "production") || len(h.cas) != 0 {
			t.Fatalf("exit %d, err %q, cas %d", code, errOut, len(h.cas))
		}
	})
	t.Run("hub holds the operator's certificates", func(t *testing.T) {
		h, srv := newFakeDemoHub(t)
		h.add("billing.example.com", "internal")
		code, _, errOut := runDemoCmd(t, srv, "seed")
		if code == 0 || !strings.Contains(errOut, "not demo data") || len(h.cas) != 0 {
			t.Fatalf("exit %d, err %q", code, errOut)
		}
	})
	t.Run("hub holds the operator's CAs", func(t *testing.T) {
		h, srv := newFakeDemoHub(t)
		h.cas = []demoCA{{ID: "a", Name: "Corp Root"}, {ID: "b", Name: "Corp Issuing"}}
		if code, _, errOut := runDemoCmd(t, srv, "seed"); code == 0 || !strings.Contains(errOut, "CAs other than") {
			t.Fatalf("exit %d, err %q", code, errOut)
		}
	})
	t.Run("bootstrap default CA is tolerated", func(t *testing.T) {
		h, srv := newFakeDemoHub(t)
		h.cas = []demoCA{{ID: "boot", Name: "Acme Root CA"}}
		if code, _, errOut := runDemoCmd(t, srv, "seed"); code != 0 {
			t.Fatalf("exit %d, err %q", code, errOut)
		}
	})
	t.Run("already seeded", func(t *testing.T) {
		h, srv := newFakeDemoHub(t)
		h.marker = "2026-10-25T00:00:00Z"
		if code, _, errOut := runDemoCmd(t, srv, "seed"); code == 0 || !strings.Contains(errOut, "already seeded") {
			t.Fatalf("exit %d, err %q", code, errOut)
		}
	})
}

func TestDemoResetTouchesOnlyDemoObjects(t *testing.T) {
	h, srv := newFakeDemoHub(t)
	if code, out, errOut := runDemoCmd(t, srv, "seed"); code != 0 {
		t.Fatalf("seed: %s%s", out, errOut)
	}
	mine := h.add("billing.example.com", "internal")
	discovered := h.add("found.demo.example", "discovered")
	discovered.Labels = []string{demoLabel}

	code, out, errOut := runDemoCmd(t, srv, "reset")
	if code != 0 {
		t.Fatalf("reset exit %d: %s%s", code, out, errOut)
	}
	if mine.RevokedAt != nil {
		t.Fatal("reset revoked a certificate that is not demo data")
	}
	for _, c := range h.certs {
		if c.isDemo() && c.RevokedAt == nil {
			t.Fatalf("demo certificate %s survived reset", c.CommonName)
		}
	}
	if h.revokeScope[discovered.Fingerprint] != "inventory_only" {
		t.Fatalf("a discovered certificate is revoked inventory-only, got %q", h.revokeScope[discovered.Fingerprint])
	}
	if h.marker != "" {
		t.Fatal("marker not cleared")
	}
	// Reset is repeatable, and seed works again afterwards on the same CAs.
	if code, _, errOut := runDemoCmd(t, srv, "reset"); code != 0 {
		t.Fatalf("second reset: %s", errOut)
	}
	delete(h.revokeScope, "")
	h.certs = h.certs[:0]
	if code, _, errOut := runDemoCmd(t, srv, "seed"); code != 0 || len(h.cas) != 2 {
		t.Fatalf("re-seed exit %d cas=%d: %s", code, len(h.cas), errOut)
	}
}

func TestDemoUsageAndFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runDemo(nil, &out, &errOut); code != 2 {
		t.Fatalf("no args exit %d", code)
	}
	if code := runDemo([]string{"seed"}, &out, &errOut); code != 2 {
		t.Fatalf("missing --hub exit %d", code)
	}
	if code := runDemo([]string{"seed", "--hub", "ftp://x", "--token", "t"}, &out, &errOut); code != 1 {
		t.Fatalf("bad scheme exit %d", code)
	}
	var o3, e3 bytes.Buffer
	missing := filepath.Join(t.TempDir(), "ca.pem")
	if code := runDemo([]string{"seed", "--hub", "https://h", "--token", "t", "--ca-file", missing, "--wait", "1s"}, &o3, &e3); code != 1 || !strings.Contains(e3.String(), "--ca-file") {
		t.Fatalf("missing ca-file exit %d: %s", code, e3.String())
	}
	_, srv := newFakeDemoHub(t)
	var o2, e2 bytes.Buffer
	if code := runDemo([]string{"seed", "--hub", srv.URL, "--token", "wrong", "--wait", "1s"}, &o2, &e2); code != 1 {
		t.Fatalf("wrong token exit %d", code)
	}
}

func TestDemoSelfSignedFixtures(t *testing.T) {
	now := time.Now()
	weak, err := demoSelfSigned("demo-weak", 1024, now.AddDate(0, -1, 0), now.AddDate(1, 0, 0), true)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(weak))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.PublicKey == nil || cert.NotAfter.Before(now) {
		t.Fatalf("weak fixture: %+v", cert.NotAfter)
	}
	expired, err := demoSelfSigned("demo-expired", 2048, now.AddDate(0, 0, -400), now.AddDate(0, 0, -35), false)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode([]byte(expired))
	cert, _ = x509.ParseCertificate(block.Bytes)
	if !cert.NotAfter.Before(now) {
		t.Fatal("expired fixture is not expired")
	}
}
