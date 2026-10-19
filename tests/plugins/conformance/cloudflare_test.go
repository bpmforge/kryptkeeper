// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock Cloudflare custom-certificate API (response envelope, list, upload,
// get, prioritize, delete) for the cloudflare plugin (W27-31). Cloudflare
// serves the certificate at the edge, so this plugin is graded with the
// normal TLS verification: Served is the active certificate with the highest
// priority for the hostname.

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/plugins/delivery"
)

const (
	cfToken = "cf-conformance-token-abcdef"
	cfZone  = "0123456789abcdef0123456789abcdef"
	cfHost  = "shop.example.com"
)

type cfCert struct {
	ID        string   `json:"id"`
	Hosts     []string `json:"hosts"`
	Status    string   `json:"status"`
	Priority  float64  `json:"priority"`
	ExpiresOn string   `json:"expires_on"`
	pem       string
}

type cloudflareDevice struct {
	ts      *httptest.Server
	mu      sync.Mutex
	certs   []*cfCert
	fresh   string // id of the most recent upload
	next    int
	fail    failSet
	initial Cert
}

func newCloudflareDevice(t *testing.T) *cloudflareDevice {
	d := &cloudflareDevice{initial: NewCert(t, "cf-initial")}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	d.Reset()
	return d
}

func (d *cloudflareDevice) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	blk, _ := pem.Decode(d.initial.CertPEM)
	l, _ := x509.ParseCertificate(blk.Bytes)
	d.certs = []*cfCert{{ID: "initial", Hosts: []string{cfHost}, Status: "active", Priority: 1,
		ExpiresOn: l.NotAfter.UTC().Format(time.RFC3339), pem: string(d.initial.CertPEM)}}
	d.fresh, d.fail = "", failSet{}
}

func (d *cloudflareDevice) FailNext(step string) { d.mu.Lock(); d.fail[step] = true; d.mu.Unlock() }

func (d *cloudflareDevice) Served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var best *cfCert
	for _, c := range d.certs {
		if c.Status == "active" && (best == nil || c.Priority > best.Priority) {
			best = c
		}
	}
	if best == nil {
		return ""
	}
	return Fingerprint(best.pem)
}

func (d *cloudflareDevice) Env() delivery.Env {
	return anyHostEnv(d.ts, map[string]string{"api_base": "https://example.com", "api_token": cfToken},
		[]string{"api_token"}, map[string]string{"zone_id": cfZone, "hostname": cfHost})
}

func (d *cloudflareDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ok := func(result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
	}
	bad := func(status int, msg string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 1000, "message": msg}}, "result": nil})
	}
	if r.Header.Get("Authorization") != "Bearer "+cfToken {
		bad(http.StatusForbidden, "Authentication error")
		return
	}
	list := "/zones/" + cfZone + "/custom_certificates"
	switch {
	case r.Method == "GET" && r.URL.Path == list:
		ok(d.certs)
	case r.Method == "POST" && r.URL.Path == list:
		if d.fail.take("upload") {
			bad(http.StatusInternalServerError, "internal error")
			return
		}
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		blk, _ := pem.Decode([]byte(b["certificate"]))
		l, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || b["private_key"] == "" {
			bad(http.StatusBadRequest, "invalid certificate")
			return
		}
		d.next++
		c := &cfCert{ID: fmt.Sprintf("upload%d", d.next), Hosts: []string{cfHost}, Status: "active",
			ExpiresOn: l.NotAfter.UTC().Format(time.RFC3339), pem: b["certificate"]}
		d.certs, d.fresh = append(d.certs, c), c.ID
		ok(c)
	case r.Method == "PUT" && r.URL.Path == list+"/prioritize":
		var b struct {
			Certificates []struct {
				ID       string  `json:"id"`
				Priority float64 `json:"priority"`
			} `json:"certificates"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		top, topP := "", -1.0
		for _, it := range b.Certificates {
			if it.Priority > topP {
				top, topP = it.ID, it.Priority
			}
		}
		step := "rollback"
		if top == d.fresh {
			step = "bind"
		}
		if d.fail.take(step) {
			bad(http.StatusInternalServerError, "prioritize failed")
			return
		}
		for _, it := range b.Certificates {
			for _, c := range d.certs {
				if c.ID == it.ID {
					c.Priority = it.Priority
				}
			}
		}
		ok(d.certs)
	case strings.HasPrefix(r.URL.Path, list+"/"):
		id := strings.TrimPrefix(r.URL.Path, list+"/")
		for i, c := range d.certs {
			if c.ID != id {
				continue
			}
			switch r.Method {
			case "GET":
				ok(c)
			case "DELETE":
				d.certs = append(d.certs[:i], d.certs[i+1:]...)
				ok(map[string]string{"id": id})
			default:
				bad(http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}
		bad(http.StatusNotFound, "certificate not found")
	default:
		bad(http.StatusNotFound, "no route")
	}
}

func TestCloudflarePluginConforms(t *testing.T) {
	rt := newRuntime(t)
	Suite(t, Load(t, rt, repoPath(t, "plugins/cloudflare")), newCloudflareDevice(t))
}
