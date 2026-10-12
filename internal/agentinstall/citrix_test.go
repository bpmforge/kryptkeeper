// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// W5-03: Citrix ADC push — systemfile uploads, sslcertkey update (add
// fallback), verify-after-push, honest no-rollback reporting.

type citrixFixture struct {
	srv        *httptest.Server
	requests   []string
	files      map[string]string // filename -> decoded content
	certkeySet map[string]string
	// updateFails makes ?action=update return 599 so add is exercised.
	updateFails bool
}

func newCitrixFixture(t *testing.T) *citrixFixture {
	t.Helper()
	f := &citrixFixture{files: map[string]string{}, certkeySet: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.Method+" "+r.URL.Path+queryOf(r))
		if r.Header.Get("X-NITRO-USER") != "nsroot" || r.Header.Get("X-NITRO-PASS") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/nitro/v1/config/systemfile":
			var body struct {
				Systemfile struct {
					Filename    string `json:"filename"`
					Filecontent string `json:"filecontent"`
				} `json:"systemfile"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			raw, _ := base64.StdEncoding.DecodeString(body.Systemfile.Filecontent) // fixture asserts content below; bad b64 = empty
			f.files[body.Systemfile.Filename] = string(raw)
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/nitro/v1/config/sslcertkey" && r.URL.RawQuery == "action=update":
			if f.updateFails {
				w.WriteHeader(599)
				return
			}
			f.recordCertkey(r)
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/nitro/v1/config/sslcertkey":
			f.recordCertkey(r)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *citrixFixture) recordCertkey(r *http.Request) {
	var body struct {
		SSLCertKey map[string]string `json:"sslcertkey"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // fixture: a malformed body leaves certkeySet empty and fails the assertion
	f.certkeySet = body.SSLCertKey
}

func queryOf(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

func citrixPusherFor(f *citrixFixture) *CitrixPusher {
	return NewCitrixPusher(CitrixConfig{
		BaseURL: f.srv.URL, Username: "nsroot", Password: "secret",
		CertKeyName: "shop-certkey",
	}, f.srv.Client())
}

func citrixReq() PushRequest {
	return PushRequest{Name: "shop-2026", CertPEM: []byte("CERTPEM"), KeyPEM: []byte("KEYPEM")}
}

func TestCitrixPushUploadsAndRepoints(t *testing.T) {
	f := newCitrixFixture(t)
	p := citrixPusherFor(f).WithVerifier(func(context.Context, string) (string, error) { return "abcd", nil })

	req := citrixReq()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "abcd"
	res, err := p.Push(context.Background(), req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Outcome != OutcomeInstalledVerified {
		t.Fatalf("expected verified: %+v", res)
	}
	// Files landed with their real content, base64-decoded server-side.
	if f.files["shop-2026.crt"] != "CERTPEM" || f.files["shop-2026.key"] != "KEYPEM" {
		t.Fatalf("uploaded content wrong: %v", f.files)
	}
	// The certkey re-points at the uploaded paths.
	if f.certkeySet["certkey"] != "shop-certkey" || f.certkeySet["cert"] != "/nsconfig/ssl/shop-2026.crt" {
		t.Fatalf("sslcertkey not re-pointed: %v", f.certkeySet)
	}
}

func TestCitrixFirstInstallFallsBackToAdd(t *testing.T) {
	f := newCitrixFixture(t)
	f.updateFails = true
	p := citrixPusherFor(f)

	if _, err := p.Push(context.Background(), citrixReq()); err != nil {
		t.Fatalf("push with add fallback: %v", err)
	}
	joined := strings.Join(f.requests, " | ")
	if !strings.Contains(joined, "sslcertkey?action=update") || !strings.HasSuffix(joined, "POST /nitro/v1/config/sslcertkey") {
		t.Fatalf("update must be tried first, then add: %v", f.requests)
	}
}

func TestCitrixVerifyMismatchReportsWithoutFakeRollback(t *testing.T) {
	f := newCitrixFixture(t)
	p := citrixPusherFor(f).WithVerifier(func(context.Context, string) (string, error) { return "ffff", nil })

	req := citrixReq()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "abcd"
	res, err := p.Push(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "no automatic rollback") {
		t.Fatalf("mismatch must error naming the no-rollback posture, got %v", err)
	}
	if res.Outcome != OutcomeVerifyFailed || res.RolledBack {
		t.Fatalf("must report verify_failed WITHOUT claiming a rollback: %+v", res)
	}
}
