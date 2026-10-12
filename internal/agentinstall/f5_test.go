// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// W5-03: F5 push — upload, install, profile re-point, verify, rollback.

type f5Fixture struct {
	srv      *httptest.Server
	requests []string // "METHOD path"
	patches  []map[string]string
}

func newF5Fixture(t *testing.T) *f5Fixture {
	t.Helper()
	f := &f5Fixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/"):
			if r.Header.Get("Content-Range") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/mgmt/tm/sys/crypto/cert" || r.URL.Path == "/mgmt/tm/sys/crypto/key":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/mgmt/tm/ltm/profile/client-ssl/"):
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"cert":"old-cert","key":"old-key"}`))
				return
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body) // fixture: malformed body shows up as an empty patch in assertions
			f.patches = append(f.patches, body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func f5PusherFor(f *f5Fixture) *F5Pusher {
	return NewF5Pusher(F5Config{
		BaseURL: f.srv.URL, Username: "admin", Password: "secret",
		ClientSSLProfile: "clientssl-shop",
	}, f.srv.Client())
}

func f5Req() PushRequest {
	return PushRequest{Name: "shop-2026", CertPEM: []byte("CERTPEM"), KeyPEM: []byte("KEYPEM")}
}

func TestF5PushSequenceAndVerify(t *testing.T) {
	f := newF5Fixture(t)
	p := f5PusherFor(f).WithVerifier(func(context.Context, string) (string, error) { return "abcd", nil })

	req := f5Req()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "AB:CD"
	res, err := p.Push(context.Background(), req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Outcome != OutcomeInstalledVerified || !res.Verified {
		t.Fatalf("expected verified push: %+v", res)
	}
	want := []string{
		"POST /mgmt/shared/file-transfer/uploads/shop-2026.crt",
		"POST /mgmt/shared/file-transfer/uploads/shop-2026.key",
		"POST /mgmt/tm/sys/crypto/cert",
		"POST /mgmt/tm/sys/crypto/key",
		"GET /mgmt/tm/ltm/profile/client-ssl/clientssl-shop",
		"PATCH /mgmt/tm/ltm/profile/client-ssl/clientssl-shop",
	}
	if len(f.requests) != len(want) {
		t.Fatalf("request sequence %v, want %v", f.requests, want)
	}
	for i := range want {
		if f.requests[i] != want[i] {
			t.Fatalf("step %d: %s, want %s", i, f.requests[i], want[i])
		}
	}
	if len(f.patches) != 1 || f.patches[0]["cert"] != "shop-2026" {
		t.Fatalf("profile must be re-pointed at the new pair: %v", f.patches)
	}
}

func TestF5VerifyMismatchRollsProfileBack(t *testing.T) {
	f := newF5Fixture(t)
	p := f5PusherFor(f).WithVerifier(func(context.Context, string) (string, error) { return "ffff", nil })

	req := f5Req()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "abcd"
	res, err := p.Push(context.Background(), req)
	if err == nil {
		t.Fatal("mismatch must error")
	}
	if res.Outcome != OutcomeVerifyFailed || !res.RolledBack {
		t.Fatalf("expected verify_failed + rollback: %+v", res)
	}
	// Two PATCHes: re-point, then restore to the recorded prior refs.
	if len(f.patches) != 2 || f.patches[1]["cert"] != "old-cert" || f.patches[1]["key"] != "old-key" {
		t.Fatalf("profile must be rolled back to prior refs: %v", f.patches)
	}
}

func TestF5AuthFailureSurfaces(t *testing.T) {
	f := newF5Fixture(t)
	p := NewF5Pusher(F5Config{BaseURL: f.srv.URL, Username: "admin", Password: "wrong", ClientSSLProfile: "x"}, f.srv.Client())
	if _, err := p.Push(context.Background(), f5Req()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("auth failure must surface the status, got %v", err)
	}
}

// Review fix (security challenger #1): when verify fails AND the
// rollback PATCH also fails, RolledBack must be FALSE (the device may
// still serve the unverified cert) — never a false claim of rollback.
func TestF5RollbackFailureReportedHonestly(t *testing.T) {
	f := newF5Fixture(t)
	// Make the profile PATCH fail (both the re-point and the restore).
	patchFails := true
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/"):
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/mgmt/tm/sys/crypto/cert" || r.URL.Path == "/mgmt/tm/sys/crypto/key":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/mgmt/tm/ltm/profile/client-ssl/"):
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"cert":"old-cert","key":"old-key"}`))
				return
			}
			if patchFails {
				w.WriteHeader(http.StatusInternalServerError) // rollback (and re-point) fail
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	p := f5PusherFor(f).WithVerifier(func(context.Context, string) (string, error) { return "ffff", nil })
	req := f5Req()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "abcd"
	res, _ := p.Push(context.Background(), req)
	// The re-point PATCH fails first → binding failure; but if it got to
	// verify, a failed restore must never claim RolledBack.
	if res.RolledBack {
		t.Fatalf("a failed rollback must not report RolledBack=true: %+v", res)
	}
}
