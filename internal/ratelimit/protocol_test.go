// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func headerResolver(r *http.Request) (string, bool) {
	c := r.Header.Get("X-Cred")
	return c, c != ""
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

func do(h http.Handler, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProtocolLimiter_ThousandCredentialsBehindOneIPNever429(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "")
	h := NewProtocolLimiter(600, 30, time.Minute, headerResolver, nil).Middleware(okHandler())
	for c := 0; c < 1000; c++ {
		for i := 0; i < 10; i++ {
			if rec := do(h, "203.0.113.5:1234", map[string]string{"X-Cred": fmt.Sprintf("cred-%d", c)}); rec.Code == http.StatusTooManyRequests {
				t.Fatalf("cred %d request %d got 429", c, i)
			}
		}
	}
}

func TestProtocolLimiter_UnauthenticatedIPLimitIs30(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "")
	h := NewProtocolLimiter(600, 30, time.Minute, headerResolver, nil).Middleware(okHandler())
	for i := 0; i < 30; i++ {
		if rec := do(h, "203.0.113.5:1", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, rec.Code)
		}
	}
	rec := do(h, "203.0.113.5:1", nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("31st: code=%d retry=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := do(h, "198.51.100.9:1", nil); rec.Code != http.StatusOK {
		t.Fatalf("other IP affected: %d", rec.Code)
	}
}

func TestProtocolLimiter_SpoofedXFFFromUntrustedPeerSharesOneBucket(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "")
	h := NewProtocolLimiter(600, 30, time.Minute, nil, nil).Middleware(okHandler())
	var last int
	for i := 0; i < 31; i++ {
		last = do(h, "203.0.113.5:1", map[string]string{"X-Forwarded-For": fmt.Sprintf("10.9.%d.%d", i/200, i%200+1)}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("31st request with rotating XFF = %d, want 429", last)
	}
}

func TestProtocolLimiter_CredentialLimit600(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "")
	h := NewProtocolLimiter(600, 30, time.Minute, headerResolver, nil).Middleware(okHandler())
	for i := 0; i < 600; i++ {
		if rec := do(h, "203.0.113.5:1", map[string]string{"X-Cred": "a"}); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, rec.Code)
		}
	}
	if rec := do(h, "203.0.113.5:1", map[string]string{"X-Cred": "a"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("601st = %d", rec.Code)
	}
	if rec := do(h, "203.0.113.5:1", nil); rec.Code != http.StatusOK {
		t.Fatalf("unauth bucket of same IP should be untouched: %d", rec.Code)
	}
}

func TestProtocolLimiter_InventedCredentialFallsBackToIP(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "")
	unknown := func(r *http.Request) (string, bool) { return "", false }
	h := NewProtocolLimiter(600, 30, time.Minute, unknown, nil).Middleware(okHandler())
	var last int
	for i := 0; i < 31; i++ {
		last = do(h, "203.0.113.5:1", map[string]string{"X-Cred": fmt.Sprintf("invented-%d", i)}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("31st invented-credential request = %d, want 429", last)
	}
}

func TestProtocolLimiter_EvictsIdleKeysAfterTenMinutes(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "")
	p := NewProtocolLimiter(600, 30, time.Minute, nil, nil)
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < 1000; i++ {
		p.cred.AllowAt(fmt.Sprintf("c:%d", i), t0)
	}
	if len(p.cred.buckets) != 1000 {
		t.Fatalf("setup: %d keys", len(p.cred.buckets))
	}
	p.cred.AllowAt("c:new", t0.Add(IdleEvictAfter))
	if n := len(p.cred.buckets); n != 1 {
		t.Fatalf("after idle window %d keys survive, want 1", n)
	}
}

func TestProtocolLimiter_ThrottleCallbackSampledPerKeyPerMinute(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "")
	calls := 0
	var scopes []string
	p := NewProtocolLimiter(600, 30, time.Minute, headerResolver, func(_ *http.Request, scope, key string) {
		calls++
		scopes = append(scopes, scope+"/"+key)
	})
	clock := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return clock }
	h := p.Middleware(okHandler())
	hdr := map[string]string{"X-Cred": "k"}
	for i := 0; i < 600; i++ {
		do(h, "203.0.113.5:1", hdr)
	}
	for i := 0; i < 100; i++ {
		if rec := do(h, "203.0.113.5:1", hdr); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", rec.Code)
		}
	}
	if calls != 1 || scopes[0] != "credential/k" {
		t.Fatalf("calls=%d scopes=%v, want 1 credential/k", calls, scopes)
	}
	// 30 s later the bucket is still full (denied) and the sample window is
	// still closed; at +61 s the original 600 have aged out, so refill them
	// first to be denied again, then expect a second notification.
	clock = clock.Add(61 * time.Second)
	for i := 0; i < 600; i++ {
		do(h, "203.0.113.5:1", hdr)
	}
	do(h, "203.0.113.5:1", hdr)
	if calls != 2 {
		t.Fatalf("after 61s calls=%d, want 2", calls)
	}
}

func jws(t *testing.T, protected, payload any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	out, _ := json.Marshal(map[string]string{"protected": enc(protected), "payload": enc(payload), "signature": "sig"})
	return string(out)
}

func acmeReq(method, ct, body string) *http.Request {
	r := httptest.NewRequest(method, "/acme/new-order", strings.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	return r
}

func acmeResolver() CredentialResolver {
	return ACMECredentialResolver(
		func(id string) bool { return id == "acct1" },
		func(kid string) bool { return kid == "eab1" },
	)
}

func TestACMECredentialResolver_KnownAccountKeysAndBodyRestored(t *testing.T) {
	body := jws(t, map[string]string{"kid": "https://ca.example/acme/account/acct1"}, map[string]string{})
	r := acmeReq(http.MethodPost, "application/jose+json", body)
	key, ok := acmeResolver()(r)
	if !ok || key != "acme-acct:acct1" {
		t.Fatalf("key=%q ok=%v", key, ok)
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != body {
		t.Fatal("body not restored for the next handler")
	}
}

func TestACMECredentialResolver_UnknownKidNotOK(t *testing.T) {
	body := jws(t, map[string]string{"kid": "https://ca.example/acme/account/invented"}, map[string]string{})
	if _, ok := acmeResolver()(acmeReq(http.MethodPost, "application/jose+json", body)); ok {
		t.Fatal("invented account id must not be keyed")
	}
}

func TestACMECredentialResolver_NonPostOrWrongContentTypeNotOK(t *testing.T) {
	body := jws(t, map[string]string{"kid": "https://ca.example/acme/account/acct1"}, map[string]string{})
	if _, ok := acmeResolver()(acmeReq(http.MethodGet, "application/jose+json", body)); ok {
		t.Fatal("GET must not be keyed")
	}
	if _, ok := acmeResolver()(acmeReq(http.MethodPost, "application/json", body)); ok {
		t.Fatal("wrong content type must not be keyed")
	}
}

func TestACMECredentialResolver_EABKidPath(t *testing.T) {
	eab := map[string]string{"protected": base64.RawURLEncoding.EncodeToString([]byte(`{"kid":"eab1"}`))}
	body := jws(t, map[string]string{"jwk": "x"}, map[string]any{"externalAccountBinding": eab})
	key, ok := acmeResolver()(acmeReq(http.MethodPost, "application/jose+json", body))
	if !ok || key != "acme-eab:eab1" {
		t.Fatalf("key=%q ok=%v", key, ok)
	}
	eab["protected"] = base64.RawURLEncoding.EncodeToString([]byte(`{"kid":"nope"}`))
	body = jws(t, map[string]string{"jwk": "x"}, map[string]any{"externalAccountBinding": eab})
	if _, ok := acmeResolver()(acmeReq(http.MethodPost, "application/jose+json", body)); ok {
		t.Fatal("unknown EAB kid must not be keyed")
	}
}

func TestACMECredentialResolver_OversizeBodyNotOKAndFullyRestored(t *testing.T) {
	body := `{"protected":"` + strings.Repeat("A", maxProtocolBody+100) + `"}`
	r := acmeReq(http.MethodPost, "application/jose+json", body)
	if _, ok := acmeResolver()(r); ok {
		t.Fatal("oversize body must not be keyed")
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != body {
		t.Fatalf("oversize body not fully restored: %d of %d bytes", len(got), len(body))
	}
}

func TestBasicUserResolver(t *testing.T) {
	res := BasicUserResolver(func(n string) bool { return n == "alice" })
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.SetBasicAuth("alice", "pw")
	if k, ok := res(r); !ok || k != "est-user:alice" {
		t.Fatalf("k=%q ok=%v", k, ok)
	}
	r.SetBasicAuth("mallory", "pw")
	if _, ok := res(r); ok {
		t.Fatal("unknown user must not be keyed")
	}
}

func TestRenewalStormSeesNoThrottle(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "")
	p := NewProtocolLimiter(600, 30, time.Minute, headerResolver, nil)
	t0 := time.Unix(1_700_000_000, 0)
	throttled := 0
	for c := 0; c < 2000; c++ {
		// Renewals land at spread-out moments across one hour.
		at := t0.Add(time.Duration(c) * 1800 * time.Millisecond)
		req := httptest.NewRequest(http.MethodPost, "/acme/x", nil)
		req.RemoteAddr = "203.0.113.5:1"
		req.Header.Set("X-Cred", fmt.Sprintf("acct-%d", c))
		for i := 0; i < 3; i++ { // new-order, finalize, download
			if ok, _, _ := p.Allow(req, at.Add(time.Duration(i)*time.Second)); !ok {
				throttled++
			}
		}
	}
	if throttled != 0 {
		t.Fatalf("%d renewal requests throttled", throttled)
	}
}
