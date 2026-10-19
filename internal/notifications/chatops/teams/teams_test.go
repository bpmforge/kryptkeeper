// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package teams

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testApp = "app-1234"
	testSvc = "https://smba.trafficmanager.net/amer/"
)

var testNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwksFor(kid string, k *rsa.PrivateKey) string {
	js, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}}})
	return string(js)
}

func mint(t *testing.T, k *rsa.PrivateKey, hdr, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func goodClaims() map[string]any {
	return map[string]any{"iss": BotFrameworkIssuer, "aud": testApp, "serviceurl": testSvc,
		"exp": testNow.Add(time.Hour).Unix(), "nbf": testNow.Add(-time.Minute).Unix()}
}

func goodHdr() map[string]any { return map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"} }

func newVal(k *rsa.PrivateKey) *Validator {
	doc := jwksFor("k1", k)
	return &Validator{AppID: testApp, JWKS: func(context.Context) (string, error) { return doc, nil }, Now: func() time.Time { return testNow }}
}

func with(m map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for a, b := range m {
		out[a] = b
	}
	if v == nil {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}

func TestValidate_Valid(t *testing.T) {
	k := genKey(t)
	v := newVal(k)
	tok := mint(t, k, goodHdr(), goodClaims())
	if err := v.Validate(t.Context(), "Bearer "+tok, testSvc); err != nil {
		t.Fatal(err)
	}
	// aud as an array and expiry inside the skew window are accepted.
	c := with(with(goodClaims(), "aud", []string{"x", testApp}), "exp", testNow.Add(-time.Minute).Unix())
	if err := v.Validate(t.Context(), "Bearer "+mint(t, k, goodHdr(), c), testSvc); err != nil {
		t.Fatal(err)
	}
}

func TestValidate_Rejections(t *testing.T) {
	k := genKey(t)
	other := genKey(t)
	v := newVal(k)
	cases := []struct {
		name string
		auth string
	}{
		{"WrongAudience", "Bearer " + mint(t, k, goodHdr(), with(goodClaims(), "aud", "other"))},
		{"WrongIssuer", "Bearer " + mint(t, k, goodHdr(), with(goodClaims(), "iss", "https://evil.example"))},
		{"Expired", "Bearer " + mint(t, k, goodHdr(), with(goodClaims(), "exp", testNow.Add(-6*time.Minute).Unix()))},
		{"NoExp", "Bearer " + mint(t, k, goodHdr(), with(goodClaims(), "exp", nil))},
		{"NotYetValid", "Bearer " + mint(t, k, goodHdr(), with(goodClaims(), "nbf", testNow.Add(6*time.Minute).Unix()))},
		{"WrongServiceURL", "Bearer " + mint(t, k, goodHdr(), with(goodClaims(), "serviceurl", "https://other.example/"))},
		{"NoServiceURLClaim", "Bearer " + mint(t, k, goodHdr(), with(goodClaims(), "serviceurl", nil))},
		{"WrongSigningKey", "Bearer " + mint(t, other, goodHdr(), goodClaims())},
		{"NoKid", "Bearer " + mint(t, k, with(goodHdr(), "kid", nil), goodClaims())},
		{"Garbage", "Bearer not.a.jwt"},
		{"TwoSegments", "Bearer a.b"},
		{"NoBearer", mint(t, k, goodHdr(), goodClaims())},
		{"Empty", ""},
	}
	for _, c := range cases {
		if err := v.Validate(t.Context(), c.auth, testSvc); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := (&Validator{JWKS: v.JWKS, Now: v.Now}).Validate(t.Context(), cases[0].auth, testSvc); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("empty AppID must fail closed: %v", err)
	}
}

func TestValidate_AlgNone(t *testing.T) {
	k := genKey(t)
	v := newVal(k)
	h, _ := json.Marshal(map[string]any{"alg": "none", "kid": "k1"})
	c, _ := json.Marshal(goodClaims())
	for _, tok := range []string{b64(h) + "." + b64(c) + ".", b64(h) + "." + b64(c) + "." + b64([]byte("x"))} {
		if err := v.Validate(t.Context(), "Bearer "+tok, testSvc); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("alg none accepted: %v", err)
		}
	}
}

func TestValidate_AlgHS256WithPublicKeyAsSecret(t *testing.T) {
	k := genKey(t)
	v := newVal(k)
	h, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": "k1"})
	c, _ := json.Marshal(goodClaims())
	in := b64(h) + "." + b64(c)
	for _, secret := range [][]byte{k.N.Bytes(), []byte(jwksFor("k1", k))} {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(in))
		if err := v.Validate(t.Context(), "Bearer "+in+"."+b64(m.Sum(nil)), testSvc); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("HS256 accepted: %v", err)
		}
	}
}

func TestValidate_SmallKeyRejected(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skip("1024-bit keys disabled")
	}
	v := newVal(small)
	if err := v.Validate(t.Context(), "Bearer "+mint(t, small, goodHdr(), goodClaims()), testSvc); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("1024-bit key accepted: %v", err)
	}
}

func TestValidate_UnknownKid_RefetchesOnce(t *testing.T) {
	oldK, newK := genKey(t), genKey(t)
	oldDoc, newDoc := jwksFor("old", oldK), jwksFor("k1", newK)
	var refreshes atomic.Int32
	v := &Validator{AppID: testApp, Now: func() time.Time { return testNow },
		JWKS:    func(context.Context) (string, error) { return oldDoc, nil },
		Refresh: func(context.Context) (string, error) { refreshes.Add(1); return newDoc, nil }}
	if err := v.Validate(t.Context(), "Bearer "+mint(t, newK, goodHdr(), goodClaims()), testSvc); err != nil {
		t.Fatal(err)
	}
	if refreshes.Load() != 1 {
		t.Fatalf("refreshes = %d", refreshes.Load())
	}
	// A kid that never appears triggers one refresh per validation, not a loop.
	refreshes.Store(0)
	if err := v.Validate(t.Context(), "Bearer "+mint(t, newK, with(goodHdr(), "kid", "ghost"), goodClaims()), testSvc); err == nil {
		t.Fatal("ghost kid accepted")
	}
	if refreshes.Load() != 1 {
		t.Fatalf("refreshes = %d", refreshes.Load())
	}
}

func TestJWKSCache_CachesAndRateLimitsRefresh(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	clock := testNow
	c := &JWKSCache{URL: srv.URL, HTTP: srv.Client(), Now: func() time.Time { return clock }}
	for range 3 {
		if _, err := c.Get(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
	if _, err := c.Refresh(t.Context()); err != nil || hits.Load() != 1 {
		t.Fatalf("refresh within a minute refetched: %d %v", hits.Load(), err)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err := c.Refresh(t.Context()); err != nil || hits.Load() != 2 {
		t.Fatalf("refresh after a minute: %d %v", hits.Load(), err)
	}
	clock = clock.Add(25 * time.Hour)
	if _, err := c.Get(t.Context()); err != nil || hits.Load() != 3 {
		t.Fatalf("ttl refetch: %d %v", hits.Load(), err)
	}
}

func TestParseActivityAndCheckFresh(t *testing.T) {
	body := `{"id":"a1","type":"message","serviceUrl":"` + testSvc + `","timestamp":"2026-10-16T12:00:00.123Z",
	 "from":{"id":"29:xyz","aadObjectId":"oid-1"},"conversation":{"id":"c1"},
	 "channelData":{"tenant":{"id":"tid-1"}},"value":{"kk_action":"approve","kind":"action","id":"act-1"}}`
	a, err := ParseActivity([]byte(body))
	if err != nil || a.From.AADObjectID != "oid-1" || a.ChannelData.Tenant.ID != "tid-1" || a.Action("id") != "act-1" {
		t.Fatalf("%+v %v", a, err)
	}
	for _, bad := range []string{`{"type":"conversationUpdate"}`, `{"type":"message","value":{}}`, `{"type":"message"}`} {
		if _, err := ParseActivity([]byte(bad)); !errors.Is(err, ErrIgnored) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := ParseActivity([]byte(`{`)); err == nil || errors.Is(err, ErrIgnored) {
		t.Errorf("malformed json: %v", err)
	}
	ts := func(d time.Duration) Activity { return Activity{Timestamp: testNow.Add(d).Format(time.RFC3339)} }
	if ts(-4*time.Minute).CheckFresh(testNow) != nil || ts(4*time.Minute).CheckFresh(testNow) != nil {
		t.Error("in-window rejected")
	}
	for _, a := range []Activity{ts(-6 * time.Minute), ts(6 * time.Minute), {}, {Timestamp: "yesterday"}} {
		if !errors.Is(a.CheckFresh(testNow), ErrStale) {
			t.Errorf("%q accepted", a.Timestamp)
		}
	}
}

func TestApprovalCard_ButtonsAndData(t *testing.T) {
	card := ApprovalCard("action", "act-1", "Revoke cert", "ann", testNow)
	js, _ := json.Marshal(card)
	var back struct {
		Type    string `json:"type"`
		Version string `json:"version"`
		Actions []struct {
			Type  string         `json:"type"`
			Title string         `json:"title"`
			Data  map[string]any `json:"data"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(js, &back); err != nil {
		t.Fatal(err)
	}
	if back.Type != "AdaptiveCard" || back.Version != "1.4" || len(back.Actions) != 2 {
		t.Fatalf("%s", js)
	}
	for i, want := range []string{"approve", "reject"} {
		a := back.Actions[i]
		if a.Type != "Action.Submit" || a.Data["kk_action"] != want || a.Data["kind"] != "action" || a.Data["id"] != "act-1" {
			t.Errorf("action %d: %+v", i, a)
		}
	}
}

func posterEnv(t *testing.T) (*Poster, *atomic.Int32, *atomic.Int32, *[]string) {
	t.Helper()
	var tokens, posts atomic.Int32
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/token":
			tokens.Add(1)
			if !strings.Contains(string(b), "client_secret=pw") || !strings.Contains(string(b), "grant_type=client_credentials") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok-1","expires_in":3600}`))
		case strings.HasSuffix(r.URL.Path, "/activities"):
			posts.Add(1)
			if r.Header.Get("Authorization") != "Bearer tok-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			seen = append(seen, r.URL.Path+"|"+string(b))
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	p := &Poster{AppID: "app", AppPassword: "pw", TokenURL: srv.URL + "/token", HTTP: srv.Client(),
		Resolver: MapResolver{"team-a": {ServiceURL: srv.URL, ConversationID: "19:abc@thread.tacv2"}}, allowInsecureServiceURL: true}
	return p, &tokens, &posts, &seen
}

func TestPoster_PostsToOwnerTeamChannelOnly(t *testing.T) {
	p, tokens, posts, seen := posterEnv(t)
	if err := p.PostApproval(t.Context(), "team-a", "action", "act-1", "Revoke", "ann", testNow); err != nil {
		t.Fatal(err)
	}
	if err := p.PostApproval(t.Context(), "team-a", "approval", "apr-2", "Issue", "bob", testNow); err != nil {
		t.Fatal(err)
	}
	if tokens.Load() != 1 || posts.Load() != 2 {
		t.Fatalf("tokens=%d posts=%d (token must be cached)", tokens.Load(), posts.Load())
	}
	got := (*seen)[0]
	if !strings.HasPrefix(got, "/v3/conversations/19:abc@thread.tacv2/activities|") ||
		!strings.Contains(got, "application/vnd.microsoft.card.adaptive") ||
		!strings.Contains(got, `"kk_action":"approve"`) || !strings.Contains(got, `"kk_action":"reject"`) {
		t.Fatalf("%s", got)
	}
	tokens.Store(0)
	posts.Store(0)
	if err := p.PostApproval(t.Context(), "team-unmapped", "action", "act-1", "x", "ann", testNow); !errors.Is(err, ErrNoTeamChannel) {
		t.Fatalf("err = %v", err)
	}
	if tokens.Load() != 0 || posts.Load() != 0 {
		t.Fatal("unmapped team made HTTP calls")
	}
}

func TestPoster_RejectsIPLiteralServiceURL(t *testing.T) {
	for _, u := range []string{"https://127.0.0.1/", "https://169.254.169.254/", "https://[::1]/", "http://smba.example/", "https://user@smba.example/", "smba.example", ""} {
		var calls atomic.Int32
		p := &Poster{AppID: "a", AppPassword: "p", TokenURL: "http://127.0.0.1:1/token",
			HTTP:     &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, errors.New("blocked") })},
			Resolver: MapResolver{"t": {ServiceURL: u, ConversationID: "c"}}}
		if err := p.PostApproval(t.Context(), "t", "action", "a", "s", "r", testNow); err == nil || errors.Is(err, ErrNoTeamChannel) {
			t.Errorf("%q: err = %v", u, err)
		}
		if calls.Load() != 0 {
			t.Errorf("%q: %d HTTP calls", u, calls.Load())
		}
	}
	if !validServiceURL("https://smba.trafficmanager.net/amer/") {
		t.Error("valid https hostname rejected")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPoster_UpdateActivity_PutsTextWithoutCard(t *testing.T) {
	var method, path, body string
	p := &Poster{AppID: "a", AppPassword: "p", TokenURL: "https://login.test/token", Resolver: MapResolver{},
		HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "token") {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"t","expires_in":3600}`))}, nil
			}
			b, _ := io.ReadAll(r.Body)
			method, path, body = r.Method, r.URL.Path, string(b)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		})}}
	if err := p.UpdateActivity(t.Context(), ChannelRef{ServiceURL: "https://smba.example", ConversationID: "19:abc"}, "act-1", "Approved by bob"); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || path != "/v3/conversations/19:abc/activities/act-1" ||
		!strings.Contains(body, "Approved by bob") || strings.Contains(body, "kk_action") {
		t.Fatalf("%s %s %s", method, path, body)
	}
	if err := p.UpdateActivity(t.Context(), ChannelRef{ServiceURL: "https://127.0.0.1", ConversationID: "c"}, "a", "x"); err == nil {
		t.Fatal("IP literal serviceUrl must be refused")
	}
}
