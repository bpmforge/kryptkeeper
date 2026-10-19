// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func cookieReq(method, host string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+"/api/v1/anything", nil)
	r.AddCookie(&http.Cookie{Name: "kk_token", Value: "session-token"})
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

// F9: unsafe cookie-authenticated requests must be same-origin.
func TestCrossSiteCookieRequest(t *testing.T) {
	const host = "kk.example.com"
	cases := []struct {
		name   string
		method string
		hdr    map[string]string
		want   bool
	}{
		{"POST same-origin fetch", "POST", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://kk.example.com"}, false},
		{"POST user-initiated none", "POST", map[string]string{"Sec-Fetch-Site": "none"}, false},
		{"POST cross-site", "POST", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, true},
		{"POST same-site sibling subdomain", "POST", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://evil.example.com"}, true},
		{"DELETE cross-site", "DELETE", map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
		{"PUT same-site", "PUT", map[string]string{"Sec-Fetch-Site": "same-site"}, true},
		{"PATCH origin mismatch no SFS", "PATCH", map[string]string{"Origin": "https://evil.example"}, true},
		{"POST origin null", "POST", map[string]string{"Origin": "null"}, true},
		{"POST origin matches host no SFS", "POST", map[string]string{"Origin": "https://kk.example.com"}, false},
		{"POST origin matches forwarded host", "POST", map[string]string{"Origin": "https://edge.example.com:3000", "X-Forwarded-Host": "edge.example.com:3000"}, false},
		{"POST no Origin no SFS (non-browser)", "POST", nil, false},
		{"GET cross-site is safe method", "GET", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"POST with spoofed SFS cannot override mismatched cross-site", "POST", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://kk.example.com"}, true},
	}
	for _, c := range cases {
		if got := crossSiteCookieRequest(cookieReq(c.method, host, c.hdr)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	// Header auth is not ambient: a cross-site Authorization-bearing request is not the cookie's concern.
	r := cookieReq("POST", host, map[string]string{"Sec-Fetch-Site": "cross-site", "Authorization": "Bearer abc"})
	if crossSiteCookieRequest(r) {
		t.Error("bearer-authenticated request must not be treated as cookie auth")
	}
	// No cookie, nothing to protect.
	r = httptest.NewRequest("POST", "http://"+host+"/x", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if crossSiteCookieRequest(r) {
		t.Error("no cookie: nothing to guard")
	}
}

// End to end: a valid session cookie is honoured same-origin but refused on a
// cross-site write, by the authenticator itself and by the 403 wrapper.
func TestCookieAuth_CrossSiteWriteRefused(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	token, _, _, _, err := auth.mintSessionForUser("local-admin", "pki-admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(method string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest(method, "http://kk.example.com/api/v1/x", nil)
		r.AddCookie(&http.Cookie{Name: "kk_token", Value: token})
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	if _, err := auth.AuthenticatePrincipalDetails(mk("POST", map[string]string{"Sec-Fetch-Site": "same-origin"}), time.Now()); err != nil {
		t.Fatalf("same-origin cookie write refused: %v", err)
	}
	if _, err := auth.AuthenticatePrincipalDetails(mk("POST", nil), time.Now()); err != nil {
		t.Fatalf("non-browser cookie write refused: %v", err)
	}
	if _, err := auth.AuthenticatePrincipalDetails(mk("GET", map[string]string{"Sec-Fetch-Site": "cross-site"}), time.Now()); err != nil {
		t.Fatalf("cross-site read must stay allowed: %v", err)
	}
	if _, err := auth.AuthenticatePrincipalDetails(mk("POST", map[string]string{"Sec-Fetch-Site": "cross-site"}), time.Now()); err == nil {
		t.Fatal("cross-site cookie write authenticated")
	}

}
