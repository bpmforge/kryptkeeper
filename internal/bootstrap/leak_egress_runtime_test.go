// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/egress"
)

// withProductionEgress turns the suite-wide loopback/plain-http seam off so a
// test sees the policy production runs under.
func withProductionEgress(t *testing.T) {
	t.Helper()
	prev := egressAllowLoopback
	egressAllowLoopback = false
	t.Cleanup(func() { egressAllowLoopback = prev })
}

// M-1: the default device push client refuses cloud metadata, loopback and
// plain http, and ignores redirects.
func TestPushDeviceHTTPClientRefusesInternalAndCleartext(t *testing.T) {
	withProductionEgress(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	c := pushDeviceHTTPClient(nil)
	for _, u := range []string{"https://169.254.169.254/latest/meta-data", srv.URL, "https://127.0.0.1:1/"} {
		_, err := c.Get(u)
		if !errors.Is(err, egress.ErrBlockedDestination) {
			t.Errorf("%s: want ErrBlockedDestination, got %v", u, err)
		}
	}
}

func TestPushCredentialBaseURLMustBeHTTPS(t *testing.T) {
	withProductionEgress(t)
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://bigip.corp.example", true},
		{"http://bigip.corp.example", false},
		{"https://u:p@bigip.corp.example", false},
		{"ftp://bigip.corp.example", false},
		{"https://", false},
	} {
		e := NewRenewalExecutor(nil, &renewalFakeCredStore{
			meta:    OutboundCredentialMeta{ID: "c", CredentialType: CredentialTypeAPIToken},
			payload: []byte(`{"base_url":"` + tc.url + `"}`),
		})
		_, err := e.resolvePushCredential(context.Background(), "c", "f5")
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected %v", tc.url, err)
		}
		if !tc.ok && !errors.Is(err, errRenewalBadCredential) {
			t.Errorf("%s: want errRenewalBadCredential, got %v", tc.url, err)
		}
	}
}

// M-2: the runtime IdP client refuses metadata, including when a discovery
// document names it.
func TestOIDCRuntimeClientRefusesMetadata(t *testing.T) {
	withProductionEgress(t)
	if _, err := oidcRuntimeClient(time.Second, "https://idp.example").Get("https://169.254.169.254/"); !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("want ErrBlockedDestination, got %v", err)
	}
}

func TestOIDCDiscoveryJWKSURIToMetadataRefused(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_endpoint":"` + srv.URL + `/a","token_endpoint":"` + srv.URL + `/token","jwks_uri":"https://169.254.169.254/jwks"}`))
	}))
	defer srv.Close()
	cache, err := newManagedOIDCJWKSCache(srv.URL, time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.fetchJWKS(context.Background()); !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("jwks_uri pointing at metadata must be refused by the egress guard, got %v", err)
	}
}

// L-3: the tls_ca_pem client keeps the address policy and ignores env proxies.
func TestPluginHTTPClientWithCAKeepsEgressPolicy(t *testing.T) {
	withProductionEgress(t)
	dev := newPluginDevice(t)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dev.ts.Certificate().Raw}))
	for _, ca := range []string{caPEM, ""} {
		c, err := pluginHTTPClient(nil, ca)
		if err != nil || c == nil {
			t.Fatalf("client: %v %v", c, err)
		}
		if _, err := c.Get("https://169.254.169.254/"); !errors.Is(err, egress.ErrBlockedDestination) {
			t.Errorf("ca=%v: metadata reachable: %v", ca != "", err)
		}
	}
}

// A loopback IdP is reachable only when the operator configured a loopback
// URL; a remote IdP's settings never open loopback.
func TestOIDCRuntimeClientLoopbackOnlyWhenOperatorConfigured(t *testing.T) {
	withProductionEgress(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if resp, err := oidcRuntimeClient(time.Second, srv.URL).Get(srv.URL); err != nil {
		t.Fatalf("operator-configured loopback IdP refused: %v", err)
	} else {
		_ = resp.Body.Close()
	}
	if _, err := oidcRuntimeClient(time.Second, "https://idp.example").Get(srv.URL); err == nil {
		t.Fatal("loopback reachable with a remote IdP configured")
	}
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1", "http://[::1]:9"} {
		if !isLoopbackURL(u) {
			t.Errorf("isLoopbackURL(%q) = false", u)
		}
	}
	if isLoopbackURL("https://idp.example") || isLoopbackURL("http://10.0.0.1") {
		t.Error("non-loopback URL classed as loopback")
	}
}

func TestOIDCDiscoveryRemoteDocumentCannotNameLoopbackTokenEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example/a","token_endpoint":"http://127.0.0.1:9/token"}`))
	}))
	defer srv.Close()
	// Serve "https://idp.example" from the fixture so the discovery URL the
	// hub sees is remote while the bytes come from the test server.
	toFixture := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}
	cache := &managedOIDCJWKSCache{
		client:       &http.Client{Transport: rewriteToHTTP{toFixture}},
		discoveryURL: "https://idp.example/.well-known/openid-configuration",
		ttl:          time.Minute,
	}
	if _, _, err := discoverOIDCEndpoints(cache); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("remote discovery naming a loopback token endpoint: want refusal, got %v", err)
	}
}

// rewriteToHTTP sends an https request as plain http so a test fixture can
// answer for a remote https name.
type rewriteToHTTP struct{ rt http.RoundTripper }

func (r rewriteToHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	return r.rt.RoundTrip(clone)
}
