// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

const testHTTPToken = "0123456789abcdef0123456789abcdef"

var testHTTPCfg = HTTPConfig{Token: testHTTPToken, BindAddr: "127.0.0.1:8080"}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

func mcpPost(t *testing.T, host, auth, origin, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewHTTPHandler(NewServer(NewHubClient("http://x", "tok")), testHTTPCfg)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMCPHTTP_AccessControls(t *testing.T) {
	good := "Bearer " + testHTTPToken
	cases := []struct {
		name               string
		host, auth, origin string
		body               string
		want               int
	}{
		{"no token", "127.0.0.1:8080", "", "", initBody, http.StatusUnauthorized},
		{"wrong token", "127.0.0.1:8080", "Bearer " + strings.Repeat("x", 32), "", initBody, http.StatusUnauthorized},
		{"non-bearer scheme", "127.0.0.1:8080", "Basic " + testHTTPToken, "", initBody, http.StatusUnauthorized},
		{"rebinding host", "evil.example.com", good, "", initBody, http.StatusForbidden},
		{"foreign origin", "127.0.0.1:8080", good, "https://evil.example.com", initBody, http.StatusForbidden},
		{"oversize body", "127.0.0.1:8080", good, "", strings.Repeat("a", MaxRequestBodyBytes+10), http.StatusRequestEntityTooLarge},
		{"ok ip", "127.0.0.1:8080", good, "", initBody, http.StatusOK},
		{"ok localhost", "localhost:8080", good, "", initBody, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := mcpPost(t, c.host, c.auth, c.origin, c.body)
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

func TestMCPHTTP_AllowlistedHostAndOrigin(t *testing.T) {
	cfg := testHTTPCfg
	cfg.AllowedHosts = []string{"mcp.example.com"}
	cfg.AllowedOrigins = []string{"https://app.example.com"}
	h := NewHTTPHandler(NewServer(NewHubClient("http://x", "tok")), cfg)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initBody))
	req.Host = "mcp.example.com"
	req.Header.Set("Authorization", "Bearer "+testHTTPToken)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPConfig_ValidateRequiresLongToken(t *testing.T) {
	if (HTTPConfig{Token: "short"}).Validate() == nil || (HTTPConfig{}).Validate() == nil {
		t.Fatal("short/empty token must be refused")
	}
	if err := (HTTPConfig{Token: testHTTPToken}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestHealthz_ReturnsOK(t *testing.T) {
	h := NewHTTPHandler(NewServer(NewHubClient("http://x", "tok")), testHTTPCfg)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != `{"status":"ok"}` {
		t.Errorf("body = %q", got)
	}
}

func TestHealthz_RejectsNonGet(t *testing.T) {
	h := NewHTTPHandler(NewServer(NewHubClient("http://x", "tok")), testHTTPCfg)
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestStreamableHTTP_RoundTrip proves the HTTP transport actually serves the
// real, hub-wired MCP server -- not merely that a handler is mountable. It
// initializes a real mcp-go client over HTTP, lists tools (asserting a
// kryptkeeper-specific tool is present, not an empty/stub server), then
// calls that tool and asserts the call reached fakeHub. Broken independently
// by (a) mounting an empty *server.MCPServer instead of NewServer(hub), and
// (b) unmounting "/mcp" from the handler's mux -- both send this test RED,
// confirming it is not vacuously green.
func TestStreamableHTTP_RoundTrip(t *testing.T) {
	f := newFakeHub(t)
	hub := NewHubClient(f.srv.URL, "secret-token")
	mcpSrv := NewServer(hub)

	ts := httptest.NewServer(NewHTTPHandler(mcpSrv, testHTTPCfg))
	defer ts.Close()

	c, err := client.NewStreamableHttpClient(ts.URL+"/mcp",
		transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + testHTTPToken}))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	ctx := t.Context()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}

	if _, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "test-client", Version: "1.0.0"},
		},
	}); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name == "list_certificates" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("list_certificates tool not present over HTTP transport -- wrong server mounted?")
	}

	callReq := mcp.CallToolRequest{}
	callReq.Params.Name = "crypto_posture"
	res, err := c.CallTool(ctx, callReq)
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("crypto_posture returned an error result: %+v", res.Content)
	}
	if f.lastPath == "" {
		t.Fatal("fakeHub never received a request -- HTTP transport did not reach the Hub client")
	}
	if !strings.HasPrefix(f.lastPath, "/api/v1/reports/crypto-posture") {
		t.Errorf("fakeHub hit %s, want prefix /api/v1/reports/crypto-posture", f.lastPath)
	}
	if f.lastAuth != "Bearer secret-token" {
		t.Errorf("auth header not forwarded over HTTP transport: %q", f.lastAuth)
	}
}

// TestNewHTTPHandler_MCPEndpointOnlyAtMountedPath guards the mux wiring
// itself: a request to a path other than /mcp must not reach the
// StreamableHTTP server.
func TestNewHTTPHandler_MCPEndpointOnlyAtMountedPath(t *testing.T) {
	h := NewHTTPHandler(NewServer(NewHubClient("http://x", "tok")), testHTTPCfg)
	req := httptest.NewRequest(http.MethodPost, "/not-mcp", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("unmounted path returned 200, want a 404/mux miss")
	}
}
