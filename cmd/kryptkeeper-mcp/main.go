// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// kryptkeeper-mcp is a Model Context Protocol (MCP) server that exposes
// Kryptkeeper's read APIs and propose-only write APIs to AI assistants. It
// is a thin adapter: every tool maps to a Hub REST call carrying
// KRYPTKEEPER_MCP_TOKEN, so the Hub's auth, RBAC, and audit apply unchanged.
// Write tools can only enqueue a pending action for a human to approve in
// the dashboard — there is no direct-mutation path in this server (see
// internal/mcpserver.NewServer).
//
// Serves over stdio by default. Set KRYPTKEEPER_MCP_TRANSPORT=http for the
// MCP StreamableHTTP transport instead (for containerized deployment). The
// HTTP transport requires its own bearer token (KRYPTKEEPER_MCP_HTTP_TOKEN,
// min 32 chars; the process refuses to start without it), checks the Host and
// Origin headers against an allowlist (DNS-rebinding defence) and caps request
// bodies at 1 MiB. KRYPTKEEPER_MCP_HTTP_ADDR still defaults to loopback-only.
//
// Environment:
//
//	KRYPTKEEPER_HUB_URL        Hub base URL (required, e.g. https://kryptkeeper.example.com)
//	KRYPTKEEPER_MCP_TOKEN      Bearer token for the Hub API (required)
//	KRYPTKEEPER_MCP_TRANSPORT  "stdio" (default) or "http"
//	KRYPTKEEPER_MCP_HTTP_ADDR  listen address for the http transport (default "127.0.0.1:8080")
//	KRYPTKEEPER_MCP_HTTP_TOKEN bearer token http clients must present (required for http, >= 32 chars)
//	KRYPTKEEPER_MCP_ALLOWED_HOSTS    extra comma-separated Host values accepted (bind address and localhost forms are always accepted)
//	KRYPTKEEPER_MCP_ALLOWED_ORIGINS  comma-separated Origin values accepted (requests with no Origin are accepted)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"kryptkeeper/internal/mcpserver"
)

// defaultHTTPAddr is loopback-only: the StreamableHTTP transport does not
// authenticate callers, so binding all interfaces by default would let any
// host that can route to the port use this process's Hub token, including
// its propose-only write tools.
const defaultHTTPAddr = "127.0.0.1:8080"

// transportFromEnv validates KRYPTKEEPER_MCP_TRANSPORT, defaulting to
// "stdio" when unset so existing stdio-launching MCP clients see no change.
func transportFromEnv(v string) (string, error) {
	switch t := strings.ToLower(strings.TrimSpace(v)); t {
	case "", "stdio":
		return "stdio", nil
	case "http":
		return "http", nil
	default:
		return "", fmt.Errorf("invalid KRYPTKEEPER_MCP_TRANSPORT %q: want \"stdio\" or \"http\"", v)
	}
}

// httpAddrFromEnv returns the configured HTTP listen address, defaulting to
// defaultHTTPAddr.
func httpAddrFromEnv(v string) string {
	if strings.TrimSpace(v) == "" {
		return defaultHTTPAddr
	}
	return v
}

// splitList parses a comma-separated env value, dropping blanks.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// httpConfigFromEnv builds and validates the http transport's access
// controls; it fails (so main refuses to start) when no usable token is set.
func httpConfigFromEnv(getenv func(string) string) (mcpserver.HTTPConfig, error) {
	cfg := mcpserver.HTTPConfig{
		Token:          getenv("KRYPTKEEPER_MCP_HTTP_TOKEN"),
		BindAddr:       httpAddrFromEnv(getenv("KRYPTKEEPER_MCP_HTTP_ADDR")),
		AllowedHosts:   splitList(getenv("KRYPTKEEPER_MCP_ALLOWED_HOSTS")),
		AllowedOrigins: splitList(getenv("KRYPTKEEPER_MCP_ALLOWED_ORIGINS")),
	}
	return cfg, cfg.Validate()
}

// version/commit/date are injected by .goreleaser.yaml's ldflags at release
// build time (W20-02); "dev"/"unknown" is what a plain `go build` leaves.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			fmt.Printf("kryptkeeper-mcp %s (commit %s, built %s)\n", version, commit, date)
			os.Exit(0)
		}
	}

	transport, err := transportFromEnv(os.Getenv("KRYPTKEEPER_MCP_TRANSPORT"))
	if err != nil {
		log.Fatal(err)
	}
	var httpCfg mcpserver.HTTPConfig
	if transport == "http" {
		if httpCfg, err = httpConfigFromEnv(os.Getenv); err != nil {
			log.Fatal(err)
		}
	}

	hubURL := os.Getenv("KRYPTKEEPER_HUB_URL")
	if hubURL == "" {
		log.Fatal("KRYPTKEEPER_HUB_URL is required")
	}
	token := os.Getenv("KRYPTKEEPER_MCP_TOKEN")
	if token == "" {
		log.Fatal("KRYPTKEEPER_MCP_TOKEN is required (a Hub bearer token; use the mcp-agent role, not an approver-capable one)")
	}

	hub := mcpserver.NewHubClient(hubURL, token)

	// D-029/R-C1's second adopted option (G-58): the Hub structurally
	// refuses to let RoleMCPAgent approve anything (W1-04), but nothing
	// stops an operator from provisioning THIS token with a genuinely
	// approver-capable role instead -- refuse to start rather than run with
	// a token that could approve its own (or anyone else's) proposals. This
	// is a boot-time DETECTION of a misprovisioned token, not PREVENTION --
	// it does not stop an approver-capable key minted "for MCP" from being
	// used directly against the Hub REST API outside this process; that
	// residual is out of scope for D-029/G-58.
	//
	// Fail-closed by design: any error reaching the Hub here (including a
	// transient outage at boot) also refuses to start, rather than starting
	// blind to the token's role. This is a deliberate behavior change from
	// before G-58, when the server started independently of Hub reachability.
	checkCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	self, err := hub.CheckSelfRole(checkCtx)
	cancel()
	if err != nil {
		log.Fatalf("could not verify this token's role before starting (hub unreachable or token invalid) -- refusing to start rather than run with an unverified role: %v", err)
	}
	if self.CanApproveActions {
		log.Fatalf("refusing to start: this token's role (%q) can approve pending actions -- provision the MCP server with a non-approver role (e.g. mcp-agent)", self.Role)
	}

	srv := mcpserver.NewServer(hub)

	switch transport {
	case "http":
		addr := httpAddrFromEnv(os.Getenv("KRYPTKEEPER_MCP_HTTP_ADDR"))
		log.Printf("kryptkeeper-mcp %s: serving over HTTP (hub=%s, role=%s, addr=%s)", mcpserver.Version, hubURL, self.Role, addr)
		if err := mcpserver.ServeHTTP(srv, addr, httpCfg); err != nil {
			log.Fatalf("mcp server: %v", err)
		}
	default:
		log.Printf("kryptkeeper-mcp %s: serving over stdio (hub=%s, role=%s)", mcpserver.Version, hubURL, self.Role)
		if err := server.ServeStdio(srv); err != nil {
			log.Fatalf("mcp server: %v", err)
		}
	}
}
