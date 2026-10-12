// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestTransportFromEnv_DefaultsToStdio(t *testing.T) {
	for _, v := range []string{"", "stdio", "STDIO", "  stdio  "} {
		got, err := transportFromEnv(v)
		if err != nil {
			t.Fatalf("transportFromEnv(%q) error: %v", v, err)
		}
		if got != "stdio" {
			t.Errorf("transportFromEnv(%q) = %q, want %q", v, got, "stdio")
		}
	}
}

func TestTransportFromEnv_AcceptsHTTPCaseInsensitive(t *testing.T) {
	for _, v := range []string{"http", "HTTP", " Http "} {
		got, err := transportFromEnv(v)
		if err != nil {
			t.Fatalf("transportFromEnv(%q) error: %v", v, err)
		}
		if got != "http" {
			t.Errorf("transportFromEnv(%q) = %q, want %q", v, got, "http")
		}
	}
}

func TestTransportFromEnv_RejectsUnknown(t *testing.T) {
	if _, err := transportFromEnv("websocket"); err == nil {
		t.Fatal("expected an error for an unsupported transport value")
	}
}

func TestHTTPAddrFromEnv_DefaultsToLoopback(t *testing.T) {
	if got := httpAddrFromEnv(""); got != defaultHTTPAddr {
		t.Errorf("httpAddrFromEnv(\"\") = %q, want %q", got, defaultHTTPAddr)
	}
	if got := httpAddrFromEnv("   "); got != defaultHTTPAddr {
		t.Errorf("httpAddrFromEnv(whitespace) = %q, want %q", got, defaultHTTPAddr)
	}
}

func TestHTTPAddrFromEnv_UsesOverride(t *testing.T) {
	if got := httpAddrFromEnv("0.0.0.0:9090"); got != "0.0.0.0:9090" {
		t.Errorf("httpAddrFromEnv override = %q, want %q", got, "0.0.0.0:9090")
	}
}

func TestDefaultHTTPAddr_IsLoopbackOnly(t *testing.T) {
	// The MCP StreamableHTTP transport authenticates nothing itself -- every
	// caller that reaches the listener gets this process's Hub token,
	// including the propose-only write tools. Guards against a future edit
	// silently widening the default bind address to all interfaces.
	if defaultHTTPAddr != "127.0.0.1:8080" {
		t.Errorf("defaultHTTPAddr = %q, want a loopback-only default", defaultHTTPAddr)
	}
}

func TestHTTPConfigFromEnv_RefusesWithoutValidToken(t *testing.T) {
	for _, tok := range []string{"", "short", strings.Repeat("a", 31)} {
		env := map[string]string{"KRYPTKEEPER_MCP_HTTP_TOKEN": tok}
		if _, err := httpConfigFromEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("token %q: want startup refusal", tok)
		}
	}
}

func TestHTTPConfigFromEnv_AcceptsTokenAndParsesLists(t *testing.T) {
	env := map[string]string{
		"KRYPTKEEPER_MCP_HTTP_TOKEN":      strings.Repeat("a", 32),
		"KRYPTKEEPER_MCP_ALLOWED_HOSTS":   "mcp.example.com, ,other:9",
		"KRYPTKEEPER_MCP_ALLOWED_ORIGINS": "https://app.example.com",
	}
	cfg, err := httpConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedHosts) != 2 || len(cfg.AllowedOrigins) != 1 || cfg.BindAddr != defaultHTTPAddr {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}
