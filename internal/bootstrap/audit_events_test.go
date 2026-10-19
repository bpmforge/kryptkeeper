// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type capturingAuditProvider struct {
	last AuditEntry
}

func (p *capturingAuditProvider) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (p *capturingAuditProvider) AppendEntry(_ context.Context, entry AuditEntry) error {
	p.last = entry
	return nil
}

// TestEmitAuditEventStampsResolvedPrincipalTenant (W2-04, tightened by L-12):
// the audit tenant is the RESOLVED principal's tenant, never the raw X-Tenant
// header, so a forged header cannot file rows under another tenant.
func TestEmitAuditEventStampsResolvedPrincipalTenant(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")

	provider := &capturingAuditProvider{}
	emit := func(resolved, header string) string {
		var got string
		withAuditTenant(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if resolved != "" {
				recordAuditTenant(r, resolved)
			}
			emitAuditEvent(r, provider, "svc-principal", "ca.suspend", "ca", "ca-1", "success")
			got = provider.last.Tenant
		})).ServeHTTP(nil, func() *http.Request {
			r := httptest.NewRequest("POST", "/api/v1/cas/ca-1/suspend", nil)
			if header != "" {
				r.Header.Set("X-Tenant", header)
			}
			return r
		}())
		return got
	}

	if got := emit("acme", "globex"); got != "acme" {
		t.Fatalf("resolved principal tenant must win over header, got %q", got)
	}
	if got := emit("", "globex"); got != DefaultTenant {
		t.Fatalf("unauthenticated request must not adopt the header, got %q", got)
	}

	t.Setenv("MULTI_TENANCY", "off")
	if got := emit("acme", "acme"); got != DefaultTenant {
		t.Fatalf("tenancy-off must record %q, got %q", DefaultTenant, got)
	}
}

// OWASP-001: the audit source IP must not be forgeable via X-Forwarded-For.
func TestExtractSourceIP_TrustedProxyAware(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "198.51.100.7:5000"
	direct.Header.Set("X-Forwarded-For", "6.6.6.6")
	if got := extractSourceIP(direct); got != "198.51.100.7" {
		t.Fatalf("untrusted peer's spoofed XFF recorded: %q", got)
	}

	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied.RemoteAddr = "10.0.0.5:5000"
	proxied.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if got := extractSourceIP(proxied); got != "203.0.113.9" {
		t.Fatalf("trusted proxy: got %q, want rightmost untrusted 203.0.113.9", got)
	}
}
