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

// TestEmitAuditEventRecordsHeaderSwitchedTenant is the W2-04 regression: two
// otherwise-identical actions with different X-Tenant headers must produce
// distinguishable Tenant values in the audit trail.
func TestEmitAuditEventRecordsHeaderSwitchedTenant(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")

	provider := &capturingAuditProvider{}

	acmeReq := httptest.NewRequest("POST", "/api/v1/cas/ca-1/suspend", nil)
	acmeReq.Header.Set("X-Tenant", "acme")
	emitAuditEvent(acmeReq, provider, "svc-principal", "ca.suspend", "ca", "ca-1", "success")
	if provider.last.Tenant != "acme" {
		t.Fatalf("expected tenant %q, got %q", "acme", provider.last.Tenant)
	}

	globexReq := httptest.NewRequest("POST", "/api/v1/cas/ca-1/suspend", nil)
	globexReq.Header.Set("X-Tenant", "globex")
	emitAuditEvent(globexReq, provider, "svc-principal", "ca.suspend", "ca", "ca-1", "success")
	if provider.last.Tenant != "globex" {
		t.Fatalf("expected tenant %q, got %q", "globex", provider.last.Tenant)
	}

	// No header at all (and multi-tenancy off) both resolve to DefaultTenant.
	noHeaderReq := httptest.NewRequest("POST", "/api/v1/cas/ca-1/suspend", nil)
	emitAuditEvent(noHeaderReq, provider, "svc-principal", "ca.suspend", "ca", "ca-1", "success")
	if provider.last.Tenant != DefaultTenant {
		t.Fatalf("expected no-header action to record %q, got %q", DefaultTenant, provider.last.Tenant)
	}

	t.Setenv("MULTI_TENANCY", "off")
	offReq := httptest.NewRequest("POST", "/api/v1/cas/ca-1/suspend", nil)
	offReq.Header.Set("X-Tenant", "acme")
	emitAuditEvent(offReq, provider, "svc-principal", "ca.suspend", "ca", "ca-1", "success")
	if provider.last.Tenant != DefaultTenant {
		t.Fatalf("expected tenancy-off action to record %q regardless of header, got %q", DefaultTenant, provider.last.Tenant)
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
