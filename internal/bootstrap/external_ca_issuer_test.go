// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kryptkeeper/internal/connectors"
)

// W36-02: the external-CA issuer bridge.

type fakeExternalConnectorStore struct {
	ConnectorStore
	rec ConnectorRecord
	err error
}

func (s fakeExternalConnectorStore) Get(context.Context, string) (ConnectorRecord, error) {
	return s.rec, s.err
}

type fakeCATenants struct {
	TenantStore
	tenant string
	err    error
}

func (s fakeCATenants) CATenant(context.Context, string) (string, error) { return s.tenant, s.err }

type fakeCredMeta struct {
	OutboundCredentialStore
	tenant string
}

func (s fakeCredMeta) Get(context.Context, string) (OutboundCredentialMeta, error) {
	return OutboundCredentialMeta{Tenant: s.tenant}, nil
}

type stubIssuer struct{ gotReq connectors.IssueRequest }

func (s *stubIssuer) ID() string     { return "conn-1" }
func (s *stubIssuer) Type() string   { return "stub" }
func (s *stubIssuer) Origin() string { return "stub" }
func (s *stubIssuer) Health(context.Context) connectors.Health {
	return connectors.Health{Status: "healthy"}
}
func (s *stubIssuer) Issue(_ context.Context, req connectors.IssueRequest) (connectors.IssueResult, error) {
	s.gotReq = req
	return connectors.IssueResult{CertificatePEM: "PEM-BUNDLE"}, nil
}

func newTestExternalIssuer(rec ConnectorRecord, tenants TenantStore, creds OutboundCredentialStore) (*externalCAIssuer, *stubIssuer) {
	stub := &stubIssuer{}
	return &externalCAIssuer{
		store: fakeExternalConnectorStore{rec: rec}, creds: creds, tenants: tenants,
		build: func(ConnectorRecord, CertificateProvider, OutboundCredentialStore) connectors.IssuerConnector {
			return stub
		},
	}, stub
}

func TestExternalCAIssuerHappyPath(t *testing.T) {
	x, stub := newTestExternalIssuer(ConnectorRecord{ID: "conn-1", Type: "est"}, nil, nil)
	got, err := x.IssueExternal(context.Background(), "ca-1", "conn-1", "CSR", "tmpl-1")
	if err != nil || got != "PEM-BUNDLE" {
		t.Fatalf("got %q, %v", got, err)
	}
	if stub.gotReq.CSRPEM != "CSR" || stub.gotReq.TemplateID != "tmpl-1" {
		t.Fatalf("request not forwarded: %+v", stub.gotReq)
	}
}

func TestExternalCAIssuerRefusals(t *testing.T) {
	cases := map[string]string{
		"internal": "an external CA cannot delegate to the hub's own internal connector",
		"scep":     "connector type scep can only renew hub-generated keys; use it as a renewal path, not as an external CA",
		"wstep":    "connector type wstep can only renew hub-generated keys; use it as a renewal path, not as an external CA",
	}
	for typ, want := range cases {
		x, _ := newTestExternalIssuer(ConnectorRecord{ID: "conn-1", Type: typ}, nil, nil)
		if _, err := x.IssueExternal(context.Background(), "ca-1", "conn-1", "CSR", ""); err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %q", typ, err, want)
		}
	}
}

func TestExternalCAIssuerStoreErrorNamesConnector(t *testing.T) {
	x := &externalCAIssuer{store: fakeExternalConnectorStore{err: errConnectorNotFound}}
	_, err := x.IssueExternal(context.Background(), "ca-1", "conn-9", "CSR", "")
	if err == nil || !strings.Contains(err.Error(), "conn-9") || !errors.Is(err, errConnectorNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestExternalCAIssuerUnsupportedType(t *testing.T) {
	x, _ := newTestExternalIssuer(ConnectorRecord{ID: "conn-1", Type: "mystery"}, nil, nil)
	x.build = func(ConnectorRecord, CertificateProvider, OutboundCredentialStore) connectors.IssuerConnector {
		return nil
	}
	if _, err := x.IssueExternal(context.Background(), "ca-1", "conn-1", "CSR", ""); err == nil || !strings.Contains(err.Error(), "mystery") {
		t.Fatalf("err = %v", err)
	}
}

func TestExternalCAIssuerTenancy(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	ctx := context.Background()
	issue := func(rec ConnectorRecord, tenants TenantStore, creds OutboundCredentialStore) error {
		x, _ := newTestExternalIssuer(rec, tenants, creds)
		_, err := x.IssueExternal(ctx, "ca-1", "conn-1", "CSR", "")
		return err
	}
	rec := ConnectorRecord{ID: "conn-1", Type: "est", Tenant: "acme"}

	if err := issue(rec, fakeCATenants{tenant: "acme"}, nil); err != nil {
		t.Errorf("matching tenants: %v", err)
	}
	if err := issue(rec, fakeCATenants{tenant: "globex"}, nil); !errors.Is(err, errExternalCATenantMismatch) {
		t.Errorf("connector in another tenant: %v", err)
	}
	// An unmapped CA is the default tenant; an unstamped connector is too.
	if err := issue(ConnectorRecord{ID: "conn-1", Type: "est"}, fakeCATenants{}, nil); err != nil {
		t.Errorf("default/default: %v", err)
	}
	if err := issue(rec, fakeCATenants{err: errors.New("db down")}, nil); err == nil {
		t.Error("tenant lookup failure must fail closed")
	}
	if err := issue(rec, nil, nil); err == nil {
		t.Error("missing tenant store must fail closed")
	}

	withCred := ConnectorRecord{ID: "conn-1", Type: "est", Tenant: "acme", CredentialRef: "cred-1"}
	if err := issue(withCred, fakeCATenants{tenant: "acme"}, fakeCredMeta{tenant: "globex"}); !errors.Is(err, errExternalCATenantMismatch) {
		t.Errorf("credential in another tenant: %v", err)
	}
	if err := issue(withCred, fakeCATenants{tenant: "acme"}, fakeCredMeta{tenant: DefaultTenant}); err != nil {
		t.Errorf("default-tenant credential: %v", err)
	}
	if err := issue(withCred, fakeCATenants{tenant: "acme"}, fakeCredMeta{tenant: "acme"}); err != nil {
		t.Errorf("same-tenant credential: %v", err)
	}
}

func TestExternalCAIssuerTenancyOffIgnoresTenants(t *testing.T) {
	x, _ := newTestExternalIssuer(ConnectorRecord{ID: "conn-1", Type: "est", Tenant: "acme"}, fakeCATenants{tenant: "globex"}, nil)
	if _, err := x.IssueExternal(context.Background(), "ca-1", "conn-1", "CSR", ""); err != nil {
		t.Fatalf("without multi-tenancy nothing changes: %v", err)
	}
}
