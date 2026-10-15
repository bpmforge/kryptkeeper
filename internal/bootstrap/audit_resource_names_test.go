// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

type namesCertProvider struct {
	CertificateProvider
	items map[string]CertificateDetail
	calls int
}

func (p *namesCertProvider) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	p.calls++
	d, ok := p.items[fp]
	return d, ok, nil
}

type namesCAProvider struct {
	CAProvider
	lists int
}

func (p *namesCAProvider) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	p.lists++
	return CAListResult{Items: []CAListItem{{ID: "ca-1", Name: "root", DisplayName: "Root CA"}}}, nil
}

type namesTemplateProvider struct{ TemplateProvider }

func (namesTemplateProvider) ListTemplates(context.Context, TemplateListQuery) (TemplateListResult, error) {
	return TemplateListResult{Items: []TemplateItem{{ID: "tpl-1", Name: "web", DisplayName: "Web Server"}}}, nil
}

type namesApprovalStore struct {
	ApprovalStore
	items map[string]ApprovalRequest
}

func (s namesApprovalStore) Get(_ context.Context, id string) (ApprovalRequest, error) {
	a, ok := s.items[id]
	if !ok {
		return ApprovalRequest{}, errors.New("not found")
	}
	return a, nil
}

func auditRow(typ, id string) AuditEntry {
	return AuditEntry{Action: "x", ResourceType: typ, ResourceID: id}
}

func TestResolveAuditNames(t *testing.T) {
	certs := &namesCertProvider{items: map[string]CertificateDetail{
		"fp-a": {CertificateItem: CertificateItem{FingerprintSHA256: "fp-a", CommonName: "a.example.com", TeamID: "team-a"}},
		"fp-b": {CertificateItem: CertificateItem{FingerprintSHA256: "fp-b", CommonName: "b.example.com", TeamID: "team-b"}},
	}}
	cas := &namesCAProvider{}
	src := auditNameSources{
		certs: certs, cas: cas, templates: namesTemplateProvider{},
		approvals: namesApprovalStore{items: map[string]ApprovalRequest{
			"apr-1": {ID: "apr-1", TemplateID: "tpl-1", Requester: "team-a"},
			"apr-2": {ID: "apr-2", TemplateID: "tpl-1", Requester: "team-b"},
		}},
	}
	admin := AuthPrincipal{ID: "root", Role: "pki-admin"}
	teamA := AuthPrincipal{ID: "team-a", Role: "viewer"}

	rows := []AuditEntry{
		auditRow("certificate", "fp-a"),
		auditRow("certificate", "fp-a"), // duplicate: one lookup
		auditRow("certificate", "fp-b"),
		auditRow("certificate", "certificates"), // pre-issue failure row: collection name
		auditRow("certificate", "gone"),         // deleted
		auditRow("ca", "ca-1"),
		auditRow("ca", "ca-2"),
		auditRow("template", "tpl-1"),
		auditRow("approval", "apr-1"),
		auditRow("approval", "apr-2"),
		auditRow("key", "k1"), // unsupported type
	}

	t.Run("admin resolves everything resolvable", func(t *testing.T) {
		certs.calls = 0
		got := src.resolveAuditNames(context.Background(), admin, rows)
		want := []string{"a.example.com", "a.example.com", "b.example.com", "", "", "Root CA", "", "Web Server", "Web Server for team-a", "Web Server for team-b", ""}
		for i, w := range want {
			if got[i].ResourceName != w {
				t.Errorf("row %d (%s:%s) name = %q, want %q", i, rows[i].ResourceType, rows[i].ResourceID, got[i].ResourceName, w)
			}
			if got[i].ResourceID != rows[i].ResourceID {
				t.Errorf("row %d resource_id mutated", i)
			}
		}
		if certs.calls != 4 { // fp-a, fp-b, certificates, gone
			t.Errorf("cert lookups = %d, want 4 (deduplicated)", certs.calls)
		}
		if cas.lists != 1 {
			t.Errorf("CA list calls = %d, want 1 per request", cas.lists)
		}
	})

	t.Run("cross-team names are not leaked", func(t *testing.T) {
		got := src.resolveAuditNames(context.Background(), teamA, rows)
		if got[0].ResourceName != "a.example.com" {
			t.Errorf("own cert name = %q", got[0].ResourceName)
		}
		if got[2].ResourceName != "" {
			t.Errorf("other team's cert name leaked: %q", got[2].ResourceName)
		}
		if got[8].ResourceName != "Web Server for team-a" {
			t.Errorf("own approval name = %q", got[8].ResourceName)
		}
		if got[9].ResourceName != "" {
			t.Errorf("other requester's approval name leaked: %q", got[9].ResourceName)
		}
	})

	t.Run("nil sources leave names empty", func(t *testing.T) {
		got := auditNameSources{}.resolveAuditNames(context.Background(), admin, rows)
		for i, g := range got {
			if g.ResourceName != "" {
				t.Errorf("row %d name = %q, want empty", i, g.ResourceName)
			}
		}
	})
}

// The audit list endpoint emits resource_name without altering stored fields.
func TestAuditListIncludesResourceName(t *testing.T) {
	mux := http.NewServeMux()
	h := newWriteGateHarness(t, mux)
	aud := &listingAudit{entries: []AuditEntry{auditRow("certificate", "fp-a"), auditRow("certificate", "fp-zz")}}
	certs := &namesCertProvider{items: map[string]CertificateDetail{
		"fp-a": {CertificateItem: CertificateItem{FingerprintSHA256: "fp-a", CommonName: "a.example.com"}},
	}}
	registerAuditHandlers(mux, h.auth, h.roles, aud, auditNameSources{certs: certs})

	rec := h.do(h.key(t, "pki-admin"), http.MethodGet, "/api/v1/audit", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 2 {
		t.Fatalf("rows = %d", len(body.Data))
	}
	if body.Data[0]["resource_name"] != "a.example.com" || body.Data[0]["resource_id"] != "fp-a" {
		t.Errorf("resolved row = %v", body.Data[0])
	}
	if _, present := body.Data[1]["resource_name"]; present {
		t.Errorf("unresolved row must omit resource_name, got %v", body.Data[1]["resource_name"])
	}
}

type listingAudit struct{ entries []AuditEntry }

func (l *listingAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: l.entries, Total: len(l.entries), Limit: 25}, nil
}
func (l *listingAudit) AppendEntry(context.Context, AuditEntry) error { return nil }
