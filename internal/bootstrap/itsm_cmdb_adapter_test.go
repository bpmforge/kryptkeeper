// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"

	"kryptkeeper/internal/notifications/itsm"
)

type cmdbStubCerts struct {
	CertificateProvider
	items []CertificateItem
	got   CertificateOwnershipRequest
}

func (s *cmdbStubCerts) ListCertificates(context.Context, CertificateListQuery) (CertificateListResult, error) {
	return CertificateListResult{Items: s.items, Total: len(s.items)}, nil
}

func (s *cmdbStubCerts) UpdateOwnership(_ context.Context, _ string, r CertificateOwnershipRequest) (CertificateItem, error) {
	s.got = r
	return CertificateItem{}, nil
}

func TestCMDBAdapter_ListHostsAndWrite(t *testing.T) {
	gone := "2026-01-01T00:00:00Z"
	certs := &cmdbStubCerts{items: []CertificateItem{
		{FingerprintSHA256: "a", CommonName: "Web.Example.com", ServiceName: "svc", OwnerTeam: "t", OwnershipSource: "cmdb"},
		{FingerprintSHA256: "b", CommonName: "10.0.0.1", SubjectAltNames: []string{"10.0.0.1", "db.example.com"}},
		{FingerprintSHA256: "c", CommonName: "rev.example.com", RevokedAt: &gone},
		{FingerprintSHA256: "d"},
	}}
	ad := &cmdbOwnershipAdapter{certs: certs}
	hosts, err := ad.ListCertHosts(context.Background())
	if err != nil || len(hosts) != 2 || hosts[0].Host != "web.example.com" || hosts[1].Host != "db.example.com" {
		t.Fatalf("hosts=%+v err=%v", hosts, err)
	}
	if err := ad.SetCMDBOwnership(context.Background(), "a", itsm.CMDBOwner{OwnerTeam: "T", OwnerEmail: "e@x.com"}, "svc"); err != nil {
		t.Fatal(err)
	}
	if certs.got.Source != OwnershipSourceCMDB || certs.got.ServiceName != "svc" || certs.got.OwnerTeam != "T" {
		t.Fatalf("request=%+v", certs.got)
	}
}
