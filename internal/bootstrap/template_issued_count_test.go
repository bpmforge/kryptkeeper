// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestTemplateIssuedCountReflectsIssuedCertificates(t *testing.T) {
	ctx := context.Background()
	db := setupIntegrationDB(t)
	certs, engine := newIntegrationCAProvider(t, db)
	caID := getFirstCAID(t, engine)

	raw := &fileTemplateProvider{filePath: filepath.Join(t.TempDir(), "templates.json")}
	mk := func(name string) TemplateItem {
		item, err := raw.CreateTemplate(ctx, TemplateUpsertRequest{
			Name: name, DisplayName: name, KeyUsage: []string{"digitalSignature"},
			ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"ECDSA"},
			ValidityPeriod: "P90D", Active: true,
		})
		if err != nil {
			t.Fatalf("create template %s: %v", name, err)
		}
		return item
	}
	used, unused := mk("used"), mk("unused")
	certs = WithTemplateProvider(certs, raw)
	tpls := WithIssuedCounts(raw, certs)

	for _, cn := range []string{"a.example.com", "b.example.com"} {
		if _, err := certs.IssueCertificate(ctx, CertificateIssueRequest{
			CAID: caID, TemplateID: used.ID, TeamID: "team-1", CSRPEM: generateTestCSRPEM(t, cn, cn),
		}); err != nil {
			t.Fatalf("issue %s: %v", cn, err)
		}
	}

	list, err := tpls.ListTemplates(ctx, TemplateListQuery{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := map[string]int{}
	for _, it := range list.Items {
		got[it.ID] = it.IssuedCount
	}
	if got[used.ID] != 2 || got[unused.ID] != 0 {
		t.Fatalf("issued counts = %v, want %s=2 %s=0", got, used.ID, unused.ID)
	}

	one, found, err := tpls.GetTemplate(ctx, used.ID)
	if err != nil || !found || one.IssuedCount != 2 {
		t.Fatalf("get: item=%+v found=%v err=%v, want IssuedCount 2", one, found, err)
	}

	if err := tpls.DeleteTemplate(ctx, used.ID); !errors.Is(err, errTemplateConflict) {
		t.Fatalf("delete of a template with issued certs = %v, want errTemplateConflict", err)
	}
	if err := tpls.DeleteTemplate(ctx, unused.ID); err != nil {
		t.Fatalf("delete of an unused template: %v", err)
	}

	byTemplate, err := certs.ListCertificates(ctx, CertificateListQuery{TemplateID: used.ID})
	if err != nil || byTemplate.Total != 2 {
		t.Fatalf("template_id filter: total=%d err=%v, want 2", byTemplate.Total, err)
	}
	none, err := certs.ListCertificates(ctx, CertificateListQuery{TemplateID: "nope"})
	if err != nil || none.Total != 0 {
		t.Fatalf("template_id filter for unknown id: total=%d err=%v, want 0", none.Total, err)
	}
}

type noCountCerts struct{ CertificateProvider }

func (noCountCerts) CertCountsByTemplate(context.Context) (map[string]int, error) {
	return map[string]int{}, nil
}

// Regression: the decorator must not hide the revision-history capability
// (the handler answered 503 for every template whenever it was on).
func TestIssuedCountDecoratorKeepsRevisionLister(t *testing.T) {
	ctx := context.Background()
	raw := &fileTemplateProvider{filePath: filepath.Join(t.TempDir(), "templates.json")}
	item, err := raw.CreateTemplate(ctx, TemplateUpsertRequest{
		Name: "t", DisplayName: "t", KeyUsage: []string{"digitalSignature"},
		ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"ECDSA"},
		ValidityPeriod: "P90D", Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tp := WithIssuedCounts(raw, noCountCerts{})
	lister, ok := tp.(TemplateRevisionLister)
	if !ok {
		t.Fatal("decorated provider lost TemplateRevisionLister")
	}
	revs, found, err := lister.ListTemplateRevisions(ctx, item.ID)
	if err != nil || !found || len(revs) == 0 {
		t.Fatalf("revisions = %d found=%v err=%v", len(revs), found, err)
	}
	// Inner provider without history: sentinel, not a silent empty list.
	bare := &issuedCountTemplateProvider{TemplateProvider: stubTemplateProvider{}, counts: noCountCerts{}}
	if _, _, err := bare.ListTemplateRevisions(ctx, "x"); !errors.Is(err, errTemplateRevisionsUnsupported) {
		t.Fatalf("err = %v", err)
	}
}
