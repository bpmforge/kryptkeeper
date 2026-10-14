// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"log"
)

type templateIssuedCounter interface {
	CertCountsByTemplate(context.Context) (map[string]int, error)
}

// issuedCountTemplateProvider fills TemplateItem.IssuedCount from the
// certificate inventory. File-backed templates have no certificate linkage of
// their own, so the stored count was a constant 0 and the Templates page
// reported "Issued 0" for templates that had issued certificates; the guard
// in DeleteTemplate that depends on it could never fire either.
type issuedCountTemplateProvider struct {
	TemplateProvider
	counts templateIssuedCounter
}

// WithIssuedCounts decorates tp with live issued-certificate counts when certs
// can supply them; otherwise it returns tp unchanged.
func WithIssuedCounts(tp TemplateProvider, certs CertificateProvider) TemplateProvider {
	counter, ok := certs.(templateIssuedCounter)
	if !ok {
		return tp
	}
	return &issuedCountTemplateProvider{TemplateProvider: tp, counts: counter}
}

// load degrades to nil on error: a broken count must not take down the
// template listing itself.
func (p *issuedCountTemplateProvider) load(ctx context.Context) map[string]int {
	counts, err := p.counts.CertCountsByTemplate(ctx)
	if err != nil {
		log.Printf("template issued counts unavailable: %v", err)
		return nil
	}
	return counts
}

func (p *issuedCountTemplateProvider) ListTemplates(ctx context.Context, q TemplateListQuery) (TemplateListResult, error) {
	res, err := p.TemplateProvider.ListTemplates(ctx, q)
	if err != nil || len(res.Items) == 0 {
		return res, err
	}
	counts := p.load(ctx)
	for i := range res.Items {
		res.Items[i].IssuedCount = counts[res.Items[i].ID]
	}
	return res, nil
}

func (p *issuedCountTemplateProvider) GetTemplate(ctx context.Context, id string) (TemplateItem, bool, error) {
	item, found, err := p.TemplateProvider.GetTemplate(ctx, id)
	if err != nil || !found {
		return item, found, err
	}
	item.IssuedCount = p.load(ctx)[id]
	return item, true, nil
}

func (p *issuedCountTemplateProvider) DeleteTemplate(ctx context.Context, id string) error {
	if p.load(ctx)[id] > 0 {
		return errTemplateConflict
	}
	return p.TemplateProvider.DeleteTemplate(ctx, id)
}
