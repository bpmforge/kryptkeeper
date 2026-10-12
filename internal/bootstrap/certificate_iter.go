// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "context"

// certificateIterator is implemented by providers that can stream the whole
// inventory. It is an optional interface so test doubles and out-of-tree
// providers that only implement paging keep compiling; they get the paging
// fallback below.
type certificateIterator interface {
	ForEachCertificate(ctx context.Context, query CertificateListQuery, fn func(CertificateItem) error) error
}

// ForEachCertificate visits every certificate matching query without the
// HTTP page cap. Limit and Offset in query are ignored. A non-nil error from
// fn stops the pass and is returned. Callers that need the complete
// inventory MUST use this rather than ListCertificates: ListCertificates
// clamps to one HTTP page, and a caller that passes a larger Limit gets a
// silent truncation (H2).
func ForEachCertificate(ctx context.Context, p CertificateProvider, query CertificateListQuery, fn func(CertificateItem) error) error {
	if it, ok := p.(certificateIterator); ok {
		return it.ForEachCertificate(ctx, query, fn)
	}
	return pageEachCertificate(ctx, p, query, fn)
}

// pageEachCertificate walks a provider that only implements ListCertificates.
// It advances Offset by the rows each call actually returned (the provider
// may clamp its page below the requested Limit) and stops on an empty page
// or once Total rows have been seen, so a misreporting provider cannot spin
// it forever.
func pageEachCertificate(ctx context.Context, p CertificateProvider, query CertificateListQuery, fn func(CertificateItem) error) error {
	query.Limit = maxCertificatePageSize
	query.Offset = 0
	seen := 0
	for {
		page, err := p.ListCertificates(ctx, query)
		if err != nil {
			return err
		}
		if len(page.Items) == 0 {
			return nil
		}
		for _, item := range page.Items {
			if err := fn(item); err != nil {
				return err
			}
		}
		seen += len(page.Items)
		if seen >= page.Total {
			return nil
		}
		query.Offset = seen
	}
}

// listAllCertificates collects every certificate matching query. Total is the
// number of items returned, so it can stand in for a ListCertificates result
// wherever the caller read Items and Total.
func listAllCertificates(ctx context.Context, p CertificateProvider, query CertificateListQuery) (CertificateListResult, error) {
	items := make([]CertificateItem, 0, 256)
	if err := ForEachCertificate(ctx, p, query, func(c CertificateItem) error {
		items = append(items, c)
		return nil
	}); err != nil {
		return CertificateListResult{}, err
	}
	return CertificateListResult{Items: items, Total: len(items), Limit: len(items)}, nil
}
