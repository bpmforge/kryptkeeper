// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

type searchResult struct {
	Kind        string `json:"kind"` // "certificate", "ca", "template", "endpoint"
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
}

func registerSearchHandlers(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, caProvider CAProvider, templateProvider TemplateProvider, discoveryProvider DiscoveryProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}

		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []searchResult{}})
			return
		}

		results := make([]searchResult, 0, 20)
		qLow := strings.ToLower(q)

		// Search certificates. The providers' own Q filter matches only the
		// common name, so SAN/fingerprint/owner matching happens here.
		certItems, cerr := searchCertificates(r.Context(), pd, certProvider, q, 10)
		if cerr != nil {
			logging.Infof("search: cert list error: %v", cerr)
		}
		for _, c := range certItems {
			results = append(results, searchResult{
				Kind:        "certificate",
				ID:          c.FingerprintSHA256,
				Label:       c.CommonName,
				Description: "Issued: " + c.ValidFrom,
				URL:         "/certificates/" + c.FingerprintSHA256,
			})
		}

		// Search CAs.
		caList, caerr := caProvider.ListCAs(r.Context(), CAListQuery{Limit: 50})
		if caerr != nil {
			logging.Infof("search: ca list error: %v", caerr)
		} else {
			for _, ca := range filterCAsByTenant(r.Context(), activeTenantStore, pd, caList.Items) {
				name := ca.DisplayName
				if name == "" {
					name = ca.Name
				}
				if strings.Contains(strings.ToLower(name), qLow) || strings.Contains(strings.ToLower(ca.ID), qLow) {
					results = append(results, searchResult{
						Kind:  "ca",
						ID:    ca.ID,
						Label: name,
						// S-43: project expiry at read time — the palette renders this
						// string verbatim, so raw stored status advertised lapsed CAs
						// as active.
						Description: "Type: " + ca.Type + " | Status: " + caEffectiveStatus(ca, time.Now()),
						URL:         "/cas/" + ca.ID,
					})
				}
				if len(results) >= 20 {
					break
				}
			}
		}

		// Search discovered endpoints. ListEndpoints has no text query, so
		// filter a page in-handler — the UI's badge map and Discovery's
		// "Open full search" link both expected this producer to exist.
		if discoveryProvider != nil {
			epList, eperr := discoveryProvider.ListEndpoints(withDiscoveryScope(r.Context(), pd), DiscoveryEndpointQuery{Limit: 100})
			if eperr != nil {
				logging.Infof("search: endpoint list error: %v", eperr)
			} else {
				for _, ep := range epList.Endpoints {
					if !strings.Contains(strings.ToLower(ep.Hostname), qLow) &&
						!strings.Contains(strings.ToLower(ep.ID), qLow) {
						continue
					}
					results = append(results, searchResult{
						Kind:        "endpoint",
						ID:          ep.ID,
						Label:       fmt.Sprintf("%s:%d", ep.Hostname, ep.Port),
						Description: "Protocol: " + ep.Protocol,
						URL:         "/discovery/endpoints/" + ep.ID,
					})
					if len(results) >= 30 {
						break
					}
				}
			}
		}

		// Search templates.
		tplList, tplerr := templateProvider.ListTemplates(r.Context(), TemplateListQuery{Q: q, Limit: searchFetchLimit(pd, 10)})
		if tplerr != nil {
			logging.Infof("search: template list error: %v", tplerr)
		} else {
			tplItems := filterTemplatesByTenant(r.Context(), activeTenantStore, pd, tplList.Items)
			if len(tplItems) > 10 {
				tplItems = tplItems[:10]
			}
			for _, t := range tplItems {
				results = append(results, searchResult{
					Kind:        "template",
					ID:          t.ID,
					Label:       t.DisplayName,
					Description: "Validity: " + t.ValidityPeriod,
					URL:         "/templates/" + t.ID,
				})
			}
		}

		// Sampled so a busy palette does not flood the append-only audit log.
		// The query text is never recorded: it can be a fingerprint or an e-mail.
		if rate := searchAuditSampleRate(); searchSampleFloat() < rate {
			emitAuditEventDetail(r, auditProvider, pd.ID, "search.query", "search", "-", AuditOutcomeSuccess,
				fmt.Sprintf(`{"query_len":%d,"results":%d,"sample_rate":%g}`, len(q), len(results), rate))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": results})
	})
}

// searchAuditSampleRate reads SEARCH_AUDIT_SAMPLE_RATE, a float in [0,1];
// unset, unparseable or out of range falls back to 0.1.
func searchAuditSampleRate() float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv("SEARCH_AUDIT_SAMPLE_RATE")), 64)
	if err != nil || v < 0 || v > 1 {
		return 0.1
	}
	return v
}

// searchSampleFloat is injectable so tests can make sampling deterministic.
var searchSampleFloat = rand.Float64

var errSearchEnough = errors.New("search: enough matches")

// certMatchesSearch reports whether qLow (lower-cased, trimmed) matches the
// certificate by CN, SAN, subject DN, owner, or fingerprint prefix.
func certMatchesSearch(c CertificateItem, qLow string) bool {
	has := func(s string) bool { return s != "" && strings.Contains(strings.ToLower(s), qLow) }
	if has(c.CommonName) || has(c.SubjectDN) || has(c.OwnerEmail) || has(c.OwnerTeam) {
		return true
	}
	for _, s := range c.SubjectAltNames {
		if has(s) {
			return true
		}
	}
	for _, s := range c.URISANs {
		if has(s) {
			return true
		}
	}
	// Short queries must not prefix-match every hash.
	fp := strings.NewReplacer(":", "", " ", "").Replace(qLow)
	return len(fp) >= 8 && strings.HasPrefix(strings.ToLower(c.FingerprintSHA256), fp)
}

// searchCertificates returns up to limit tenant-visible matches in provider
// list order. Tenant semantics mirror filterCertificatesByTenant (deny by
// default when a CA's tenant lookup fails), memoised per CA for the scan.
func searchCertificates(ctx context.Context, pd AuthPrincipal, p CertificateProvider, q string, limit int) ([]CertificateItem, error) {
	qLow := strings.ToLower(strings.TrimSpace(q))
	store := activeTenantStore
	scoped := !tenantBypass(pd)
	visible := map[string]bool{}
	out := make([]CertificateItem, 0, limit)
	err := ForEachCertificate(ctx, p, CertificateListQuery{}, func(c CertificateItem) error {
		if !certMatchesSearch(c, qLow) {
			return nil
		}
		if scoped {
			ok, seen := visible[c.CAID]
			if !seen {
				// No tenant store means no membership answer: deny (D-202).
				if store != nil {
					t, err := store.CATenant(ctx, c.CAID)
					ok = err == nil && t == pd.Tenant
				}
				visible[c.CAID] = ok
			}
			if !ok {
				return nil
			}
		}
		out = append(out, c)
		if len(out) >= limit {
			return errSearchEnough
		}
		return nil
	})
	if err != nil && !errors.Is(err, errSearchEnough) {
		return nil, err
	}
	return out, nil
}

// searchFetchLimit widens a provider page for tenant-scoped callers because the
// tenant filter is applied after the provider's own limit.
func searchFetchLimit(pd AuthPrincipal, n int) int {
	if tenantBypass(pd) {
		return n
	}
	return 200
}
