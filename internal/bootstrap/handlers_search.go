// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
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
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		_ = principal

		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []searchResult{}})
			return
		}

		results := make([]searchResult, 0, 20)
		qLow := strings.ToLower(q)

		// Search certificates.
		certList, cerr := certProvider.ListCertificates(r.Context(), CertificateListQuery{Q: q, Limit: 10})
		if cerr != nil {
			log.Printf("search: cert list error: %v", cerr)
		} else {
			for _, c := range certList.Items {
				results = append(results, searchResult{
					Kind:        "certificate",
					ID:          c.FingerprintSHA256,
					Label:       c.CommonName,
					Description: "Issued: " + c.ValidFrom,
					URL:         "/certificates/" + c.FingerprintSHA256,
				})
			}
		}

		// Search CAs.
		caList, caerr := caProvider.ListCAs(r.Context(), CAListQuery{Limit: 50})
		if caerr != nil {
			log.Printf("search: ca list error: %v", caerr)
		} else {
			for _, ca := range caList.Items {
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
			epList, eperr := discoveryProvider.ListEndpoints(r.Context(), DiscoveryEndpointQuery{Limit: 100})
			if eperr != nil {
				log.Printf("search: endpoint list error: %v", eperr)
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
		tplList, tplerr := templateProvider.ListTemplates(r.Context(), TemplateListQuery{Q: q, Limit: 10})
		if tplerr != nil {
			log.Printf("search: template list error: %v", tplerr)
		} else {
			for _, t := range tplList.Items {
				results = append(results, searchResult{
					Kind:        "template",
					ID:          t.ID,
					Label:       t.DisplayName,
					Description: "Validity: " + t.ValidityPeriod,
					URL:         "/templates/" + t.ID,
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": results})
	})
}
