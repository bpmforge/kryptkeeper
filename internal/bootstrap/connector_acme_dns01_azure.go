// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W27-21: Azure DNS dns-01 adapter. OAuth client-credentials token plus ARM
// REST, hand-rolled (no azure-sdk-for-go), same token request shape as
// internal/cloudinventory/azure_keyvault.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	azureDNSAPIBase   = "https://management.azure.com"
	azureDNSTokenBase = "https://login.microsoftonline.com"
	azureDNSAPIVer    = "2018-05-01"
)

func init() { registerDNSProvider("azure", newAzureDNSFromConfig) }

type azureDNS struct {
	tenant, clientID, clientSecret, subscription, resourceGroup string

	apiBase   string
	tokenBase string
	client    *http.Client
	now       func() time.Time

	mu       sync.Mutex
	token    string
	tokenExp time.Time
	zones    map[string]azureZone // fqdn -> zone
}

type azureZone struct{ id, name string }

func newAzureDNSFromConfig(_ acmeConnectorConfig, p acmeCredentialPayload) (dnsProvider, error) {
	var d struct {
		TenantID       string `json:"tenant_id"`
		ClientID       string `json:"client_id"`
		ClientSecret   string `json:"client_secret"`
		SubscriptionID string `json:"subscription_id"`
		ResourceGroup  string `json:"resource_group"`
	}
	if len(p.DNS) == 0 || json.Unmarshal(p.DNS, &d) != nil ||
		d.TenantID == "" || d.ClientID == "" || d.ClientSecret == "" || d.SubscriptionID == "" {
		return nil, errors.New(`acme connector dns_provider azure needs a "dns" object in its credential (tenant_id, client_id, client_secret, subscription_id)`)
	}
	return &azureDNS{
		tenant: d.TenantID, clientID: d.ClientID, clientSecret: d.ClientSecret,
		subscription: d.SubscriptionID, resourceGroup: d.ResourceGroup,
		apiBase: azureDNSAPIBase, tokenBase: azureDNSTokenBase,
		client: dnsAPIClient(), now: time.Now, zones: map[string]azureZone{},
	}, nil
}

func (a *azureDNS) secrets() []string { return []string{a.clientSecret, a.token} }

func azureErrText(body []byte) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Code != "" {
		return ": " + e.Error.Code + " " + e.Error.Message
	}
	return ""
}

func (a *azureDNS) bearer(ctx context.Context) (string, error) {
	if a.token != "" && a.now().Before(a.tokenExp.Add(-60*time.Second)) {
		return a.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"scope":         {"https://management.azure.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(a.tokenBase, "/")+"/"+url.PathEscape(a.tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, body, err := dnsRoundTrip(a.client, req)
	if err != nil {
		return "", fmt.Errorf("azure token request: %s", redact(err.Error(), a.secrets()...))
	}
	if status >= 300 {
		return "", fmt.Errorf("azure token request: HTTP %d", status)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &tok) != nil || tok.AccessToken == "" {
		return "", errors.New("azure token request: no access token in the response")
	}
	if tok.ExpiresIn <= 0 {
		tok.ExpiresIn = 300
	}
	a.token, a.tokenExp = tok.AccessToken, a.now().Add(time.Duration(tok.ExpiresIn)*time.Second)
	return a.token, nil
}

// do calls an absolute ARM URL with the bearer token.
func (a *azureDNS) do(ctx context.Context, method, fullURL string, body any) (int, []byte, error) {
	tok, err := a.bearer(ctx)
	if err != nil {
		return 0, nil, err
	}
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	status, resp, err := dnsRoundTrip(a.client, req)
	if err != nil {
		return 0, nil, fmt.Errorf("azure %s: %s", method, redact(err.Error(), a.secrets()...))
	}
	return status, resp, nil
}

func (a *azureDNS) failure(method string, status int, body []byte) error {
	return fmt.Errorf("azure DNS %s: HTTP %d%s", method, status, snippet(redact(azureErrText(body), a.secrets()...)))
}

func (a *azureDNS) zoneFor(ctx context.Context, fqdn string) (string, error) {
	listURL := a.apiBase + "/subscriptions/" + url.PathEscape(a.subscription)
	if a.resourceGroup != "" {
		listURL += "/resourceGroups/" + url.PathEscape(a.resourceGroup)
	}
	listURL += "/providers/Microsoft.Network/dnszones?api-version=" + azureDNSAPIVer
	base, err := url.Parse(a.apiBase)
	if err != nil {
		return "", err
	}
	var best azureZone
	for page := 0; listURL != "" && page < 50; page++ {
		status, body, err := a.do(ctx, http.MethodGet, listURL, nil)
		if err != nil {
			return "", err
		}
		if status >= 300 {
			return "", a.failure("list zones", status, body)
		}
		var list struct {
			Value []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return "", errors.New("azure DNS: zone list is unreadable")
		}
		for _, z := range list.Value {
			name := strings.ToLower(strings.TrimSuffix(z.Name, "."))
			if (fqdn == name || strings.HasSuffix(fqdn, "."+name)) && len(name) > len(best.name) && strings.HasPrefix(z.ID, "/subscriptions/") {
				best = azureZone{id: z.ID, name: name}
			}
		}
		listURL = list.NextLink
		if listURL != "" {
			// The bearer token rides on the next request: never follow a
			// link to another host.
			nu, err := url.Parse(listURL)
			if err != nil || nu.Host != base.Host {
				return "", errors.New("azure DNS: zone list pointed at an unexpected host")
			}
		}
	}
	if best.name == "" {
		return "", fmt.Errorf("no Azure DNS zone these credentials can see holds %s", fqdn)
	}
	a.zones[fqdn] = best
	return best.name, nil
}

func (a *azureDNS) recordURL(fqdn string) string {
	z := a.zones[fqdn]
	rel := "@"
	if fqdn != z.name {
		rel = strings.TrimSuffix(fqdn, "."+z.name)
	}
	return a.apiBase + z.id + "/TXT/" + url.PathEscape(rel) + "?api-version=" + azureDNSAPIVer
}

func (a *azureDNS) read(ctx context.Context, fqdn string) ([]string, error) {
	status, body, err := a.do(ctx, http.MethodGet, a.recordURL(fqdn), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status >= 300 {
		return nil, a.failure("read TXT", status, body)
	}
	var rs struct {
		Properties struct {
			TXT []struct {
				Value []string `json:"value"`
			} `json:"TXTRecords"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(body, &rs); err != nil {
		return nil, errors.New("azure DNS: record set is unreadable")
	}
	out := make([]string, 0, len(rs.Properties.TXT))
	for _, r := range rs.Properties.TXT {
		out = append(out, strings.Join(r.Value, ""))
	}
	return out, nil
}

// chunk255 splits a value into the 255-byte strings a TXT record holds.
func chunk255(v string) []string {
	if len(v) <= 255 {
		return []string{v}
	}
	var out []string
	for len(v) > 255 {
		out = append(out, v[:255])
		v = v[255:]
	}
	return append(out, v)
}

func (a *azureDNS) write(ctx context.Context, fqdn string, _, next []string) error {
	if len(next) == 0 {
		status, body, err := a.do(ctx, http.MethodDelete, a.recordURL(fqdn), nil)
		if err != nil {
			return err
		}
		if status >= 300 && status != http.StatusNotFound {
			return a.failure("delete TXT", status, body)
		}
		return nil
	}
	type txtRec struct {
		Value []string `json:"value"`
	}
	recs := make([]txtRec, 0, len(next))
	for _, v := range next {
		recs = append(recs, txtRec{Value: chunk255(v)})
	}
	status, body, err := a.do(ctx, http.MethodPut, a.recordURL(fqdn), map[string]any{
		"properties": map[string]any{"TTL": 60, "TXTRecords": recs},
	})
	if err != nil {
		return err
	}
	if status >= 300 {
		return a.failure("write TXT", status, body)
	}
	return nil
}

func (a *azureDNS) quote(v string) string { return v }

func (a *azureDNS) Present(ctx context.Context, fqdn, value string) (string, func(context.Context) error, error) {
	return presentRRSet(ctx, &a.mu, a, fqdn, value)
}
