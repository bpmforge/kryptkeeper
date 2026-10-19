// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W27-22: CNAME-delegation dns-01 adapter (acme-dns style). The customer
// points _acme-challenge.<name> at a name served by an acme-dns instance
// once; the hub then only ever holds a credential that can write that one
// TXT value, never the customer's real zone.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

func init() { registerDNSProvider("delegated", newDelegatedDNSFromConfig) }

type delegatedAccount struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Subdomain  string `json:"subdomain"`
	FullDomain string `json:"fulldomain"`
}

type delegatedDNS struct {
	baseURL  string
	accounts map[string]delegatedAccount // lowercase zone-ish key -> account

	client      *http.Client
	lookupCNAME func(ctx context.Context, name string) (string, error)
}

func newDelegatedDNSFromConfig(_ acmeConnectorConfig, p acmeCredentialPayload) (dnsProvider, error) {
	const need = `acme connector dns_provider delegated needs a "dns" object in its credential (base_url, accounts{name: username, password, subdomain, fulldomain})`
	var d struct {
		BaseURL  string                      `json:"base_url"`
		Accounts map[string]delegatedAccount `json:"accounts"`
	}
	if len(p.DNS) == 0 || json.Unmarshal(p.DNS, &d) != nil || d.BaseURL == "" || len(d.Accounts) == 0 {
		return nil, errors.New(need)
	}
	if !strings.HasPrefix(d.BaseURL, "https://") && !(egressAllowLoopback && strings.HasPrefix(d.BaseURL, "http://")) {
		return nil, errors.New("acme connector dns_provider delegated: base_url must be https")
	}
	accts := make(map[string]delegatedAccount, len(d.Accounts))
	for k, a := range d.Accounts {
		a.FullDomain = strings.TrimSuffix(strings.ToLower(a.FullDomain), ".")
		if k == "" || a.Username == "" || a.Password == "" || a.Subdomain == "" || a.FullDomain == "" {
			return nil, errors.New(need)
		}
		accts[strings.TrimSuffix(strings.ToLower(k), ".")] = a
	}
	return &delegatedDNS{
		baseURL: strings.TrimRight(d.BaseURL, "/"), accounts: accts,
		client:      dnsAPIClient(),
		lookupCNAME: net.DefaultResolver.LookupCNAME,
	}, nil
}

// accountFor picks the account whose key is the longest dot-suffix of name.
func (d *delegatedDNS) accountFor(name string) (delegatedAccount, bool) {
	var best delegatedAccount
	bestLen := -1
	for k, a := range d.accounts {
		if (name == k || strings.HasSuffix(name, "."+k)) && len(k) > bestLen {
			best, bestLen = a, len(k)
		}
	}
	return best, bestLen >= 0
}

func (d *delegatedDNS) Present(ctx context.Context, fqdn, value string) (string, func(context.Context) error, error) {
	name := strings.TrimPrefix(strings.ToLower(fqdn), "_acme-challenge.")
	acct, ok := d.accountFor(name)
	if !ok {
		return "", nil, fmt.Errorf("no acme-dns account is configured for %s", name)
	}
	// The CNAME is what makes the delegated write legitimate: without it the
	// CA would never see the value, so fail before touching the API.
	got, err := d.lookupCNAME(ctx, "_acme-challenge."+name+".")
	if got = strings.TrimSuffix(strings.ToLower(got), "."); err != nil || got != acct.FullDomain {
		return "", nil, fmt.Errorf("_acme-challenge.%s has no CNAME to %s; create \"_acme-challenge.%s. CNAME %s.\" and retry", name, acct.FullDomain, name, acct.FullDomain)
	}

	body, err := json.Marshal(map[string]string{"subdomain": acct.Subdomain, "txt": value})
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+"/update", bytes.NewReader(body))
	if err != nil {
		return "", nil, errors.New("acme-dns base_url is not a valid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-User", acct.Username)
	req.Header.Set("X-Api-Key", acct.Password)
	status, _, err := dnsRoundTrip(d.client, req)
	if err != nil {
		return "", nil, fmt.Errorf("acme-dns update: %s", snippet(redact(err.Error(), acct.Password, acct.Username)))
	}
	switch {
	case status == http.StatusOK:
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "", nil, errors.New("acme-dns rejected the account credentials")
	case status == http.StatusBadRequest:
		return "", nil, errors.New("acme-dns refused the TXT value")
	default:
		return "", nil, fmt.Errorf("acme-dns returned HTTP %d", status)
	}

	zone := acct.FullDomain
	if i := strings.Index(zone, "."); i >= 0 {
		zone = zone[i+1:]
	}
	// acme-dns has no delete and keeps the last two values; the value is a
	// one-time digest, so there is nothing to remove.
	return zone, func(context.Context) error { return nil }, nil
}
