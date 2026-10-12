// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W20-29: dns-01 for the ACME upstream connector, with Cloudflare as the
// first DNS provider. dns-01 is what public CAs need when the hub is not
// reachable at the certificate's name (the usual case for an inventory hub)
// and the only way to get wildcards. The token lives in the connector's
// outbound credential (cloudflare_api_token), never in config or env, and
// should be scoped to DNS edit on the one zone.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dnsProvider publishes one TXT record and returns how to remove it.
type dnsProvider interface {
	// Present creates the TXT record fqdn=value and returns the zone it went
	// into (for the propagation check) and a cleanup that deletes it.
	Present(ctx context.Context, fqdn, value string) (zone string, cleanup func(context.Context) error, err error)
}

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

type cloudflareDNS struct {
	token   string
	apiBase string
	client  *http.Client
}

func newCloudflareDNS(token string) *cloudflareDNS {
	return &cloudflareDNS{token: token, apiBase: cloudflareAPIBase, client: &http.Client{Timeout: 30 * time.Second}}
}

type cloudflareEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int
		Message string
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

// call does one API request. Errors carry Cloudflare's messages but never
// the token.
func (c *cloudflareDNS) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: %w", method, strings.SplitN(path, "?", 2)[0], err)
	}
	defer resp.Body.Close()
	var env cloudflareEnvelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: HTTP %d, unreadable response", method, strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	if !env.Success || resp.StatusCode >= 300 {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return nil, fmt.Errorf("cloudflare %s %s: HTTP %d: %s", method, strings.SplitN(path, "?", 2)[0], resp.StatusCode, strings.Join(msgs, "; "))
	}
	return env.Result, nil
}

// zoneFor finds the zone holding fqdn by trying each parent name, longest
// first, so delegated subzones win over their parent.
func (c *cloudflareDNS) zoneFor(ctx context.Context, fqdn string) (id, name string, err error) {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := 1; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		raw, err := c.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(candidate), nil)
		if err != nil {
			return "", "", err
		}
		var zones []struct{ ID, Name string }
		if err := json.Unmarshal(raw, &zones); err != nil {
			return "", "", fmt.Errorf("cloudflare zones: %w", err)
		}
		for _, z := range zones {
			if strings.EqualFold(z.Name, candidate) {
				return z.ID, z.Name, nil
			}
		}
	}
	return "", "", fmt.Errorf("no Cloudflare zone this token can see holds %s", fqdn)
}

func (c *cloudflareDNS) Present(ctx context.Context, fqdn, value string) (string, func(context.Context) error, error) {
	zoneID, zoneName, err := c.zoneFor(ctx, fqdn)
	if err != nil {
		return "", nil, err
	}
	raw, err := c.call(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", map[string]any{
		"type": "TXT", "name": fqdn, "content": `"` + value + `"`, "ttl": 60,
		"comment": "kryptkeeper acme dns-01 (temporary)",
	})
	if err != nil {
		return "", nil, err
	}
	var rec struct{ ID string }
	if err := json.Unmarshal(raw, &rec); err != nil || rec.ID == "" {
		return "", nil, errors.New("cloudflare: created TXT record has no id")
	}
	cleanup := func(ctx context.Context) error {
		_, err := c.call(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+rec.ID, nil)
		return err
	}
	return zoneName, cleanup, nil
}

// txtLookup answers TXT records for name from one nameserver ("" means the
// system resolver).
type txtLookup func(ctx context.Context, nameserver, name string) ([]string, error)

func lookupTXTAt(ctx context.Context, nameserver, name string) ([]string, error) {
	if nameserver == "" {
		return net.DefaultResolver.LookupTXT(ctx, name)
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(nameserver, "53"))
	}}
	return r.LookupTXT(ctx, name)
}

// waitForTXT polls the zone's authoritative nameservers (the ones the CA's
// validator ends up asking) until each serves value at fqdn. Asking a
// caching resolver instead could pin a stale negative answer for the
// zone's negative TTL.
func waitForTXT(ctx context.Context, lookupNS func(context.Context, string) ([]*net.NS, error), lookup txtLookup, zone, fqdn, value string, interval time.Duration) error {
	nss, err := lookupNS(ctx, zone)
	if err != nil || len(nss) == 0 {
		return fmt.Errorf("dns-01: nameservers for %s: %v", zone, err)
	}
	pending := map[string]bool{}
	for _, ns := range nss {
		pending[strings.TrimSuffix(ns.Host, ".")] = true
	}
	for {
		for ns := range pending {
			txts, _ := lookup(ctx, ns, fqdn)
			for _, t := range txts {
				if t == value {
					delete(pending, ns)
					break
				}
			}
		}
		if len(pending) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			left := make([]string, 0, len(pending))
			for ns := range pending {
				left = append(left, ns)
			}
			return fmt.Errorf("dns-01: %s not visible at %s before the deadline", fqdn, strings.Join(left, ", "))
		case <-time.After(interval):
		}
	}
}
