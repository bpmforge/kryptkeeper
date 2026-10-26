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
	"sort"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/egress"
)

// dnsProvider publishes one TXT record and returns how to remove it.
type dnsProvider interface {
	// Present creates the TXT record fqdn=value and returns the zone it went
	// into (for the propagation check) and a cleanup that deletes it.
	Present(ctx context.Context, fqdn, value string) (zone string, cleanup func(context.Context) error, err error)
}

// ---- provider registry (W27-21) -------------------------------------------

// dnsProviderFactory builds a provider from the connector config and its
// resolved credential payload.
type dnsProviderFactory func(cfg acmeConnectorConfig, p acmeCredentialPayload) (dnsProvider, error)

var dnsProviderRegistry = map[string]dnsProviderFactory{}

// registerDNSProvider adds a provider; adapters call it from init(). A
// duplicate name is a programming error.
func registerDNSProvider(name string, f dnsProviderFactory) {
	if _, dup := dnsProviderRegistry[name]; dup {
		panic("dns provider registered twice: " + name)
	}
	dnsProviderRegistry[name] = f
}

// supportedDNSProviders lists registered names, sorted.
func supportedDNSProviders() []string {
	names := make([]string, 0, len(dnsProviderRegistry))
	for n := range dnsProviderRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func unsupportedDNSProviderError(name string) error {
	return fmt.Errorf("acme connector dns_provider %q is not supported (%s)", name, strings.Join(supportedDNSProviders(), ", "))
}

func newDNSProviderFromConfig(cfg acmeConnectorConfig, p acmeCredentialPayload) (dnsProvider, error) {
	if cfg.DNSProvider == "" {
		return nil, fmt.Errorf("acme connector challenge dns-01 needs config_json.dns_provider (%s)", strings.Join(supportedDNSProviders(), ", "))
	}
	f, ok := dnsProviderRegistry[cfg.DNSProvider]
	if !ok {
		return nil, unsupportedDNSProviderError(cfg.DNSProvider)
	}
	return f(cfg, p)
}

// secretConfigKeys may never appear at the top level of config_json: that
// column is not encrypted and is echoed by the API.
var secretConfigKeys = []string{"secret", "token", "password", "private_key", "client_secret", "secret_access_key", "access_token", "service_account_json"}

// validateACMEConnectorConfig is the connector-create check for acme rows.
// Unparseable JSON passes (existing rows must keep loading; the runtime
// zeroes malformed config).
func validateACMEConnectorConfig(configJSON string) error {
	if strings.TrimSpace(configJSON) == "" {
		return nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &top); err != nil {
		return nil
	}
	for _, k := range secretConfigKeys {
		if _, bad := top[k]; bad {
			return errors.New("credentials belong in credential_ref, not config_json")
		}
	}
	var cfg acmeConnectorConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil
	}
	if cfg.DNSProvider != "" {
		if _, ok := dnsProviderRegistry[cfg.DNSProvider]; !ok {
			return fmt.Errorf("dns_provider %q is not supported (%s)", cfg.DNSProvider, strings.Join(supportedDNSProviders(), ", "))
		}
		if cfg.DNSProvider == "plugin" {
			return validateDNSPluginConfig(cfg)
		}
	}
	return nil
}

func init() {
	registerDNSProvider("cloudflare", func(_ acmeConnectorConfig, p acmeCredentialPayload) (dnsProvider, error) {
		if p.CloudflareAPIToken == "" {
			return nil, errors.New("acme connector dns-01 via cloudflare needs cloudflare_api_token in its credential")
		}
		return newCloudflareDNS(p.CloudflareAPIToken), nil
	})
}

// ---- shared adapter helpers (W27-21) ---------------------------------------

// dnsAPIClient is the egress-policy client every non-Cloudflare adapter
// uses; provider hosts are fixed vendor hosts. Tests reach httptest servers
// through egressAllowLoopback.
func dnsAPIClient() *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowLoopback:         egressAllowLoopback,
		RequireHTTPS:          !egressAllowLoopback,
		AllowPrivate:          true,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               30 * time.Second,
	}))
}

// redact replaces every non-empty secret in s with [redacted].
func redact(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

// snippet cuts a provider message at 200 characters.
func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// dnsRoundTrip does one request and returns status and (capped) body.
func dnsRoundTrip(c *http.Client, req *http.Request) (int, []byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, body, err
}

// quoteTXT renders a value as one quoted TXT string.
func quoteTXT(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// mergeTXT returns existing plus add (compared unquoted); foreign entries
// keep their stored form.
func mergeTXT(existing []string, add string) []string {
	out := append([]string(nil), existing...)
	for _, e := range existing {
		if unquoteTXT(e) == unquoteTXT(add) {
			return out
		}
	}
	return append(out, add)
}

// withoutTXT returns existing minus remove (compared unquoted).
func withoutTXT(existing []string, remove string) []string {
	out := make([]string, 0, len(existing))
	for _, e := range existing {
		if unquoteTXT(e) != unquoteTXT(remove) {
			out = append(out, e)
		}
	}
	return out
}

// rrsetBackend is what a read-modify-write TXT adapter implements. Values
// are in the provider's stored form (see quote).
type rrsetBackend interface {
	// zoneFor resolves and remembers the zone for fqdn; returns its name.
	zoneFor(ctx context.Context, fqdn string) (string, error)
	read(ctx context.Context, fqdn string) ([]string, error)
	// write replaces old with next; empty next removes the rrset.
	write(ctx context.Context, fqdn string, old, next []string) error
	quote(v string) string
}

// presentRRSet publishes value into the TXT rrset at fqdn without
// disturbing other values, and returns a cleanup that removes only ours.
func presentRRSet(ctx context.Context, mu *sync.Mutex, b rrsetBackend, fqdn, value string) (string, func(context.Context) error, error) {
	mu.Lock()
	defer mu.Unlock()
	zone, err := b.zoneFor(ctx, fqdn)
	if err != nil {
		return "", nil, err
	}
	old, err := b.read(ctx, fqdn)
	if err != nil {
		return "", nil, err
	}
	if err := b.write(ctx, fqdn, old, mergeTXT(old, b.quote(value))); err != nil {
		return "", nil, err
	}
	cleanup := func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		cur, err := b.read(ctx, fqdn)
		if err != nil {
			return err
		}
		rest := withoutTXT(cur, b.quote(value))
		if len(rest) == len(cur) {
			return nil // already gone
		}
		return b.write(ctx, fqdn, cur, rest)
	}
	return zone, cleanup, nil
}

// parentCandidates lists fqdn's parent names longest first, stopping before
// the bare TLD (as cloudflareDNS.zoneFor does).
func parentCandidates(fqdn string) []string {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	var out []string
	for i := 1; i < len(labels)-1; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
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

// txtLookup answers TXT records for name from one nameserver, host or
// host:port ("" means the system resolver).
type txtLookup func(ctx context.Context, nameserver, name string) ([]string, error)

func lookupTXTAt(ctx context.Context, nameserver, name string) ([]string, error) {
	if nameserver == "" {
		return net.DefaultResolver.LookupTXT(ctx, name)
	}
	addr := nameserver
	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		addr = net.JoinHostPort(nameserver, "53") // bare host or bare IPv6
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}}
	return r.LookupTXT(ctx, name)
}
