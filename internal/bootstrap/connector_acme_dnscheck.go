// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// dns-01 propagation checks. The check only exists so the hub does not ask
// the CA to validate before the TXT record is visible; the CA's own
// validator is the authority. Querying the zone's authoritative nameservers
// directly is the most precise method but needs outbound port 53 to
// arbitrary hosts, which many enterprise networks block except to a local
// resolver. The other methods exist for those networks.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	dnsCheckAuto          = "auto"
	dnsCheckAuthoritative = "authoritative"
	dnsCheckResolver      = "resolver"
	dnsCheckDoH           = "doh"
	dnsCheckNone          = "none"

	defaultDNSPropagationTimeout = 3 * time.Minute
	// maxDNSPropagationTimeout bounds config and sizes the renewal
	// handler's response deadline (handlers_renewal_execute.go).
	maxDNSPropagationTimeout   = 10 * time.Minute
	defaultDNSPropagationDelay = 30 * time.Second
	defaultDoHURL              = "https://cloudflare-dns.com/dns-query"
)

// dnsPropagation is the validated propagation-check configuration.
type dnsPropagation struct {
	mode     string
	timeout  time.Duration
	delay    time.Duration // mode none: fixed wait before the CA validates
	resolver string        // mode resolver: host[:port]; "" = system resolver
	dohURL   string
}

// propagation validates the dns-01 propagation settings. It runs before any
// record is published so a bad config fails the order up front.
func (cfg acmeConnectorConfig) propagation(allowHTTPForTest bool) (dnsPropagation, error) {
	p := dnsPropagation{
		mode: strings.ToLower(strings.TrimSpace(cfg.DNSPropagation)), timeout: defaultDNSPropagationTimeout,
		delay: defaultDNSPropagationDelay, resolver: strings.TrimSpace(cfg.DNSResolver), dohURL: strings.TrimSpace(cfg.DNSDoHURL),
	}
	switch p.mode {
	case "":
		p.mode = dnsCheckAuto
	case dnsCheckAuto, dnsCheckAuthoritative, dnsCheckResolver, dnsCheckDoH, dnsCheckNone:
	default:
		return p, fmt.Errorf("acme connector dns_propagation %q: use auto, authoritative, resolver, doh or none", cfg.DNSPropagation)
	}
	var err error
	if p.timeout, err = parsePropagationDuration("dns_propagation_timeout", cfg.DNSPropagationTimeout, p.timeout); err != nil {
		return p, err
	}
	if p.delay, err = parsePropagationDuration("dns_propagation_delay", cfg.DNSPropagationDelay, p.delay); err != nil {
		return p, err
	}
	if p.dohURL == "" {
		p.dohURL = defaultDoHURL
	}
	u, err := url.Parse(p.dohURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(allowHTTPForTest && u.Scheme == "http")) {
		return p, errors.New("acme connector dns_doh_url must be an https URL")
	}
	if u.User != nil {
		return p, errors.New("acme connector dns_doh_url must not carry credentials")
	}
	return p, nil
}

func parsePropagationDuration(field, raw string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || d <= 0 || d > maxDNSPropagationTimeout {
		return 0, fmt.Errorf("acme connector %s %q: use a duration such as 3m, above 0 and at most %s", field, raw, maxDNSPropagationTimeout)
	}
	return d, nil
}

// answered reports whether err is a DNS answer rather than a failure to get
// one: success, NXDOMAIN, or no TXT data all prove the query reached a
// server that responded. Timeouts, refusals and SERVFAIL do not.
func answered(err error) bool {
	if err == nil {
		return true
	}
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// dnsMethod is one way to see a TXT record. check returns whether the
// record is fully visible and whether any query got a DNS answer.
type dnsMethod struct {
	name  string
	check func(ctx context.Context) (seen, gotAnswer bool, err error)
	// pending describes what is still missing, for the deadline error.
	pending func() string
}

var errMethodUnreachable = errors.New("dns method unreachable")

// poll runs m until the record is seen or ctx ends. With canFallBack it
// returns errMethodUnreachable as soon as a round gets no DNS answer at
// all and none ever did, so auto can move to the next method.
func (m dnsMethod) poll(ctx context.Context, interval time.Duration, canFallBack bool) error {
	everAnswered := false
	for {
		seen, got, err := m.check(ctx)
		if seen {
			return nil
		}
		everAnswered = everAnswered || got
		if err != nil && !canFallBack {
			return err
		}
		if !everAnswered && canFallBack && ctx.Err() == nil {
			return fmt.Errorf("%w: %s", errMethodUnreachable, m.name)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("dns-01: TXT record not visible %s before the deadline", m.pending())
		case <-time.After(interval):
		}
	}
}

// dnsCheckState lets one Issue call reuse the method auto settled on and
// log it once.
type dnsCheckState struct{ method string }

// waitPropagation blocks until the TXT record for fqdn is visible by the
// configured method (or the fixed delay has passed for mode none).
func (c *acmeIssuerConnector) waitPropagation(ctx context.Context, p dnsPropagation, st *dnsCheckState, zone, fqdn, value string, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if p.mode == dnsCheckNone {
		c.noteDNSMethod(st, dnsCheckNone)
		select {
		case <-ctx.Done():
			return fmt.Errorf("dns-01: propagation delay %s exceeds the timeout", p.delay)
		case <-time.After(p.delay):
			return nil
		}
	}
	lookupNS, lookup := c.lookupNS, c.lookupTXT
	if lookupNS == nil {
		lookupNS = net.DefaultResolver.LookupNS
	}
	if lookup == nil {
		lookup = lookupTXTAt
	}
	methods := map[string]dnsMethod{
		dnsCheckAuthoritative: authoritativeMethod(lookupNS, lookup, zone, fqdn, value),
		dnsCheckDoH:           c.dohMethod(p.dohURL, fqdn, value),
		dnsCheckResolver:      resolverMethod(lookup, p.resolver, fqdn, value),
	}
	order := []string{p.mode}
	if p.mode == dnsCheckAuto {
		order = []string{dnsCheckAuthoritative, dnsCheckDoH, dnsCheckResolver}
		for i, name := range order {
			if st.method == name {
				order = order[i:]
				break
			}
		}
	}
	for i, name := range order {
		last := i == len(order)-1
		err := methods[name].poll(ctx, interval, p.mode == dnsCheckAuto && !last)
		if errors.Is(err, errMethodUnreachable) {
			log.Printf("acme connector %s: dns-01 %s check got no DNS answer; falling back", c.id, name)
			continue
		}
		if err == nil {
			c.noteDNSMethod(st, name)
		}
		return err
	}
	return errors.New("dns-01: no propagation method available")
}

func (c *acmeIssuerConnector) noteDNSMethod(st *dnsCheckState, name string) {
	if st.method != name {
		log.Printf("acme connector %s: dns-01 propagation checked via %s", c.id, name)
		st.method = name
	}
}

// authoritativeMethod asks every authoritative nameserver of the zone (the
// ones the CA's validator ends up asking) and needs each to serve value.
// Asking a caching resolver instead could pin a stale negative answer for
// the zone's negative TTL.
func authoritativeMethod(lookupNS func(context.Context, string) ([]*net.NS, error), lookup txtLookup, zone, fqdn, value string) dnsMethod {
	var pending map[string]bool
	return dnsMethod{
		name: dnsCheckAuthoritative,
		check: func(ctx context.Context) (bool, bool, error) {
			if pending == nil {
				nss, err := lookupNS(ctx, zone)
				if err != nil || len(nss) == 0 {
					return false, false, fmt.Errorf("dns-01: nameservers for %s: %v", zone, err)
				}
				pending = map[string]bool{}
				for _, ns := range nss {
					pending[strings.TrimSuffix(ns.Host, ".")] = true
				}
			}
			got := false
			for ns := range pending {
				txts, err := lookup(ctx, ns, fqdn)
				got = got || answered(err)
				if containsTXT(txts, value) {
					delete(pending, ns)
				}
			}
			return len(pending) == 0, got, nil
		},
		pending: func() string {
			left := make([]string, 0, len(pending))
			for ns := range pending {
				left = append(left, ns)
			}
			return "at " + strings.Join(left, ", ")
		},
	}
}

func resolverMethod(lookup txtLookup, addr, fqdn, value string) dnsMethod {
	return dnsMethod{
		name: dnsCheckResolver,
		check: func(ctx context.Context) (bool, bool, error) {
			txts, err := lookup(ctx, addr, fqdn)
			return containsTXT(txts, value), answered(err), nil
		},
		pending: func() string { return "via the resolver" },
	}
}

func (c *acmeIssuerConnector) dohMethod(endpoint, fqdn, value string) dnsMethod {
	lookup := c.lookupDoH
	if lookup == nil {
		lookup = c.dohLookup
	}
	return dnsMethod{
		name: dnsCheckDoH,
		check: func(ctx context.Context) (bool, bool, error) {
			txts, err := lookup(ctx, endpoint, fqdn)
			return containsTXT(txts, value), answered(err), nil
		},
		pending: func() string { return "via DNS-over-HTTPS" },
	}
}

func containsTXT(txts []string, value string) bool {
	for _, t := range txts {
		if t == value {
			return true
		}
	}
	return false
}

// dohAnswer is the application/dns-json shape both Cloudflare and Google
// serve (RFC 8484's wire format is not needed for a propagation probe).
type dohAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

const (
	dnsTypeTXT   = 16
	dnsRcodeOK   = 0
	dnsRcodeNXDM = 3
)

// dohLookup asks a DoH JSON endpoint for the TXT records at name. It sends
// only the query name and type: no credentials, and never the zone's DNS
// API token. It goes through the same egress guard as directory_url.
func (c *acmeIssuerConnector) dohLookup(ctx context.Context, endpoint, name string) ([]string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("doh: bad endpoint: %w", err)
	}
	q := u.Query()
	q.Set("name", name)
	q.Set("type", "TXT")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := c.httpClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh query: HTTP %d", resp.StatusCode)
	}
	return parseDoHTXT(io.LimitReader(resp.Body, 1<<20), name)
}

// parseDoHTXT extracts TXT strings from a dns-json body. NOERROR with no
// TXT answer and NXDOMAIN both map to a not-found DNSError (the CA would
// see the same), other rcodes (SERVFAIL, REFUSED) are failures.
func parseDoHTXT(r io.Reader, name string) ([]string, error) {
	var ans dohAnswer
	if err := json.NewDecoder(r).Decode(&ans); err != nil {
		return nil, fmt.Errorf("doh query: unreadable response: %w", err)
	}
	if ans.Status != dnsRcodeOK && ans.Status != dnsRcodeNXDM {
		return nil, fmt.Errorf("doh query: DNS rcode %d", ans.Status)
	}
	var txts []string
	for _, a := range ans.Answer {
		if a.Type == dnsTypeTXT {
			txts = append(txts, unquoteTXT(a.Data))
		}
	}
	if len(txts) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return txts, nil
}

// unquoteTXT turns presentation-format TXT data into the record's string:
// Cloudflare quotes each 255-byte chunk ("a" "b"), Google returns the
// chunks already joined and unquoted.
func unquoteTXT(data string) string {
	data = strings.TrimSpace(data)
	if !strings.HasPrefix(data, `"`) {
		return data
	}
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		switch {
		case ch == '\\' && inQuote && i+1 < len(data):
			i++
			b.WriteByte(data[i])
		case ch == '"':
			inQuote = !inQuote
		case inQuote:
			b.WriteByte(ch)
		}
	}
	return b.String()
}
