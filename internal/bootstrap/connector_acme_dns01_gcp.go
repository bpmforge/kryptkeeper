// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W27-21: Google Cloud DNS dns-01 adapter. Hand-rolled REST against
// dns.googleapis.com/dns/v1; a service-account key is exchanged for a token
// with a stdlib-signed JWT (no cloud.google.com/go/dns).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	gcpDNSAPIBase  = "https://dns.googleapis.com"
	gcpDNSTokenURL = "https://oauth2.googleapis.com/token"
	gcpDNSScope    = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
)

func init() { registerDNSProvider("gcp", newGCPDNSFromConfig) }

type gcpDNS struct {
	project     string
	accessToken string // static token, or ""
	saEmail     string
	saKey       *rsa.PrivateKey
	saKeyText   string // raw private_key PEM, kept only to redact it

	apiBase  string
	tokenURL string
	client   *http.Client
	now      func() time.Time

	mu       sync.Mutex
	token    string
	tokenExp time.Time
	zones    map[string]string // fqdn -> managed zone name
	ttls     map[string]int64  // fqdn -> TTL of the rrset as read (a deletion must match it)
}

func newGCPDNSFromConfig(_ acmeConnectorConfig, p acmeCredentialPayload) (dnsProvider, error) {
	var d struct {
		ProjectID          string `json:"project_id"`
		ServiceAccountJSON string `json:"service_account_json"`
		AccessToken        string `json:"access_token"`
	}
	const need = `acme connector dns_provider gcp needs a "dns" object in its credential (project_id and exactly one of service_account_json, access_token)`
	if len(p.DNS) == 0 || json.Unmarshal(p.DNS, &d) != nil || d.ProjectID == "" ||
		(d.ServiceAccountJSON == "") == (d.AccessToken == "") {
		return nil, errors.New(need)
	}
	g := &gcpDNS{
		project: d.ProjectID, accessToken: d.AccessToken,
		apiBase: gcpDNSAPIBase, tokenURL: gcpDNSTokenURL,
		client: dnsAPIClient(), now: time.Now, zones: map[string]string{}, ttls: map[string]int64{},
	}
	if d.ServiceAccountJSON != "" {
		var sa struct {
			ClientEmail string `json:"client_email"`
			PrivateKey  string `json:"private_key"`
		}
		if json.Unmarshal([]byte(d.ServiceAccountJSON), &sa) != nil || sa.ClientEmail == "" || sa.PrivateKey == "" {
			return nil, errors.New("acme connector dns_provider gcp: service_account_json needs client_email and private_key")
		}
		key, err := parseRSAPrivateKey(sa.PrivateKey)
		if err != nil {
			return nil, errors.New("acme connector dns_provider gcp: service_account_json private_key is not a usable RSA PEM key")
		}
		g.saEmail, g.saKey, g.saKeyText = sa.ClientEmail, key, sa.PrivateKey
	}
	return g, nil
}

func parseRSAPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(pemText))
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("not an RSA key")
	}
	return x509.ParsePKCS1PrivateKey(blk.Bytes)
}

func (g *gcpDNS) secrets() []string {
	return []string{g.accessToken, g.token, g.saKeyText}
}

func (g *gcpDNS) bearer(ctx context.Context) (string, error) {
	if g.accessToken != "" {
		return g.accessToken, nil
	}
	if g.token != "" && g.now().Before(g.tokenExp.Add(-60*time.Second)) {
		return g.token, nil
	}
	b64 := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	now := g.now()
	claims, _ := json.Marshal(map[string]any{
		"iss": g.saEmail, "scope": gcpDNSScope, "aud": g.tokenURL,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	signing := b64.EncodeToString(hdr) + "." + b64.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.saKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", errors.New("gcp token: signing the service-account assertion failed")
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signing + "." + b64.EncodeToString(sig)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, body, err := dnsRoundTrip(g.client, req)
	if err != nil {
		return "", fmt.Errorf("gcp token request: %s", redact(err.Error(), g.secrets()...))
	}
	if status >= 300 {
		return "", fmt.Errorf("gcp token request: HTTP %d", status)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &tok) != nil || tok.AccessToken == "" {
		return "", errors.New("gcp token request: no access token in the response")
	}
	if tok.ExpiresIn <= 0 {
		tok.ExpiresIn = 300
	}
	g.token, g.tokenExp = tok.AccessToken, now.Add(time.Duration(tok.ExpiresIn)*time.Second)
	return g.token, nil
}

func (g *gcpDNS) call(ctx context.Context, method, path string, q url.Values, body any) ([]byte, error) {
	tok, err := g.bearer(ctx)
	if err != nil {
		return nil, err
	}
	u := g.apiBase + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	status, resp, err := dnsRoundTrip(g.client, req)
	if err != nil {
		return nil, fmt.Errorf("gcp DNS %s %s: %s", method, path, redact(err.Error(), g.secrets()...))
	}
	if status >= 300 {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		msg := ""
		if json.Unmarshal(resp, &e) == nil && e.Error.Message != "" {
			msg = ": " + e.Error.Message
		}
		return nil, fmt.Errorf("gcp DNS %s %s: HTTP %d%s", method, path, status, snippet(redact(msg, g.secrets()...)))
	}
	return resp, nil
}

func (g *gcpDNS) zonesPath() string {
	return "/dns/v1/projects/" + url.PathEscape(g.project) + "/managedZones"
}

func (g *gcpDNS) zoneFor(ctx context.Context, fqdn string) (string, error) {
	for _, cand := range parentCandidates(fqdn) {
		raw, err := g.call(ctx, http.MethodGet, g.zonesPath(), url.Values{"dnsName": {cand + "."}}, nil)
		if err != nil {
			return "", err
		}
		var list struct {
			Zones []struct {
				Name       string `json:"name"`
				DNSName    string `json:"dnsName"`
				Visibility string `json:"visibility"`
			} `json:"managedZones"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			return "", errors.New("gcp DNS: zone list is unreadable")
		}
		for _, z := range list.Zones {
			if strings.EqualFold(z.DNSName, cand+".") && !strings.EqualFold(z.Visibility, "private") && z.Name != "" {
				g.zones[fqdn] = z.Name
				return cand, nil
			}
		}
	}
	return "", fmt.Errorf("no Cloud DNS public zone in project %s holds %s", g.project, fqdn)
}

type gcpRRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int64    `json:"ttl"`
	RRDatas []string `json:"rrdatas"`
}

func (g *gcpDNS) read(ctx context.Context, fqdn string) ([]string, error) {
	raw, err := g.call(ctx, http.MethodGet, g.zonesPath()+"/"+url.PathEscape(g.zones[fqdn])+"/rrsets",
		url.Values{"name": {fqdn + "."}, "type": {"TXT"}}, nil)
	if err != nil {
		return nil, err
	}
	var list struct {
		RRSets []gcpRRSet `json:"rrsets"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, errors.New("gcp DNS: record set response is unreadable")
	}
	for _, s := range list.RRSets {
		if strings.EqualFold(s.Name, fqdn+".") && s.Type == "TXT" {
			g.ttls[fqdn] = s.TTL
			return s.RRDatas, nil
		}
	}
	return nil, nil
}

func (g *gcpDNS) write(ctx context.Context, fqdn string, old, next []string) error {
	change := map[string]any{}
	if len(old) > 0 {
		ttl := g.ttls[fqdn]
		if ttl <= 0 {
			ttl = 60
		}
		change["deletions"] = []gcpRRSet{{Name: fqdn + ".", Type: "TXT", TTL: ttl, RRDatas: old}}
	}
	if len(next) > 0 {
		change["additions"] = []gcpRRSet{{Name: fqdn + ".", Type: "TXT", TTL: 60, RRDatas: next}}
	}
	_, err := g.call(ctx, http.MethodPost, g.zonesPath()+"/"+url.PathEscape(g.zones[fqdn])+"/changes", nil, change)
	return err
}

func (g *gcpDNS) quote(v string) string { return quoteTXT(v) }

func (g *gcpDNS) Present(ctx context.Context, fqdn, value string) (string, func(context.Context) error, error) {
	return presentRRSet(ctx, &g.mu, g, fqdn, value)
}
