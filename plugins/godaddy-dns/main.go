// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command godaddy-dns is a dns01 plugin that publishes and removes ACME
// challenge TXT records in GoDaddy DNS through the Domains v1 API. The only
// host it may reach is api.godaddy.com.
//
// Auth: "Authorization: sso-key <key>:<secret>", the classic developer key.
// GoDaddy marks that credential deprecated for Domains through 2026 and
// recommends Personal Access Tokens, which authenticate the v3 API; v1 is
// documented as taking the sso-key form, so this plugin uses it. A v3 plugin
// is a ROADMAP row.
// https://developer.godaddy.com/en/docs/api-users/auth (credential table)
//
// GoDaddy has no record ids; records are addressed by type and name, and a
// name's TXT records form one set:
//   - GET    /v1/domains/{domain}/records/TXT/{name}    list the set
//   - PATCH  /v1/domains/{domain}/records               append (204)
//   - PUT    /v1/domains/{domain}/records/TXT/{name}    replace the set (204)
//   - DELETE /v1/domains/{domain}/records/TXT/{name}    delete the whole set (204)
//
// {name} is relative to the domain. DELETE removes every TXT record at the
// name, so cleanup never uses it while other values remain: it reads the set
// and replaces it without our value (dns01.CleanupRRSet). The minimum TTL is
// 600 seconds.
// Zone: GET /v1/domains/{domain} answers 200 (203 with verification notes)
// for a domain on the account, 404 otherwise.
// https://developer.godaddy.com/en/docs/references/rest/domains/v1/get
// https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-add
// https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-get
// https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-replace-type-name
// https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-delete-type-name
// https://developer.godaddy.com/en/docs/api-users/domains/manage/dns (TTL)
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/dns01"
)

func init() { dns01.Register(gd{}) }

func main() {}

const (
	apiBase = "https://api.godaddy.com"
	vendor  = "godaddy"
	minTTL  = 600
)

type gd struct{}

type doer func(abi.HTTPRequest) (abi.HTTPResponse, error)

// backend implements dns01.RRSet for one operation.
type backend struct {
	auth string
	ttl  int
	send doer
}

func newBackend(h *delivery.Host, cred map[string]string, ttl int) (*backend, error) {
	if cred["api_key"] == "" || cred["api_secret"] == "" {
		return nil, errors.New("the credential needs api_key and api_secret")
	}
	return &backend{auth: "sso-key " + cred["api_key"] + ":" + cred["api_secret"], ttl: max(ttl, minTTL), send: h.HTTP}, nil
}

func (b *backend) call(method, path string, body any) (abi.HTTPResponse, error) {
	req := abi.HTTPRequest{Method: method, URL: apiBase + path, Headers: map[string]string{"Authorization": b.auth, "Accept": "application/json"}}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return abi.HTTPResponse{}, err
		}
		req.Body = raw
		req.Headers["Content-Type"] = "application/json"
	}
	return b.send(req)
}

func authError(resp abi.HTTPResponse) error {
	if resp.Status == 401 || resp.Status == 403 {
		return fmt.Errorf("%s: the key was refused (HTTP %d); check api_key, api_secret and that the key is a production key with access to this domain", vendor, resp.Status)
	}
	return nil
}

func setPath(zone, fqdn string) string {
	return "/v1/domains/" + url.PathEscape(zone) + "/records/TXT/" + url.PathEscape(dns01.RelativeName(fqdn, zone))
}

func (b *backend) Zone(fqdn string) (string, error) {
	for _, cand := range dns01.ParentCandidates(fqdn) {
		resp, err := b.call("GET", "/v1/domains/"+url.PathEscape(cand), nil)
		if err != nil {
			return "", err
		}
		switch resp.Status {
		case 200, 203: // 203: found, with verification notes
			return cand, nil
		case 404, 422: // not a domain on this account
			continue
		}
		if err := authError(resp); err != nil {
			return "", err
		}
		return "", dns01.Refused(vendor, "looking up domain "+cand, resp)
	}
	return "", fmt.Errorf("%s: no domain on this account holds %s", vendor, fqdn)
}

func (b *backend) Read(zone, fqdn string) ([]string, error) {
	resp, err := b.call("GET", setPath(zone, fqdn), nil)
	if err != nil {
		return nil, err
	}
	if resp.Status == 404 {
		return nil, nil
	}
	if resp.Status != 200 {
		if err := authError(resp); err != nil {
			return nil, err
		}
		return nil, dns01.Refused(vendor, "listing TXT records", resp)
	}
	var recs []struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &recs); err != nil {
		return nil, errors.New(vendor + ": unreadable record list")
	}
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Data)
	}
	return out, nil
}

func (b *backend) Write(zone, fqdn string, old, next []string) error {
	var resp abi.HTTPResponse
	var err error
	switch {
	case len(next) == 0:
		resp, err = b.call("DELETE", setPath(zone, fqdn), nil)
	case len(old) == 0:
		resp, err = b.call("PATCH", "/v1/domains/"+url.PathEscape(zone)+"/records",
			[]map[string]any{{"type": "TXT", "name": dns01.RelativeName(fqdn, zone), "data": next[0], "ttl": b.ttl}})
	default:
		recs := make([]map[string]any, 0, len(next))
		for _, v := range next {
			recs = append(recs, map[string]any{"data": v, "ttl": b.ttl})
		}
		resp, err = b.call("PUT", setPath(zone, fqdn), recs)
	}
	if err != nil {
		return err
	}
	if resp.Status == 200 || resp.Status == 204 {
		return nil
	}
	if err := authError(resp); err != nil {
		return err
	}
	return dns01.Refused(vendor, "writing the TXT record set", resp)
}

// Encode and Decode: GoDaddy stores a TXT value as the bare string.
func (*backend) Encode(v string) string { return v }
func (*backend) Decode(s string) string { return s }

func (gd) Present(h *delivery.Host, req abi.DNS01PresentRequest) (abi.DNS01PresentResult, error) {
	b, err := newBackend(h, req.Credential, req.TTLSeconds)
	if err != nil {
		return abi.DNS01PresentResult{}, err
	}
	return dns01.PresentRRSet(b, req.FQDN, req.Value)
}

func (gd) Cleanup(h *delivery.Host, req abi.DNS01CleanupRequest) (abi.DNS01CleanupResult, error) {
	b, err := newBackend(h, req.Credential, 0)
	if err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	return dns01.CleanupRRSet(b, req.FQDN, req.Value, req.RecordID)
}
