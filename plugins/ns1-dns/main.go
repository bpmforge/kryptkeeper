// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command ns1-dns is a dns01 plugin that publishes and removes ACME challenge
// TXT records in NS1 (IBM NS1 Connect) managed DNS. The only host it may
// reach is api.nsone.net.
//
// Auth: the API key in an "X-NSONE-Key" header; base URL
// https://api.nsone.net/v1/. Endpoints, as the vendor's own Go client
// (github.com/ns1/ns1-go, rest/record.go, rest/zone.go, rest/client.go)
// calls them and the IBM NS1 Connect API reference describes them:
//   - GET    /v1/zones/{zone}?records=false      zone exists (404 otherwise)
//   - GET    /v1/zones/{zone}/{domain}/TXT       read the record ("record not found" as 404)
//   - PUT    /v1/zones/{zone}/{domain}/TXT       create; body zone, domain, type, ttl, answers
//   - POST   /v1/zones/{zone}/{domain}/TXT       update; answers replace the record's answers
//   - DELETE /v1/zones/{zone}/{domain}/TXT       delete the record and all its answers
//
// {domain} is the fully qualified name. A TXT answer is {"answer": ["text"]}
// (rdata strings of one answer). NS1 keeps all TXT values of a name in one
// record, so Present and Cleanup read, change and write the set
// (dns01.PresentRRSet) rather than create and delete blindly: DELETE would
// take other challenge values with it.
// https://developer.ibm.com/apis/catalog/ns1--ibm-ns1-connect-api/api/API--ns1--ibm-ns1-connect-api
// https://github.com/ns1/ns1-go/blob/v2/rest/record.go
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/dns01"
)

func init() { dns01.Register(ns1{}) }

func main() {}

const (
	apiBase = "https://api.nsone.net/v1"
	vendor  = "ns1"
)

type ns1 struct{}

type doer func(abi.HTTPRequest) (abi.HTTPResponse, error)

type backend struct {
	key  string
	ttl  int
	send doer
}

func newBackend(h *delivery.Host, cred map[string]string, ttl int) (*backend, error) {
	if cred["api_key"] == "" {
		return nil, errors.New("the credential needs api_key")
	}
	return &backend{key: cred["api_key"], ttl: ttl, send: h.HTTP}, nil
}

func (b *backend) call(method, path string, body any) (abi.HTTPResponse, error) {
	req := abi.HTTPRequest{Method: method, URL: apiBase + path, Headers: map[string]string{"X-NSONE-Key": b.key, "Accept": "application/json"}}
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
		return fmt.Errorf("%s: the API key was refused (HTTP %d); it needs permission to view and manage the zone's records", vendor, resp.Status)
	}
	return nil
}

func recordPath(zone, fqdn string) string {
	return "/zones/" + url.PathEscape(zone) + "/" + url.PathEscape(fqdn) + "/TXT"
}

func (b *backend) Zone(fqdn string) (string, error) {
	for _, cand := range dns01.ParentCandidates(fqdn) {
		resp, err := b.call("GET", "/zones/"+url.PathEscape(cand)+"?records=false", nil)
		if err != nil {
			return "", err
		}
		if resp.Status == 200 {
			return cand, nil
		}
		if resp.Status == 404 {
			continue
		}
		if err := authError(resp); err != nil {
			return "", err
		}
		return "", dns01.Refused(vendor, "looking up zone "+cand, resp)
	}
	return "", fmt.Errorf("%s: no zone this key can see holds %s", vendor, fqdn)
}

type answer struct {
	Answer []string `json:"answer"`
}

// Read returns each answer as the JSON of its rdata strings, so foreign
// answers (even ones split into several strings) are written back unchanged.
func (b *backend) Read(zone, fqdn string) ([]string, error) {
	resp, err := b.call("GET", recordPath(zone, fqdn), nil)
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
		return nil, dns01.Refused(vendor, "reading the TXT record", resp)
	}
	var rec struct {
		Answers []answer `json:"answers"`
	}
	if err := json.Unmarshal(resp.Body, &rec); err != nil {
		return nil, errors.New(vendor + ": unreadable record")
	}
	out := make([]string, 0, len(rec.Answers))
	for _, a := range rec.Answers {
		raw, _ := json.Marshal(a.Answer)
		out = append(out, string(raw))
	}
	return out, nil
}

func (b *backend) Write(zone, fqdn string, old, next []string) error {
	var resp abi.HTTPResponse
	var err error
	answers := make([]answer, 0, len(next))
	for _, s := range next {
		var parts []string
		if json.Unmarshal([]byte(s), &parts) != nil {
			return errors.New(vendor + ": internal error: malformed stored answer")
		}
		answers = append(answers, answer{Answer: parts})
	}
	switch {
	case len(next) == 0:
		resp, err = b.call("DELETE", recordPath(zone, fqdn), nil)
	case len(old) == 0:
		resp, err = b.call("PUT", recordPath(zone, fqdn), map[string]any{
			"zone": zone, "domain": fqdn, "type": "TXT", "ttl": b.ttl, "answers": answers,
		})
	default:
		resp, err = b.call("POST", recordPath(zone, fqdn), map[string]any{
			"zone": zone, "domain": fqdn, "type": "TXT", "answers": answers,
		})
	}
	if err != nil {
		return err
	}
	if resp.Status >= 200 && resp.Status < 300 {
		return nil
	}
	if err := authError(resp); err != nil {
		return err
	}
	return dns01.Refused(vendor, "writing the TXT record", resp)
}

func (*backend) Encode(v string) string {
	raw, _ := json.Marshal([]string{v})
	return string(raw)
}

func (*backend) Decode(s string) string {
	var parts []string
	if json.Unmarshal([]byte(s), &parts) != nil {
		return ""
	}
	return strings.Join(parts, "")
}

func (ns1) Present(h *delivery.Host, req abi.DNS01PresentRequest) (abi.DNS01PresentResult, error) {
	b, err := newBackend(h, req.Credential, req.TTLSeconds)
	if err != nil {
		return abi.DNS01PresentResult{}, err
	}
	return dns01.PresentRRSet(b, req.FQDN, req.Value)
}

func (ns1) Cleanup(h *delivery.Host, req abi.DNS01CleanupRequest) (abi.DNS01CleanupResult, error) {
	b, err := newBackend(h, req.Credential, 0)
	if err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	return dns01.CleanupRRSet(b, req.FQDN, req.Value, req.RecordID)
}
