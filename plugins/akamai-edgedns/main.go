// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command akamai-edgedns is a dns01 plugin that publishes and removes ACME
// challenge TXT records in Akamai Edge DNS through the Edge DNS API v2
// (config-dns/v2). Requests are signed with EdgeGrid (edgegrid.go).
//
// The API host is per API client ("akab-xxxx.luna.akamaiapis.net", the
// "host" of an .edgerc section), so the manifest grants the host named by
// the credential's "host" field, as an https URL. The plugin additionally
// refuses any host outside akamaiapis.net: a mistyped or hostile credential
// field cannot send a signed request anywhere else.
//
// Endpoints (base https://{hostname}/config-dns/v2); changes made through
// them go to the network immediately, with no change list:
//   - GET    /zones/{zone}                              200 when the zone exists
//   - GET    /zones/{zone}/names/{name}/types/TXT       200 {name, type, ttl, rdata[]}, 404 if none
//   - POST   /zones/{zone}/names/{name}/types/TXT       create, 201 (409 if it exists)
//   - PUT    /zones/{zone}/names/{name}/types/TXT       replace, 200
//   - DELETE /zones/{zone}/names/{name}/types/TXT       delete the record set, 204
//
// {name} is the fully qualified name; rdata strings are in master file
// format, so a TXT value is quoted. A record set holds every TXT value of a
// name, so the plugin reads, changes and writes the set (dns01.PresentRRSet)
// and DELETE is used only when nothing else remains.
// https://techdocs.akamai.com/edge-dns/reference/post-zones-zone-names-name-types-type
// https://techdocs.akamai.com/edge-dns/reference/get-zone-name-type
// https://techdocs.akamai.com/edge-dns/reference/put-zones-zone-names-name-types-type
// https://techdocs.akamai.com/edge-dns/reference/delete-zone-name-type
// https://techdocs.akamai.com/edge-dns/reference/get-zone
// https://techdocs.akamai.com/edge-dns/reference/use-change-lists
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/dns01"
)

func init() { dns01.Register(akamai{}) }

func main() {}

const (
	vendor     = "akamai"
	hostSuffix = ".akamaiapis.net"
)

type akamai struct{}

type doer func(abi.HTTPRequest) (abi.HTTPResponse, error)

type backend struct {
	host string
	eg   edgeGrid
	ttl  int
	send doer
	now  func() time.Time
}

// apiHost extracts the API host from the credential's host URL and refuses
// anything that is not a bare https akamaiapis.net host.
func apiHost(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return "", errors.New("the credential's host must be https://<host from your .edgerc>, with no path or port")
	}
	h := strings.ToLower(u.Hostname())
	if !strings.HasSuffix(h, hostSuffix) || len(h) == len(hostSuffix) {
		return "", fmt.Errorf("the credential's host must end in %s", hostSuffix)
	}
	return h, nil
}

func newBackend(h *delivery.Host, cred map[string]string, ttl int) (*backend, error) {
	host, err := apiHost(cred["host"])
	if err != nil {
		return nil, err
	}
	if cred["client_token"] == "" || cred["client_secret"] == "" || cred["access_token"] == "" {
		return nil, errors.New("the credential needs client_token, client_secret and access_token")
	}
	return &backend{
		host: host, ttl: ttl, send: h.HTTP, now: time.Now,
		eg: edgeGrid{clientToken: cred["client_token"], clientSecret: cred["client_secret"], accessToken: cred["access_token"]},
	}, nil
}

func (b *backend) call(method, path string, body any) (abi.HTTPResponse, error) {
	req := abi.HTTPRequest{Method: method, URL: "https://" + b.host + path, Headers: map[string]string{"Accept": "application/json"}}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return abi.HTTPResponse{}, err
		}
		req.Body = raw
		req.Headers["Content-Type"] = "application/json"
	}
	auth, err := b.eg.sign(method, b.host, path, req.Body, b.now())
	if err != nil {
		return abi.HTTPResponse{}, err
	}
	req.Headers["Authorization"] = auth
	return b.send(req)
}

func authError(resp abi.HTTPResponse) error {
	if resp.Status == 401 || resp.Status == 403 {
		return fmt.Errorf("%s: the API client was refused (HTTP %d); check the credential fields, the system clock (EdgeGrid allows about 30 seconds of skew) and that the client has read-write access to Edge DNS", vendor, resp.Status)
	}
	return nil
}

func setPath(zone, fqdn string) string {
	return "/config-dns/v2/zones/" + url.PathEscape(zone) + "/names/" + url.PathEscape(fqdn) + "/types/TXT"
}

func (b *backend) Zone(fqdn string) (string, error) {
	for _, cand := range dns01.ParentCandidates(fqdn) {
		resp, err := b.call("GET", "/config-dns/v2/zones/"+url.PathEscape(cand), nil)
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
	return "", fmt.Errorf("%s: no zone this client can see holds %s", vendor, fqdn)
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
		return nil, dns01.Refused(vendor, "reading the TXT record set", resp)
	}
	var rs struct {
		TTL   int      `json:"ttl"`
		RData []string `json:"rdata"`
	}
	if err := json.Unmarshal(resp.Body, &rs); err != nil {
		return nil, errors.New(vendor + ": unreadable record set")
	}
	// A cleanup writes the remaining values back under the set's own TTL; a
	// zero would make Akamai treat the set as uncached.
	if b.ttl == 0 {
		b.ttl = rs.TTL
	}
	return rs.RData, nil
}

func (b *backend) Write(zone, fqdn string, old, next []string) error {
	var resp abi.HTTPResponse
	var err error
	set := map[string]any{"name": fqdn, "type": "TXT", "ttl": b.ttl, "rdata": next}
	switch {
	case len(next) == 0:
		resp, err = b.call("DELETE", setPath(zone, fqdn), nil)
	case len(old) == 0:
		resp, err = b.call("POST", setPath(zone, fqdn), set)
	default:
		resp, err = b.call("PUT", setPath(zone, fqdn), set)
	}
	if err != nil {
		return err
	}
	if resp.Status == 200 || resp.Status == 201 || resp.Status == 204 {
		return nil
	}
	if err := authError(resp); err != nil {
		return err
	}
	return dns01.Refused(vendor, "writing the TXT record set", resp)
}

// Encode quotes a value as one master-file string; Decode undoes exactly
// that, so a foreign multi-string or escaped value never matches ours.
func (*backend) Encode(v string) string { return `"` + v + `"` }

func (*backend) Decode(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' && !strings.ContainsAny(s[1:len(s)-1], `"\`) {
		return s[1 : len(s)-1]
	}
	return "\x00" + s // cannot equal a validated value (dns01.CheckName refuses control characters)
}

func (akamai) Present(h *delivery.Host, req abi.DNS01PresentRequest) (abi.DNS01PresentResult, error) {
	b, err := newBackend(h, req.Credential, req.TTLSeconds)
	if err != nil {
		return abi.DNS01PresentResult{}, err
	}
	return dns01.PresentRRSet(b, req.FQDN, req.Value)
}

func (akamai) Cleanup(h *delivery.Host, req abi.DNS01CleanupRequest) (abi.DNS01CleanupResult, error) {
	b, err := newBackend(h, req.Credential, 0)
	if err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	return dns01.CleanupRRSet(b, req.FQDN, req.Value, req.RecordID)
}
