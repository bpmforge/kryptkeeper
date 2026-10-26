// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command digitalocean-dns is a dns01 plugin that publishes and removes ACME
// challenge TXT records in DigitalOcean DNS (API v2). The only host it may
// reach is api.digitalocean.com (the manifest's fixed network grant).
//
// Auth: "Authorization: Bearer <token>"; the token needs the domain:create
// (or domain:update), domain:read and domain:delete (or domain:update)
// scopes. Base URL https://api.digitalocean.com.
// https://docs.digitalocean.com/reference/api/reference/domains/
//
// Zone: GET /v2/domains/{name} answers 200 for a domain on the account.
//
// Create: POST /v2/domains/{domain}/records with {type, name, data, ttl};
// name is relative to the domain ("_acme-challenge"), 201 returns
// {"domain_record": {"id": <int>, ...}}.
// https://docs.digitalocean.com/reference/api/reference/domain-records/
// (operation domains_create_record in github.com/digitalocean/openapi)
//
// List: GET /v2/domains/{domain}/records?name=<fqdn>&type=TXT; the name
// filter takes the fully qualified name. Delete: DELETE
// /v2/domains/{domain}/records/{id} answers 204.
// https://github.com/digitalocean/openapi/blob/main/specification/resources/domains/domains_delete_record.yml
//
// Every record has its own id, so cleanup removes exactly the record Present
// wrote and leaves other challenge values at the same name alone.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/dns01"
)

func init() { dns01.Register(do{}) }

func main() {}

const (
	apiBase = "https://api.digitalocean.com"
	vendor  = "digitalocean"
	// minTTL is a floor, not a documented minimum: DigitalOcean's reference does
	// not state one, and a TTL it rejects comes back as a 422 that is reported
	// with its status.
	minTTL = 30
)

type do struct{}

// doer sends one request; a test replaces the host.
type doer func(abi.HTTPRequest) (abi.HTTPResponse, error)

type client struct {
	token string
	send  doer
}

func newClient(h *delivery.Host, cred map[string]string) (*client, error) {
	if cred["api_token"] == "" {
		return nil, errors.New("the credential needs api_token")
	}
	return &client{token: cred["api_token"], send: h.HTTP}, nil
}

func (c *client) call(method, path string, body any) (abi.HTTPResponse, error) {
	req := abi.HTTPRequest{Method: method, URL: apiBase + path, Headers: map[string]string{"Authorization": "Bearer " + c.token}}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return abi.HTTPResponse{}, err
		}
		req.Body = raw
		req.Headers["Content-Type"] = "application/json"
	}
	return c.send(req)
}

// authError turns a 401 or 403 into a message that names the likely cause.
func authError(resp abi.HTTPResponse) error {
	if resp.Status == 401 || resp.Status == 403 {
		return fmt.Errorf("%s: the token was refused (HTTP %d); it needs the domain read, create and delete scopes", vendor, resp.Status)
	}
	return nil
}

// zone finds the domain on the account that holds fqdn, longest parent first
// so a delegated subdomain managed separately wins.
func (c *client) zone(fqdn string) (string, error) {
	for _, cand := range dns01.ParentCandidates(fqdn) {
		resp, err := c.call("GET", "/v2/domains/"+url.PathEscape(cand), nil)
		if err != nil {
			return "", err
		}
		switch {
		case resp.Status == 200:
			return cand, nil
		case resp.Status == 404:
			continue
		}
		if err := authError(resp); err != nil {
			return "", err
		}
		return "", dns01.Refused(vendor, "looking up domain "+cand, resp)
	}
	return "", fmt.Errorf("%s: no domain on this account holds %s", vendor, fqdn)
}

func (do) Present(h *delivery.Host, req abi.DNS01PresentRequest) (abi.DNS01PresentResult, error) {
	c, err := newClient(h, req.Credential)
	if err != nil {
		return abi.DNS01PresentResult{}, err
	}
	return c.present(req)
}

func (c *client) present(req abi.DNS01PresentRequest) (abi.DNS01PresentResult, error) {
	zone, err := c.zone(req.FQDN)
	if err != nil {
		return abi.DNS01PresentResult{}, err
	}
	resp, err := c.call("POST", "/v2/domains/"+url.PathEscape(zone)+"/records", map[string]any{
		"type": "TXT", "name": dns01.RelativeName(req.FQDN, zone), "data": req.Value, "ttl": max(req.TTLSeconds, minTTL),
	})
	if err != nil {
		return abi.DNS01PresentResult{}, err
	}
	if resp.Status != 201 {
		if err := authError(resp); err != nil {
			return abi.DNS01PresentResult{}, err
		}
		return abi.DNS01PresentResult{}, dns01.Refused(vendor, "creating the TXT record", resp)
	}
	var out struct {
		Record struct {
			ID json.Number `json:"id"`
		} `json:"domain_record"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil || out.Record.ID == "" {
		return abi.DNS01PresentResult{}, errors.New(vendor + ": the created record has no id")
	}
	return abi.DNS01PresentResult{RecordID: zone + "/" + out.Record.ID.String(), Zone: zone}, nil
}

func (do) Cleanup(h *delivery.Host, req abi.DNS01CleanupRequest) (abi.DNS01CleanupResult, error) {
	c, err := newClient(h, req.Credential)
	if err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	return c.cleanup(req)
}

// parseID splits the record id Present returned; ok is false for anything
// else, in which case cleanup searches by name and value.
func parseID(recordID string) (zone string, id int64, ok bool) {
	zone, n, found := strings.Cut(recordID, "/")
	if !found || zone == "" {
		return "", 0, false
	}
	id, err := strconv.ParseInt(n, 10, 64)
	return zone, id, err == nil && id > 0
}

func (c *client) cleanup(req abi.DNS01CleanupRequest) (abi.DNS01CleanupResult, error) {
	zone, id, ok := parseID(req.RecordID)
	if ok {
		return c.remove(zone, id)
	}
	zone, err := c.zone(req.FQDN)
	if err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	q := url.Values{"name": {req.FQDN}, "type": {"TXT"}, "per_page": {"200"}}
	resp, err := c.call("GET", "/v2/domains/"+url.PathEscape(zone)+"/records?"+q.Encode(), nil)
	if err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	if resp.Status != 200 {
		if err := authError(resp); err != nil {
			return abi.DNS01CleanupResult{}, err
		}
		return abi.DNS01CleanupResult{}, dns01.Refused(vendor, "listing TXT records", resp)
	}
	var list struct {
		Records []struct {
			ID   int64  `json:"id"`
			Data string `json:"data"`
		} `json:"domain_records"`
	}
	if err := json.Unmarshal(resp.Body, &list); err != nil {
		return abi.DNS01CleanupResult{}, errors.New(vendor + ": unreadable record list")
	}
	for _, r := range list.Records {
		if r.Data == req.Value {
			if _, err := c.remove(zone, r.ID); err != nil {
				return abi.DNS01CleanupResult{}, err
			}
		}
	}
	return abi.DNS01CleanupResult{Removed: true}, nil
}

// remove deletes one record; one that is already gone counts as removed.
func (c *client) remove(zone string, id int64) (abi.DNS01CleanupResult, error) {
	resp, err := c.call("DELETE", "/v2/domains/"+url.PathEscape(zone)+"/records/"+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	if resp.Status == 204 || resp.Status == 404 {
		return abi.DNS01CleanupResult{Removed: true}, nil
	}
	if err := authError(resp); err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	return abi.DNS01CleanupResult{}, dns01.Refused(vendor, "deleting the TXT record", resp)
}
